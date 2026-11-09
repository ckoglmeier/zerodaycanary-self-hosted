import "server-only";
// Operator intake: brief → drafts → explicit publication. Publication is the only path
// into the public catalog and always creates an immutable revision.
import { createHash, randomBytes } from "node:crypto";
import { revalidatePath } from "next/cache";
import { q, one, tx } from "./db";
import { extractBrief, type LlmOutput } from "./llm/extract";
import { AdvisoryDraft, SCHEMA_VERSION, draftProblems, normalizeIdentifier, type AdvisoryRecord } from "@/intel/schema";
import { rematchAll } from "./assess";
import { rematchDevelopers } from "./developer/evaluate";
import { rematchSharedSystems } from "./review/reports";
import {HttpError} from './auth';

const sha = (s: string) => createHash("sha256").update(s.trim().replace(/\r\n/g, "\n")).digest("hex");

export function toDraft(a: LlmOutput["advisories"][number]): AdvisoryDraft {
  const isUrl = (u: string | null) => {
    if (!u) return false;
    try {
      return /^https?:$/.test(new URL(u).protocol);
    } catch {
      return false;
    }
  };
  const uncertainty = [...a.uncertainty];
  const sources = a.sources.filter((s) => isUrl(s.url));
  if (sources.length < a.sources.length) uncertainty.push("Some source entries were not valid links and were dropped.");
  return AdvisoryDraft.parse({
    title: a.title,
    product: a.product,
    summary: a.summary,
    identifiers: [...new Set(a.identifiers.map(normalizeIdentifier).filter(Boolean))],
    severity: a.severity,
    cvss_score: a.cvss_score,
    severity_source: a.severity_source,
    exploitation: {
      category: a.exploitation_category,
      source_url: isUrl(a.exploitation_source_url) ? a.exploitation_source_url : null,
      as_of: a.exploitation_as_of,
    },
    affected: a.affected.map((p) => ({
      product: p.product_key.toLowerCase(),
      other_branches: "unknown",
      ranges: p.ranges.map((r) => ({ introduced: r.introduced, fixed: r.fixed, last_affected: r.last_affected, ambiguous: r.ambiguous, note: r.note || undefined })),
    })),
    conditions: a.conditions,
    sources,
    published_at: a.published_at,
    uncertainty,
    brief_excerpt: a.brief_excerpt,
  });
}

export async function createIntake(brief: string, attribution: string | null, by: string, extractor: (brief: string, runId?: string) => ReturnType<typeof extractBrief> = extractBrief) {
  const digest = sha(brief);
  // Re-submitting the same brief returns the existing intake instead of duplicating drafts.
  const dup = await one<{ id: string }>("select id from feed_intakes where brief_sha256 = $1 and status in ('extracted','reviewed','extracting') order by created_at desc limit 1", [digest]);
  if (dup) return { id: dup.id, duplicate: true };
  const intake = (await one<{ id: string }>(
    "insert into feed_intakes (created_by, brief, brief_sha256, attribution, status) values ($1,$2,$3,$4,'extracting') returning id",
    [by, brief, digest, attribution],
  ))!;
  try {
    const { output, usage, model } = await extractor(brief, intake.id);
    await tx(async (c) => {
      for (const a of output.advisories) {
        const draft = toDraft(a);
        const match = await c.query<{ advisory_id: string }>("select advisory_id from advisory_aliases where alias = any($1) limit 1", [draft.identifiers]);
        await c.query("insert into advisory_drafts (intake_id, draft, target_advisory_id) values ($1,$2,$3)", [intake.id, JSON.stringify(draft), match.rows[0]?.advisory_id ?? null]);
      }
      // Leads are kept as rejected-by-default notes so nothing in the brief is silently lost.
      for (const lead of output.unresolved_leads)
        await c.query("insert into advisory_drafts (intake_id, draft, status, review_note) values ($1,$2,'rejected',$3)", [
          intake.id,
          JSON.stringify({ title: lead.slice(0, 200), product: "unknown", summary: lead, identifiers: [], severity: "unknown", cvss_score: null, severity_source: null, exploitation: { category: "none_confirmed", source_url: null, as_of: null }, affected: [], conditions: [], sources: [], published_at: null, uncertainty: ["Unverified lead from brief"], brief_excerpt: lead }),
          "Unverified lead (not individually verified in the brief)",
        ]);
      await c.query("update feed_intakes set status = 'extracted', model = $2, usage = $3 where id = $1", [intake.id, model, JSON.stringify(usage)]);
    });
  } catch (e) {
    await q("update feed_intakes set status = 'failed', error = $2 where id = $1", [intake.id, (e as Error).message.slice(0, 500)]);
    await q("insert into feed_reviews (intake_id, outcome, detail) values ($1,'failed',$2)", [intake.id, (e as Error).message.slice(0, 500)]);
    revalidateCatalog([]);
  }
  return { id: intake.id, duplicate: false };
}

export async function updateDraft(draftId: string, draft: unknown, targetAdvisoryId: string | null) {
  const parsed = AdvisoryDraft.parse(draft);
  parsed.identifiers = [...new Set(parsed.identifiers.map(normalizeIdentifier))];
  await q("update advisory_drafts set draft = $2, target_advisory_id = $3 where id = $1 and status = 'draft'", [draftId, JSON.stringify(parsed), targetAdvisoryId || null]);
  return parsed;
}

export async function rejectDraft(draftId: string, note: string) {
  await q("update advisory_drafts set status = 'rejected', review_note = $2, reviewed_at = now() where id = $1 and status = 'draft'", [draftId, note || "Rejected by operator"]);
}

const newId = () => "zdc-" + randomBytes(5).toString("hex");

// Publishes the selected drafts as one catalog revision, then re-matches every system.
export async function publishDrafts(intakeId: string, draftIds: string[], by: string, note: string, sourceReviewConfirmed=false) {
  const t0 = performance.now();
  const drafts = await q<{ id: string; draft: AdvisoryDraft; target_advisory_id: string | null; status: string;source_id:string|null;source_hash:string|null }>(
    "select id, draft, target_advisory_id, status,source_id,source_hash from advisory_drafts where intake_id = $1 and id = any($2)",
    [intakeId, draftIds],
  );
  const problems = drafts.flatMap((d) => (d.status !== "draft" ? [`${d.draft.title}: already ${d.status}`] : draftProblems(d.draft).map((p) => `${d.draft.title}: ${p}`)));
  if(drafts.some(d=>d.source_id)&&!sourceReviewConfirmed)problems.push('Confirm primary-source review before publishing source-feed drafts.');
  if (drafts.length === 0) problems.push("Select at least one draft.");
  if (problems.length) return { ok: false as const, problems };

  const published: string[] = [];
  const rev = await tx(async (c) => {
    const r = await c.query<{ id: string }>("insert into catalog_revisions (intake_id, note) values ($1,$2) returning id", [intakeId, note || "Nightly brief review"]);
    const revId = Number(r.rows[0].id);
    const now = new Date().toISOString();
    for (const d of drafts) {
      if(d.source_id){const current=(await c.query<{content_hash:string}>('select content_hash from source_vulnerabilities where id=$1 for share',[d.source_id])).rows[0];if(current?.content_hash!==d.source_hash)throw new HttpError(409,'Source record changed after this draft was prepared; prepare a fresh review draft.');}
      // Identify an existing record by explicit target or by any shared alias, keeping its stable id.
      const existing = d.target_advisory_id
        ? d.target_advisory_id
        : (await c.query<{ advisory_id: string }>("select advisory_id from advisory_aliases where alias = any($1) limit 1", [d.draft.identifiers])).rows[0]?.advisory_id;
      const prev = existing ? (await c.query<{ revision: number }>("select revision from advisories where id = $1 for update", [existing])).rows[0] : undefined;
      const id = existing ?? newId();
      const revision = (prev?.revision ?? 0) + 1;
      const { brief_excerpt: _excerpt, ...fields } = d.draft;
      void _excerpt;
      const record: AdvisoryRecord = {
        ...fields,
        id,
        schema_version: SCHEMA_VERSION,
        revision,
        catalog_revision: revId,
        status: "published",
        reviewed_at: now,
        updated_at: now,
        status_note: null,
      };
      const search = [record.product, record.title, ...record.identifiers, ...record.affected.map((a) => a.product)].join(" ").toLowerCase();
      await c.query(
        `insert into advisories (id, status, revision, catalog_revision, record, exploitation, severity, product, identifiers, search, reviewed_at, updated_at)
         values ($1,'published',$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)
         on conflict (id) do update set status = 'published', revision = excluded.revision, catalog_revision = excluded.catalog_revision, record = excluded.record,
           exploitation = excluded.exploitation, severity = excluded.severity, product = excluded.product, identifiers = excluded.identifiers,
           search = excluded.search, reviewed_at = excluded.reviewed_at, updated_at = excluded.updated_at`,
        [id, revision, revId, JSON.stringify(record), record.exploitation.category, record.severity, record.product, record.identifiers, search, now],
      );
      await c.query("insert into advisory_revisions (advisory_id, revision, catalog_revision, record, change_note, created_by) values ($1,$2,$3,$4,$5,$6)", [
        id, revision, revId, JSON.stringify(record), prev ? "Updated from reviewed brief" : "Published from reviewed brief", by,
      ]);
      for (const alias of record.identifiers) {
        const owner = await c.query<{ advisory_id: string }>("insert into advisory_aliases (alias, advisory_id) values ($1,$2) on conflict (alias) do nothing returning advisory_id", [alias, id]);
        if (!owner.rows.length) {
          const cur = await c.query<{ advisory_id: string }>("select advisory_id from advisory_aliases where alias = $1", [alias]);
          if (cur.rows[0]?.advisory_id !== id) throw new Error(`Identifier ${alias} already belongs to ${cur.rows[0]?.advisory_id}; resolve the duplicate before publishing.`);
        }
      }
      await c.query("update advisory_drafts set status = 'published', published_advisory_id = $2, reviewed_at = now() where id = $1", [d.id, id]);
      published.push(id);
    }
    await c.query("insert into feed_reviews (intake_id, outcome, catalog_revision, detail) values ($1,'published',$2,$3)", [intakeId, revId, `${published.length} record(s)`]);
    await c.query("update feed_intakes set status = 'reviewed' where id = $1", [intakeId]);
    return revId;
  });
  revalidateCatalog(published);
  try {
    const rematch = await rematchAll(`catalog revision ${rev}`);
    const developer = await rematchDevelopers(`catalog revision ${rev}`);
    await rematchSharedSystems();
    const { recordOperation } = await import("./usage");
    await recordOperation("catalog_publication_rematch", "shared_feed", "completed", performance.now() - t0, 0);
    return { ok: true as const, catalog_revision: rev, published, rematch, developer };
  } finally {
    // Post-publication matching can take seconds. Expire again at completion,
    // including if matching fails, before returning the operator response.
    revalidateCatalog(published);
  }
}

export async function recordNoChanges(intakeId: string) {
  const result = await tx(async (c) => {
    const intake = (await c.query<{ status: string }>("select status from feed_intakes where id = $1 for update", [intakeId])).rows[0];
    if (intake?.status !== "extracted") return { ok: false as const, problem: "Only a successfully extracted, unreviewed brief can be recorded as no changes." };
    const pending = (await c.query("select id from advisory_drafts where intake_id = $1 and status = 'draft' limit 1", [intakeId])).rows.length;
    if (pending) return { ok: false as const, problem: "Review or reject the remaining drafts before recording no changes." };
    await c.query("insert into feed_reviews (intake_id, outcome, detail) values ($1,'no_changes','Reviewed; no new or changed alerts')", [intakeId]);
    await c.query("update feed_intakes set status = 'reviewed' where id = $1", [intakeId]);
    return { ok: true as const };
  });
  if (result.ok) revalidateCatalog([]);
  return result;
}

// Withdraw/supersede keeps the record and history; API clients see the status change.
export async function changeStatus(advisoryId: string, status: "withdrawn" | "superseded" | "published", note: string, by: string) {
  const rev = await tx(async (c) => {
    const cur = (await c.query<{ record: AdvisoryRecord; revision: number }>("select record, revision from advisories where id = $1 for update", [advisoryId])).rows[0];
    if (!cur) throw new Error("Alert not found");
    const r = await c.query<{ id: string }>("insert into catalog_revisions (note) values ($1) returning id", [`${status}: ${advisoryId}`]);
    const revId = Number(r.rows[0].id);
    const now = new Date().toISOString();
    const record: AdvisoryRecord = { ...cur.record, status, status_note: note, revision: cur.revision + 1, catalog_revision: revId, updated_at: now, reviewed_at: now };
    await c.query("update advisories set status = $2, revision = $3, catalog_revision = $4, record = $5, updated_at = $6 where id = $1", [advisoryId, status, record.revision, revId, JSON.stringify(record), now]);
    await c.query("insert into advisory_revisions (advisory_id, revision, catalog_revision, record, change_note, created_by) values ($1,$2,$3,$4,$5,$6)", [advisoryId, record.revision, revId, JSON.stringify(record), `Status → ${status}: ${note}`, by]);
    await c.query("insert into feed_reviews (outcome, catalog_revision, detail) values ('published',$1,$2)", [revId, `${advisoryId} ${status}`]);
    return revId;
  });
  revalidateCatalog([advisoryId]);
  try {
    await rematchAll(`catalog revision ${rev}`);
    await rematchDevelopers(`catalog revision ${rev}`);
    await rematchSharedSystems();
    return rev;
  } finally {
    revalidateCatalog([advisoryId]);
  }
}

function revalidateCatalog(ids: string[]) {
  try {
    // Match the shared route-group tag as well as concrete URLs. Includes all
    // catalog views, metadata and stable-id / alias detail pages.
    revalidatePath("/(public)", "layout");
    revalidatePath("/");
    revalidatePath("/advisories");
    revalidatePath("/about");
    revalidatePath("/(public)/advisory/[id]", "page");
    revalidatePath("/advisories/poc");
    revalidatePath("/advisories/all");
    revalidatePath("/(public)/advisories/[view]", "page");
    for (const id of ids) revalidatePath(`/advisory/${id}`);
  } catch {
    // Outside a request (scripts/tests): nothing to revalidate.
  }
}
