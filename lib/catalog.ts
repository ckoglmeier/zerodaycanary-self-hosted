import "server-only";
// Read access to the published catalog. Page and API both read from here, so they
// always represent the same catalog revision.
import { q, one } from "./db";
import type { AdvisoryRecord } from "@/intel/schema";
import { normalizeIdentifier } from "@/intel/schema";

export type CatalogMeta = {
  catalog_revision: number;
  catalog_updated_at: string | null;
  last_successful_review_at: string | null;
  last_review_outcome: string | null;
  last_failure_at: string | null;
};

export async function catalogMeta(): Promise<CatalogMeta> {
  const rev = await one<{ id: string; created_at: Date }>("select id, created_at from catalog_revisions order by id desc limit 1");
  // A status edit is a catalog change, not a review of the incoming feed. Test
  // intakes remain auditable but must neither clear a real failure nor create one.
  const ok = await one<{ created_at: Date; outcome: string }>(`select r.created_at, r.outcome
    from feed_reviews r join feed_intakes i on i.id = r.intake_id
    where not i.is_test and r.outcome in ('published','no_changes')
    order by r.created_at desc, r.id desc limit 1`);
  const fail = await one<{ created_at: Date }>(`select r.created_at
    from feed_reviews r left join feed_intakes i on i.id = r.intake_id
    where r.outcome = 'failed' and not coalesce(i.is_test, false)
    order by r.created_at desc, r.id desc limit 1`);
  return {
    catalog_revision: rev ? Number(rev.id) : 0,
    catalog_updated_at: rev ? rev.created_at.toISOString() : null,
    last_successful_review_at: ok ? ok.created_at.toISOString() : null,
    last_review_outcome: ok?.outcome ?? null,
    last_failure_at: fail && (!ok || fail.created_at > ok.created_at) ? fail.created_at.toISOString() : null,
  };
}

export async function allAdvisories(opts: { includeInactive?: boolean; featuredOnly?: boolean } = {}): Promise<AdvisoryRecord[]> {
  const where=[...(!opts.includeInactive?["status = 'published'"]:[]),...(opts.featuredOnly?["featured = true"]:[])];
  const rows = await q<{ record: AdvisoryRecord }>(
    `select record from advisories ${where.length?'where '+where.join(' and '):''} order by updated_at desc, id`,
  );
  return rows.map((r) => r.record);
}

export async function getAdvisory(idOrAlias: string): Promise<{ record: AdvisoryRecord; history: { revision: number; change_note: string; created_at: string }[] } | null> {
  const key = normalizeIdentifier(decodeURIComponent(idOrAlias));
  const row =
    (await one<{ id: string; record: AdvisoryRecord }>("select id, record from advisories where id = $1", [key])) ??
    (await one<{ id: string; record: AdvisoryRecord }>("select a.id, a.record from advisory_aliases x join advisories a on a.id = x.advisory_id where x.alias = $1", [key]));
  if (!row) return null;
  const history = await q<{ revision: number; change_note: string; created_at: Date }>(
    "select revision, change_note, created_at from advisory_revisions where advisory_id = $1 order by revision desc",
    [row.id],
  );
  return { record: row.record, history: history.map((h) => ({ ...h, created_at: h.created_at.toISOString() })) };
}

export type ListParams = {
  exploitation?: string;
  product?: string;
  identifier?: string;
  severity?: string;
  status?: string; // published (default), withdrawn, superseded, all
  updated_since?: string;
  cursor?: string;
  limit?: number;
};

// Deterministic keyset pagination on (catalog_revision, id). With updated_since the
// stream includes corrections, status changes and withdrawals in order of change.
export async function listAdvisories(p: ListParams) {
  const limit = Math.min(Math.max(p.limit ?? 50, 1), 200);
  const where: string[] = [];
  const args: unknown[] = [];
  const arg = (v: unknown) => {
    args.push(v);
    return `$${args.length}`;
  };
  const incremental = !!p.updated_since;
  if (!incremental && (!p.status || p.status === "published")) where.push(`status = 'published'`);
  else if (p.status && p.status !== "all" && p.status !== "published") where.push(`status = ${arg(p.status)}`);
  if (p.exploitation) where.push(`exploitation = ${arg(p.exploitation)}`);
  if (p.severity) where.push(`severity = ${arg(p.severity)}`);
  if (p.product) where.push(`search like ${arg("%" + p.product.toLowerCase() + "%")}`);
  if (p.identifier) where.push(`${arg(normalizeIdentifier(p.identifier))} = any(identifiers)`);
  if (p.updated_since) where.push(`updated_at > ${arg(new Date(p.updated_since).toISOString())}`);
  if (p.cursor) {
    const [rev, id] = Buffer.from(p.cursor, "base64url").toString().split(":");
    where.push(`(catalog_revision, id) > (${arg(Number(rev))}, ${arg(id)})`);
  }
  const rows = await q<{ record: AdvisoryRecord; catalog_revision: string; id: string }>(
    `select record, catalog_revision, id from advisories ${where.length ? "where " + where.join(" and ") : ""}
     order by catalog_revision, id limit ${limit + 1}`,
    args,
  );
  const page = rows.slice(0, limit);
  const last = page[page.length - 1];
  const next = rows.length > limit && last ? Buffer.from(`${last.catalog_revision}:${last.id}`).toString("base64url") : null;
  return { data: page.map((r) => r.record), next_cursor: next };
}
