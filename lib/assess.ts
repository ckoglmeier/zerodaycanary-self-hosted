import "server-only";
// Re-evaluates systems against the current catalog without refetching sites or calling a
// model (CACHE-2). Public observations come from the shared cache; administrator evidence
// is private to its workspace and only ever joins that workspace's assessment.
import { q, one } from "./db";
import { allAdvisories, catalogMeta } from "./catalog";
import { assessAll, catalogCoverage, strongest, STATUS_LABEL, type AdvisoryAssessment, type AssessmentStatus } from "@/intel/match";
import type { EvidenceGap, EvidenceSet, TechObservation } from "@/intel/evidence";
import { techName } from "./scan/detect";
import { syncFindings, syncInactiveFindings } from "./review/findings";

export type ObservationRow = {
  id: string;
  scope_id: string;
  observed_at: Date;
  outcome: "complete" | "partial" | "failed";
  final_url: string | null;
  evidence: { techs: TechObservation[]; facts: Record<string, boolean> };
  gaps: EvidenceGap[];
  trigger: string;
};

export type AssessmentSummary = {
  strongest: { status: AssessmentStatus; label: string; advisory: string; title: string; next_step: string } | null;
  counts: Partial<Record<AssessmentStatus, number>>;
  coverage: string[];
  uncovered: string[];
  gaps: EvidenceGap[];
  observation: { id: string | null; observed_at: string | null; outcome: string | null; trigger: string | null };
  last_attempt: { observed_at: string; outcome: string } | null;
  catalog_revision: number;
  admin_evidence: number;
};

export async function latestSuccessfulObservation(scopeId: string): Promise<ObservationRow | null> {
  return one<ObservationRow>("select * from observations where scope_id = $1 and outcome <> 'failed' order by observed_at desc limit 1", [scopeId]);
}
export async function latestObservation(scopeId: string): Promise<ObservationRow | null> {
  return one<ObservationRow>("select * from observations where scope_id = $1 order by observed_at desc limit 1", [scopeId]);
}

type SystemRow = { id: string; workspace_id: string; scope_id: string };

export async function assessSystem(systemId: string, reason: string): Promise<{ changed: boolean }> {
  const sys = await one<SystemRow>("select id, workspace_id, scope_id from systems where id = $1 and removed_at is null", [systemId]);
  if (!sys) return { changed: false };
  const [advisories, meta, obs, lastAttempt, adminRows, prev] = await Promise.all([
    allAdvisories(),
    catalogMeta(),
    latestSuccessfulObservation(sys.scope_id),
    latestObservation(sys.scope_id),
    q<{ product: string; version: string; note: string | null; created_at: Date }>(
      "select product, version, note, created_at from system_evidence where system_id = $1 and workspace_id = $2 order by created_at",
      [sys.id, sys.workspace_id],
    ),
    one<{ results: AdvisoryAssessment[]; summary: AssessmentSummary }>("select results, summary from assessments where system_id = $1 order by computed_at desc limit 1", [sys.id]),
  ]);

  const adminTechs: TechObservation[] = adminRows.map((r) => ({
    product: r.product, name: techName(r.product), version: r.version, version_basis: "admin_supplied", evidence_type: "administrator",
    location: "administrator-supplied", detail: r.note ?? "Version supplied by the workspace administrator", confidence: "medium",
    observed_at: r.created_at.toISOString(), limitations: ["Supplied by the administrator; not independently observed."],
  }));
  const evidence: EvidenceSet = {
    techs: [...(obs?.evidence.techs ?? []), ...adminTechs],
    facts: obs?.evidence.facts ?? {},
    observed_at: obs ? obs.observed_at.toISOString() : null,
  };

  const priorObservedAt = prev?.summary.observation.observed_at ?? null;
  const prior = (prev?.results ?? []).map((r) => ({ advisory_id: r.advisory_id, status: r.status, observed_at: priorObservedAt }));
  let results = obs || adminTechs.length ? assessAll(advisories, evidence, prior) : [];
  // A fix stays verified for an advisory until the evidence changes again.
  results = results.map((r) => {
    const p = prev?.results.find((x) => x.advisory_id === r.advisory_id);
    if (p?.status === "fix_verified" && r.status === "not_affected" && evidence.observed_at === priorObservedAt) return { ...r, status: "fix_verified", reason: p.reason };
    return r;
  });

  const coverage = catalogCoverage(advisories);
  const products = [...new Set(evidence.techs.map((t) => t.product))];
  const s = strongest(results);
  const counts: AssessmentSummary["counts"] = {};
  for (const r of results) counts[r.status] = (counts[r.status] ?? 0) + 1;
  const summary: AssessmentSummary = {
    strongest: s ? { status: s.status, label: STATUS_LABEL[s.status], advisory: s.primary_identifier, title: s.title, next_step: s.next_step } : null,
    counts,
    coverage,
    uncovered: products.filter((p) => !coverage.includes(p)).map(techName),
    gaps: obs?.gaps ?? [],
    observation: { id: obs?.id ?? null, observed_at: obs ? obs.observed_at.toISOString() : null, outcome: obs?.outcome ?? null, trigger: obs?.trigger ?? null },
    last_attempt: lastAttempt ? { observed_at: lastAttempt.observed_at.toISOString(), outcome: lastAttempt.outcome } : null,
    catalog_revision: meta.catalog_revision,
    admin_evidence: adminTechs.length,
  };

  const sig = (rs: AdvisoryAssessment[]) => JSON.stringify(rs.map((r) => [r.advisory_id, r.advisory_revision, r.status, r.version_used]).sort());
  const changed = !prev || sig(prev.results) !== sig(results) || prev.summary.observation.id !== summary.observation.id || prev.summary.catalog_revision !== summary.catalog_revision || prev.summary.last_attempt?.observed_at !== summary.last_attempt?.observed_at;
  if (obs || adminTechs.length) await syncFindings(sys.workspace_id, sys.id, results.map(result => {
    const tech = evidence.techs.find(t => t.name === result.product);
    const product = tech?.product ?? result.product.toLowerCase();
    return { result, product, componentKey: product, sourceKind: "public" as const,
      sourceAt: tech?.observed_at ?? obs?.observed_at.toISOString() ?? new Date().toISOString(),
      sourceId: `${obs?.id ?? 'admin'}:${tech?.version_basis ?? 'unknown'}:${tech?.version ?? 'unknown'}` };
  }));
  await syncInactiveFindings(sys.workspace_id,sys.id);
  if (!changed) return { changed: false };

  await q(
    "insert into assessments (workspace_id, system_id, observation_id, catalog_revision, results, summary) values ($1,$2,$3,$4,$5,$6)",
    [sys.workspace_id, sys.id, obs?.id ?? null, meta.catalog_revision || null, JSON.stringify(results), JSON.stringify(summary)],
  );
  // In-app updates for meaningful status changes.
  for (const r of results) {
    const p = prev?.results.find((x) => x.advisory_id === r.advisory_id);
    if (!p || p.status !== r.status)
      await q("insert into system_events (workspace_id, system_id, kind, detail) values ($1,$2,'finding_changed',$3)", [
        sys.workspace_id, sys.id, JSON.stringify({ advisory: r.primary_identifier, title: r.title, from: p?.status ?? null, to: r.status, reason, catalog_revision: meta.catalog_revision }),
      ]);
  }
  return { changed: true };
}

export async function rematchScope(scopeId: string, reason: string) {
  const rows = await q<{ id: string }>("select id from systems where scope_id = $1 and removed_at is null", [scopeId]);
  for (const r of rows) await assessSystem(r.id, reason);
  return rows.length;
}

// Bounded batch over all systems; returns how many were re-evaluated.
export async function rematchAll(reason: string, limit = 500) {
  const rows = await q<{ id: string }>("select id from systems where removed_at is null order by created_at limit $1", [limit]);
  let changed = 0;
  for (const r of rows) if ((await assessSystem(r.id, reason)).changed) changed++;
  return { systems: rows.length, changed };
}
