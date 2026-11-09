// Normalized advisory record shared by the public page, the API, matching and the
// future CLI. This module must not import anything from the paid application.
import { z } from "zod";

export const SCHEMA_VERSION = "2026-10-22";

export const ExploitationCategory = z.enum([
  "known_exploited",
  "public_poc",
  "none_confirmed",
]);
export type ExploitationCategory = z.infer<typeof ExploitationCategory>;

export const AdvisoryStatus = z.enum(["published", "withdrawn", "superseded"]);
export type AdvisoryStatus = z.infer<typeof AdvisoryStatus>;

export const Severity = z.enum(["critical", "high", "medium", "low", "unknown"]);

export const Source = z.object({
  url: z.string().url(),
  kind: z.enum(["vendor", "ghsa", "cve", "kev", "release_notes", "brief", "other"]),
  title: z.string().optional(),
  retrieved_at: z.string().optional(),
});

// One affected range on one release branch. `introduced` inclusive, `fixed` exclusive.
// `ambiguous` marks a range whose boundary is disputed between sources; matching
// treats it as unknown rather than guessing.
export const VersionRange = z.object({
  introduced: z.string().nullable(),
  fixed: z.string().nullable(),
  last_affected: z.string().nullable().optional(),
  ambiguous: z.boolean().default(false),
  note: z.string().optional(),
});

export const AffectedProduct = z.object({
  product: z.string(), // lowercase product key, e.g. "php", "nextjs", "gitlab"
  ranges: z.array(VersionRange),
  // What to conclude for a version on a branch not covered by any range.
  other_branches: z.enum(["unknown", "not_affected"]).default("unknown"),
});

// A prerequisite the deployment must meet for the advisory to apply. `fact` names an
// observable fact (e.g. "nextjs.app_router"); null means it can only be checked by hand.
export const Condition = z.object({
  description: z.string(),
  fact: z.string().nullable(),
});

export const ExploitationEvidence = z.object({
  category: ExploitationCategory,
  source_url: z.string().url().nullable(),
  as_of: z.string().nullable(), // date the evidence was recorded
  note: z.string().optional(),
});

export const AdvisoryRecord = z.object({
  id: z.string(), // stable internal id, never changes when aliases are added
  schema_version: z.string(),
  revision: z.number().int(),
  catalog_revision: z.number().int(),
  status: AdvisoryStatus,
  title: z.string(),
  product: z.string(), // display name
  summary: z.string(),
  identifiers: z.array(z.string()), // CVE, GHSA, vendor ids; first is primary
  severity: Severity,
  cvss_score: z.number().nullable(),
  severity_source: z.string().nullable(),
  exploitation: ExploitationEvidence,
  affected: z.array(AffectedProduct),
  conditions: z.array(Condition),
  sources: z.array(Source),
  published_at: z.string().nullable(), // vendor publication date
  reviewed_at: z.string(), // when our operator reviewed this revision
  updated_at: z.string(), // when this record last changed in the catalog
  status_note: z.string().nullable(),
  uncertainty: z.array(z.string()), // machine-readable list of open questions
});
export type AdvisoryRecord = z.infer<typeof AdvisoryRecord>;
export type AffectedProduct = z.infer<typeof AffectedProduct>;
export type VersionRange = z.infer<typeof VersionRange>;
export type Condition = z.infer<typeof Condition>;

// Draft shape produced by extraction and edited by the operator before publication.
export const AdvisoryDraft = z.object({
  title: z.string(),
  product: z.string(),
  summary: z.string(),
  identifiers: z.array(z.string()),
  severity: Severity,
  cvss_score: z.number().nullable(),
  severity_source: z.string().nullable(),
  exploitation: ExploitationEvidence,
  affected: z.array(AffectedProduct),
  conditions: z.array(Condition),
  sources: z.array(Source),
  published_at: z.string().nullable(),
  uncertainty: z.array(z.string()),
  brief_excerpt: z.string(), // pointer back to the part of the brief this came from
});
export type AdvisoryDraft = z.infer<typeof AdvisoryDraft>;

// Problems that block publication of a draft. Deterministic, never model-judged.
export function draftProblems(d: AdvisoryDraft): string[] {
  const p: string[] = [];
  if (d.identifiers.length === 0) p.push("Needs at least one identifier (CVE, GHSA or vendor id).");
  if (d.sources.length === 0) p.push("Needs at least one primary source link.");
  if (d.exploitation.category !== "none_confirmed" && !d.exploitation.source_url)
    p.push("Exploitation evidence needs a cited source, or set it to 'No confirmed exploit evidence'.");
  if (d.exploitation.category === "known_exploited" && !d.exploitation.as_of)
    p.push("Known exploited needs the date of the evidence.");
  for (const a of d.affected)
    for (const r of a.ranges)
      // An all-unknown range is allowed only when explicitly marked ambiguous
      // (e.g. known exploited, fixed build not yet established).
      if (!r.introduced && !r.fixed && !r.last_affected && !r.ambiguous)
        p.push(`${a.product}: a range needs at least one boundary, or must be marked ambiguous.`);
  return p;
}

export const IDENTIFIER_RE = /^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|[A-Z][A-Z0-9]+-[A-Za-z0-9-]+)$/;

export function normalizeIdentifier(id: string): string {
  const t = id.trim();
  if (/^cve-/i.test(t)) return t.toUpperCase();
  if (/^ghsa-/i.test(t)) return "GHSA" + t.slice(4).toLowerCase();
  return t;
}
