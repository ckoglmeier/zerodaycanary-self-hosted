// Groups per-advisory results into one concern per piece of software and phrases the one
// precise question a system owner or developer can answer. Pure: used by pages, the owner
// request and the evidence report. Never upgrades a status; only summarizes it.
import { STATUS_RANK, type AdvisoryAssessment, type AssessmentStatus } from "@/intel/match";

export type Concern = {
  product: string;
  version: string | null;
  basis: AdvisoryAssessment["version_basis"];
  open: AdvisoryAssessment[]; // still needs an answer
  closed: AdvisoryAssessment[]; // unaffected by / fixed for a specific advisory
  worst: AssessmentStatus;
  question: string | null;
  nextStep: string | null;
};

const OPEN: AssessmentStatus[] = ["applicability_confirmed", "affected_version_matched", "needs_verification", "not_assessed"];
const ids = (rs: AdvisoryAssessment[]) => rs.map((r) => r.primary_identifier).join(", ");

export function groupConcerns(results: AdvisoryAssessment[], systemName: string): Concern[] {
  const by = new Map<string, AdvisoryAssessment[]>();
  for (const r of results) by.set(r.product, [...(by.get(r.product) ?? []), r]);
  const out: Concern[] = [];
  for (const [product, rs] of by) {
    const open = rs.filter((r) => OPEN.includes(r.status)).sort((a, b) => STATUS_RANK[b.status] - STATUS_RANK[a.status]);
    const closed = rs.filter((r) => !OPEN.includes(r.status));
    const withVersion = rs.find((r) => r.version_used);
    const version = withVersion?.version_used ?? null;
    const worst = (open[0] ?? closed[0]).status;
    out.push({ product, version, basis: withVersion?.version_basis ?? null, open, closed, worst, question: question(product, version, open, systemName), nextStep: open[0]?.next_step ?? null });
  }
  return out.sort((a, b) => STATUS_RANK[b.worst] - STATUS_RANK[a.worst]);
}

function question(product: string, version: string | null, open: AdvisoryAssessment[], system: string): string | null {
  if (open.length === 0) return null;
  if (!version || open.some((r) => !r.version_used)) return `Which exact version of ${product} does ${system} run? (Alerts to check: ${ids(open)}.)`;
  const affected = open.filter((r) => r.status === "affected_version_matched" || r.status === "applicability_confirmed");
  if (affected.length) {
    const fixed = [...new Set(affected.map((r) => r.matched_range?.fixed).filter(Boolean))];
    const conds = [...new Set(affected.flatMap((r) => r.conditions.filter((c) => c.state === "unknown").map((c) => c.description)))];
    return (
      `Is ${system} still running ${product} ${version}? If so, can it be updated${fixed.length ? ` to ${fixed.join(" / ")} or later` : ""}? (${ids(affected)}.)` +
      (conds.length ? ` These vulnerabilities only apply if: ${conds.join("; ")}. Does that describe ${system}?` : "")
    );
  }
  return `Does the ${product} ${version} build on ${system} include the fixes for ${ids(open)}?`;
}
