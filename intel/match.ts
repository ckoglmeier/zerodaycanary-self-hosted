// Deterministic matching of evidence against reviewed alert records.
// No model calls and no guessing: anything uncertain comes back as needs_verification.
import type { AdvisoryRecord, AffectedProduct, VersionRange } from "./schema";
import type { EvidenceSet, TechObservation, VersionBasis } from "./evidence";
import { branchOf, compareVersions, parseVersion, type ParsedVersion } from "./version";

export type AssessmentStatus =
  | "needs_verification"
  | "affected_version_matched"
  | "applicability_confirmed"
  | "fix_verified"
  | "not_affected"
  | "not_assessed";

export const STATUS_LABEL: Record<AssessmentStatus, string> = {
  needs_verification: "Needs verification",
  affected_version_matched: "Affected version matched",
  applicability_confirmed: "Applicability confirmed",
  fix_verified: "Fixed, confirmed by evidence",
  not_affected: "Unaffected by this vulnerability",
  not_assessed: "Not assessed / incomplete",
};

// Higher = needs attention sooner. Used only to order findings, never shown as a score.
export const STATUS_RANK: Record<AssessmentStatus, number> = {
  applicability_confirmed: 5,
  affected_version_matched: 4,
  needs_verification: 3,
  not_assessed: 2,
  fix_verified: 1,
  not_affected: 0,
};

export type ConditionState = { description: string; fact: string | null; state: "met" | "unmet" | "unknown" };

export type AdvisoryAssessment = {
  advisory_id: string;
  advisory_revision: number;
  primary_identifier: string;
  title: string;
  product: string;
  status: AssessmentStatus;
  reason: string;
  next_step: string;
  version_used: string | null;
  version_basis: VersionBasis | null;
  matched_range: VersionRange | null;
  conditions: ConditionState[];
  evidence_location: string | null;
};

type Prior = Pick<AdvisoryAssessment, "status" | "advisory_id"> & { observed_at: string | null };

function inRange(v: ParsedVersion, r: VersionRange): boolean | null {
  const intro = r.introduced ? parseVersion(r.introduced) : null;
  const fixed = r.fixed ? parseVersion(r.fixed) : null;
  const last = r.last_affected ? parseVersion(r.last_affected) : null;
  if ((r.introduced && !intro) || (r.fixed && !fixed) || (r.last_affected && !last)) return null;
  if (intro && compareVersions(v, intro) < 0) return false;
  if (fixed) return compareVersions(v, fixed) < 0;
  if (last) return compareVersions(v, last) <= 0;
  return true;
}

// Does the range span the version's major.minor branch? Used to decide whether a
// version outside every range is on a branch the advisory actually speaks about.
function rangeTouchesBranch(v: ParsedVersion, r: VersionRange): boolean {
  const lo = r.introduced ? parseVersion(r.introduced) : null;
  const hiRaw = r.fixed ?? r.last_affected ?? null;
  const hi = hiRaw ? parseVersion(hiRaw) : null;
  const b = parseVersion(branchOf(v)) as ParsedVersion;
  const lb = lo ? (parseVersion(branchOf(lo)) as ParsedVersion) : null;
  const hb = hi ? (parseVersion(branchOf(hi)) as ParsedVersion) : null;
  if (lb && compareVersions(b, lb) < 0) return false;
  if (hb && compareVersions(b, hb) > 0) return false;
  return true;
}

function pickVersion(techs: TechObservation[]):
  | { kind: "none" }
  | { kind: "inferred"; tech: TechObservation }
  | { kind: "conflict"; versions: string[] }
  | { kind: "ok"; tech: TechObservation } {
  const usable = techs.filter((t) => t.version && (t.version_basis === "observed" || t.version_basis === "admin_supplied" || t.version_basis === "developer_supplied"));
  if (usable.length === 0) {
    const inf = techs.find((t) => t.version && t.version_basis === "inferred");
    return inf ? { kind: "inferred", tech: inf } : { kind: "none" };
  }
  const distinct = [...new Set(usable.map((t) => t.version as string))];
  if (distinct.length > 1) return { kind: "conflict", versions: distinct };
  // Prefer a public observation over administrator-supplied evidence of the same version.
  return { kind: "ok", tech: usable.find((t) => t.version_basis === "observed") ?? usable[0] };
}

const NEXT_STEP = {
  ask_version: (p: string) => `Ask the system owner or developer which exact ${p} version is running, or add version evidence.`,
  check_conditions: (c: string[]) => `Ask whether these conditions apply: ${c.join("; ")}.`,
  update: (r: VersionRange | null, p: string) =>
    r?.fixed ? `Update ${p} to ${r.fixed} or later on this branch (or apply the vendor's fix), then re-analyze.` : `Apply the vendor's fix for ${p}, then re-analyze.`,
  none: "No action needed for this vulnerability.",
  refresh: "Request a fresh analysis.",
  vendor: (p: string) => `Ask the system owner or vendor whether this ${p} build includes the fix.`,
};

export function assessAdvisory(
  advisory: AdvisoryRecord,
  evidence: EvidenceSet,
  prior?: Prior,
): AdvisoryAssessment[] {
  if (advisory.status !== "published") return [];
  const out: AdvisoryAssessment[] = [];
  for (const ap of advisory.affected) {
    const techs = evidence.techs.filter((t) => t.product === ap.product);
    if (techs.length === 0) continue; // product not detected: no claim either way
    out.push(assessProduct(advisory, ap, techs, evidence, prior));
  }
  return out;
}

function assessProduct(
  advisory: AdvisoryRecord,
  ap: AffectedProduct,
  techs: TechObservation[],
  evidence: EvidenceSet,
  prior?: Prior,
): AdvisoryAssessment {
  const base = {
    advisory_id: advisory.id,
    advisory_revision: advisory.revision,
    primary_identifier: advisory.identifiers[0] ?? advisory.id,
    title: advisory.title,
    product: techs[0].name,
    conditions: advisory.conditions.map((c) => ({
      description: c.description,
      fact: c.fact,
      state: (c.fact && c.fact in evidence.facts ? (evidence.facts[c.fact] ? "met" : "unmet") : "unknown") as ConditionState["state"],
    })),
  };
  const pick = pickVersion(techs);
  const result = (
    status: AssessmentStatus,
    reason: string,
    next_step: string,
    t: TechObservation | null,
    r: VersionRange | null = null,
  ): AdvisoryAssessment => ({
    ...base,
    status,
    reason,
    next_step,
    version_used: t?.version ?? null,
    version_basis: t?.version_basis ?? null,
    matched_range: r,
    evidence_location: t?.location ?? techs[0].location,
  });

  if (pick.kind === "none")
    return result("needs_verification", `${techs[0].name} detected, but its version is not visible.`, NEXT_STEP.ask_version(techs[0].name), null);
  if (pick.kind === "inferred")
    return result(
      "needs_verification",
      `${pick.tech.name} version ${pick.tech.version} is only inferred, not observed.`,
      NEXT_STEP.ask_version(pick.tech.name),
      null,
    );
  if (pick.kind === "conflict")
    return result(
      "needs_verification",
      `Conflicting ${techs[0].name} versions in evidence: ${pick.versions.join(", ")}.`,
      NEXT_STEP.ask_version(techs[0].name),
      null,
    );

  const tech = pick.tech;
  const v = parseVersion(tech.version as string);
  if (!v)
    return result("needs_verification", `Version "${tech.version}" could not be parsed.`, NEXT_STEP.ask_version(tech.name), tech);

  let hit: VersionRange | null = null;
  for (const r of ap.ranges) {
    const ir = inRange(v, r);
    if (ir === null)
      return result("needs_verification", "The alert's version range could not be interpreted.", NEXT_STEP.ask_version(tech.name), tech, r);
    if (ir) {
      hit = r;
      break;
    }
  }

  if (hit) {
    if (hit.ambiguous)
      return result(
        "needs_verification",
        `Version ${tech.version} falls in a range whose boundary is disputed between sources${hit.note ? `: ${hit.note}` : "."}`,
        NEXT_STEP.vendor(tech.name),
        tech,
        hit,
      );
    if (v.distro)
      return result(
        "needs_verification",
        `Version ${tech.version} is a distribution build; the vendor may have backported the fix.`,
        NEXT_STEP.vendor(tech.name),
        tech,
        hit,
      );
    const unmet = base.conditions.filter((c) => c.state === "unmet");
    if (unmet.length)
      return result(
        "not_affected",
        `Version ${tech.version} is in the affected range, but a required condition is absent: ${unmet.map((c) => c.description).join("; ")}.`,
        NEXT_STEP.none,
        tech,
        hit,
      );
    const unknown = base.conditions.filter((c) => c.state === "unknown");
    if (base.conditions.length > 0 && unknown.length === 0)
      return result(
        "applicability_confirmed",
        `Version ${tech.version} is affected and the vulnerability's prerequisites were observed. This is not evidence of an attack.`,
        NEXT_STEP.update(hit, tech.name),
        tech,
        hit,
      );
    return result(
      "affected_version_matched",
      `Version ${tech.version} is within the affected range${hit.fixed ? ` (fixed in ${hit.fixed})` : ""}.${unknown.length ? " Prerequisites are not confirmed." : ""}`,
      unknown.length ? NEXT_STEP.update(hit, tech.name) + " " + NEXT_STEP.check_conditions(unknown.map((c) => c.description)) : NEXT_STEP.update(hit, tech.name),
      tech,
      hit,
    );
  }

  // Outside every range. A version at or above every fixed release is past the advisory
  // (OSV semantics); only older branches the advisory does not list stay unknown.
  const fixedVersions = ap.ranges.filter((r) => !r.ambiguous && r.fixed).map((r) => parseVersion(r.fixed as string)).filter((x): x is ParsedVersion => !!x);
  const pastAll = fixedVersions.length > 0 && !ap.ranges.some((r) => r.ambiguous) && fixedVersions.every((f) => compareVersions(v, f) >= 0);
  const branchCovered = pastAll || ap.ranges.some((r) => !r.ambiguous && rangeTouchesBranch(v, r));
  const ambiguousNear = ap.ranges.some((r) => r.ambiguous && rangeTouchesBranch(v, r));
  if (!branchCovered && (ambiguousNear || ap.other_branches === "unknown"))
    return result(
      "needs_verification",
      `Version ${tech.version} is on a release branch this alert does not list; it may be end-of-life or unassessed.`,
      NEXT_STEP.vendor(tech.name),
      tech,
    );

  const wasAffected = prior && (prior.status === "affected_version_matched" || prior.status === "applicability_confirmed");
  const newerEvidence = prior && tech.observed_at && (!prior.observed_at || tech.observed_at > prior.observed_at);
  if (wasAffected && newerEvidence && tech.version_basis === "observed")
    return result(
      "fix_verified",
      `A newer public observation shows ${tech.name} ${tech.version}, outside the affected range for this vulnerability.`,
      NEXT_STEP.none,
      tech,
    );
  return result("not_affected", `Version ${tech.version} is outside the affected ranges for this vulnerability.`, NEXT_STEP.none, tech);
}

export function assessAll(advisories: AdvisoryRecord[], evidence: EvidenceSet, prior: Prior[] = []): AdvisoryAssessment[] {
  const byId = new Map(prior.map((p) => [p.advisory_id, p]));
  return advisories
    .flatMap((a) => assessAdvisory(a, evidence, byId.get(a.id)))
    .sort((x, y) => STATUS_RANK[y.status] - STATUS_RANK[x.status]);
}

export function strongest(results: AdvisoryAssessment[]): AdvisoryAssessment | null {
  return results.reduce<AdvisoryAssessment | null>((b, r) => (!b || STATUS_RANK[r.status] > STATUS_RANK[b.status] ? r : b), null);
}

export function catalogCoverage(advisories: AdvisoryRecord[]): string[] {
  return [...new Set(advisories.filter((a) => a.status === "published").flatMap((a) => a.affected.map((p) => p.product)))].sort();
}
