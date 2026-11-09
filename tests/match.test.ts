import { describe, expect, it } from "vitest";
import { assessAdvisory, type AssessmentStatus } from "../intel/match";
import type { EvidenceSet, TechObservation } from "../intel/evidence";
import { NEXT_CACHE, NEXT_SVG, PHP_OOM, PLEX_KEV } from "../intel/fixtures/advisories";
import { cmp } from "../intel/version";
import { draftProblems } from "../intel/schema";

const T0 = "2026-10-22T00:00:00Z";
const tech = (product: string, version: string | null, basis: TechObservation["version_basis"] = "observed", at = T0): TechObservation => ({
  product,
  name: product,
  version,
  version_basis: version ? basis : null,
  evidence_type: "header",
  location: "https://example.test/",
  detail: "fixture",
  confidence: "high",
  observed_at: at,
  limitations: [],
});
const ev = (techs: TechObservation[], facts: Record<string, boolean> = {}): EvidenceSet => ({ techs, facts, observed_at: T0 });
const status = (a: Parameters<typeof assessAdvisory>[0], e: EvidenceSet, prior?: Parameters<typeof assessAdvisory>[2]): AssessmentStatus | undefined =>
  assessAdvisory(a, e, prior)[0]?.status;

describe("version comparison", () => {
  it("orders prereleases before releases", () => {
    expect(cmp("16.4.1-canary.3", "16.4.1")).toBe(-1);
    expect(cmp("16.4.1-canary.10", "16.4.1-canary.9")).toBe(1);
    expect(cmp("8.2.35", "8.2.4")).toBe(1);
    expect(cmp("v1.2", "1.2.0")).toBe(0);
  });
});

describe("PHP branch boundaries (A09)", () => {
  it.each([
    ["8.2.34", "affected_version_matched"],
    ["8.2.35", "not_affected"],
    ["8.3.35", "affected_version_matched"],
    ["8.3.36", "not_affected"],
    ["8.4.27", "not_affected"],
    ["8.5.11", "affected_version_matched"],
    ["8.5.12", "not_affected"],
    ["7.4.33", "needs_verification"], // EOL branch not listed
    ["8.1.30", "needs_verification"],
    ["8.6.0", "not_affected"], // newer than every fixed release
    ["9.0.0", "not_affected"],
  ] as const)("%s → %s", (v, s) => {
    expect(status(PHP_OOM, ev([tech("php", v)]))).toBe(s);
  });

  it("treats distro builds in range as needing vendor confirmation (backports)", () => {
    expect(status(PHP_OOM, ev([tech("php", "8.2.20-1ubuntu0.2")]))).toBe("needs_verification");
    expect(status(PHP_OOM, ev([tech("php", "8.2.20+deb12u1")]))).toBe("needs_verification");
  });

  it("PHP detected without a version needs verification, never 'not affected'", () => {
    expect(status(PHP_OOM, ev([tech("php", null)]))).toBe("needs_verification");
  });

  it("no PHP evidence produces no claim", () => {
    expect(assessAdvisory(PHP_OOM, ev([tech("wordpress", "6.8.1")]))).toEqual([]);
  });
});

describe("Next.js distinct ranges and prerequisites (A09)", () => {
  it("cache issue needs App Router to confirm applicability", () => {
    expect(status(NEXT_CACHE, ev([tech("nextjs", "16.2.0")]))).toBe("affected_version_matched");
    expect(status(NEXT_CACHE, ev([tech("nextjs", "16.2.0")], { "nextjs.app_router": true }))).toBe("applicability_confirmed");
    expect(status(NEXT_CACHE, ev([tech("nextjs", "16.2.0")], { "nextjs.app_router": false }))).toBe("not_affected");
  });
  it("cache issue does not apply to 15.x", () => {
    expect(status(NEXT_CACHE, ev([tech("nextjs", "15.5.27")], { "nextjs.app_router": true }))).toBe("not_affected");
  });
  it("prerelease of the fixed version is still affected", () => {
    expect(status(NEXT_CACHE, ev([tech("nextjs", "16.4.1-canary.2")]))).toBe("affected_version_matched");
    expect(status(NEXT_CACHE, ev([tech("nextjs", "16.4.1")]))).toBe("not_affected");
  });
  it("SVG: disputed 16.0.0 boundary stays unknown; exact builds elsewhere resolve", () => {
    expect(status(NEXT_SVG, ev([tech("nextjs", "16.0.0")]))).toBe("needs_verification");
    expect(status(NEXT_SVG, ev([tech("nextjs", "16.0.1")]))).toBe("affected_version_matched");
    expect(status(NEXT_SVG, ev([tech("nextjs", "15.5.27")]))).toBe("affected_version_matched");
    expect(status(NEXT_SVG, ev([tech("nextjs", "15.5.28")]))).toBe("not_affected");
  });
  it("advisory with no established fixed build never resolves to safe", () => {
    expect(status(PLEX_KEV, ev([tech("plex", "1.43.3")]))).toBe("needs_verification");
  });
});

describe("hidden and conflicting versions (A10)", () => {
  it("an inferred version is never matched as observed", () => {
    const r = assessAdvisory(PHP_OOM, ev([tech("php", "8.2.10", "inferred")]))[0];
    expect(r.status).toBe("needs_verification");
    expect(r.version_used).toBeNull();
  });
  it("conflicting observed versions stay visible as unknown", () => {
    const r = assessAdvisory(PHP_OOM, ev([tech("php", "8.2.10"), tech("php", "8.3.40")]))[0];
    expect(r.status).toBe("needs_verification");
    expect(r.reason).toMatch(/8\.2\.10.*8\.3\.40/);
  });
  it("fix verified only from a newer public observation after an affected result", () => {
    const prior = { advisory_id: PHP_OOM.id, status: "affected_version_matched" as const, observed_at: "2026-10-21T00:00:00Z" };
    expect(status(PHP_OOM, ev([tech("php", "8.2.35", "observed", "2026-10-22T01:00:00Z")]), prior)).toBe("fix_verified");
    // same-age evidence is not new proof
    expect(status(PHP_OOM, ev([tech("php", "8.2.35", "observed", "2026-10-21T00:00:00Z")]), prior)).toBe("not_affected");
    // administrator-supplied version can exclude the advisory but not verify a fix
    expect(status(PHP_OOM, ev([tech("php", "8.2.35", "admin_supplied", "2026-10-22T01:00:00Z")]), prior)).toBe("not_affected");
    // a still-hidden version after an upgrade claim is not a fix
    expect(status(PHP_OOM, ev([tech("php", null, null, "2026-10-22T01:00:00Z")]), prior)).toBe("needs_verification");
  });
  it("withdrawn advisories produce no findings", () => {
    expect(assessAdvisory({ ...PHP_OOM, status: "withdrawn" }, ev([tech("php", "8.2.1")]))).toEqual([]);
  });
});

describe("draft publication checks", () => {
  it("known exploited without a source and date cannot publish", () => {
    const d = {
      title: "x", product: "x", summary: "x", identifiers: ["CVE-2026-1"], severity: "high" as const, cvss_score: null,
      severity_source: null, exploitation: { category: "known_exploited" as const, source_url: null, as_of: null },
      affected: [], conditions: [], sources: [{ url: "https://a.test/", kind: "vendor" as const }], published_at: null, uncertainty: [], brief_excerpt: "",
    };
    expect(draftProblems(d).length).toBe(2);
  });
  it("an unbounded range must be marked ambiguous", () => {
    const d = {
      title: "x", product: "x", summary: "x", identifiers: ["CVE-2026-1"], severity: "high" as const, cvss_score: null, severity_source: null,
      exploitation: { category: "none_confirmed" as const, source_url: null, as_of: null }, conditions: [], sources: [{ url: "https://a.test/", kind: "vendor" as const }],
      published_at: null, uncertainty: [], brief_excerpt: "",
      affected: [{ product: "plex", other_branches: "unknown" as const, ranges: [{ introduced: null, fixed: null, last_affected: null, ambiguous: false }] }],
    };
    expect(draftProblems(d)).toHaveLength(1);
    d.affected[0].ranges[0].ambiguous = true;
    expect(draftProblems(d)).toHaveLength(0);
  });
});
