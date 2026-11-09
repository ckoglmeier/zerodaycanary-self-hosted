import { describe, expect, it } from "vitest";
import { groupConcerns } from "../lib/concerns";
import { assessAll } from "../intel/match";
import { NEXT_CACHE, NEXT_SVG, PHP_OOM } from "../intel/fixtures/advisories";
import type { TechObservation } from "../intel/evidence";

const t = (product: string, version: string | null): TechObservation => ({
  product, name: product === "nextjs" ? "Next.js" : "PHP", version, version_basis: version ? "observed" : null, evidence_type: "header",
  location: "https://portal.example.edu/", detail: "fixture", confidence: "high", observed_at: "2026-10-22T00:00:00Z", limitations: [],
});

describe("grouped concerns", () => {
  it("related advisories for one product become one concern with one question", () => {
    const rs = assessAll([NEXT_CACHE, NEXT_SVG], { techs: [t("nextjs", "16.2.0")], facts: {}, observed_at: null });
    const g = groupConcerns(rs, "portal.example.edu");
    expect(g).toHaveLength(1);
    expect(g[0].open.length).toBe(2);
    expect(g[0].question).toMatch(/still running Next.js 16.2.0/);
    expect(g[0].question).toMatch(/16.4.1 or later/);
    expect(g[0].question).toMatch(/only apply if/);
  });
  it("a hidden version asks for the version, not for a fix", () => {
    const g = groupConcerns(assessAll([PHP_OOM], { techs: [t("php", null)], facts: {}, observed_at: null }), "lab.example.edu");
    expect(g[0].question).toMatch(/Which exact version of PHP/);
  });
  it("a concern with nothing open asks nothing", () => {
    const g = groupConcerns(assessAll([PHP_OOM], { techs: [t("php", "8.2.35")], facts: {}, observed_at: null }), "x");
    expect(g[0].question).toBeNull();
    expect(g[0].worst).toBe("not_affected");
  });
});
