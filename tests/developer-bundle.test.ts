// Contract tests against the companion's own fixtures (read-only, from its checkout when
// present). Proves the app accepts what the companion produces and computes the same hashes.
import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { canonical, parseStrict, JsonRejected } from "../lib/developer/json";
import { inventoryFromLock, packFromUpload, validateBundle, sha256 } from "../lib/developer/bundle";

const C = new URL("../skills/zero-day-canary-skill/examples", import.meta.url).pathname;
const have = existsSync(C);
const read = (f: string) => readFileSync(`${C}/${f}`);

describe.skipIf(!have)("companion fixtures", () => {
  for (const f of ["sample-bundle.json", "sample-after-bundle.json", "sample-detail-bundle.json"]) {
    it(`${f} validates and canonicalizes like the companion`, () => {
      const v = parseStrict(read(f).toString("utf8"));
      const b = validateBundle(v);
      expect(b.schema_version).toBe("canary-evidence/1");
      // Python canonical(): re-serialization must be stable.
      const once = canonical(v);
      expect(canonical(parseStrict(once))).toBe(once);
    });
  }
  it("lockfile port reproduces the companion's inventory exactly", () => {
    const ours = inventoryFromLock(parseStrict(read("package-lock.json").toString("utf8")));
    const theirs = (parseStrict(read("sample-bundle.json").toString("utf8")) as { inventory: unknown }).inventory;
    expect(ours).toEqual(theirs);
  });
  it("findings provenance hash matches the companion's report_sha256", () => {
    const theirs = parseStrict(read("sample-bundle.json").toString("utf8")) as { audit: { report_sha256: string } };
    expect(sha256(read("findings.json"))).toBe(theirs.audit.report_sha256);
  });
  it("web upload packing produces a valid bundle without detailed findings by default", () => {
    const b = packFromUpload({
      repositoryId: "synthetic/app",
      lock: { value: parseStrict(read("package-lock.json").toString("utf8")), bytes: read("package-lock.json") },
      findings: { value: parseStrict(read("findings.json").toString("utf8")), bytes: read("findings.json") },
      includeFindings: false,
    });
    expect(b.audit.selected_findings).toEqual([]);
    expect(b.audit.total_records).toBe(3);
    expect(b.inventory.components.some((c) => c.name === "next")).toBe(true);
  });
});

describe("strict JSON bounds (malformed input)", () => {
  it.each([
    ['{"a":1,"a":2}', /Duplicate/],
    ["[".repeat(60) + "]".repeat(60), /deep/],
    ['{"a":NaN}', /Invalid/],
    ["[1e400]", /Non-finite/],
    ['{"a":1} x', /Trailing/],
    ['"\u0001"', /Control/],
    ["[" + "9".repeat(130) + "]", /integer/],
  ])("rejects %s", (txt, re) => {
    expect(() => parseStrict(txt)).toThrow(JsonRejected);
    expect(() => parseStrict(txt)).toThrow(re);
  });
  it("canonical escaping matches Python ensure_ascii", () => {
    expect(canonical({ b: "é 😀", a: [true, null, 1] })).toBe('{"a":[true,null,1],"b":"\\u00e9\\u2028\\ud83d\\ude00"}\n');
  });
});

describe("bundle semantic rejection", () => {
  const base = () => parseStrict(readFileSync(`${C}/sample-bundle.json`, "utf8")) as Record<string, any>;
  it.skipIf(!have).each([
    ["unknown property", (b: any) => (b.extra = 1)],
    ["purl disagrees with identity", (b: any) => (b.inventory.components[0].purl = "pkg:npm/other@1.0.0")],
    ["limitations changed", (b: any) => b.limitations.pop()],
    ["counts disagree", (b: any) => (b.audit.total_records = 99)],
    ["duplicate instance", (b: any) => (b.inventory.components[1].instance = b.inventory.components[0].instance)],
    ["traversal in scope", (b: any) => (b.scope = ["../etc"])],
    ["future audit", (b: any) => (b.audit.context.audited_at = "2099-01-01T00:00:00Z")],
    ["inventory without provenance", (b: any) => (b.sources = b.sources.filter((s: any) => s.id !== "inventory-1"))],
  ])("rejects %s", (_n, mutate) => {
    const b = base();
    mutate(b);
    expect(() => validateBundle(b)).toThrow(JsonRejected);
  });
});

describe("package identity mapping (no fuzzy matching)", async () => {
  const { productForPackage } = await import("../intel/packages");
  const { evaluateComponentsPure } = await import("./helpers/dev-eval");
  it.each([
    ["next", "nextjs"],
    ["next-auth", null],
    ["@next/font", null],
    ["nextjs", null],
    ["Next", null],
  ])("npm %s → %s", (name, product) => expect(productForPackage("npm", name)).toBe(product));
  it("distinct installed versions are evaluated separately, never merged", () => {
    const r = evaluateComponentsPure([
      { instance: 1, name: "next", exact_version: "16.2.0", relationship: "direct", development: null, ecosystem: "npm" },
      { instance: 2, name: "next", exact_version: "16.4.1", relationship: "transitive", development: null, ecosystem: "npm" },
      { instance: 3, name: "next-auth", exact_version: "4.0.0", relationship: "direct", development: null, ecosystem: "npm" },
    ]);
    const byInst = (i: number) => r.results.filter((x) => x.component.instance === i).map((x) => x.status);
    expect(byInst(1)).toContain("affected_version_matched");
    expect(byInst(2).every((s) => s === "not_affected")).toBe(true);
    expect(byInst(3)).toEqual([]);
    expect(r.coverage.components_covered).toBe(2);
    expect(r.results.some((x) => x.status === "fix_verified")).toBe(false);
  });
});
