import { describe, expect, it } from "vitest";
import { disclosureDate, recentAdvisories } from "../lib/recent-advisories";
import { PHP_OOM } from "../intel/fixtures/advisories";
import type { AdvisoryRecord } from "../intel/schema";

const record = (id: string, published_at: string | null, overrides: Partial<AdvisoryRecord> = {}): AdvisoryRecord => ({ ...PHP_OOM, id, published_at, updated_at: "2026-10-22T10:00:00Z", ...overrides });

describe("recent disclosure selection", () => {
  it("orders by disclosure date, not by urgency or catalog edit date", () => {
    const records = [record("old-edited", "2026-09-01", { updated_at: "2026-10-22T12:00:00Z", exploitation: { category: "known_exploited", source_url: "https://example.com", as_of: "2026-10-22" } }), record("new", "2026-10-21"), record("middle", "2026-10-14")];
    expect(recentAdvisories(records).map((r) => r.id)).toEqual(["new", "middle", "old-edited"]);
    expect(records[0].id).toBe("old-edited");
  });
  it("does not show withdrawn or superseded disclosures", () => {
    expect(recentAdvisories([record("withdrawn", "2026-10-22", { status: "withdrawn" }), record("superseded", "2026-10-22", { status: "superseded" }), record("active", "2026-10-14")]).map((r) => r.id)).toEqual(["active"]);
  });
  it("keeps unknown and invalid disclosure dates after dated records without inventing a date", () => {
    const records = [record("missing", null), record("invalid", "not a date"), record("dated", "2026-10-21")];
    expect(recentAdvisories(records).map((r) => r.id)).toEqual(["dated", "invalid", "missing"]);
    expect(recentAdvisories(records)[2].published_at).toBeNull();
  });
  it("has stable ordering for tied dates and bounds the response", () => {
    const records = [record("b", "2026-10-21"), record("a", "2026-10-21")];
    expect(recentAdvisories(records, 1).map((r) => r.id)).toEqual(["a"]);
    expect(recentAdvisories(records, 0)).toEqual([]);
  });
  it("handles an empty catalog", () => expect(recentAdvisories([])).toEqual([]));
});

describe("disclosure dates", () => {
  it("shows the vendor date without inventing a publication time", () => expect(disclosureDate("2026-10-21")).toBe("Oct 21, 2026"));
  it("keeps missing and malformed dates unknown", () => { expect(disclosureDate(null)).toBeNull(); expect(disclosureDate("unknown")).toBeNull(); });
});
