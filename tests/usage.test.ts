// COST-* fixture tests for usage accounting. Fixture numbers, not live measurements.
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
const inserted: unknown[][] = [];
vi.mock("../lib/db", () => ({
  q: async (_sql: string, params: unknown[]) => {
    inserted.push(params);
    return [];
  },
}));
const { estimateCost, recordModelCall, rateTable, DEFAULT_RATES } = await import("../lib/usage");

beforeEach(() => {
  inserted.length = 0;
  delete process.env.MODEL_RATE_TABLE;
});

describe("cost estimation", () => {
  it("prices input and output from the dated table", () => {
    // 3,738 in / 6,782 out on Opus 5.5 at $4/$20 per MTok
    expect(estimateCost("claude-opus-5-5", { input_tokens: 3738, output_tokens: 6782 })).toBeCloseTo(0.150592, 6);
  });
  it("includes cache reads at the listed rate", () => {
    expect(estimateCost("claude-opus-5-5", { input_tokens: 1000, output_tokens: 0, cache_read_input_tokens: 1_000_000 })).toBeCloseTo(0.204, 6);
  });
  it("missing usage is unknown, not zero", () => {
    expect(estimateCost("claude-opus-5-5", null)).toBeNull();
    expect(estimateCost("claude-opus-5-5", { input_tokens: 10, output_tokens: null })).toBeNull();
  });
  it("an unlisted model is unknown, not zero", () => {
    expect(estimateCost("some-other-model", { input_tokens: 10, output_tokens: 10 })).toBeNull();
  });
  it("cache writes without a listed rate make the call unknown", () => {
    expect(estimateCost("claude-opus-5-5", { input_tokens: 10, output_tokens: 10, cache_creation_input_tokens: 500 })).toBeNull();
  });
  it("zero-token calls cost zero only when usage is actually reported", () => {
    expect(estimateCost("claude-opus-5-5", { input_tokens: 0, output_tokens: 0 })).toBe(0);
  });
  it("a configured override replaces the table; a broken override keeps defaults", () => {
    process.env.MODEL_RATE_TABLE = JSON.stringify({ name: "test-2026-11-01", as_of: "2026-11-01", source: "fixture", models: { "claude-opus-5-5": { input: 1, output: 1 } } });
    expect(rateTable().name).toBe("test-2026-11-01");
    expect(estimateCost("claude-opus-5-5", { input_tokens: 1e6, output_tokens: 1e6 })).toBe(2);
    process.env.MODEL_RATE_TABLE = "{not json";
    expect(rateTable()).toBe(DEFAULT_RATES);
  });
});

describe("recording", () => {
  it("stores only metadata and the estimate, never content", async () => {
    await recordModelCall({
      provider: "anthropic", model: "claude-opus-5-5", operation: "nightly_feed_extraction", cost_pool: "shared_feed", run_id: "intake-1", request_id: "req_1",
      attempt: 2, outcome: "failure", error_class: "RateLimitError", latency_ms: 1234.4, usage: null, measurement: "fixture",
    });
    const row = inserted[0];
    expect(row).toContain("nightly_feed_extraction");
    expect(row).toContain(2); // attempt number kept for retry accounting
    expect(row[14]).toBeNull(); // estimated cost unknown for a failed call without usage
    expect(JSON.stringify(row)).not.toMatch(/brief|prompt|sk-ant/i);
  });
  it("separates the shared feed pool from per-customer operations", async () => {
    await recordModelCall({ provider: "anthropic", model: "claude-opus-5-5", operation: "nightly_feed_extraction", cost_pool: "shared_feed", attempt: 1, outcome: "success", latency_ms: 10, usage: { input_tokens: 1, output_tokens: 1 }, measurement: "fixture" });
    expect(inserted[0][3]).toBe("shared_feed");
  });
});
