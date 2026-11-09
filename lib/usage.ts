import "server-only";
// Server-side accounting for real model calls and for the operations that deliberately make
// none. Stores counts, ids and timings only: never prompts, briefs, private reports or keys.
// Costs are ESTIMATES from a dated rate table; missing usage or an unlisted model yields
// null ("unknown"), never zero.
import { q } from "./db";

// Per-million-token USD rates. Source: Anthropic published API pricing for Claude Opus 5.5
// as listed in the Claude API reference cached 2026-10-06 (input $4, output $20, cache read
// $0.20). Cache-write is not listed there; it is recorded as unknown unless configured.
// Override with MODEL_RATE_TABLE (JSON: {"name","as_of","source","models":{id:{...}}}).
export type Rates = { input: number; output: number; cache_read?: number; cache_write?: number };
export type RateTable = { name: string; as_of: string; source: string; models: Record<string, Rates> };

export const DEFAULT_RATES: RateTable = {
  name: "anthropic-2026-10-06",
  as_of: "2026-10-06",
  source: "Anthropic API pricing as listed in the Claude API reference (cached 2026-10-06); verify before relying on it",
  models: {
    "claude-opus-5-5": { input: 4, output: 20, cache_read: 0.2 },
    "claude-sonnet-5-5": { input: 2, output: 10, cache_read: 0.2 },
    "claude-haiku-5-5": { input: 0.1, output: 0.5 },
  },
};

export function rateTable(): RateTable {
  const raw = process.env.MODEL_RATE_TABLE;
  if (!raw) return DEFAULT_RATES;
  try {
    const t = JSON.parse(raw) as RateTable;
    if (t && t.name && t.models) return t;
  } catch {
    // fall through to defaults; a bad override must not zero out costs
  }
  return DEFAULT_RATES;
}

export type Usage = { input_tokens?: number | null; output_tokens?: number | null; cache_read_input_tokens?: number | null; cache_creation_input_tokens?: number | null };

// Returns null when any billed component cannot be priced.
export function estimateCost(model: string, u: Usage | null, table = rateTable()): number | null {
  if (!u || u.input_tokens == null || u.output_tokens == null) return null;
  const r = table.models[model] ?? table.models[model.replace(/-\d{8}$/, "")];
  if (!r) return null;
  let cost = (u.input_tokens * r.input + u.output_tokens * r.output) / 1e6;
  if (u.cache_read_input_tokens) {
    if (r.cache_read == null) return null;
    cost += (u.cache_read_input_tokens * r.cache_read) / 1e6;
  }
  if (u.cache_creation_input_tokens) {
    if (r.cache_write == null) return null;
    cost += (u.cache_creation_input_tokens * r.cache_write) / 1e6;
  }
  return Math.round(cost * 1e6) / 1e6;
}

export type ModelCallRecord = {
  provider: string;
  model: string;
  operation: string;
  cost_pool: "shared_feed" | "per_customer";
  run_id?: string | null;
  request_id?: string | null;
  attempt: number;
  outcome: "success" | "failure";
  error_class?: string | null;
  latency_ms: number;
  usage: Usage | null;
  measurement?: "live" | "backfilled_from_record" | "fixture";
};

export async function recordModelCall(r: ModelCallRecord) {
  const table = rateTable();
  try {
    await q(
      `insert into model_usage (provider, model, operation, cost_pool, run_id, request_id, attempt, outcome, error_class, latency_ms,
        input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, estimated_cost_usd, rate_table, measurement)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
      [
        r.provider, r.model, r.operation, r.cost_pool, r.run_id ?? null, r.request_id ?? null, r.attempt, r.outcome, r.error_class ?? null,
        Math.round(r.latency_ms), r.usage?.input_tokens ?? null, r.usage?.output_tokens ?? null, r.usage?.cache_read_input_tokens ?? null,
        r.usage?.cache_creation_input_tokens ?? null, estimateCost(r.model, r.usage, table), table.name, r.measurement ?? "live",
      ],
    );
  } catch (e) {
    // Accounting must never break the product path.
    console.error("usage accounting failed:", (e as Error).message);
  }
}

// Operations that by design make no model call still get a row, so their cost per unit
// is measured (zero model spend) rather than assumed.
export async function recordOperation(operation: string, cost_pool: "shared_feed" | "per_customer", outcome: string, latency_ms: number | null, model_calls = 0) {
  try {
    await q("insert into operation_log (operation, cost_pool, model_calls, latency_ms, outcome) values ($1,$2,$3,$4,$5)", [operation, cost_pool, model_calls, latency_ms == null ? null : Math.round(latency_ms), outcome]);
  } catch (e) {
    console.error("operation accounting failed:", (e as Error).message);
  }
}

export async function usageSummary(sinceDays = 90) {
  const calls = await q<{ operation: string; cost_pool: string; model: string; measurement: string; calls: string; failures: string; input: string | null; output: string | null; cache_read: string | null; known_cost: string | null; unknown_cost_calls: string; p50_ms: number | null; max_ms: number | null }>(
    `select operation, cost_pool, model, measurement, count(*) calls, count(*) filter (where outcome = 'failure') failures,
       sum(input_tokens) input, sum(output_tokens) output, sum(cache_read_tokens) cache_read,
       sum(estimated_cost_usd) known_cost, count(*) filter (where estimated_cost_usd is null) unknown_cost_calls,
       percentile_disc(0.5) within group (order by latency_ms) p50_ms, max(latency_ms) max_ms
     from model_usage where created_at > now() - ($1 || ' days')::interval
     group by 1,2,3,4 order by 2,1`,
    [String(sinceDays)],
  );
  const ops = await q<{ operation: string; cost_pool: string; measurement: string; n: string; model_calls: string; p50_ms: number | null; p95_ms: number | null }>(
    `select operation, cost_pool, measurement, count(*) n, sum(model_calls) model_calls,
       percentile_disc(0.5) within group (order by latency_ms) p50_ms, percentile_disc(0.95) within group (order by latency_ms) p95_ms
     from operation_log where created_at > now() - ($1 || ' days')::interval group by 1,2,3 order by 2,1`,
    [String(sinceDays)],
  );
  return { calls, ops, rates: rateTable() };
}

export async function usageRows(sinceDays = 90) {
  return q<Record<string, unknown>>(
    `select created_at, provider, model, operation, cost_pool, run_id, request_id, attempt, outcome, error_class, latency_ms,
       input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, estimated_cost_usd, rate_table, measurement
     from model_usage where created_at > now() - ($1 || ' days')::interval order by created_at`,
    [String(sinceDays)],
  );
}
