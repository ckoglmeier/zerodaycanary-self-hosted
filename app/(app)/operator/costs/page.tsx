import { requireOperator } from "@/lib/auth";
import { usageSummary } from "@/lib/usage";

export const metadata = { title: "Inference costs" };

const usd = (n: number | null) => (n == null ? "unknown" : `$${n.toFixed(n < 0.01 ? 6 : 4)}`);

// Operator-only evidence for pricing decisions. Shows measured usage, not projections.
export default async function Costs() {
  await requireOperator();
  const { calls, ops, rates } = await usageSummary(90);
  return (
    <div className="stack" style={{ ["--gap" as string]: "24px" }}>
      <div className="stack prose" style={{ ["--gap" as string]: "8px" }}>
        <h1 className="h-page">Inference costs (last 90 days)</h1>
        <p className="small">
          Model calls are recorded server-side with token usage and latency only; prompts, briefs and private reports are never logged. Costs are estimates from
          the dated rate table below. A call without usage, or a model without a listed rate, is shown as unknown, never zero. No paid price has been chosen.
        </p>
        <p className="small">
          <a href="/api/operator/costs">Export model calls (CSV)</a>
        </p>
      </div>

      <section className="panel stack">
        <h2 className="h-section">Model calls</h2>
        {calls.length === 0 ? <p className="muted">No model calls recorded yet.</p> : (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th scope="col">Pool</th>
                  <th scope="col">Operation</th>
                  <th scope="col">Model</th>
                  <th scope="col">Measurement</th>
                  <th scope="col">Calls (failed)</th>
                  <th scope="col">Input / output / cache-read tokens</th>
                  <th scope="col">Estimated cost</th>
                  <th scope="col">Per successful call</th>
                  <th scope="col">Latency p50 / max</th>
                </tr>
              </thead>
              <tbody>
                {calls.map((c, i) => {
                  const ok = Number(c.calls) - Number(c.failures);
                  const known = c.known_cost == null ? null : Number(c.known_cost);
                  return (
                    <tr key={i}>
                      <td>{c.cost_pool === "shared_feed" ? "Shared nightly feed" : "Per customer"}</td>
                      <td className="mono">{c.operation}</td>
                      <td className="mono">{c.model}</td>
                      <td>{c.measurement === "live" ? "live" : c.measurement === "backfilled_from_record" ? "backfilled (recorded usage)" : "fixture"}</td>
                      <td>
                        {c.calls} ({c.failures})
                      </td>
                      <td className="mono">
                        {c.input ?? "?"} / {c.output ?? "?"} / {c.cache_read ?? 0}
                      </td>
                      <td>
                        {usd(known)}
                        {Number(c.unknown_cost_calls) ? ` + ${c.unknown_cost_calls} call(s) unknown` : ""}
                      </td>
                      <td>{known != null && ok > 0 && !Number(c.unknown_cost_calls) ? usd(known / ok) : "unknown"}</td>
                      <td>
                        {c.p50_ms ?? "?"} / {c.max_ms ?? "?"} ms
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel stack">
        <h2 className="h-section">Operations</h2>
        <p className="small muted">Deterministic matching, cached lookups and scans make no model calls by design; the counts below confirm it from live traffic.</p>
        {ops.length === 0 ? <p className="muted">No operations recorded yet.</p> : (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th scope="col">Pool</th>
                  <th scope="col">Operation</th>
                  <th scope="col">Count</th>
                  <th scope="col">Model calls</th>
                  <th scope="col">Latency p50 / p95</th>
                </tr>
              </thead>
              <tbody>
                {ops.map((o, i) => (
                  <tr key={i}>
                    <td>{o.cost_pool === "shared_feed" ? "Shared nightly feed" : "Per customer"}</td>
                    <td className="mono">{o.operation}</td>
                    <td>{o.n}</td>
                    <td>{o.model_calls}</td>
                    <td>
                      {o.p50_ms ?? "?"} / {o.p95_ms ?? "?"} ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel stack">
        <h2 className="h-section">Rate table</h2>
        <p className="small">
          <strong>{rates.name}</strong> (as of {rates.as_of}). Source: {rates.source}.
        </p>
        <ul className="small mono">
          {Object.entries(rates.models).map(([m, r]) => (
            <li key={m}>
              {m}: input ${r.input}/M, output ${r.output}/M, cache read {r.cache_read != null ? `$${r.cache_read}/M` : "unlisted"}, cache write{" "}
              {r.cache_write != null ? `$${r.cache_write}/M` : "unlisted (unknown)"}
            </li>
          ))}
        </ul>
      </section>

      <section className="panel stack">
        <h2 className="h-section">Not included (separate overheads)</h2>
        <ul className="small">
          <li>Hosting (Vercel functions, bandwidth), database and storage (Supabase): not measured here; take them from those providers&rsquo; invoices.</li>
          <li>Payment processing (Stripe fees per charge): not measured here; depends on the account&rsquo;s pricing and card mix.</li>
          <li>Outbound scan bandwidth and DNS lookups: negligible per scan but unmeasured.</li>
          <li>The nightly feed cost is shared across all customers; per-customer cost should allocate it, not double-count it.</li>
        </ul>
      </section>
    </div>
  );
}
