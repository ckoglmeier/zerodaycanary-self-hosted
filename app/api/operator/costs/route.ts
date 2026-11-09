import { NextResponse } from "next/server";
import { apiViewer, HttpError } from "@/lib/auth";
import { usageRows } from "@/lib/usage";

const cell = (v: unknown) => {
  const s = v instanceof Date ? v.toISOString() : v == null ? "" : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

// Operator-only CSV of recorded model calls (metadata only: no prompts or content).
export async function GET() {
  try {
    await apiViewer({ operator: true });
    const rows = await usageRows(365);
    const cols = ["created_at", "provider", "model", "operation", "cost_pool", "run_id", "request_id", "attempt", "outcome", "error_class", "latency_ms", "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "estimated_cost_usd", "rate_table", "measurement"];
    const csv = [cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\n") + "\n";
    return new NextResponse(csv, { headers: { "content-type": "text/csv", "cache-control": "private, no-store", "content-disposition": 'attachment; filename="zdc-model-usage.csv"' } });
  } catch (e) {
    return NextResponse.json({ error: { message: e instanceof HttpError ? e.message : "error" } }, { status: e instanceof HttpError ? e.status : 500 });
  }
}
