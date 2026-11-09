import { listAdvisories } from "@/lib/catalog";
import { apiError, cachedJson } from "@/lib/api-public";
import { rateLimit } from "@/lib/rate";
import { HttpError } from "@/lib/auth";

const EXPLOIT = new Set(["known_exploited", "public_poc", "none_confirmed"]);
const SEVERITY = new Set(["critical", "high", "medium", "low", "unknown"]);
const STATUS = new Set(["published", "withdrawn", "superseded", "all"]);

export async function GET(req: Request) {
  const u = new URL(req.url);
  const p = Object.fromEntries(u.searchParams);
  try {
    await rateLimit(`api:${req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "anon"}`, 600, 3600);
  } catch (e) {
    if (e instanceof HttpError) return apiError(429, "rate_limited", e.message);
    throw e;
  }
  if (p.exploitation && !EXPLOIT.has(p.exploitation)) return apiError(400, "invalid_parameter", "exploitation must be known_exploited, public_poc or none_confirmed");
  if (p.severity && !SEVERITY.has(p.severity)) return apiError(400, "invalid_parameter", "severity must be critical, high, medium, low or unknown");
  if (p.status && !STATUS.has(p.status)) return apiError(400, "invalid_parameter", "status must be published, withdrawn, superseded or all");
  if (p.updated_since && Number.isNaN(Date.parse(p.updated_since))) return apiError(400, "invalid_parameter", "updated_since must be an ISO 8601 timestamp");
  const limit = p.limit ? Number(p.limit) : undefined;
  if (limit !== undefined && (!Number.isInteger(limit) || limit < 1 || limit > 200)) return apiError(400, "invalid_parameter", "limit must be an integer from 1 to 200");
  if (p.cursor && !/^[A-Za-z0-9_-]+$/.test(p.cursor)) return apiError(400, "invalid_cursor", "cursor is not valid");
  const r = await listAdvisories({ ...p, limit });
  const next = r.next_cursor ? (() => {
    const n = new URL(u);
    n.searchParams.set("cursor", r.next_cursor!);
    return n.pathname + n.search;
  })() : null;
  return cachedJson(req, { data: r.data, next_cursor: r.next_cursor, next });
}
