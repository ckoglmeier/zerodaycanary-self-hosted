import "server-only";
import { one } from "./db";
import { HttpError } from "./auth";

// Fixed-window counter in Postgres; survives across serverless invocations.
export async function rateLimit(key: string, limit: number, windowSeconds: number) {
  const row = await one<{ count: number }>(
    `insert into rate_limits (key, window_start, count)
     values ($1, to_timestamp(floor(extract(epoch from now()) / $2) * $2), 1)
     on conflict (key, window_start) do update set count = rate_limits.count + 1
     returning count`,
    [key, windowSeconds],
  );
  if (row && row.count > limit) throw new HttpError(429, "Too many requests. Please wait and try again.");
}
