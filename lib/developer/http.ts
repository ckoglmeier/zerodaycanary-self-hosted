import "server-only";
import { NextResponse } from "next/server";
import { ApiError } from "./tokens";
import { MAX_BYTES } from "./json";
import { HttpError } from "../auth";

import {recordError} from "../monitoring/server";

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PRIVATE = { "cache-control": "private, no-store", "x-content-type-options": "nosniff" };

export function apiJson(body: unknown, status: number) {
  return NextResponse.json(body, { status, headers: PRIVATE });
}

// Bounded machine codes only: never echoes tokens, bodies or stack traces.
export async function apiFail(e: unknown) {
  if (e instanceof ApiError) return apiJson({ error: { code: e.code } }, e.status);
  if (e instanceof HttpError && e.status === 429) return apiJson({ error: { code: "rate_limited" } }, 429);
  await recordError("api");
  return apiJson({ error: { code: "temporarily_unavailable" } }, 503);
}

// Reads at most MAX_BYTES; anything larger is refused without buffering it all.
export async function readBounded(req: Request): Promise<Uint8Array> {
  const len = Number(req.headers.get("content-length") ?? "0");
  if (len > MAX_BYTES) throw new ApiError(413, "payload_too_large");
  if (!req.body) return new Uint8Array();
  const reader = req.body.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BYTES) {
      await reader.cancel();
      throw new ApiError(413, "payload_too_large");
    }
    parts.push(value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
