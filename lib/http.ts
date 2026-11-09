import "server-only";
import { NextResponse } from "next/server";
import { HttpError } from "./auth";
import { FetchBlocked } from "./scan/net";
import { safeReturnTo } from "./navigation";

import {recordError} from "./monitoring/server";
import {errorArea} from "./monitoring/policy";

const wantsJson = (req: Request) => (req.headers.get("accept") ?? "").includes("application/json");

// Same-origin check for state-changing form posts (defense in depth alongside SameSite cookies).
export function assertSameOrigin(req: Request) {
  const origin = req.headers.get("origin");
  if (origin && origin !== new URL(req.url).origin) throw new HttpError(403, "Cross-site request refused.");
}

// Route handler wrapper: forms get 303 redirects with a message; JSON clients get JSON.
export function action<P = Record<string, string>>(fn: (req: Request, ctx: { params: P }) => Promise<{ redirect?: string; json?: unknown }>) {
  return async (req: Request, ctx: { params: Promise<P> }) => {
    const back = req.headers.get("referer") ?? "/";
    try {
      assertSameOrigin(req);
      const r = await fn(req, { params: await ctx.params });
      if (wantsJson(req) || !r.redirect) return NextResponse.json(r.json ?? { ok: true });
      return NextResponse.redirect(new URL(r.redirect, req.url), 303);
    } catch (e) {
      const status = e instanceof HttpError ? e.status : e instanceof FetchBlocked ? 400 : 500;
      const message = e instanceof HttpError || e instanceof FetchBlocked ? e.message : "Could not confirm the outcome. Refresh to check the current state before retrying.";
      if (status === 500) await recordError(errorArea(new URL(req.url).pathname));
      if (wantsJson(req)) return NextResponse.json({ error: { message } }, { status });
      if (status === 401) { const source = new URL(back, req.url); const next = source.origin === new URL(req.url).origin ? safeReturnTo(source.pathname + source.search) : "/systems"; return NextResponse.redirect(new URL(`/login?next=${encodeURIComponent(next)}`, req.url), 303); }
      const u = new URL(back, req.url);
      u.searchParams.set("error", message);
      return NextResponse.redirect(u, 303);
    }
  };
}

export async function formOf(req: Request): Promise<Record<string, string>> {
  const ct = req.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) return (await req.json()) as Record<string, string>;
  const f = await req.formData();
  const o: Record<string, string> = {};
  for (const [k, v] of f.entries()) if (typeof v === "string") o[k] = v;
  return o;
}
