import "server-only";
import { redirect } from "next/navigation";
import { userClient } from "./supabase/server";
import { one } from "./db";
import { env } from "./env";
import { safeReturnTo } from "./navigation";
import { headers } from "next/headers";

export type Viewer = { id: string; email: string; workspaceId: string; isOperator: boolean; emailVerified?: boolean };

// getUser() validates the JWT with Supabase Auth; never trust the cookie payload alone.
export async function getViewer(): Promise<Viewer | null> {
  const sb = await userClient();
  const { data } = await sb.auth.getUser();
  const u = data.user;
  if (!u || !u.email) return null;
  let ws = await one<{ id: string }>("select id from workspaces where owner_id = $1", [u.id]);
  if (!ws) ws = await one<{ id: string }>("insert into workspaces (owner_id) values ($1) on conflict (owner_id) do update set owner_id = excluded.owner_id returning id", [u.id]);
  return { id: u.id, email: u.email.toLowerCase(), emailVerified: Boolean(u.email_confirmed_at), workspaceId: ws!.id, isOperator: env.operatorEmails().includes(u.email.toLowerCase()) };
}

export async function requireViewer(next = "/systems"): Promise<Viewer> {
  const v = await getViewer();
  if (!v) {
    const requested = (await headers()).get("x-canary-return-to");
    redirect(`/login?next=${encodeURIComponent(safeReturnTo(requested, safeReturnTo(next)))}`);
  }
  return v;
}

export async function requireOperator(): Promise<Viewer> {
  const v = await requireViewer("/operator");
  if (!v.isOperator) redirect("/systems");
  return v;
}

export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// For route handlers: returns the viewer or throws 401/403.
export async function apiViewer(opts: { operator?: boolean } = {}): Promise<Viewer> {
  const v = await getViewer();
  if (!v) throw new HttpError(401, "Sign in required.");
  if (opts.operator && !v.isOperator) throw new HttpError(403, "Operator access required.");
  return v;
}
