import { NextResponse } from "next/server";
import { userClient } from "@/lib/supabase/server";
import { safeReturnTo } from "@/lib/navigation";

// PKCE magic-link callback.
export async function GET(req: Request) {
  const u = new URL(req.url);
  const code = u.searchParams.get("code");
  const next = safeReturnTo(u.searchParams.get("next"));
  if (code) {
    const sb = await userClient();
    const { error } = await sb.auth.exchangeCodeForSession(code);
    if (!error) return NextResponse.redirect(new URL(next, u.origin), 303);
  }
  return NextResponse.redirect(new URL(`/login?error=link&next=${encodeURIComponent(next)}`, u.origin), 303);
}
