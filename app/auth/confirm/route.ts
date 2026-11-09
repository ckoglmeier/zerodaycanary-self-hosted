import { NextResponse } from "next/server";
import type { EmailOtpType } from "@supabase/supabase-js";
import { userClient } from "@/lib/supabase/server";
import { safeReturnTo } from "@/lib/navigation";

// Token-hash confirmation (works across devices; used by custom email templates).
export async function GET(req: Request) {
  const u = new URL(req.url);
  const token_hash = u.searchParams.get("token_hash");
  const type = (u.searchParams.get("type") ?? "magiclink") as EmailOtpType;
  if (token_hash) {
    const sb = await userClient();
    const { error } = await sb.auth.verifyOtp({ token_hash, type });
    if (!error) return NextResponse.redirect(new URL(safeReturnTo(u.searchParams.get("next")), u.origin), 303);
  }
  return NextResponse.redirect(new URL(`/login?error=link&next=${encodeURIComponent(safeReturnTo(u.searchParams.get("next")))}`, u.origin), 303);
}
