import { after, NextResponse } from "next/server";
import { authDeliveries, verifyHookSignature } from "@/lib/auth-email";
import { brandedSender, replyToAddress } from "@/lib/email-brand";
import { env } from "@/lib/env";

import {recordError} from "@/lib/monitoring/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Supabase Auth Send Email Hook. Supabase waits about 5 seconds, so each
// Resend call is bounded below that. Request bodies contain sign-in tokens
// and are never logged.
const fail = (status: number, message: string) => NextResponse.json({ error: { http_code: status, message } }, { status });

export async function POST(req: Request) {
  const secret = process.env.SUPABASE_SEND_EMAIL_HOOK_SECRET;
  const apiKey = process.env.RESEND_API_KEY, from = process.env.CANARY_EMAIL_FROM;
  if (!secret || !apiKey || !from) return fail(500, "Email delivery is not configured.");
  const body = await req.text();
  try { verifyHookSignature(secret, req.headers, body); } catch { return fail(401, "Invalid signature."); }
  let deliveries;
  try { deliveries = authDeliveries(JSON.parse(body), env.supabaseUrl(), env.siteUrl()); }
  catch { return fail(400, "Unsupported email request."); }
  const id = req.headers.get("webhook-id")!;
  const replyTo = replyToAddress();
  const results = await Promise.all(deliveries.map(async (m, i) => {
    try {
      const r = await fetch("https://api.resend.com/emails", {
        method: "POST", signal: AbortSignal.timeout(4_000),
        headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json", "idempotency-key": `auth-${id}-${i}` },
        body: JSON.stringify({ from: brandedSender(from), to: [m.to], ...(replyTo ? { reply_to: replyTo } : {}), subject: m.subject, html: m.html, text: m.text }),
      });
      if (!r.ok) console.error("auth email: resend status", r.status);
      return r.ok;
    } catch (e) { console.error("auth email: send failed", (e as Error).name); return false; }
  }));
  if(!results.every(Boolean))after(()=>recordError("mail"));
  return results.every(Boolean) ? NextResponse.json({}) : fail(502, "Email could not be sent. Please try again.");
}
