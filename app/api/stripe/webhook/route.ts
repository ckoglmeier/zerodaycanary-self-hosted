import { NextResponse } from "next/server";
import { stripe, handleStripeEvent } from "@/lib/billing";
import { env } from "@/lib/env";

import {recordError} from "@/lib/monitoring/server";

// Paid activation is driven only by signature-verified events.
export async function POST(req: Request) {
  const sig = req.headers.get("stripe-signature");
  const body = await req.text();
  if (!sig) return NextResponse.json({ error: "missing signature" }, { status: 400 });
  let event;
  try {
    event = stripe().webhooks.constructEvent(body, sig, env.stripeWebhookSecret());
  } catch {
    return NextResponse.json({ error: "invalid signature" }, { status: 400 });
  }
  try {
    const r = await handleStripeEvent(event);
    return NextResponse.json(r);
  } catch (e) {
    await recordError("billing");
    return NextResponse.json({ error: "processing failed" }, { status: 500 }); // Stripe retries
  }
}
