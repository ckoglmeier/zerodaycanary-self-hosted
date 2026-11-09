"use client";
import Link from "next/link";
import { useEffect, useState } from "react";

type Status = { subscription: { status: string; quantity: number } | null; systems: { id: string; label: string; monitoring: string }[] };

export function ConfirmPoller() {
  const [s, setS] = useState<Status | null>(null);
  const [tries, setTries] = useState(0);
  const pending = !s || s.systems.some((x) => x.monitoring === "pending_payment");
  useEffect(() => {
    if (!pending || tries > 40) return;
    const t = setTimeout(async () => {
      const r = await fetch("/api/app/billing/status", { cache: "no-store" });
      if (r.ok) setS(await r.json());
      setTries((n) => n + 1);
    }, tries === 0 ? 0 : 2000);
    return () => clearTimeout(t);
  }, [tries, pending]);

  const active = s?.systems.filter((x) => x.monitoring === "active") ?? [];
  const waiting = s?.systems.filter((x) => x.monitoring === "pending_payment") ?? [];
  return (
    <div className="panel stack" aria-live="polite">
      {pending && tries <= 40 ? <p>Waiting for payment confirmation…</p> : null}
      {pending && tries > 40 ? (
        <p className="notice n-warning">
          We have not received confirmation yet. Your first system stays free while Team confirmation is pending. If you completed checkout, check <Link href="/billing">Billing</Link> in a
          few minutes.
        </p>
      ) : null}
      {!pending && active.length && s?.subscription && ["active","trialing"].includes(s.subscription.status) ? <p className="notice n-success">Payment confirmed. Monitoring is active for {active.map((a) => a.label).join(", ")}.</p> : null}
      {s?.subscription && !["active", "trialing"].includes(s.subscription.status) ? <p className="notice n-warning">Subscription status: {s.subscription.status}.</p> : null}
      {waiting.length && !pending ? null : null}
      <p className="small">
        <Link href="/systems">Back to your systems</Link>
      </p>
    </div>
  );
}
