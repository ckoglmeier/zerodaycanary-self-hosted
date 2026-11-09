import Link from "next/link";
import { requireViewer } from "@/lib/auth";
import { desiredQuantity, workspacePrice, money, subscriptionFor } from "@/lib/billing";
import { q } from "@/lib/db";
import { MonitoringBadge } from "@/components/badges";
import { abs } from "@/components/time";
import { Submit } from "@/components/submit";
import { creditBalance } from "@/lib/admin";

export const metadata = { title: "Billing" };

export default async function Billing({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const sp = await searchParams;
  const v = await requireViewer("/billing");
  const [price, sub, qty, systems, credit] = await Promise.all([
    workspacePrice(v.workspaceId).catch(() => null),
    subscriptionFor(v.workspaceId),
    desiredQuantity(v.workspaceId),
    q<{ id: string; label: string; monitoring: string }>("select id, label, monitoring from systems where workspace_id = $1 and removed_at is null order by created_at", [v.workspaceId]),
    creditBalance(v.workspaceId).catch(()=>null),
  ]);
  return (
    <div className="stack" style={{ ["--gap" as string]: "24px", maxWidth: 820 }}>
      <div className="spread"><h1 className="h-page">Billing</h1><Link href="/pricing" className="btn btn-secondary">View pricing</Link></div>
      <p className="small muted">Developer projects and monitoring, reviewed alerts and the public API are free. Your first monitored system is free. Team covers up to 25.</p>
      {sp.error ? <p className="notice n-danger" role="alert">{sp.error}</p> : null}
      <section className="panel stack">
        <div className="spread"><h2 className="h-section">Plan</h2><Link href="/billing/checkout">Review monitored systems</Link></div>
        <p>{sub&&['active','trialing','past_due','unpaid','paused','incomplete'].includes(sub.status)?sub.billing_model==='workspace'?'Team workspace: up to 25 systems.':'Legacy per-system subscription. Contact us to change plans.':'Free: one monitored system, no card required.'}</p>
        <dl className="facts">
          <dt>Subscription</dt>
          <dd>{sub ? `${sub.status}${sub.cancel_at_period_end ? " (ends at period end)" : ""}` : "none"}</dd>
          <dt>Billing units</dt>
          <dd>{sub && !["canceled","incomplete_expired"].includes(sub.status) ? sub.quantity : 0}</dd>
          <dt>Requested systems</dt>
          <dd>{qty}</dd>
          <dt>Available invoice credit</dt>
          <dd>{credit ? money(credit.available) : "Balance unavailable"}</dd>
          {sub?.current_period_end && !["canceled","incomplete_expired"].includes(sub.status) ? (
            <>
              <dt>Current period ends</dt>
              <dd>{abs(sub.current_period_end)}</dd>
            </>
          ) : null}
          {price && sub?.billing_model === "workspace" && ["active","trialing","past_due","unpaid"].includes(sub.status) ? (
            <>
              <dt>Monthly total</dt>
              <dd>{money(price.unit_amount * (sub?.quantity ?? 0), price.currency)}</dd>
            </>
          ) : null}
        </dl>
        <p className="small muted">Team costs the same when you add or pause systems within 25. Cancel through the billing portal to return to Free at period end. Your oldest requested system stays monitored; other systems retain their history. Legacy plans retain per-system billing.</p>
        <p className="small muted">Invoice credit applies automatically to the next finalized monitoring invoice; unused credit carries forward. The monthly rate above is before credits.</p>
        <form method="post" action="/api/app/billing/portal">
          <Submit className="btn btn-secondary" busy="Opening billing portal…">Manage payment and invoices</Submit>
        </form>
      </section>
      <section className="panel stack">
        <h2 className="h-section">Systems</h2>
        <ul className="list">
          {systems.map((s) => (
            <li key={s.id} className="spread">
              <Link href={`/systems/${s.id}`}>{s.label}</Link>
              <MonitoringBadge state={s.monitoring} />
            </li>
          ))}
          {systems.length === 0 ? <li className="muted">No systems yet.</li> : null}
        </ul>
      </section>
    </div>
  );
}
