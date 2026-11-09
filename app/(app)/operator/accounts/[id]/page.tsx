import Link from "next/link";
import { randomUUID } from "node:crypto";
import { notFound } from "next/navigation";
import { requireOperator, HttpError } from "@/lib/auth";
import { account,creditBalance } from "@/lib/admin";
import { money } from "@/lib/billing";
import { abs } from "@/components/time";
import { CreditForm } from "@/components/credit-form";

export const metadata = { title: "Account · Admin" };
export default async function Account({params}:{params:Promise<{id:string}>}) {
  const v=await requireOperator(),{id}=await params;
  const data=await account(v,id).catch(e=>{if(e instanceof HttpError&&e.status===404)notFound();throw e;});
  const {a,systems,projects,subscription,credits}=data;
  const pending=credits.find(c=>c.state==='pending');
  const balance=a.workspace_id?await creditBalance(a.workspace_id).catch(()=>null):null;
  return <div className="stack" style={{["--gap" as string]:"24px",maxWidth:1000}}>
    <p><Link href="/operator/accounts">← Accounts</Link></p>
    <div><h1 className="h-page wrap">{a.email}</h1><p className="small muted">{a.name||'No workspace yet'} · {a.verified?'Email verified':'Email not verified'}</p></div>
    <section className="panel stack"><h2 className="h-section">Account and billing</h2><dl className="facts"><dt>Account ID</dt><dd className="mono wrap">{a.id}</dd><dt>Joined</dt><dd>{abs(a.created_at)}</dd><dt>Last sign-in</dt><dd>{a.last_sign_in_at?abs(a.last_sign_in_at):'Never'}</dd><dt>Workspace ID</dt><dd className="mono wrap">{a.workspace_id||'Not opened'}</dd><dt>Subscription</dt><dd>{subscription?`${subscription.status} · ${subscription.quantity} apps${subscription.cancel_at_period_end?' · ends at period end':''}`:'None'}</dd><dt>Nonprofit rate</dt><dd>{a.nonprofit?'Self-reported nonprofit':'Not applied'}</dd><dt>Available invoice credit</dt><dd>{balance?`${money(balance.available)}${balance.livemode?'':' · Test mode'}`:'Balance unavailable'}</dd>{balance?.due?<><dt>Invoice balance due</dt><dd>{money(balance.due)}</dd></>:null}</dl></section>
    {a.workspace_id?<CreditForm accountId={a.id} email={a.email} clientKey={pending?.client_key||randomUUID()} retry={pending?{amount:(pending.amount_cents/100).toFixed(2),reason:pending.reason}:undefined} testMode={!balance?.livemode} balanceAvailable={balance!==null}/>:null}
    <section className="panel stack"><h2 className="h-section">Credit history</h2><p className="small muted">Amounts are grants, not the remaining balance. Reasons are internal. A pending outcome must be reconciled before making a replacement adjustment.</p><ul className="list">{credits.map(c=><li key={c.id} className="stack"><strong>{money(c.amount_cents)} · {c.state==='applied'?'Applied to invoice balance':'Outcome pending'}{!c.livemode?' · Test':''}</strong><span>{c.reason}</span><span className="small muted wrap">{abs(c.created_at)} · {c.actor_email} · {c.stripe_transaction_id||c.id}</span>{c.last_error?<p className="notice n-warning">{c.last_error}</p>:null}</li>)}{!credits.length?<li>No adjustments yet.</li>:null}</ul></section>
    <section className="panel stack"><h2 className="h-section">Apps ({systems.length}{systems.length===100?'+':''})</h2><ul className="list">{systems.map(s=><li key={s.id} className="spread"><span>{s.label}</span><span>{s.monitoring}</span></li>)}{!systems.length?<li>No apps.</li>:null}</ul></section>
    <section className="panel stack"><h2 className="h-section">Free developer projects ({projects.length}{projects.length===100?'+':''})</h2><ul className="list">{projects.map(p=><li key={p.id} className="spread"><span>{p.name}</span><span>{p.state}</span></li>)}{!projects.length?<li>No projects.</li>:null}</ul></section>
  </div>;
}
