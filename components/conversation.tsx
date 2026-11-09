import Link from "next/link";
import type { ReactNode } from "react";
import { randomUUID } from "node:crypto";
import { reviewData } from "@/lib/review/requests";
import { abs } from "./time";
import { Submit } from "./submit";

export function Conversation({data,composer}:{data:Awaited<ReturnType<typeof reviewData>>;composer?:ReactNode}){
  const answers=new Map(data.answers.map(a=>[a.id,a]));
  return <section className="panel stack" aria-labelledby="conversation-title"><h2 className="h-section" id="conversation-title">Conversation</h2><p className="small muted">{data.requester} &amp; the invited app owner · This app only</p>
    <ol className="review-messages">{data.messages.map(m=>{const a=m.answer_id?answers.get(m.answer_id):null;return <li key={m.id} className="stack"><div className="spread"><strong className="wrap">{m.author_email}</strong><span className="small muted">{abs(m.created_at)}</span></div><p style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{m.body}</p>{a?<><p className="small muted">Owner-supplied answer; not independently verified.</p>{a.remediation_plan?<dl className="facts small"><dt>Fix plan</dt><dd>{a.remediation_plan}</dd><dt>Target</dt><dd>{a.date_pending?'Date being determined':a.target_date?abs(a.target_date).slice(0,10):'Not supplied'} · Estimate</dd></dl>:null}{a.evidence_note?<details><summary>Evidence supplied by owner</summary><p style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{a.evidence_note}</p></details>:null}</>:null}{m.report_id?<Link href={`/reports/attachment/${m.report_id}`} prefetch={false}>Read shared report</Link>:null}</li>;})}</ol>
    {composer??<form method="post" action={`/api/app/reviews/${data.conversation.id}/reply`} className="stack no-print"><input name="client_key" type="hidden" value={randomUUID()}/><div><label htmlFor="review-reply">Reply</label><textarea id="review-reply" name="body" required maxLength={4000} rows={3}/></div><Submit className="btn btn-secondary" busy="Posting…">Post reply</Submit></form>}
  </section>;
}
