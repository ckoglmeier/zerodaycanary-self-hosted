import Link from "next/link";
import { randomUUID } from "node:crypto";
import { notFound } from "next/navigation";
import { requireViewer, HttpError } from "@/lib/auth";
import { reviewData } from "@/lib/review/requests";
import { reportRequestContext, requestOutcome } from "@/lib/review/presentation";
import { invitationDeliveryAvailable } from "@/lib/review/mail";
import { RequestContext } from "@/components/request-context";
import { Conversation } from "@/components/conversation";
import { ReviewComposer } from "@/components/review-composer";
import { Submit } from "@/components/submit";
import { CopyButton } from "@/components/copy";
import { env } from "@/lib/env";

export const metadata = { title:"App conversation", robots:{index:false,follow:false} };
export default async function Review({params,searchParams}:{params:Promise<{id:string}>;searchParams:Promise<{error?:string;msg?:string;delivery?:string}>}) {
  const {id}=await params, sp=await searchParams, v=await requireViewer(`/reviews/${id}`);
  const d=await reviewData(v,id).catch(e=>{if(e instanceof HttpError&&e.status===404)notFound();throw e;});
  const request=d.requests[0], latestInvite=d.invites.find(i=>!i.revoked_at&&i.email===request?.recipient_email);
  return <div className="stack conversation-page" style={{["--gap" as string]:"24px"}}>
    <p><Link href={d.buyer?`/systems/${d.conversation.system_id}`:"/requests"}>← {d.buyer?"Back to app":"Requests"}</Link></p>
    <header className="stack"><h1 className="h-page wrap">{d.label}</h1><p className="mono wrap">{d.url}</p><p><strong>{requestOutcome(request,d.answers,d.messages)}</strong></p><p className="hint">Owner answers and source reports do not independently verify a deployed fix.</p></header>
    {sp.error?<p className="notice n-danger" role="alert">{sp.error}</p>:null}
    {sp.msg?<p className="notice n-success" role="status">{sp.msg}</p>:null}
    {d.buyer&&latestInvite&&(!latestInvite.accepted_at||sp.delivery)?<section className={`notice ${latestInvite.accepted_at||latestInvite.delivery_state==="sent"?"n-neutral":"n-warning"} stack`} aria-label="Invitation delivery">
      <strong>{latestInvite.accepted_at?"Request saved — the owner already has access":latestInvite.delivery_state==="sent"?"Invitation emailed":"Request saved — share the invitation link"}</strong>
      <p className="small">{latestInvite.accepted_at?`Share this link with ${latestInvite.email} to bring them to the current request.`:latestInvite.delivery_state==="sent"?`An invitation was sent to ${latestInvite.email}.`:`Email has not been sent. Copy this link and send it to ${latestInvite.email}.`} Only the invited account can open it.</p>
      <CopyButton text={`${env.siteUrl()}/requests/${latestInvite.id}`} label="Copy invitation link"/>
    </section>:null}
    {request?<RequestContext context={reportRequestContext(d)}/>:null}
    {!d.buyer?<section className="panel stack"><h2 className="h-section">Check the evidence</h2><p>Give a quick answer below, or run the free Canary skill to check your source and packages. Review the report before sharing it with {d.requester}. You can reuse that report with other clients for free.</p><div><Link href={`/developer/skill?request=${id}`} className="btn btn-brand">Run the deeper check</Link></div><details><summary>Use a report you already have</summary><p><Link href={`/developer?request=${id}`}>Choose a private project to review and share</Link></p></details></section>:null}
    <Conversation data={d} composer={<ReviewComposer conversationId={id} requestId={request?.id} owner={!d.buyer} clientKey={randomUUID()}/>}/>
    {d.buyer?<details className="panel"><summary>Manage owner access</summary><div className="stack">{d.invites.map(i=><div className="stack" key={i.id}><p className="small wrap">{i.email} · {i.revoked_at?"Access removed":i.accepted_at?"Accepted":i.delivery_state==="sent"?"Invitation emailed":"Email not sent"}</p>{!i.revoked_at?<div className="row"><CopyButton text={`${env.siteUrl()}/requests/${i.id}`} label="Copy owner access link"/>{invitationDeliveryAvailable()?<form method="post" action={`/api/app/reviews/${i.id}/retry-invite`}><input type="hidden" name="conversation_id" value={id}/><Submit busy="Sending…" className="btn btn-secondary">Retry email</Submit></form>:null}<form method="post" action={`/api/app/reviews/${i.id}/revoke-invite`}><input type="hidden" name="conversation_id" value={id}/><Submit busy="Removing…" className="btn btn-danger" confirm="Remove this person's access to this app conversation?">Remove access</Submit></form></div>:null}</div>)}<Link href={`/systems/${d.conversation.system_id}/request`}>Ask a new question</Link></div></details>:null}
  </div>;
}
