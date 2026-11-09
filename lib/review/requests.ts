import "server-only";
import { randomUUID } from "node:crypto";
import { q, one, tx } from "../db";
import { ownSystem } from "../systems";
import { HttpError, type Viewer } from "../auth";
import { rateLimit } from "../rate";
import { answerSchema, emailSchema, idSchema, WORKFLOW_LABEL } from "./validation";
import { deliverInvite, type InviteMail, type MailResult } from "./mail";

export type Conversation = { id: string; workspace_id: string; system_id: string };
export type Finding = { id: string; advisory_id: string; product: string; workflow_status: string; evidence: Record<string, unknown>; changed_at: Date; title: string; identifiers: string[] };

function validId(id: string) { if (!idSchema.safeParse(id).success) throw new HttpError(404, "Not found."); }
function verified(v: Viewer) { if (!v.emailVerified) throw new HttpError(403, "Verify your email before opening an invitation."); }

export async function conversationAccess(v: Viewer, id: string): Promise<{ conversation: Conversation; buyer: boolean }> {
  validId(id);
  const c = await one<Conversation>("select * from app_conversations where id=$1", [id]);
  if (!c) throw new HttpError(404, "Conversation not found.");
  if (c.workspace_id === v.workspaceId) return { conversation: c, buyer: true };
  verified(v);
  const member = await one(`select 1 from conversation_invites where conversation_id=$1 and email=$2 and accepted_by=$3 and revoked_at is null`, [id, v.email, v.id]);
  if (!member) throw new HttpError(404, "Conversation not found.");
  return { conversation: c, buyer: false };
}

export async function invitation(v: Viewer, id: string) {
  validId(id); verified(v);
  const i = await one<{ id: string; conversation_id: string; email: string; expires_at: Date; accepted_by: string | null; revoked_at: Date | null; label: string; url: string; requester: string }>(
    `select i.*,s.label,sc.url,w.name requester from conversation_invites i join app_conversations c on c.id=i.conversation_id
     join systems s on s.id=c.system_id join scan_scopes sc on sc.id=s.scope_id join workspaces w on w.id=c.workspace_id
     where i.id=$1 and s.removed_at is null`, [id]);
  if (!i || i.email !== v.email || i.revoked_at || (i.accepted_by && i.accepted_by !== v.id)) throw new HttpError(404, "Invitation not available for this account.");
  if (!i.accepted_by && i.expires_at.getTime() < Date.now()) throw new HttpError(410, "This invitation expired. Ask the requester for a new invitation.");
  return i;
}

export async function acceptInvitation(v: Viewer, id: string) {
  const i = await invitation(v, id);
  await q("update conversation_invites set accepted_by=$2,accepted_at=coalesce(accepted_at,now()) where id=$1 and revoked_at is null and (accepted_by is null or accepted_by=$2)", [id, v.id]);
  await conversationAccess(v, i.conversation_id);
  return i.conversation_id;
}

export async function requestCheck(v: Viewer, systemId: string, input: { email: string; question: string; finding_id?: string; client_key: string }, transport?: (mail: InviteMail) => Promise<MailResult>) {
  await ownSystem(v, systemId);
  const parsedEmail = emailSchema.safeParse(input.email);
  if (!parsedEmail.success || !input.question?.trim() || input.question.length > 4000 || !idSchema.safeParse(input.client_key).success) throw new HttpError(400, "Enter an owner email and a specific question.");
  const email = parsedEmail.data;
  if (input.finding_id) {
    const finding = await one("select 1 from app_findings where id=$1 and system_id=$2 and workspace_id=$3", [input.finding_id, systemId, v.workspaceId]);
    if (!finding) throw new HttpError(404, "Finding not found.");
  }
  await rateLimit(`owner-request:${v.id}`, 30, 3600);
  const result = await tx(async c => {
    const conv = (await c.query<Conversation>(`insert into app_conversations (workspace_id,system_id) values ($1,$2)
      on conflict(system_id) do update set system_id=excluded.system_id returning *`, [v.workspaceId, systemId])).rows[0];
    const request = (await c.query<{ id: string }>(`insert into app_requests (workspace_id,system_id,conversation_id,finding_id,recipient_email,question,client_key,created_by)
      values($1,$2,$3,$4,$5,$6,$7,$8) on conflict(conversation_id,client_key) do nothing returning id`,
      [v.workspaceId, systemId, conv.id, input.finding_id || null, email, input.question.trim(), input.client_key, v.id])).rows[0];
    if (request) await c.query(`insert into conversation_messages (conversation_id,request_id,author_id,author_email,kind,body,client_key) values($1,$2,$3,$4,'request',$5,$6) on conflict do nothing`, [conv.id, request.id, v.id, v.email, input.question.trim(), input.client_key]);
    let invite = (await c.query<{ id: string }>(`select id from conversation_invites where conversation_id=$1 and email=$2 and revoked_at is null and (accepted_at is not null or expires_at>now()) order by created_at desc limit 1`, [conv.id, email])).rows[0];
    if (!invite) invite = (await c.query<{ id: string }>(`insert into conversation_invites (conversation_id,email,expires_at) values($1,$2,now()+interval '14 days') returning id`, [conv.id, email])).rows[0];
    return { conversationId: conv.id, inviteId: invite.id, created: Boolean(request) };
  });
  const delivery = await deliverInvite(result.inviteId, transport);
  return { ...result, delivery };
}

export async function retryInvitation(v: Viewer, id: string, transport?: (mail: InviteMail) => Promise<MailResult>) {
  validId(id);
  const i = await one<{ conversation_id: string }>("select conversation_id from conversation_invites where id=$1 and revoked_at is null", [id]);
  if (!i || !(await conversationAccess(v, i.conversation_id)).buyer) throw new HttpError(404, "Invitation not found.");
  await rateLimit(`owner-invite-retry:${v.id}`, 10, 3600);
  return deliverInvite(id, transport);
}

export async function revokeInvitation(v: Viewer, id: string) {
  validId(id);
  const i = await one<{ conversation_id: string; email: string }>("select conversation_id,email from conversation_invites where id=$1", [id]);
  if (!i || !(await conversationAccess(v, i.conversation_id)).buyer) throw new HttpError(404, "Invitation not found.");
  await q("update conversation_invites set revoked_at=coalesce(revoked_at,now()) where conversation_id=$1 and email=$2", [i.conversation_id, i.email]);
}

export async function postReply(v: Viewer, conversationId: string, body: string, clientKey: string, progressRequestId?: string) {
  const { conversation } = await conversationAccess(v, conversationId);
  if (!body?.trim() || body.length > 4000 || !idSchema.safeParse(clientKey).success) throw new HttpError(400, "Write a reply (at most 4,000 characters).");
  await rateLimit(`review-reply:${v.id}`, 60, 3600);
  const progressRequest=progressRequestId?await one<{finding_id:string|null;recipient_email:string}>('select finding_id,recipient_email from app_requests where id=$1 and conversation_id=$2',[progressRequestId,conversationId]):null;
  if(progressRequestId&&(!progressRequest||!v.emailVerified||progressRequest.recipient_email!==v.email))throw new HttpError(404,'Request not found for this recipient.');
  await tx(async c => {
    const m = (await c.query(`insert into conversation_messages (conversation_id,author_id,author_email,kind,body,client_key,request_id) values($1,$2,$3,$4,$5,$6,$7) on conflict do nothing returning id`, [conversationId, v.id, v.email, progressRequestId ? "progress" : "reply", body.trim(), clientKey, progressRequestId||null])).rows[0];
    if(m&&progressRequest?.finding_id){const changed=(await c.query<{id:string}>("update app_findings set workflow_status='fix_reported',changed_at=now() where id=$1 and workspace_id=$2 and workflow_status='owner_affected' returning id",[progressRequest.finding_id,conversation.workspace_id])).rows[0];if(changed)await c.query("insert into finding_transitions(finding_id,from_status,to_status,detail,transition_key) values($1,'owner_affected','fix_reported',$2,$3) on conflict do nothing",[changed.id,JSON.stringify({message_id:m.id,independently_verified:false}),`progress:${m.id}`]);}
  });
}

export async function answerRequest(v: Viewer, requestId: string, raw: unknown) {
  validId(requestId);
  const parsed = answerSchema.safeParse(raw);
  if (!parsed.success) throw new HttpError(400, parsed.error.issues[0].message);
  const a = parsed.data;
  const request = await one<{ id: string; conversation_id: string; finding_id: string | null; recipient_email: string }>("select * from app_requests where id=$1", [requestId]);
  if (!request) throw new HttpError(404, "Request not found.");
  await conversationAccess(v, request.conversation_id);
  if (!v.emailVerified || request.recipient_email !== v.email) throw new HttpError(404, "Request not found for this recipient.");
  return tx(async c => {
    const row = (await c.query<{ id: string }>(`insert into owner_answers (request_id,outcome,reason,remediation_plan,target_date,date_pending,evidence_note,actor_id,actor_email,client_key)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) on conflict(request_id,client_key) do nothing returning id`,
      [requestId,a.outcome,a.reason,a.outcome==='affected'?a.remediation_plan:null,a.outcome==='affected'&&!a.date_pending?a.target_date||null:null,a.outcome==='affected'&&a.date_pending,a.evidence_note||null,v.id,v.email,a.client_key])).rows[0];
    if (!row) return { created: false };
    const label = a.outcome==='not_affected'?"Owner confirmed: not affected by this alert":a.outcome==='affected'?"Owner confirmed: affected":"Needs more evidence";
    await c.query(`insert into conversation_messages (conversation_id,request_id,author_id,author_email,kind,body,answer_id,client_key) values($1,$2,$3,$4,'answer',$5,$6,$7)`, [request.conversation_id,requestId,v.id,v.email,`${label}. ${a.reason}`,row.id,randomUUID()]);
    await c.query("update app_requests set state=$2 where id=$1", [requestId,a.outcome==='unknown'?'needs_evidence':'answered']);
    if (request.finding_id) {
      const finding = (await c.query<{ workflow_status: string }>("select workflow_status from app_findings where id=$1 for update", [request.finding_id])).rows[0];
      if(finding.workflow_status==='withdrawn')return {created:true,id:row.id};
      const status = a.outcome==='not_affected'?'owner_not_affected':a.outcome==='affected'?'owner_affected':'unknown';
      await c.query("update app_findings set workflow_status=$2,changed_at=now() where id=$1", [request.finding_id,status]);
      await c.query("insert into finding_transitions (finding_id,from_status,to_status,detail,transition_key) values($1,$2,$3,$4,$5) on conflict do nothing", [request.finding_id,finding.workflow_status,status,JSON.stringify({ answer_id:row.id,actor_email:v.email,independently_verified:false }),`answer:${row.id}`]);
    }
    return { created: true, id: row.id };
  });
}

export async function reviewData(v: Viewer, conversationId: string) {
  const access = await conversationAccess(v, conversationId);
  const context = (await one<{ label: string; url: string; requester: string }>(`select s.label,sc.url,w.name requester from app_conversations c join systems s on s.id=c.system_id join scan_scopes sc on sc.id=s.scope_id join workspaces w on w.id=c.workspace_id where c.id=$1 and s.removed_at is null`, [conversationId]));
  if (!context) throw new HttpError(404, "App not found.");
  const [requests,messages,answers,invites] = await Promise.all([
    q<{ id:string;question:string;state:string;recipient_email:string;finding_id:string|null;created_at:Date }>("select * from app_requests where conversation_id=$1 order by created_at desc", [conversationId]),
    q<{ id:string;request_id:string|null;author_email:string;kind:string;body:string;answer_id:string|null;report_id:string|null;created_at:Date }>("select * from conversation_messages where conversation_id=$1 order by created_at,id", [conversationId]),
    q<{ id:string;request_id:string;outcome:string;reason:string;remediation_plan:string|null;target_date:Date|null;date_pending:boolean;evidence_note:string|null;actor_email:string;created_at:Date }>("select a.* from owner_answers a join app_requests r on r.id=a.request_id where r.conversation_id=$1 order by a.created_at", [conversationId]),
    access.buyer?q<{ id:string;email:string;delivery_state:string;accepted_at:Date|null;revoked_at:Date|null }>("select id,email,delivery_state,accepted_at,revoked_at from conversation_invites where conversation_id=$1 order by created_at desc", [conversationId]):Promise.resolve([]),
  ]);
  return { ...access,...context,requests:access.buyer?requests:requests.filter(r=>r.recipient_email===v.email),messages,answers,invites };
}

export async function systemReview(v: Viewer, id: string) {
  await ownSystem(v,id);
  const findings = await q<Finding>(`select f.*,coalesce(a.record->>'title',f.evidence->>'title') title,coalesce(a.identifiers,array[f.evidence->>'primary_identifier']) identifiers from app_findings f left join advisories a on a.id=f.advisory_id where f.system_id=$1 and f.workspace_id=$2
    and (f.source_kind='public' or exists(select 1 from shared_reports r join report_grants g on g.page_id=r.page_id where r.id::text=f.source_id and g.email=$3 and g.revoked_at is null)) order by f.changed_at desc`, [id,v.workspaceId,v.email]);
  const conv = await one<Conversation>("select * from app_conversations where system_id=$1 and workspace_id=$2", [id,v.workspaceId]);
  const history=await q<{id:number;finding_id:string;to_status:string;created_at:Date;detail:{reason?:string};title:string}>(`select t.*,coalesce(a.record->>'title',f.evidence->>'title') title from finding_transitions t join app_findings f on f.id=t.finding_id left join advisories a on a.id=f.advisory_id where f.id=any($1::uuid[]) order by t.id desc limit 30`,[findings.map(f=>f.id)]);
  return { findings,history,conversation:conv?await reviewData(v,conv.id):null,labels:WORKFLOW_LABEL };
}

// A small, authorized portfolio projection; raw shared inventory stays on the
// explicitly granted report page. Never turn an owner answer into a scan result.
export async function portfolioReviews(v:Viewer){
  const [findings,answers,reports,waiting]=await Promise.all([
    q<{system_id:string;workflow_status:string;assessment_status:string;evidence:{primary_identifier:string;title:string;next_step:string;version_used:string|null};product:string}>(`select f.system_id,f.workflow_status,f.assessment_status,f.evidence,f.product from app_findings f where f.workspace_id=$1 and (f.source_kind='public' or exists(select 1 from shared_reports r join report_pages p on p.id=r.page_id join developer_projects d on d.id=p.project_id and d.deleted_at is null join report_grants g on g.page_id=r.page_id where r.id::text=f.source_id and g.email=$2 and g.revoked_at is null))`,[v.workspaceId,v.email]),
    q<{system_id:string;outcome:string;created_at:Date}>(`select distinct on(r.system_id) r.system_id,a.outcome,a.created_at from owner_answers a join app_requests r on r.id=a.request_id where r.workspace_id=$1 order by r.system_id,a.created_at desc,a.id`,[v.workspaceId]),
    q<{system_id:string;n:string}>(`select l.system_id,count(*) n from system_report_links l join report_grants g on g.page_id=l.page_id and g.email=$2 and g.revoked_at is null join report_pages p on p.id=l.page_id join developer_projects d on d.id=p.project_id and d.deleted_at is null where l.workspace_id=$1 group by l.system_id`,[v.workspaceId,v.email]),
    q<{system_id:string;n:string}>("select system_id,count(*) n from app_requests where workspace_id=$1 and state in ('waiting','needs_evidence') group by system_id",[v.workspaceId]),
  ]);
  return {findings,answers,reports,waiting};
}

export async function incomingInvites(v: Viewer) {
  verified(v);
  return q<{ id:string;label:string;requester:string;conversation_id:string;accepted_at:Date|null }>(`select i.id,s.label,w.name requester,i.conversation_id,i.accepted_at from conversation_invites i join app_conversations c on c.id=i.conversation_id join systems s on s.id=c.system_id join workspaces w on w.id=c.workspace_id where i.email=$1 and i.revoked_at is null and (i.accepted_by=$2 or (i.accepted_by is null and i.expires_at>now())) and s.removed_at is null order by i.created_at desc`, [v.email,v.id]);
}
