import "server-only";
import { tx } from "../db";
import { env } from "../env";
import { brandedSender,invitationEmail,replyToAddress } from "../email-brand";


import {after} from "next/server";
import {recordError} from "../monitoring/server";

export type InviteMail = { email: string; url: string; app: string; requester: string; key: string };
export type MailResult = "sent" | "unconfigured" | "failed";
export function invitationDeliveryAvailable() {
  return process.env.CANARY_INVITATION_MODE !== "hold" && Boolean(process.env.RESEND_API_KEY && process.env.CANARY_EMAIL_FROM);
}
export async function sendInviteMail(mail: InviteMail): Promise<MailResult> {
  if(process.env.CANARY_INVITATION_MODE==='hold')return 'unconfigured';
  // Invitations are contextual mail, not a sign-in initiated in somebody
  // else's browser. The recipient signs in through the normal app flow.
  if (!invitationDeliveryAvailable() || !process.env.CANARY_EMAIL_FROM) return 'unconfigured';
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST", signal: AbortSignal.timeout(15_000),
      headers: { authorization: `Bearer ${process.env.RESEND_API_KEY}`, "content-type": "application/json", "idempotency-key": mail.key },
      body: JSON.stringify({ from: brandedSender(process.env.CANARY_EMAIL_FROM), to: [mail.email], ...(replyToAddress() ? { reply_to: replyToAddress() } : {}), ...invitationEmail(mail) }),
    });
    if(!response.ok)after(()=>recordError("mail"));
    return response.ok ? "sent" : "failed";
  } catch { after(()=>recordError("mail"));return "failed"; }
}

export async function deliverInvite(id: string, transport = sendInviteMail) {
  return tx(async c=>{
    const invite=(await c.query<{email:string;label:string;name:string;delivery_state:string}>(
      `select i.email,i.delivery_state,s.label,w.name from conversation_invites i
       join app_conversations c on c.id=i.conversation_id join systems s on s.id=c.system_id
       join workspaces w on w.id=c.workspace_id where i.id=$1 and i.revoked_at is null for update of i`,[id])).rows[0];
    if(!invite||invite.delivery_state==='sent')return invite?.delivery_state??'failed';
    const result=await transport({email:invite.email,url:`${env.siteUrl()}/requests/${id}`,app:invite.label,requester:invite.name,key:`invite-${id}`});
    await c.query('update conversation_invites set delivery_state=$2,delivery_error=$3 where id=$1',[id,result,result==='failed'?'Delivery failed; retry or share the recipient-bound link.':null]);
    return result;
  });
}
