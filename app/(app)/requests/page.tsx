import Link from "next/link";
import { requireViewer } from "@/lib/auth";
import { incomingInvites } from "@/lib/review/requests";
export const metadata={title:'Requests for you'};
export default async function Inbox(){const v=await requireViewer('/requests'),invites=await incomingInvites(v);return <div className="stack"><h1 className="h-page">Requests for you</h1><p>App-specific questions from clients. Checking and answering are free.</p>{invites.length?<ul className="list">{invites.map(i=><li key={i.id}><Link href={i.accepted_at?`/reviews/${i.conversation_id}`:`/requests/${i.id}`}>{i.label}</Link><p className="small muted">{i.requester} · {i.accepted_at?'Conversation open':'Invitation'}</p></li>)}</ul>:<p className="panel">No app-check invitations for this email.</p>}</div>;}
