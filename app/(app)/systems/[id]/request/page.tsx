import Link from "next/link";
import { randomUUID } from "node:crypto";
import { notFound } from "next/navigation";
import { requireViewer } from "@/lib/auth";
import { getSystem } from "@/lib/portfolio";
import { systemReview } from "@/lib/review/requests";
import { RequestCheck } from "@/components/request-check";
import {systemOverview} from '@/lib/system-overview';
import {invitationDeliveryAvailable} from '@/lib/review/mail';
export const metadata={title:'Ask the app owner'};
export default async function RequestPage({params,searchParams}:{params:Promise<{id:string}>;searchParams:Promise<{finding?:string;clue?:string}>}){
 const {id}=await params,sp=await searchParams,v=await requireViewer(`/systems/${id}/request`),d=await getSystem(id);if(!d)notFound();
 const review=await systemReview(v,id),finding=review.findings.find(f=>f.id===sp.finding);
 if(sp.finding&&!finding)notFound();
 const overview=sp.clue?await systemOverview(v,id):null,clue=overview?.clues.find(c=>c.product===sp.clue);
 if(sp.clue&&!clue)notFound();
 const lastContact=review.conversation?.requests[0]?.recipient_email||'';
 const basis=finding?`Canary flagged ${finding.product} on ${d.system.label}, which may be affected by ${finding.title} (${finding.identifiers.join(', ')}). ${String(finding.evidence.reason||'The available evidence is incomplete.')} Please confirm the current deployed version and relevant configuration.`:`Canary could not establish the internal software inventory for ${d.system.label}. This is a coverage check, not a confirmed vulnerability. Please confirm which software this app runs and whether any relevant reviewed alerts need attention.`;
 const clueBasis=clue?`An overview we added for ${d.system.label} mentions ${clue.name}${clue.mentions.some(m=>m.version)?` (document versions: ${[...new Set(clue.mentions.flatMap(m=>m.version?[m.version]:[]))].join(', ')})`:''}. This may be historical, a recommendation or an exclusion; it does not establish current use or exposure. Please confirm whether this app currently uses ${clue.name}, its deployed version and relevant configuration.${clue.alerts.length?` Related reviewed alerts, applicability not assessed: ${clue.alerts.slice(0,5).map(a=>a.identifier).join(', ')}${clue.alerts.length>5?' (first five; see the related alert list for more)':''}.`:''}`:null;
 const question=`We use Zero Day Canary to monitor our applications for vulnerabilities.\n\n${clueBasis||basis}\n\nApp: ${d.system.scope?.url}\n\nPlease answer here: not affected (with a brief reason), affected (with a fix plan and target date, or say the date is being determined), or not sure (what evidence is missing). A quick answer is enough; you can optionally run a deeper supported check and share a reviewed report.`;
 return <div className="stack prose"><Link href={`/systems/${id}`}>← {d.system.label}</Link><h1 className="h-page">Ask the app owner to check</h1><p>{finding?'One specific question about a possible vulnerability.':clue?'Confirm a specific technology clue before treating it as exposure.':'Ask for missing inventory evidence without creating a vulnerability claim.'}</p><RequestCheck systemId={id} findingId={finding?.id} email={lastContact} question={question} clientKey={randomUUID()} deliveryEnabled={invitationDeliveryAvailable()}/></div>;
}
