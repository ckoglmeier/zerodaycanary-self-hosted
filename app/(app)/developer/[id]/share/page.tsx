import Link from "next/link";
import { requireViewer } from "@/lib/auth";
import { reportDraft } from "@/lib/review/reports";
import { reportRequestContext } from "@/lib/review/presentation";
import { RequestContext } from "@/components/request-context";
import { reviewData } from "@/lib/review/requests";
import { ReportView } from "@/components/report-view";
import { ShareReportForm } from "@/components/share-report-form";
import { missingRequestedTargets } from "@/lib/review/report-groups";
export const metadata={title:'Review report before sharing'};
export default async function Share({params,searchParams}:{params:Promise<{id:string}>;searchParams:Promise<{request?:string;error?:string}>}){
 const {id}=await params,sp=await searchParams,v=await requireViewer(`/developer/${id}/share`),draft=await reportDraft(v,id);
 const request=sp.request?await reviewData(v,sp.request):null;
 const missing=request?missingRequestedTargets(draft.snapshot,reportRequestContext(request).identifiers):[];
 return <div className="stack"><Link href={`/developer/${id}${sp.request?'?request='+sp.request:''}`}>← Private project</Link><h1 className="h-page">Review before sharing</h1>{request?<RequestContext context={reportRequestContext(request)}/>:null}{missing.length?<p className="notice n-warning">Not covered in this report: {missing.join(", ")}. These requested alerts still need evidence. Sharing this report does not answer or close them.</p>:null}<p>Only the report below is shared. CVE summaries and file/line references shown below will be shared. Review them for confidential information. Source files, raw lockfiles, detailed source audits and client conversations are excluded. Invited clients can read free.</p>{sp.error?<p className="notice n-danger" role="alert">{sp.error}</p>:null}<div><a href="#share-report" className="btn btn-secondary">Continue to sharing</a></div><ReportView snapshot={draft.snapshot}/>
 <ShareReportForm projectId={id} requestId={sp.request} requester={request?.requester} needsFix={draft.needsFix}/></div>;
}
