import { action,formOf } from "@/lib/http";
import { apiViewer,HttpError } from "@/lib/auth";
import { acceptInvitation,answerRequest,conversationAccess,postReply,requestCheck,retryInvitation,revokeInvitation } from "@/lib/review/requests";
import { attachReport,grantReport,publishReport,revokeReportGrant,sharedReportData,rematchSharedSystem } from "@/lib/review/reports";
import { addAndAnalyze } from "@/lib/systems";
import { q } from "@/lib/db";

export const maxDuration=60;
export const POST=action(async(req,{params})=>{
  const v=await apiViewer(),f=await formOf(req),id=params.id;
  switch(params.op){
    case 'request':{const r=await requestCheck(v,id,{email:f.email,question:f.question,finding_id:f.finding_id||undefined,client_key:f.client_key});return {redirect:`/reviews/${r.conversationId}?delivery=${r.delivery}`,json:r};}
    case 'accept':{const conv=await acceptInvitation(v,id);return {redirect:`/reviews/${conv}`,json:{conversationId:conv}};}
    case 'respond':{
      await conversationAccess(v,id);
      if(f.outcome){const requests=await q('select 1 from app_requests where id=$1 and conversation_id=$2',[f.request_id,id]);if(!requests.length)throw new HttpError(404,'Request not found.');if(f.outcome==='fix_reported')await postReply(v,id,f.body,f.client_key,f.request_id);else await answerRequest(v,f.request_id,{...f,reason:f.body,date_pending:f.date_pending==='on'});}
      else await postReply(v,id,f.body,f.client_key);
      return {redirect:`/reviews/${id}`,json:{ok:true}};
    }
    case 'reply':await postReply(v,id,f.body,f.client_key);return {redirect:`/reviews/${id}`};
    case 'progress':await postReply(v,id,f.body,f.client_key,f.fix_deployed==='on'?f.request_id:undefined);return {redirect:`/reviews/${id}`};
    case 'answer':{await conversationAccess(v,id);const access=await q("select 1 from app_requests where id=$1 and conversation_id=$2",[f.request_id,id]);if(!access.length)throw new HttpError(404,'Request not found.');const r=await answerRequest(v,f.request_id,{...f,date_pending:f.date_pending==='on'});return {redirect:`/reviews/${id}?msg=Answer%20shared`,json:r};}
    case 'retry-invite':{const delivery=await retryInvitation(v,id);return {redirect:`/reviews/${f.conversation_id}?delivery=${delivery}`,json:{delivery}};}
    case 'revoke-invite':await revokeInvitation(v,id);return {redirect:`/reviews/${f.conversation_id}?msg=Invitation%20access%20removed`};
    case 'publish-report':{if(f.conversation_id)await conversationAccess(v,f.conversation_id);const r=await publishReport(v,id,{remediation_plan:f.remediation_plan,target_date:f.target_date,date_pending:f.date_pending==='on'});if(f.conversation_id)await attachReport(v,f.conversation_id,r.pageId);return {redirect:f.conversation_id?`/reviews/${f.conversation_id}?msg=Report%20shared`:`/reports/${r.pageId}`,json:r};}
    case 'attach-report':await attachReport(v,id,f.page_id);return {redirect:`/reviews/${id}?msg=Report%20shared`};
    case 'grant-report':await grantReport(v,id,f.email);return {redirect:`/reports/${id}?msg=Client%20access%20granted`};
    case 'revoke-report':await revokeReportGrant(v,id,f.grant_id);return {redirect:`/reports/${id}?msg=Client%20access%20removed`};
    case 'add-report-app':{await sharedReportData(v,id);const r=await addAndAnalyze(v,f.url);await q(`insert into system_report_links(system_id,workspace_id,page_id,recipient_email) values($1,$2,$3,$4) on conflict do nothing`,[r.systemId,v.workspaceId,id,v.email]);await rematchSharedSystem(r.systemId,v.workspaceId);return {redirect:`/systems/${r.systemId}`};}
    default:throw new HttpError(404,'Action not found.');
  }
});
