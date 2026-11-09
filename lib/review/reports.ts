import "server-only";
import { randomUUID } from "node:crypto";
import { one, q, tx } from "../db";
import { HttpError, type Viewer } from "../auth";
import { ownProject } from "../developer/projects";
import { evaluateComponents, type DevResult } from "../developer/evaluate";
import { allAdvisories } from "../catalog";
import { productForPackage } from "@/intel/packages";
import { assessAdvisory } from "@/intel/match";
import { conversationAccess } from "./requests";
import { syncFindings, syncInactiveFindings, type FindingCandidate } from "./findings";
import { emailSchema, idSchema } from "./validation";
import {storedChecks,refreshChecks} from '../osv/store';
import type {CveReview} from "../developer/cve-report";

export type SharedComponent = { instance:number;name:string;version:string|null;ecosystem:string;relationship:string;development:boolean|null;public_registry?:boolean };
export type AuditSummary = {run_status:string;audited_at:string|null;confirmed:number;needs_validation:number;rejected:number;total_records:number};
export type ReportSnapshot = { cve_review?:CveReview; audit?:AuditSummary; project_name:string;received_at:string;checked_build:string|null;source_dirty?:boolean;inventory_unknowns?:number;coverage:Record<string,unknown>;results:DevResult[];components:SharedComponent[];limits:string[] };
export type SharedReport = { id:string;page_id:string;snapshot:ReportSnapshot;remediation_plan:string|null;target_date:Date|null;date_pending:boolean;created_at:Date };

export async function reportDraft(v: Viewer, projectId: string) {
  const p = await ownProject(v,projectId);
  const evaluation = await one<{ id:string;evidence_id:string;results:DevResult[];coverage:Record<string,unknown>;received_at:Date;repository_commit:string|null;repository_dirty:boolean;unknowns:unknown[];cve_review:CveReview|null;audit_summary:{context:{run_status:string;audited_at:string|null};verdict_counts:{confirmed:number;needs_validation:number;rejected:number};total_records:number} }>(
    `select e.id,e.evidence_id,e.results,e.coverage,d.received_at,d.repository_commit,d.repository_dirty,d.unknowns,d.cve_review,d.audit_summary from developer_evaluations e join developer_evidence d on d.id=e.evidence_id
     where e.project_id=$1 and e.workspace_id=$2 and e.state='completed' and e.evidence_id=$3 order by e.completed_at desc limit 1`, [p.id,v.workspaceId,p.latest_evidence_id]);
  if (!evaluation) throw new HttpError(400,"Upload an inventory and wait for a completed evaluation before sharing.");
  const components = await q<SharedComponent>("select instance,name,exact_version version,ecosystem,relationship,development,public_registry from developer_components where evidence_id=$1 and workspace_id=$2 order by instance", [evaluation.evidence_id,v.workspaceId]);
  const audit=evaluation.audit_summary;
  const snapshot:ReportSnapshot = { ...(evaluation.cve_review?{cve_review:evaluation.cve_review}:{}),...(audit&&(audit.total_records||audit.context.run_status!=='unknown')?{audit:{run_status:audit.context.run_status,audited_at:audit.context.audited_at,confirmed:audit.verdict_counts.confirmed,needs_validation:audit.verdict_counts.needs_validation,rejected:audit.verdict_counts.rejected,total_records:audit.total_records}}:{}),project_name:p.name,received_at:evaluation.received_at.toISOString(),checked_build:evaluation.repository_commit,source_dirty:evaluation.repository_dirty,inventory_unknowns:evaluation.unknowns?.length||0,
    coverage:evaluation.coverage,results:evaluation.results,components,limits:["Developer-supplied source inventory; production is not independently verified.","Public packages with exact versions are checked using available OSV data and Canary-reviewed rules. Private, missing and unsupported inventory stays unassessed. No matching record does not prove security.","Source files, raw lockfiles, detailed source audits and client conversations are excluded. CVE summaries and file/line references shown here are shared."] };
  return { p,evaluation,snapshot,needsFix:Boolean(snapshot.audit?.confirmed)||Boolean(snapshot.cve_review?.assessments.some(a=>a.conclusion==='source_prerequisites_supported'))||snapshot.results.some(r=>['affected_version_matched','applicability_confirmed'].includes(r.status)) };
}

export async function publishReport(v: Viewer, projectId:string, input:{ remediation_plan?:string;target_date?:string;date_pending?:boolean }) {
  const draft = await reportDraft(v,projectId);
  const plan = input.remediation_plan?.trim().slice(0,2000)||'';
  const date = input.target_date||null;
  if (draft.needsFix&&(!plan||(!date&&!input.date_pending))) throw new HttpError(400,"Add a fix plan and target date, or say the date is being determined.");
  if(date&&(!/^\d{4}-\d{2}-\d{2}$/.test(date)||Number.isNaN(Date.parse(date))||new Date(`${date}T12:00Z`).toISOString().slice(0,10)!==date))throw new HttpError(400,"Use a valid target date.");
  return tx(async c=>{
    const page=(await c.query<{id:string}>(`insert into report_pages (project_id,owner_workspace_id) values($1,$2) on conflict(project_id) do update set project_id=excluded.project_id returning id`,[projectId,v.workspaceId])).rows[0];
    const report=(await c.query<{id:string}>(`insert into shared_reports (page_id,evidence_id,evaluation_id,snapshot,remediation_plan,target_date,date_pending,shared_by) values($1,$2,$3,$4,$5,$6,$7,$8) on conflict(page_id,evaluation_id) do nothing returning id`,[page.id,draft.evaluation.evidence_id,draft.evaluation.id,JSON.stringify(draft.snapshot),draft.needsFix?plan:null,draft.needsFix&&!input.date_pending?date:null,draft.needsFix&&Boolean(input.date_pending),v.id])).rows[0]
      ??(await c.query<{id:string}>("select id from shared_reports where page_id=$1 and evaluation_id=$2",[page.id,draft.evaluation.id])).rows[0];
    return {pageId:page.id,reportId:report.id};
  });
}

export async function reportAccess(v:Viewer,pageId:string) {
  if(!idSchema.safeParse(pageId).success)throw new HttpError(404,"Report not found.");
  const page=await one<{id:string;owner_workspace_id:string;project_id:string}>(`select r.* from report_pages r join developer_projects p on p.id=r.project_id where r.id=$1 and p.deleted_at is null`,[pageId]);
  if(!page)throw new HttpError(404,"Report not found.");
  const owner=page.owner_workspace_id===v.workspaceId;
  if(!owner&&(!v.emailVerified||!await one("select 1 from report_grants where page_id=$1 and email=$2 and revoked_at is null",[pageId,v.email])))throw new HttpError(404,"Report not available for this account.");
  return {page,owner};
}

export async function sharedReportData(v:Viewer,pageId:string,reportId?:string) {
  const access=await reportAccess(v,pageId);
  if(reportId&&!idSchema.safeParse(reportId).success)throw new HttpError(404,"Report not found.");
  const report=await one<SharedReport>(`select * from shared_reports where page_id=$1 ${reportId?'and id=$2':''} order by created_at desc,id desc limit 1`,reportId?[pageId,reportId]:[pageId]);
  if(!report)throw new HttpError(404,"Report not found.");
  const grants=access.owner?await q<{id:string;email:string;revoked_at:Date|null}>("select id,email,revoked_at from report_grants where page_id=$1 order by created_at",[pageId]):[];
  return {...access,report,grants};
}

export async function grantReport(v:Viewer,pageId:string,email:string) {
  const {owner}=await reportAccess(v,pageId);
  if(!owner)throw new HttpError(404,"Report not found.");
  const parsed=emailSchema.safeParse(email);if(!parsed.success)throw new HttpError(400,"Enter the client's email.");
  await q(`insert into report_grants (page_id,email,granted_by) values($1,$2,$3) on conflict(page_id,email) do update set revoked_at=null,granted_by=excluded.granted_by`,[pageId,parsed.data,v.id]);
}
export async function revokeReportGrant(v:Viewer,pageId:string,grantId:string) {
  const {owner}=await reportAccess(v,pageId);if(!owner)throw new HttpError(404,"Report not found.");
  await q("update report_grants set revoked_at=coalesce(revoked_at,now()) where id=$1 and page_id=$2",[grantId,pageId]);
}

export async function attachReport(v:Viewer,conversationId:string,pageId:string) {
  const {conversation,buyer}=await conversationAccess(v,conversationId);
  const {owner,report}=await sharedReportData(v,pageId);
  if(!owner)throw new HttpError(403,"Only the report owner can share it.");
  // The requester receives only this explicitly reviewed snapshot, not raw private uploads.
  const recipient=await one<{email:string}>("select u.email from workspaces w join auth.users u on u.id=w.owner_id where w.id=$1",[conversation.workspace_id]);
  if(!recipient)throw new HttpError(404,"Requester not found.");
  await tx(async c=>{
    await c.query(`insert into report_grants(page_id,email,granted_by) values($1,$2,$3) on conflict(page_id,email) do update set revoked_at=null`,[pageId,recipient.email.toLowerCase(),v.id]);
    await c.query(`insert into system_report_links(system_id,workspace_id,page_id,recipient_email) values($1,$2,$3,$4) on conflict(system_id,page_id) do update set recipient_email=excluded.recipient_email`,[conversation.system_id,conversation.workspace_id,pageId,recipient.email.toLowerCase()]);
    const key=report.id;
    await c.query(`insert into conversation_messages(conversation_id,author_id,author_email,kind,body,report_id,client_key) values($1,$2,$3,'report',$4,$5,$6) on conflict do nothing`,[conversationId,v.id,v.email,'Shared a reviewed report. Its coverage and production limits apply.',report.id,key]);
  });
  await rematchSharedSystem(conversation.system_id,conversation.workspace_id);
  return report.id;
}

export async function systemReports(v:Viewer,systemId:string) {
  return q<SharedReport>(`select r.* from system_report_links l join report_pages p on p.id=l.page_id
    join developer_projects d on d.id=p.project_id join report_grants g on g.page_id=p.id and g.email=$3 and g.revoked_at is null
    join lateral(select * from shared_reports r where r.page_id=p.id order by r.created_at desc limit 1) r on true
    where l.system_id=$1 and l.workspace_id=$2 and d.deleted_at is null`,[systemId,v.workspaceId,v.email]);
}

export async function rematchSharedSystem(systemId:string,workspaceId:string) {
  const links=await q<{id:string;page_id:string;snapshot:ReportSnapshot;created_at:Date}>(`select r.* from system_report_links l join report_grants g on g.page_id=l.page_id and g.email=l.recipient_email and g.revoked_at is null
    join report_pages p on p.id=l.page_id join developer_projects d on d.id=p.project_id and d.deleted_at is null
    join lateral(select * from shared_reports where page_id=p.id order by created_at desc limit 1) r on true where l.system_id=$1 and l.workspace_id=$2`,[systemId,workspaceId]);
  const catalog=await allAdvisories();
  for(const report of links){
    const candidates:FindingCandidate[]=[];
    for(const component of report.snapshot.components){
      const product=productForPackage(component.ecosystem,component.name);if(!product)continue;
      for(const advisory of catalog){
        const results=assessAdvisory(advisory,{techs:[{product,name:component.name,version:component.version,version_basis:component.version?'developer_supplied':null,evidence_type:'inventory',location:'explicitly shared report',detail:'Retained shared inventory',confidence:'medium',observed_at:report.snapshot.received_at,limitations:['Source inventory; production is not independently verified.']}],facts:{},observed_at:report.snapshot.received_at});
        for(const result of results)candidates.push({result,componentKey:report.snapshot.components.filter(c=>productForPackage(c.ecosystem,c.name)===product).length===1?product:`${product}:${component.instance}`,product,sourceKind:'shared_report',sourceAt:report.snapshot.received_at,sourceId:report.id});
      }
    }
    const components=report.snapshot.components.map(c=>({...c,exact_version:c.version}));
    const checks=await storedChecks(components);
    const {results}=evaluateComponents(components,catalog,report.snapshot.received_at,checks);
    for(const r of results.filter(r=>r.dataset==='osv')){
      const product=`${r.component.ecosystem}:${r.component.name}`;
      candidates.push({product,componentKey:`${product}:${r.component.instance}`,sourceKind:'shared_report',sourceAt:report.snapshot.received_at,sourceId:report.id,result:{advisory_id:r.advisory_id,advisory_revision:r.advisory_revision,primary_identifier:r.identifier,title:r.title,product,status:r.status,reason:r.reason,next_step:r.next_step,version_used:r.component.version,version_basis:r.component.version?'developer_supplied':null,matched_range:null,conditions:[],evidence_location:'Explicitly shared source inventory'}});
    }
    const previous=await q<{advisory_id:string;component_key:string;product:string;evidence:FindingCandidate['result']}>(`select f.* from app_findings f join shared_reports r on r.id::text=f.source_id where f.system_id=$1 and f.workspace_id=$2 and f.source_kind='shared_report' and r.page_id=$3`,[systemId,workspaceId,report.page_id]);
    for(const old of previous){
      if(candidates.some(c=>c.result.advisory_id===old.advisory_id&&c.componentKey===old.component_key))continue;
      // Removal/unsupported inventory is a coverage gap, never evidence of a fix.
      candidates.push({componentKey:old.component_key,product:old.product,sourceKind:'shared_report',sourceAt:report.snapshot.received_at,sourceId:report.id,result:{...old.evidence,status:'not_assessed',version_used:null,version_basis:null,matched_range:null,conditions:[],reason:'The latest shared report does not provide assessable inventory for this previous finding. Removal does not verify a fix.',next_step:'Ask the owner for current component and deployment evidence.'}});
    }
    await syncFindings(workspaceId,systemId,candidates);
  }
  await syncInactiveFindings(workspaceId,systemId);
}
export async function rematchSharedSystems(){const links=await q<{system_id:string;workspace_id:string}>("select distinct l.system_id,l.workspace_id from system_report_links l join systems s on s.id=l.system_id where s.monitoring='active' and s.removed_at is null");const deadline=Date.now()+90000;for(const l of links){
 const inventories=await q<{snapshot:ReportSnapshot}>(`select r.snapshot from system_report_links l join report_grants g on g.page_id=l.page_id and g.email=l.recipient_email and g.revoked_at is null join report_pages p on p.id=l.page_id join developer_projects d on d.id=p.project_id and d.deleted_at is null join lateral(select snapshot from shared_reports where page_id=p.id order by created_at desc limit 1) r on true where l.system_id=$1 and l.workspace_id=$2`,[l.system_id,l.workspace_id]);
 if(Date.now()<deadline)await refreshChecks(inventories.flatMap(r=>r.snapshot.components.map(c=>({...c,exact_version:c.version}))),Math.min(deadline,Date.now()+15000));
 await rematchSharedSystem(l.system_id,l.workspace_id);
 }return links.length;}
