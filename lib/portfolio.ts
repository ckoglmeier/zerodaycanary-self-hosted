import "server-only";
// Private reads: validated Supabase identity plus explicit workspace predicates and RLS.
import { requireViewer } from "./auth";
import { userQ } from "./db";
import type { AdvisoryAssessment } from "@/intel/match";
import type { AssessmentSummary, ObservationRow } from "./assess";
import { portfolioReviews } from "./review/requests";

export type SystemRow = {
  id: string;
  label: string;
  business_use: string | null;
  owner_vendor: string | null;
  monitoring: string;
  created_at: string;
  host_request_token: string;
  scope: { id: string; url: string; host: string; scope_key: string } | null;
};
export type Claim = { id: string; scope_id: string; product: string; claimed_version: string; upgraded_at: string | null; reference_url: string | null; created_at: string; state: string; outcome_detail: string | null; updated_at: string };

export async function listSystems() {
  const v=await requireViewer();
  const systems=await userQ<SystemRow>(v,`select s.id,s.label,s.business_use,s.owner_vendor,s.monitoring,s.created_at,s.host_request_token,
    jsonb_build_object('id',sc.id,'url',sc.url,'host',sc.host,'scope_key',sc.scope_key) scope
    from systems s join scan_scopes sc on sc.id=s.scope_id where s.workspace_id=$1 and s.removed_at is null order by s.created_at`,[v.workspaceId]);
  const ids=systems.map(s=>s.id),scopeIds=systems.map(s=>s.scope!.id);
  const [assessments,claims,reviews]=await Promise.all([
    userQ<{system_id:string;computed_at:string;results:AdvisoryAssessment[];summary:AssessmentSummary}>(v,'select system_id,computed_at,results,summary from assessments where workspace_id=$1 and system_id=any($2::uuid[]) order by computed_at desc',[v.workspaceId,ids]),
    userQ<Claim>(v,'select * from host_claims where scope_id=any($1::uuid[]) order by created_at desc',[scopeIds]),
    portfolioReviews(v),
  ]);
  const latest=new Map<string,(typeof assessments)[number]>();for(const a of assessments)if(!latest.has(a.system_id))latest.set(a.system_id,a);
  const lastClaim=new Map<string,Claim>();for(const c of claims)if(!lastClaim.has(c.scope_id))lastClaim.set(c.scope_id,c);
  return systems.map(s=>({system:s,assessment:latest.get(s.id)??null,claim:s.scope?lastClaim.get(s.scope.id)??null:null,review:{findings:reviews.findings.filter(f=>f.system_id===s.id),answer:reviews.answers.find(a=>a.system_id===s.id)??null,reports:Number(reviews.reports.find(r=>r.system_id===s.id)?.n??0),waiting:Number(reviews.waiting.find(r=>r.system_id===s.id)?.n??0)}}));
}

export async function getSystem(id:string){
  if(!/^[0-9a-f-]{36}$/.test(id))return null;
  const v=await requireViewer(`/systems/${id}`);
  const systems=await userQ<SystemRow>(v,`select s.id,s.label,s.business_use,s.owner_vendor,s.monitoring,s.created_at,s.host_request_token,
    jsonb_build_object('id',sc.id,'url',sc.url,'host',sc.host,'scope_key',sc.scope_key) scope
    from systems s join scan_scopes sc on sc.id=s.scope_id where s.id=$1 and s.workspace_id=$2 and s.removed_at is null`,[id,v.workspaceId]);
  const system=systems[0];if(!system)return null;
  const [assessments,observations,claims,events,evidence]=await Promise.all([
    userQ<{id:string;computed_at:string;results:AdvisoryAssessment[];summary:AssessmentSummary;catalog_revision:number|null}>(v,'select id,computed_at,results,summary,catalog_revision from assessments where system_id=$1 and workspace_id=$2 order by computed_at desc limit 20',[id,v.workspaceId]),
    userQ<Omit<ObservationRow,'observed_at'>&{observed_at:string;fetch_log:{url:string;status:number|null;ms:number;note?:string}[]}>(v,'select * from observations where scope_id=$1 order by observed_at desc limit 10',[system.scope!.id]),
    userQ<Claim>(v,'select * from host_claims where scope_id=$1 order by created_at desc',[system.scope!.id]),
    userQ<{id:number;kind:string;detail:Record<string,unknown>;created_at:string}>(v,'select * from system_events where system_id=$1 and workspace_id=$2 order by created_at desc limit 30',[id,v.workspaceId]),
    userQ<{id:string;product:string;version:string;note:string|null;created_at:string}>(v,'select * from system_evidence where system_id=$1 and workspace_id=$2 order by created_at',[id,v.workspaceId]),
  ]);
  return {system,assessments,observations,claims,events,evidence};
}
