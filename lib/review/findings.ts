import "server-only";
import { createHash } from "node:crypto";
import { tx } from "../db";
import type { AdvisoryAssessment } from "@/intel/match";

export type FindingCandidate = { result: AdvisoryAssessment; componentKey: string; product: string; sourceKind: "public" | "shared_report"; sourceAt: string; sourceId: string };
const CLOSED = new Set(["not_affected", "fix_verified"]);
export const findingSignature = (c: FindingCandidate) => createHash("sha256").update(JSON.stringify({
  // Catalog edit time/revision does not make identical applicability new.
  advisory:c.result.advisory_id,status:c.result.status,version:c.result.version_used,
  basis:c.result.version_basis,range:c.result.matched_range,conditions:c.result.conditions,
  source:c.sourceKind,
})).digest("hex");
const scopeFor = (candidate:FindingCandidate) => candidate.sourceKind==='shared_report'?'explicitly shared source inventory; not verified production':candidate.result.version_basis==='admin_supplied'?'administrator-supplied version; not independently observed':'public observations';

export async function syncFindings(workspaceId: string, systemId: string, candidates: FindingCandidate[]) {
  let changed = 0;
  for (const candidate of candidates) {
    const r = candidate.result;
    const signature = findingSignature(candidate);
    await tx(async c => {
      // Serialize one system/component/alert even when two matcher jobs race.
      await c.query("select pg_advisory_xact_lock(hashtextextended($1,0))", [`${systemId}:${r.advisory_id}:${candidate.componentKey}`]);
      const existing = (await c.query<{ id:string;signature:string;workflow_status:string;source_at:Date;source_kind:string }>(
        "select * from app_findings where system_id=$1 and advisory_id=$2 and component_key=$3 for update", [systemId,r.advisory_id,candidate.componentKey])).rows[0];
      if (!existing && CLOSED.has(r.status)) return;
      if (existing) {
        const older = new Date(candidate.sourceAt).getTime() < existing.source_at.getTime();
        const lowerPriority = candidate.sourceKind==='public' && existing.source_kind==='shared_report' && (!r.version_used || new Date(candidate.sourceAt).getTime() <= existing.source_at.getTime());
        if (older || lowerPriority || existing.signature===signature) {
          if(!older&&!lowerPriority&&existing.signature===signature)await c.query("update app_findings set last_checked_at=now(),source_at=$2,source_id=$3,evidence=$4 where id=$1",[existing.id,candidate.sourceAt,candidate.sourceId,JSON.stringify({...r,scope:scopeFor(candidate),source_at:candidate.sourceAt})]);
          else await c.query("update app_findings set last_checked_at=now() where id=$1", [existing.id]);
          return;
        }
      }
      const workflow = CLOSED.has(r.status)?'no_match_in_report':'check_required';
      const evidence = JSON.stringify({ ...r,scope:scopeFor(candidate),source_at:candidate.sourceAt });
      const row = (await c.query<{id:string}>(`insert into app_findings (workspace_id,system_id,advisory_id,component_key,product,assessment_status,workflow_status,evidence,signature,source_kind,source_at,source_id)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        on conflict(system_id,advisory_id,component_key) do update set assessment_status=excluded.assessment_status,workflow_status=excluded.workflow_status,evidence=excluded.evidence,signature=excluded.signature,source_kind=excluded.source_kind,source_at=excluded.source_at,source_id=excluded.source_id,last_checked_at=now(),changed_at=now() returning id`,
        [workspaceId,systemId,r.advisory_id,candidate.componentKey,candidate.product,r.status,workflow,evidence,signature,candidate.sourceKind,candidate.sourceAt,candidate.sourceId])).rows[0];
      await c.query(`insert into finding_transitions (finding_id,from_status,to_status,detail,transition_key) values($1,$2,$3,$4,$5) on conflict do nothing`, [row.id,existing?.workflow_status||null,workflow,JSON.stringify({reason:r.reason,source_kind:candidate.sourceKind,source_id:candidate.sourceId}),`${signature}:${candidate.sourceAt}`]);
      changed++;
    });
  }
  return changed;
}

// A withdrawn/superseded alert is historical, not a newly proved fix. Keep its
// evidence/answers, and record the catalog correction once. Republish rematching
// clears this marker and can reopen the same finding.
export async function syncInactiveFindings(workspaceId:string,systemId:string){
  return tx(async c=>{
    const rows=(await c.query<{id:string;workflow_status:string;revision:number;status:string}>(`select f.id,f.workflow_status,a.revision,a.status from app_findings f join advisories a on a.id=f.advisory_id where f.system_id=$1 and f.workspace_id=$2 and a.status in ('withdrawn','superseded') and f.workflow_status<>'withdrawn' for update of f`,[systemId,workspaceId])).rows;
    for(const row of rows){await c.query("update app_findings set workflow_status='withdrawn',signature='inactive:'||$2,changed_at=now(),last_checked_at=now() where id=$1",[row.id,`${row.status}:${row.revision}`]);await c.query("insert into finding_transitions(finding_id,from_status,to_status,detail,transition_key) values($1,$2,'withdrawn',$3,$4) on conflict do nothing",[row.id,row.workflow_status,JSON.stringify({reason:`Alert ${row.status} by catalog review; this is not verification of a fix.`}),`inactive:${row.status}:${row.revision}`]);}
    return rows.length;
  });
}
