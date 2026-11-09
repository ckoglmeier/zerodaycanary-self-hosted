import "server-only";
// Accepts a canary-evidence/1 bundle into a private project. One transaction stores the
// immutable revision, its components and a durable evaluation job, keyed by
// (workspace, project, idempotency key). No billing, subscription or system enrollment.
import { tx, one } from "../db";
import { canonical, decodeUtf8, parseStrict, JsonRejected, MAX_BYTES } from "./json";
import { sha256, validateBundle, type Bundle } from "./bundle";
import {parseCveReport,type CveReview} from './cve-report';
import {assessAdvisory} from '@/intel/match';
import { ApiError } from "./tokens";
import { evaluationIdentity, evaluateEvidence } from "./evaluate";
import { catalogMeta,allAdvisories } from "../catalog";
import {cveRecord} from '../cve';
import { recordOperation } from "../usage";

export type Receipt = {
  schema_version: "canary-receipt/1";
  project_id: string;
  bundle_sha256: string;
  evidence_id: string;
  monitoring_state: "pending" | "active";
  billing_mode: "developer_inventory_free";
};

// jsonb does not keep key order; every response emits the receipt in one stable order.
export const orderedReceipt = (r: Receipt): Receipt => ({
  schema_version: r.schema_version,
  project_id: r.project_id,
  bundle_sha256: r.bundle_sha256,
  evidence_id: r.evidence_id,
  monitoring_state: r.monitoring_state,
  billing_mode: r.billing_mode,
});

export async function existingReceipt(workspaceId: string, projectId: string, key: string, digest: string) {
  const prior = await one<{ receipt: Receipt; bundle_sha256: string }>(
    "select receipt, bundle_sha256 from developer_evidence where workspace_id = $1 and project_id = $2 and idempotency_key = $3",
    [workspaceId, projectId, key],
  );
  if (!prior) return null;
  if (prior.bundle_sha256 !== digest) throw new ApiError(409, "idempotency_conflict");
  return orderedReceipt(prior.receipt);
}

// bytes: exact request body. Returns {receipt, created}.
export async function acceptEvidence(opts: { workspaceId: string; projectId: string; key: string; bytes: Uint8Array; via: "api" | "web_bundle" | "web_files"; by: string }) {
  const t0 = performance.now();
  if (opts.bytes.length > MAX_BYTES) throw new ApiError(413, "payload_too_large");
  const digest = sha256(opts.bytes);
  const replay = await existingReceipt(opts.workspaceId, opts.projectId, opts.key, digest);
  if (replay) return { receipt: replay, created: false };
  if (opts.key !== digest) throw new ApiError(422, "idempotency_key_mismatch");
  let bundle: Bundle;let cveReview:CveReview|null=null;
  try {
    const text = decodeUtf8(opts.bytes);
    const value = parseStrict(text);
    if (canonical(value) !== text) throw new JsonRejected("Body is not canonical JSON.");
    if(['canary-cve-report/1','canary-cve-report/2'].includes((value as {schema_version?:string})?.schema_version||'')){
      if(opts.via==='api')throw new JsonRejected('CVE source reports use the reviewed web upload.');
      const report=parseCveReport(value);bundle=report.bundle;cveReview=report.review;
      if(cveReview.schema_version==='canary-cve-review/2'){
        const ids=[...new Set(cveReview.assessments.map(a=>a.advisory_id))];
        if(ids.length>25)throw new JsonRejected('A targeted report may contain at most 25 distinct CVEs.');
        let index=0;const deadline=Date.now()+20000;
        await Promise.all(Array.from({length:Math.min(5,ids.length)},async()=>{while(index<ids.length){const id=ids[index++];
          let target;try{target=await cveRecord(id,fetch,deadline);}catch{throw new ApiError(503,'advisory_source_unavailable');}
          for(const a of cveReview!.assessments.filter(a=>a.advisory_id===id)){
            if(a.target_sha256!==null&&(!target?.published||target.sha256!==a.target_sha256))throw new JsonRejected('CVE target changed or is not published; refresh its public record.');
          }
        }}));
      }else{
      const catalog=await allAdvisories(),meta=await catalogMeta();
      if(cveReview.catalog_revision>meta.catalog_revision)throw new JsonRejected('Unknown source catalog revision.');
      for(const a of cveReview.assessments){
        const target=catalog.find(r=>r.id===a.advisory_id&&r.revision===a.advisory_revision&&r.affected.some(p=>p.product==='nextjs')&&r.status==='published');
        if(!target||target.catalog_revision>cveReview.catalog_revision)throw new JsonRejected('Source review target is unknown or outdated.');
        const comp=bundle.inventory.components.find(c=>c.instance===a.component_instance)!;
        const result=assessAdvisory(target,{techs:[{product:'nextjs',name:'next',version:comp.version,version_basis:comp.version?'developer_supplied':null,evidence_type:'inventory',location:'CVE report',detail:'Developer-supplied inventory',confidence:'medium',observed_at:bundle.created_at,limitations:[]}],facts:{},observed_at:bundle.created_at})[0];
        if((a.conclusion==='version_excluded'&&result?.status!=='not_affected')||(['source_prerequisites_supported','source_prerequisites_excluded'].includes(a.conclusion)&&result?.status==='not_affected'))throw new JsonRejected('Source conclusion conflicts with the supplied version.');
      }
      }
    }else bundle = validateBundle(value);
  } catch (e) {
    if (e instanceof JsonRejected) throw new ApiError(422, "invalid_evidence");
    throw e;
  }
  const project = await one<{ state: string }>("select state from developer_projects where id = $1 and workspace_id = $2 and deleted_at is null", [opts.projectId, opts.workspaceId]);
  if (!project) throw new ApiError(404, "not_found");
  const meta = await catalogMeta();

  const result = await tx(async (c) => {
    const ins = await c.query<{ id: string }>(
      `insert into developer_evidence (project_id, workspace_id, schema_version, bundle_sha256, idempotency_key, canonical_body, receipt, submitted_via, submitted_by,
         repository_id, repository_commit, repository_dirty, deployment, inventory_format, unknowns, audit_summary, has_detailed_findings, bundle_created_at,cve_review)
       values ($1,$2,$18,$3,$4,$5,'{}',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
       on conflict (workspace_id, project_id, idempotency_key) do nothing returning id`,
      [
        opts.projectId, opts.workspaceId, digest, opts.key, decodeUtf8(opts.bytes), opts.via, opts.by, bundle.repository.id, bundle.repository.commit,
        bundle.repository.dirty, bundle.deployment ? JSON.stringify(bundle.deployment) : null, bundle.inventory.format, JSON.stringify(bundle.inventory.unknowns),
        JSON.stringify({ context: bundle.audit.context, verdict_counts: bundle.audit.verdict_counts, total_records: bundle.audit.total_records, report_sha256: bundle.audit.report_sha256, compatibility_revision: bundle.audit.compatibility_revision }),
        bundle.audit.selected_findings.length > 0, bundle.created_at,cveReview?JSON.stringify(cveReview):null,cveReview?'canary-cve-report/'+cveReview.schema_version.slice(-1):bundle.schema_version,
      ],
    );
    if (!ins.rows[0]) return null; // a concurrent identical request won; read its receipt below
    const id = ins.rows[0].id;
    const receipt: Receipt = {
      schema_version: "canary-receipt/1",
      project_id: opts.projectId,
      bundle_sha256: digest,
      evidence_id: id,
      monitoring_state: project.state === "active" ? "active" : "pending",
      billing_mode: "developer_inventory_free",
    };
    await c.query("update developer_evidence set receipt = $2 where id = $1", [id, JSON.stringify(receipt)]);
    const comps = bundle.inventory.components;
    for (let k = 0; k < comps.length; k += 500) {
      const chunk = comps.slice(k, k + 500);
      const vals: unknown[] = [];
      const rows = chunk.map((x, j) => {
        vals.push(id, opts.projectId, opts.workspaceId, x.instance, x.ecosystem, x.name, x.version, x.purl, x.relationship, x.development, x.optional, x.source_id,x.public_registry===true);
        const b = j * 13;
        return `(${Array.from({ length: 13 }, (_, n) => `$${b + n + 1}`).join(",")})`;
      });
      await c.query(
        `insert into developer_components (evidence_id, project_id, workspace_id, instance, ecosystem, name, exact_version, purl, relationship, development, optional, source_id,public_registry) values ${rows.join(",")}`,
        vals,
      );
    }
    // Durable job in the same transaction as the evidence.
    await c.query(
      `insert into developer_evaluations (project_id, workspace_id, evidence_id, catalog_revision, matcher_revision, state) values ($1,$2,$3,$4,$5,'pending')
       on conflict do nothing`,
      [opts.projectId, opts.workspaceId, id, meta.catalog_revision, evaluationIdentity()],
    );
    await c.query("update developer_projects set latest_evidence_id = $2 where id = $1 and workspace_id = $3", [opts.projectId, id, opts.workspaceId]);
    return { id, receipt };
  });

  if (!result) {
    const again = await existingReceipt(opts.workspaceId, opts.projectId, opts.key, digest);
    if (!again) throw new ApiError(503, "temporarily_unavailable");
    return { receipt: again, created: false };
  }
  // Evaluate now (bounded, deterministic). A failure leaves the job retryable; the evidence stays accepted.
  await evaluateEvidence(result.id, "inventory upload",Date.now()+Math.max(1000,45000-(performance.now()-t0)));
  await recordOperation("developer_upload", "per_customer", "accepted", performance.now() - t0, 0);
  return { receipt: result.receipt, created: true };
}

export async function readEvidence(workspaceId: string, projectId: string, evidenceId: string) {
  if (!/^[0-9a-f-]{36}$/.test(evidenceId)) return null;
  return one<{ receipt: Receipt; canonical_body: string }>(
    "select receipt, canonical_body from developer_evidence where id = $1 and project_id = $2 and workspace_id = $3",
    [evidenceId, projectId, workspaceId],
  );
}
