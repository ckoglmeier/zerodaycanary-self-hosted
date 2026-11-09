import "server-only";
// Deterministic re-evaluation of a project's private inventory against the reviewed
// catalog and stored OSV package checks. Refresh occurs on intake/daily jobs only.
// No model calls. Results are developer-supplied source evidence:
// they can say a declared version matches an affected range, never that production is
// affected or fixed.
import { q, one } from "../db";
import { allAdvisories, catalogMeta } from "../catalog";
import { assessAdvisory, type AssessmentStatus } from "@/intel/match";
import { PACKAGE_COVERAGE, productForPackage } from "@/intel/packages";
import { recordOperation } from "../usage";
import type { AdvisoryRecord } from "@/intel/schema";
import { canQuery,packageKey,freshCheck,matchingRecords,type PackageCheck,type InventoryComponent } from '@/intel/osv';
import {refreshChecks,storedChecks} from '../osv/store';

export const MATCHER_REVISION = "dev-inventory-2";
export const evaluationIdentity=()=>MATCHER_REVISION+':'+new Date().toISOString().slice(0,10);
const RELEVANT: AssessmentStatus[] = ["affected_version_matched", "applicability_confirmed", "needs_verification", "not_assessed"];

export type DevResult = {
  advisory_id: string;
  advisory_revision: number;
  identifier: string;
  title: string;
  exploitation: string;
  status: AssessmentStatus;
  reason: string;
  next_step: string;
  dataset?:'canary_reviewed'|'osv';
  advisory_url?:string;
  sources?:string[];
  identifiers?:string[];
  checked_at?:string;
  component: { ecosystem?:string;instance: number; name: string; version: string | null; relationship: string; development: boolean | null };
};

type Comp = InventoryComponent;

export function evaluateComponents(components: Comp[], advisories: AdvisoryRecord[], receivedAt: string, checks:PackageCheck[]=[], now=Date.now()) {
  const results: DevResult[] = [];
  const covered = new Set<number>();
  for (const c of components) {
    const product = productForPackage(c.ecosystem, c.name);
    if (!product) continue;
    covered.add(c.instance);
    // One component instance at a time: distinct installed versions are never merged.
    const evidence = {
      techs: [{
        product, name: c.name, version: c.exact_version, version_basis: c.exact_version ? ("developer_supplied" as const) : null, evidence_type: "inventory" as const,
        location: `lockfile entry ${c.instance}`, detail: "Declared in a developer-supplied lockfile", confidence: "medium" as const, observed_at: receivedAt,
        limitations: ["Source inventory, not the deployed system."],
      }],
      facts: {},
      observed_at: receivedAt,
    };
    for (const a of advisories) {
      for (const r of assessAdvisory(a, evidence)) {
        results.push({
          advisory_id: a.id, advisory_revision: a.revision, identifier: a.identifiers[0] ?? a.id, title: a.title, exploitation: a.exploitation.category,
          status: r.status, reason: r.reason.replace(/\.$/, "") + " (developer-supplied lockfile version).", next_step: r.status === "not_affected" ? "No action for this vulnerability." : r.next_step.replace("then re-analyze", "then upload a refreshed inventory"),
          dataset:'canary_reviewed',advisory_url:`/advisory/${a.id}`,sources:a.sources.map(s=>s.url),identifiers:a.identifiers,
          component: {ecosystem:c.ecosystem,instance:c.instance,name:c.name,version:c.exact_version,relationship:c.relationship,development:c.development},
        });
      }
    }
  }
  const byKey=new Map(checks.map(c=>[packageKey(c),c]));
  const component_coverage=components.map(c=>{
    const check=canQuery(c)?byKey.get(packageKey({ecosystem:c.ecosystem,name:c.name,version:c.exact_version!})):undefined;
    const fresh=check&&freshCheck(check,now)&&(!check.records.length||matchingRecords({...check,records:check.records.map(r=>({...r,withdrawn:undefined}))}).length>0);
    if(fresh)covered.add(c.instance);
    if(check){for(const record of matchingRecords(check)){
      const aliases=[record.id,...record.aliases];
      const existing=results.find(r=>r.component.instance===c.instance&&r.identifiers?.some(id=>aliases.includes(id)));
      if(existing){if(existing.status==='not_affected'){existing.status='needs_verification';existing.reason='Canary and OSV range evidence disagree. Resolve the advisory boundaries before relying on a version exclusion.';existing.next_step='Resolve the advisory boundary and prerequisites with the owner; production remains unverified.';}existing.sources=[...new Set([...(existing.sources||[]),...record.references.map(r=>r.url)])];continue;}
      // Multiple OSV sources may describe one CVE. One finding per component/CVE.
      if(results.some(r=>r.component.instance===c.instance&&r.dataset==='osv'&&r.identifiers?.some(id=>aliases.includes(id))))continue;
      const identifier=aliases.find(id=>id.startsWith('CVE-'))||record.id;
      results.push({advisory_id:'osv-'+record.id,advisory_revision:Math.max(1,Math.min(2147483647,Math.floor(Date.parse(record.modified)/60000))),identifier,identifiers:aliases,title:record.summary||identifier,exploitation:'unverified',dataset:'osv',advisory_url:'https://osv.dev/vulnerability/'+encodeURIComponent(record.id),sources:record.references.map(r=>r.url),checked_at:check.checked_at,
       status:fresh?'affected_version_matched':'needs_verification',reason:fresh?'OSV matches this declared package version. Source prerequisites and production deployment still need confirmation.':'A previous OSV check matched this version, but the lookup is stale. Refresh before relying on it.',next_step:'Review the linked advisory, check its prerequisites and deployed version, and upgrade or mitigate as directed.',component:{ecosystem:c.ecosystem,instance:c.instance,name:c.name,version:c.exact_version,relationship:c.relationship,development:c.development}});
    }}
    return {instance:c.instance,ecosystem:c.ecosystem,name:c.name,checked_at:check?.checked_at||null,status:fresh?(matchingRecords(check!).length?'checked':'checked_no_match'):'not_assessed',reason:fresh?'Checked against OSV; no match never proves security.':!c.public_registry?'Public registry origin is not confirmed; no external query was sent.':!c.exact_version?'Exact version is missing.':'Package data is unavailable, stale or unsupported.'};
  });
  return {results,coverage:{components_total:components.length,components_covered:covered.size,covered_packages:PACKAGE_COVERAGE.map(p=>`${p.ecosystem}:${p.name}`),component_coverage,
   checked_no_match:component_coverage.filter(c=>c.status==='checked_no_match').length,
   note:'Public packages with exact versions are checked across OSV ecosystems, alongside Canary-reviewed alerts. Private packages, unsupported identities and stale or missing data remain unassessed. A source inventory does not verify production or establish security.'}};

}

const key = (r: DevResult) => `${r.advisory_id}|${r.component.ecosystem||"npm"}:${r.component.name}:${r.component.instance}`;

export async function evaluateEvidence(evidenceId: string, reason: string,deadline=Date.now()+35000): Promise<{ state: string; id: string | null }> {
  const t0 = performance.now();
  const ev = await one<{ id: string; project_id: string; workspace_id: string; received_at: Date }>("select id, project_id, workspace_id, received_at from developer_evidence where id = $1", [evidenceId]);
  if (!ev) return { state: "missing", id: null };
  const meta = await catalogMeta();
  const identity=evaluationIdentity();
  const job =
    (await one<{ id: string; state: string }>(
      `insert into developer_evaluations (project_id, workspace_id, evidence_id, catalog_revision, matcher_revision, state)
       values ($1,$2,$3,$4,$5,'pending') on conflict (project_id, evidence_id, catalog_revision, matcher_revision) do nothing returning id, state`,
      [ev.project_id, ev.workspace_id, ev.id, meta.catalog_revision, identity],
    )) ??
    (await one<{ id: string; state: string }>(
      "select id, state from developer_evaluations where project_id = $1 and evidence_id = $2 and catalog_revision = $3 and matcher_revision = $4",
      [ev.project_id, ev.id, meta.catalog_revision, identity],
    ))!;
  if (job.state === "completed") return { state: "completed", id: job.id };
  const claimed = await one<{ id: string }>(
    "update developer_evaluations set state = 'running', attempts = attempts + 1, started_at = now() where id = $1 and (state in ('pending','failed') or (state = 'running' and started_at < now() - interval '2 minutes')) returning id",
    [job.id],
  );
  if (!claimed) return { state: "running", id: job.id };
  try {
    const [components, advisories] = await Promise.all([
      q<Comp>("select instance, name, exact_version, relationship, development, ecosystem,public_registry from developer_components where evidence_id = $1 and project_id = $2 and workspace_id = $3 order by instance", [ev.id, ev.project_id, ev.workspace_id]),
      allAdvisories({ includeInactive: true }),
    ]);
    await refreshChecks(components,deadline);
    const checks=await storedChecks(components);
    const published = advisories.filter((a) => a.status === "published");
    const { results, coverage } = evaluateComponents(components, published, ev.received_at.toISOString(),checks);
    // Notices compare with the previous completed evaluation of this project (any revision).
    const prev = await one<{ results: DevResult[]; evidence_id: string }>(
      "select results, evidence_id from developer_evaluations where project_id = $1 and state = 'completed' and id <> $2 order by completed_at desc limit 1",
      [ev.project_id, job.id],
    );
    // Lost inventory or a disappearing provider result is not evidence of a fix.
    for(const old of prev?.results||[])if(old.dataset==='osv'&&RELEVANT.includes(old.status)&&!results.some(r=>key(r)===key(old))){
      results.push({...old,status:'not_assessed',reason:'This previous finding cannot be confirmed from the latest inventory and stored package check. Disappearance does not verify a fix.',next_step:'Ask the owner to confirm the component, advisory prerequisites and deployed version.'});
    }
    await q("update developer_evaluations set state = 'completed', results = $2, coverage = $3, error = null, completed_at = now() where id = $1", [job.id, JSON.stringify(results), JSON.stringify(coverage)]);
    if (prev) {
      const before = new Map(prev.results.filter((r) => RELEVANT.includes(r.status)).map((r) => [key(r), r]));
      const now = new Map(results.filter((r) => RELEVANT.includes(r.status)).map((r) => [key(r), r]));
      const byId = new Map(advisories.map((a) => [a.id, a]));
      const events: [string, DevResult | (typeof prev.results)[number], string | null, string | null][] = [];
      for (const [k, r] of now) {
        const b = before.get(k);
        if (!b) events.push(["newly_relevant", r, null, r.status]);
        else if (b.status !== r.status) events.push(["status_changed", r, b.status, r.status]);
      }
      for (const [k, b] of before)
        if (!now.has(k)) {
          const adv = byId.get(b.advisory_id);
          events.push([adv && adv.status !== "published" ? "advisory_withdrawn" : "no_longer_relevant", { ...b, advisory_revision: adv?.revision ?? b.advisory_revision }, b.status, null]);
        }
      for (const [kind, r, prior, cur] of events)
        await q(
          `insert into developer_events (workspace_id, project_id, evidence_id, advisory_id, advisory_revision, kind, prior_status, current_status, detail)
           values ($1,$2,$3,$4,$5,$6,$7,$8,$9) on conflict (evidence_id, advisory_id, advisory_revision, kind) do nothing`,
          [ev.workspace_id, ev.project_id, ev.id, r.advisory_id, r.advisory_revision, kind, prior, cur,
            JSON.stringify({ identifier: r.identifier, title: r.title, package: r.component.name, version: r.component.version, reason, catalog_revision: meta.catalog_revision })],
        );
    }
    await recordOperation("developer_evaluation", "per_customer", "completed", performance.now() - t0, 0);
    return { state: "completed", id: job.id };
  } catch (e) {
    await q("update developer_evaluations set state = 'failed', error = $2 where id = $1", [job.id, (e as Error).message.slice(0, 300)]);
    await recordOperation("developer_evaluation", "per_customer", "failed", performance.now() - t0, 0);
    return { state: "failed", id: job.id };
  }
}

// After every reviewed catalog revision: re-evaluate the latest inventory of each project
// that has not been paused. Prior results and failures are kept.
export async function rematchDevelopers(reason: string, limit = 1000,deadline=Date.now()+90000) {
  const rows = await q<{ latest_evidence_id: string }>(
    "select latest_evidence_id from developer_projects where deleted_at is null and state <> 'paused' and latest_evidence_id is not null order by (select max(e.completed_at) from developer_evaluations e where e.project_id=developer_projects.id) asc nulls first,created_at limit $1",
    [limit],
  );
  let failed = 0,projects=0;
  for (const r of rows){if(Date.now()>=deadline)break;projects++;if ((await evaluateEvidence(r.latest_evidence_id, reason,Math.min(deadline,Date.now()+20000))).state === "failed") failed++;}
  return { projects, failed,pending:rows.length-projects };
}
