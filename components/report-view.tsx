import Link from "next/link";
import { advisoryHref } from "@/intel/packages";
import type { ReportSnapshot } from "@/lib/review/reports";
import { groupReport } from "@/lib/review/report-groups";
import { abs } from "./time";
import { StatusBadge } from "./badges";
import { CveReviewView } from "./cve-review";

export function ReportView({snapshot}:{snapshot:ReportSnapshot}) {
  const groups=groupReport(snapshot), reviewCount=groups.filter(g=>g.needsReview).length;
  const covered=Number(snapshot.coverage.components_covered||0), total=Number(snapshot.coverage.components_total||0);
  return <section className="panel stack report-content">
    <h2 className="h-section wrap">{snapshot.project_name}</h2>
    <p><strong>{reviewCount?`${reviewCount} component${reviewCount===1?" has":"s have"} findings to review.`:"No findings requiring review were returned for the covered inventory."}</strong> This is a source report; the deployed app has not been independently verified.</p>
    <p className="small">{covered} of {total} inventoried components have an available package check. {Math.max(0,total-covered)} {total-covered===1?"remains":"remain"} unassessed.{snapshot.inventory_unknowns?` ${snapshot.inventory_unknowns} inventory ${snapshot.inventory_unknowns===1?"entry has":"entries have"} additional unknowns.`:""} Inventory received {abs(snapshot.received_at)}.</p>
    <h3>Review by component</h3>
    <p className="hint">Open a component for its version matches, source checks and next steps. These describe different evidence; a version match alone does not confirm deployed exposure.</p>
    <div className="stack report-groups">
      {groups.map(group=><details className="report-group" key={group.component.instance}>
        <summary><span><strong className="wrap">{group.component.name} <span className="mono">{group.component.version||"Unknown version"}</span></strong><span className="small muted">{group.component.ecosystem} · {group.results.length} version result{group.results.length===1?"":"s"} · {group.assessments.length} source check{group.assessments.length===1?"":"s"}</span><span className="small">{group.needsReview?"Check applicability and deployed evidence":group.results.length||group.assessments.length?"Review the scope of these exclusions":group.packageState==="checked_no_match"?"Checked packages — no version match returned":group.packageState==="not_assessed"?"Not assessed — more evidence needed":"No version matches returned — see coverage"}</span></span></summary>
        <div className="stack" style={{paddingTop:12}}>
          {group.results.length?<section className="stack"><h4>Package version results</h4><ul className="list">{group.results.map((r,i)=><li key={`${r.advisory_id}:${i}`} className="stack print-item"><div className="row"><StatusBadge status={r.status}/><Link href={advisoryHref(r.advisory_id)}>{r.identifier}</Link></div><p className="small">{r.reason}</p><p className="small"><strong>Next step:</strong> {r.next_step}</p></li>)}</ul></section>:<p className="small">{group.packageState==="checked_no_match"?"No affected package version was returned by this lookup. This does not verify production or overall security.":"No package version result is available for this component. Check the coverage and source evidence; do not treat it as unaffected."}</p>}
          {snapshot.cve_review&&group.assessments.length?<CveReviewView review={{...snapshot.cve_review,assessments:group.assessments}} labels={Object.fromEntries(snapshot.results.map(r=>[r.advisory_id,r.identifier]))}/>:null}
        </div>
      </details>)}
    </div>
    <details className="report-group"><summary>Checked build, coverage and limits</summary><div className="stack"><dl className="facts"><dt>Checked source build</dt><dd className="mono">{snapshot.checked_build||"Not supplied"}{snapshot.source_dirty?" · Uncommitted changes; commit alone does not identify the source.":""}</dd><dt>Inventory received</dt><dd>{abs(snapshot.received_at)}</dd></dl><ul className="small muted">{snapshot.limits.map(l=><li key={l}>{l}</li>)}</ul></div></details>
    {snapshot.audit?<details className="report-group"><summary>Source audit summary</summary><div className="stack print-item"><p className="small">Supplied by the developer · Run {snapshot.audit.run_status}{snapshot.audit.audited_at?` · ${abs(snapshot.audit.audited_at)}`:""}</p><p>{snapshot.audit.confirmed} confirmed by the auditor · {snapshot.audit.needs_validation} need validation · {snapshot.audit.rejected} rejected</p><p className="hint">These are the auditor’s verdicts, not independent Canary verification. Detailed source findings and code are excluded. A completed source review does not establish runtime exploitability or production status.</p></div></details>:null}
    <p className="print-only small">The full shared component inventory is available in the app; this printed report includes the assessed matches and source checks above.</p>
    <details className="no-print report-group"><summary>Shared component inventory ({snapshot.components.length})</summary><div className="table-wrap" role="region" aria-label="Shared component inventory" tabIndex={0}><table className="t"><thead><tr><th scope="col">Component</th><th scope="col">Version</th><th scope="col">Source</th></tr></thead><tbody>{snapshot.components.map(c=><tr key={c.instance}><td className="mono">{c.ecosystem}:{c.name}</td><td className="mono">{c.version||"Unknown"}</td><td>Developer-supplied inventory</td></tr>)}</tbody></table></div></details>
  </section>;
}
