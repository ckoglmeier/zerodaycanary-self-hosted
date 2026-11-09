import { alertCopy } from "@/lib/alert-copy";
import { notFound } from "next/navigation";
import { requireViewer } from "@/lib/auth";
import { getSystem } from "@/lib/portfolio";
import { STATUS_LABEL } from "@/intel/match";
import { abs } from "@/components/time";
import { allAdvisories } from "@/lib/catalog";
import { EXPLOIT_LABEL } from "@/components/badges";
import { PrintButton } from "./print-button";
import { groupConcerns } from "@/lib/concerns";
import { systemReview } from "@/lib/review/requests";
import { systemReports } from "@/lib/review/reports";
import { WORKFLOW_LABEL } from "@/lib/review/validation";
import { ReportView } from "@/components/report-view";

export const metadata = { title: "Evidence report" };
export const dynamic = "force-dynamic";

export default async function Report({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const v = await requireViewer(`/systems/${id}/report`);
  const d = await getSystem(id);
  if (!d) notFound();
  const { system: s, assessments, observations, claims, evidence } = d;
  const [review,reports]=await Promise.all([systemReview(v,id),systemReports(v,id)]);
  const a = assessments[0];
  const obs = observations.find((o) => o.id === a?.summary.observation.id) ?? null;
  const advisories = new Map((await allAdvisories({ includeInactive: true })).map((x) => [x.id, x]));
  const generated = new Date().toISOString();
  return (
    <main id="main-content" tabIndex={-1} className="container evidence-report" style={{ maxWidth: 900, paddingTop: 32, paddingBottom: 48 }}>
      <div className="stack" style={{ ["--gap" as string]: "20px" }}>
        <div className="row no-print">
          <PrintButton />
          <a href={`/systems/${s.id}`}>Back to system</a>
        </div>
        <header className="spread">
          <div className="stack" style={{ ["--gap" as string]: "4px" }}>
            <p className="small muted">Zero Day Canary · Evidence report</p>
            <h1 className="h-page wrap">{s.label}</h1>
            <p className="mono wrap">{s.scope?.url}</p>
          </div>
          <img src="/brand/canary-160.png" alt="" width={56} height={56} />
        </header>
        <p className="notice n-neutral small">
          This report is dated evidence about one address and the reviewed alerts that might affect it. &ldquo;Unaffected by this vulnerability&rdquo;
          answers one vulnerability only. The report is not a certification or a complete inventory, and no matching alert does not mean no vulnerabilities.
        </p>
        <dl className="facts panel">
          <dt>Generated</dt>
          <dd>{abs(generated)} for {v.email}</dd>
          <dt>Scope</dt>
          <dd className="wrap">{s.scope?.scope_key} (this address and path only)</dd>
          <dt>Public evidence observed</dt>
          <dd>{obs ? `${abs(obs.observed_at)} (${obs.outcome})` : "No successful public check"}</dd>
          <dt>Assessed</dt>
          <dd>{a ? `${abs(a.computed_at)} against catalog revision ${a.summary.catalog_revision}` : "Not assessed"}</dd>
          <dt>Catalog coverage</dt>
          <dd>{a?.summary.coverage.join(", ") || "none"}</dd>
        </dl>

        {a?.results.length ? (
          <section className="stack">
            <h2 className="h-section">Questions from the public check</h2>
            {groupConcerns(a.results, s.label).filter((c) => c.question).length === 0 ? (
              <p className="small">No open questions from the public check. Owner answers and shared reports are recorded separately below.</p>
            ) : (
              <ul className="small">
                {groupConcerns(a.results, s.label)
                  .filter((c) => c.question)
                  .map((c) => (
                    <li key={c.product}>
                      <strong>{c.product}:</strong> {c.question}
                    </li>
                  ))}
              </ul>
            )}
          </section>
        ) : null}

        <section className="stack">
          <h2 className="h-section">Alerts and outcomes</h2>
          {!a || a.results.length === 0 ? (
            <p>No reviewed alert matched the software identified. This does not mean the system has no vulnerabilities.</p>
          ) : (
            <div className="table-wrap" role="region" aria-label="Alerts and outcomes" tabIndex={0}>
            <table className="t">
              <caption className="sr-only">Alert outcomes, version sources and exploit evidence</caption>
              <thead>
                <tr>
                  <th scope="col">Alert</th>
                  <th scope="col">Outcome</th>
                  <th scope="col">Version and source</th>
                  <th scope="col">Exploit evidence</th>
                </tr>
              </thead>
              <tbody>
                {a.results.map((r) => {
                  const adv = advisories.get(r.advisory_id);
                  return (
                    <tr key={r.advisory_id + r.product} className="print-item">
                      <td>
                        <span className="mono">{r.primary_identifier}</span>
                        <br />
                        {r.title}
                        <br />
                        <span className="small muted wrap">{adv?.sources.map((x) => <a key={x.url} href={x.url} className="report-source">{x.url}</a>)}</span>
                      </td>
                      <td>
                        <strong>{STATUS_LABEL[r.status]}</strong>
                        <br />
                        <span className="small">{alertCopy(r.reason)}</span>
                        <br />
                        <span className="small">Next: {alertCopy(r.next_step)}</span>
                      </td>
                      <td className="small">
                        {r.version_used ? `${r.product} ${r.version_used} (${r.version_basis === "admin_supplied" ? "administrator-supplied" : "observed"})` : "No usable version"}
                        <br />
                        <span className="muted wrap">{r.evidence_location && /^https?:\/\//.test(r.evidence_location) ? <a href={r.evidence_location} className="report-source">{r.evidence_location}</a> : r.evidence_location}</span>
                      </td>
                      <td className="small">
                        {adv ? EXPLOIT_LABEL[adv.exploitation.category] : "—"}
                        {adv?.exploitation.as_of && adv.exploitation.category !== "none_confirmed" ? ` (${adv.exploitation.as_of})` : ""}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            </div>
          )}
        </section>

        <section className="stack">
          <h2 className="h-section">Software and version evidence</h2>
          <ul className="small">
            {(obs?.evidence.techs ?? []).map((t, i) => (
              <li key={i}>
                {t.name}: {t.version ? `${t.version} (${t.version_basis === "observed" ? "seen in public signals" : t.version_basis})` : "detected, version not visible"}. {t.detail}. <span className="muted wrap">{t.location}</span>
              </li>
            ))}
            {evidence.map((e) => (
              <li key={e.id}>
                {e.product}: {e.version} (administrator-supplied, {abs(e.created_at)}){e.note ? `: ${e.note}` : ""}
              </li>
            ))}
            {!obs?.evidence.techs.length && !evidence.length ? <li>No covered technology identified.</li> : null}
          </ul>
        </section>

        <section className="stack">
          <h2 className="h-section">Attributed owner answers</h2>
          <p className="small muted">These are answers supplied by the signed-in recipient, not independent verification of the deployed system.</p>
          {review.conversation?.answers.length?<ul className="list small">{review.conversation.answers.map(answer=><li key={answer.id} className="stack print-item"><p><strong>{answer.outcome==='not_affected'?'Not affected by the requested alert':answer.outcome==='affected'?'Affected':'Not sure'}</strong> · {answer.actor_email} · {abs(answer.created_at)}</p><p>{answer.reason}</p>{answer.remediation_plan?<p>Fix plan: {answer.remediation_plan}<br/>Target: {answer.date_pending?'Being determined':abs(answer.target_date).slice(0,10)} (estimate)</p>:null}{answer.evidence_note?<p>Owner’s evidence: {answer.evidence_note}</p>:null}</li>)}</ul>:<p className="small">No owner answer recorded.</p>}
        </section>
        <section className="stack"><h2 className="h-section">Current tracked findings</h2>{review.findings.length?<ul className="list small">{review.findings.map(f=><li key={f.id} className="print-item"><strong>{f.title}</strong> · {WORKFLOW_LABEL[f.workflow_status]}<p>{String(f.evidence.reason||'Evidence needs checking.')}</p><p className="muted">{String(f.evidence.scope||'Source limits apply')} · Updated {abs(f.changed_at)}</p></li>)}</ul>:<p className="small">No tracked finding from the available evidence. This does not establish that the app is safe.</p>}</section>
        <section className="stack"><h2 className="h-section">Developer reports shared with this workspace</h2>{reports.length?reports.map(report=><div key={report.id} className="stack"><p className="small">Shared {abs(report.created_at)} · Report {report.id}</p><ReportView snapshot={report.snapshot}/>{report.remediation_plan?<p className="small">Developer’s fix plan: {report.remediation_plan}<br/>Target: {report.date_pending?'Being determined':abs(report.target_date).slice(0,10)} (estimate)</p>:null}</div>):<p className="small">No developer report shared.</p>}</section>
        <section className="stack">
          <h2 className="h-section">Domain-verified version claims</h2>
          {claims.length === 0 ? (
            <p className="small">No domain-verified version claim.</p>
          ) : (
            <ul className="small">
              {claims.map((c) => (
                <li key={c.id}>
                  {abs(c.created_at)}: the owner (domain control verified) reported {c.product} {c.claimed_version}. Outcome of the fresh check: {c.state.replace(/_/g, " ")}. {alertCopy(c.outcome_detail)}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="stack">
          <h2 className="h-section">Unknowns and gaps</h2>
          <ul className="small">
            {(a?.summary.gaps ?? []).map((g, i) => (
              <li key={i}>{alertCopy(g.detail)}</li>
            ))}
            {a?.summary.uncovered.length ? <li>Detected but not covered by this catalog: {a.summary.uncovered.join(", ")}.</li> : null}
            <li>Public checks cannot see internal packages, authenticated areas, hidden versions, configuration conditions or vendor backports.</li>
          </ul>
        </section>
        <p className="small muted">All times UTC. Report generated from records held by Zero Day Canary for this workspace only.</p>
      </div>
    </main>
  );
}
