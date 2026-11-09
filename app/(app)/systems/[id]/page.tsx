import {advisoryHref} from '@/intel/packages';
import { alertCopy } from "@/lib/alert-copy";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getSystem } from "@/lib/portfolio";
import { requireViewer } from "@/lib/auth";
import { workspacePrice, money, desiredQuantity, subscriptionFor } from "@/lib/billing";
import { ClaimBadge, MonitoringBadge, StatusBadge } from "@/components/badges";
import { When, abs } from "@/components/time";
import { Submit } from "@/components/submit";
import { env } from "@/lib/env";
import type { TechObservation } from "@/intel/evidence";
import { groupConcerns } from "@/lib/concerns";
import { systemReview } from "@/lib/review/requests";
import { systemReports } from "@/lib/review/reports";
import { WORKFLOW_LABEL } from "@/lib/review/validation";
import { Badge } from "@/components/badges";
import { Conversation } from "@/components/conversation";
import {OverviewClues} from '@/components/overview-clues';
import { requestOutcome } from "@/lib/review/presentation";
import {systemOverview} from '@/lib/system-overview';

export const metadata = { title: "System" };

export default async function SystemPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | undefined>> }) {
  const { id } = await params;
  const sp = await searchParams;
  const v = await requireViewer(`/systems/${id}`);
  const d = await getSystem(id);
  if (!d) notFound();
  const { system: s, assessments, observations, claims, events, evidence } = d;
  const [review,sharedReports,overview]=await Promise.all([systemReview(v,id),systemReports(v,id),systemOverview(v,id)]);
  const a = assessments[0] ?? null;
  const obs = observations.find((o) => o.id === a?.summary?.observation?.id) ?? observations.find((o) => o.outcome !== "failed") ?? null;
  const lastAttempt = observations[0] ?? null;
  const techs = obs?.evidence.techs ?? [];
  const observed = techs.filter((t) => t.version && t.version_basis === "observed");
  const detectedOnly = techs.filter((t) => !t.version || t.version_basis !== "observed");
  const [price, qty, sub] = await Promise.all([workspacePrice(v.workspaceId).catch(() => null), desiredQuantity(v.workspaceId), subscriptionFor(v.workspaceId)]);
  const hostLink = `${env.siteUrl()}/host/${s.host_request_token}`;
  const concerns = groupConcerns(a?.results ?? [], s.label);
  const stale = obs && Date.now() - new Date(obs.observed_at).getTime() > env.freshnessHours() * 3600_000;
  const quantityAfter = s.monitoring === "none" || s.monitoring === "paused" ? qty + 1 : qty;

  return (
    <div className="stack" style={{ ["--gap" as string]: "24px" }}>
      <p className="small">
        <Link href="/systems">← Your systems</Link>
      </p>
      {sp.error ? <p className="notice n-danger" role="alert">{sp.error}</p> : null}
      {sp.checkout === "cancelled" ? <p className="notice n-neutral">Checkout was cancelled. Monitoring has not started and nothing was charged.</p> : null}
      {sp.msg ? <p className="notice n-success" role="status">{sp.msg}</p> : null}

      <header className="spread">
        <div className="stack" style={{ ["--gap" as string]: "6px" }}>
          <h1 className="h-page wrap">{s.label}</h1>
          <p className="mono wrap">{s.scope?.url}</p>
          <p className="small muted">Scope: this exact address and path. Other hosts, subdomains or paths are separate systems.</p>
          <div className="row">
            <MonitoringBadge state={s.monitoring} />
          </div>
        </div>
        <div className="row no-print">
          <form method="post" action={`/api/app/systems/${s.id}/reanalyze`}>
            <Submit className="btn btn-secondary" busy="Checking public signals…">Re-analyze</Submit>
          </form>
          <Link className="btn btn-secondary" href={`/systems/${s.id}/report`}>
            Print report
          </Link>
        </div>
      </header>

      {lastAttempt && lastAttempt.outcome === "failed" && obs && lastAttempt.id !== obs.id ? (
        <p className="notice n-warning">
          Could not complete the most recent check ({abs(lastAttempt.observed_at)}): {alertCopy(lastAttempt.gaps[0]?.detail)}. Last successful check: {abs(obs.observed_at)}. Findings below use that evidence.
        </p>
      ) : null}
      {!obs && lastAttempt ? <p className="notice n-warning">This address could not be analyzed: {alertCopy(lastAttempt.gaps[0]?.detail)} A check that did not complete tells us nothing about whether the system is affected.</p> : null}
      {stale ? <p className="notice n-warning">The public evidence is {Math.round((Date.now() - new Date(obs!.observed_at).getTime()) / 3600_000)} hours old. Re-analyze for a fresh check.</p> : null}

      <section className="panel stack" aria-labelledby="app-status"><h2 id="app-status" className="h-section">Current status</h2><p><strong>{review.conversation?requestOutcome(review.conversation.requests[0],review.conversation.answers,review.conversation.messages):concerns.some(c=>c.open.length)?"Possible vulnerabilities need an owner check":!obs||!techs.length?"We couldn’t establish the internal software":"Public evidence checked; internal software still needs confirmation"}</strong></p><p className="small">Public check: <When at={obs?.observed_at??null}/> · Developer evidence: {sharedReports.length?`${sharedReports.length} shared report${sharedReports.length===1?'':'s'}`:'no report shared'}.</p><p className="small muted">Public checks cannot see hidden packages or logged-in areas. An owner answer or source report is separate from verified deployment evidence.</p><div><Link className="btn btn-brand" href={review.conversation?`/reviews/${review.conversation.conversation.id}`:`/systems/${s.id}/request`}>{review.conversation?'Open conversation':'Ask the owner to check'}</Link></div></section>
      {overview?<OverviewClues systemId={id} overview={overview}/>:null}

      <details className="panel"><summary>Tracked findings and owner checks</summary><div className="stack"><p className="small muted">A quick attributed answer is enough. A deeper report is optional. Owner confirmations do not replace the public evidence below.</p>
      {review.findings.length?<ul className="list">{review.findings.map(f=><li key={f.id} className="stack"><div className="spread"><Link href={advisoryHref(f.advisory_id)}>{f.title}</Link><Badge tone={f.workflow_status==='owner_affected'?'danger':'neutral'}>{WORKFLOW_LABEL[f.workflow_status]}</Badge></div><p className="small">{String(f.evidence.reason||'Evidence needs checking.')}</p><p className="small muted">Updated {abs(f.changed_at)} · {String(f.evidence.scope||'Source limits apply')}</p><Link href={`/systems/${s.id}/request?finding=${f.id}`} className="small no-print">Ask about this alert</Link></li>)}</ul>:<p className="small">No app-specific alert finding is open from available evidence. You can still ask the owner for missing inventory; this is not evidence that the app is safe.</p>}
      {review.conversation?<Link className="no-print" href={`/reviews/${review.conversation.conversation.id}`}>Open tracked conversation</Link>:null}
      </div></details>
      <section className="panel stack"><h2 className="h-section">Developer reports shared with you</h2>{sharedReports.length?<ul>{sharedReports.map(r=><li key={r.id}><Link href={`/reports/${r.page_id}`}>{r.snapshot.project_name}</Link> · shared {abs(r.created_at)} · source inventory, production unverified</li>)}</ul>:<p className="small muted">No reviewed report has been shared. Private developer uploads are not automatically visible here.</p>}</section>

      {review.history.length?<details className="panel"><summary>Finding history</summary><ul className="list small">{review.history.map(h=><li key={h.id}><strong>{h.title}</strong> · {WORKFLOW_LABEL[h.to_status]||h.to_status} · {abs(h.created_at)}{h.detail.reason?<p>{h.detail.reason}</p>:null}</li>)}</ul></details>:null}
      <div className="split">
        <div className="stack" style={{ ["--gap" as string]: "24px" }}>
          <section className="panel stack">
            <h2 className="h-section">Public check</h2>
            <p className="small muted">
              {obs ? (
                <>
                  Public evidence from <When at={obs.observed_at} /> ({obs.trigger === "initial" ? "first check" : obs.trigger.replace("_", " ")}) · Compared with reviewed alerts <When at={a?.computed_at} /> (catalog revision {a?.summary.catalog_revision ?? 0})
                </>
              ) : (
                "No successful public check yet."
              )}
            </p>
            {!a || a.results.length === 0 ? (
              <div className="stack" style={{ ["--gap" as string]: "8px" }}>
                <p>
                  <strong>No reviewed alert matches what we can see.</strong>
                </p>
                <p className="small">
                  That does not mean the system has no vulnerabilities: public checks cannot see internal packages or hidden versions. Vulnerability alerts currently cover {a?.summary.coverage.length ? a.summary.coverage.join(", ") : "no products yet"}
                  {a?.summary.uncovered.length ? `; detected here but not covered: ${a.summary.uncovered.join(", ")}` : ""}.
                </p>
              </div>
            ) : (
              <ul className="list">
                {concerns.map((c) => (
                  <li key={c.product} className="stack print-item" style={{ ["--gap" as string]: "10px" }}>
                    <div className="spread">
                      <p style={{ fontWeight: 600 }}>
                        {c.product} {c.version ? <span className="mono">{c.version}</span> : <span className="muted">(version not visible)</span>}
                      </p>
                      <StatusBadge status={c.worst} />
                    </div>
                    <p className="small muted">
                      {c.version ? (c.basis === "admin_supplied" ? "Version supplied by you, not independently observed." : "Version seen in public signals.") : "We can see this software, but not which version it is."}
                    </p>
                    {c.question ? (
                      <div className="notice n-neutral" style={{ display: "grid", gap: 4 }}>
                        <strong>Question for the owner or developer</strong>
                        <span>{c.question}</span>
                      </div>
                    ) : (
                      <p className="small">Unaffected by the vulnerabilities below, based on the version evidence shown. This covers these vulnerabilities only.</p>
                    )}
                    <details>
                      <summary className="small">
                        {c.open.length + c.closed.length} related alert{c.open.length + c.closed.length === 1 ? "" : "s"}
                      </summary>
                      <ul className="small stack" style={{ ["--gap" as string]: "8px", paddingLeft: 18 }}>
                        {[...c.open, ...c.closed].map((r) => (
                          <li key={r.advisory_id}>
                            <div className="row">
                              <StatusBadge status={r.status} />
                              <Link href={advisoryHref(r.advisory_id)} className="mono">
                                {r.primary_identifier}
                              </Link>
                            </div>
                            <p>{r.title}. {alertCopy(r.reason)}</p>
                            {r.conditions.length ? (
                              <p className="muted">
                                Applies only if: {r.conditions.map((cd) => `${cd.description} (${cd.state === "met" ? "seen" : cd.state === "unmet" ? "not present" : "unknown"})`).join("; ")}
                              </p>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    </details>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="panel stack">
            <h2 className="h-section">Technology evidence</h2>
            {observed.length === 0 && detectedOnly.length === 0 && evidence.length === 0 ? <p className="muted">No covered technology identified from public evidence.</p> : null}
            {observed.length ? <EvidenceTable title="Observed versions" rows={observed} /> : null}
            {detectedOnly.length ? <EvidenceTable title="Detected, version not observed" rows={detectedOnly} /> : null}
            {evidence.length ? (
              <div className="stack" style={{ ["--gap" as string]: "8px" }}>
                <h3 style={{ fontSize: 16 }}>Administrator-supplied (private to your workspace)</h3>
                <ul className="small">
                  {evidence.map((e) => (
                    <li key={e.id}>
                      {e.product} <span className="mono">{e.version}</span> — added {abs(e.created_at)}
                      {e.note ? `: ${e.note}` : ""}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            <details className="no-print">
              <summary>Add version evidence</summary>
              <form method="post" action={`/api/app/systems/${s.id}/evidence`} className="stack" style={{ marginTop: 8 }}>
                <p className="small muted">Private to your workspace. Used in your assessment with its source shown; never shared with other workspaces or the public cache.</p>
                <div className="row" style={{ alignItems: "end" }}>
                  <div style={{ flex: "1 1 160px" }}>
                    <label htmlFor="product">Product</label>
                    <select id="product" name="product" required>
                      {["php", "nextjs", "wordpress", "gitlab", "nodejs", "plex", "nginx", "apache", "drupal"].map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div style={{ flex: "1 1 160px" }}>
                    <label htmlFor="version">Exact version</label>
                    <input id="version" name="version" type="text" required placeholder="8.2.35" />
                  </div>
                </div>
                <div>
                  <label htmlFor="note">Source of this version</label>
                  <input id="note" name="note" type="text" placeholder="e.g. php -v on the web server, vendor ticket #123" />
                </div>
                <Submit className="btn btn-secondary" busy="Saving…">Save evidence</Submit>
              </form>
            </details>
          </section>

          <section className="panel stack">
            <h2 className="h-section">Gaps and limits</h2>
            <ul className="small">
              {(a?.summary.gaps ?? obs?.gaps ?? []).map((g, i) => (
                <li key={i}>{alertCopy(g.detail)}</li>
              ))}
              {techs.flatMap((t) => t.limitations).filter((x, i, arr) => arr.indexOf(x) === i).map((l) => (
                <li key={l}>{l}</li>
              ))}
              <li>Public evidence cannot see internal systems, authenticated services, hidden versions or vendor backports.</li>
            </ul>
          </section>

          <details className="panel">
            <summary>Domain-verified upgrade reports</summary><div className="stack">
            {claims.length === 0 ? <p className="muted small">No domain-verified upgrade report. Owner answers are recorded in the tracked conversation.</p> : (
              <ol className="timeline small">
                {claims.map((c) => (
                  <li key={c.id} className="stack" style={{ ["--gap" as string]: "4px" }}>
                    <div className="row">
                      <ClaimBadge state={c.state} />
                      <span>
                        Host reported {c.product} <span className="mono">{c.claimed_version}</span>
                      </span>
                    </div>
                    <span className="muted">
                      Reported {abs(c.created_at)} by a host who verified domain control{c.upgraded_at ? ` · upgraded ${abs(c.upgraded_at)}` : ""}
                      {c.reference_url ? (
                        <>
                          {" "}· <a href={c.reference_url}>reference</a>
                        </>
                      ) : null}
                    </span>
                    {c.outcome_detail ? <span>{alertCopy(c.outcome_detail)}</span> : null}
                    <span className="muted">Domain control shows who reported the upgrade. Only the fresh evidence decides whether it is fixed.</span>
                  </li>
                ))}
              </ol>
            )}
            <details>
              <summary>Recent activity</summary>
              <ul className="small">
                {events.map((e) => (
                  <li key={e.id}>
                    {abs(e.created_at)}: {describeEvent(e.kind, e.detail)}
                  </li>
                ))}
              </ul>
            </details>
          </div></details>
        </div>

        <aside className="stack no-print" style={{ ["--gap" as string]: "24px" }}>
          <section className="panel stack">
            <h2 className="h-section">Monitoring</h2>
            {s.monitoring === "active" ? (
              <p className="small">Monitored: re-checked against each newly reviewed alert and at least daily. You see a change here only when a reviewed alert might affect this system.</p>
            ) : s.monitoring === "pending_payment" ? (
              <p className="small">Monitoring is waiting for confirmed payment. It starts when the payment provider confirms the subscription.</p>
            ) : s.monitoring === "payment_issue" ? (
              <p className="small">The subscription has a payment problem. History is kept; update payment in <Link href="/billing">Billing</Link>.</p>
            ) : (
              <p className="small">Checking is free. Monitoring re-checks this system whenever a newly reviewed alert might affect it and keeps a dated evidence history.</p>
            )}
            {s.monitoring === "none" || s.monitoring === "paused" ? (
              <div className="stack"><p className="small">Your first system is free. Team covers up to 25 systems for one monthly workspace price.</p><Link className="btn btn-brand" href={`/billing/checkout?system=${s.id}`}>Review monitoring plan</Link></div>
            ) : (
              <form method="post" action={`/api/app/systems/${s.id}/pause`}>
                <Submit className="btn btn-secondary" busy="Pausing…" confirm="Pause monitoring? History is kept. Your Team subscription continues until you cancel it in Billing.">
                  Pause monitoring
                </Submit>
              </form>
            )}
          </section>

          <details className="panel"><summary>Advanced domain-control check</summary><p className="small">A separate advanced flow can verify control of the domain by DNS and recheck a reported upgrade. This is not required for a quick invited-owner answer.</p><Link href={hostLink}>Open domain-control check</Link></details>
          <details className="panel">
            <summary>App settings</summary><div className="stack">
            <form method="post" action={`/api/app/systems/${s.id}/update`} className="stack" style={{ ["--gap" as string]: "8px" }}>
              <div>
                <label htmlFor="label">Name</label>
                <input id="label" name="label" type="text" defaultValue={s.label} required maxLength={120} />
              </div>
              <div>
                <label htmlFor="business_use">Business use</label>
                <input id="business_use" name="business_use" type="text" defaultValue={s.business_use ?? ""} maxLength={160} />
              </div>
              <div>
                <label htmlFor="owner_vendor">System owner or developer</label>
                <input id="owner_vendor" name="owner_vendor" type="text" defaultValue={s.owner_vendor ?? ""} maxLength={160} />
              </div>
              <Submit className="btn btn-secondary" busy="Saving…">Save details</Submit>
            </form>
            {!overview?<OverviewClues systemId={id} overview={null}/>:null}
            <form method="post" action={`/api/app/systems/${s.id}/remove`}>
              <Submit className="btn btn-danger" busy="Removing…" confirm="Remove this system from your list? Monitoring stops and billing quantity is reduced. Past reports stay in our records.">
                Remove system
              </Submit>
            </form>
          </div></details>
        </aside>
      </div>
    </div>
  );
}

function EvidenceTable({ title, rows }: { title: string; rows: TechObservation[] }) {
  return (
    <div className="stack" style={{ ["--gap" as string]: "8px" }}>
      <h3 style={{ fontSize: 16 }}>{title}</h3>
      <div className="table-wrap" role="region" aria-label={title} tabIndex={0}>
        <table className="t">
          <thead>
            <tr>
              <th scope="col">Technology</th>
              <th scope="col">Version</th>
              <th scope="col">Evidence</th>
              <th scope="col">Confidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((t, i) => (
              <tr key={i}>
                <td>{t.name}</td>
                <td className="mono">{t.version ? `${t.version}${t.version_basis === "inferred" ? " (inferred)" : ""}` : "unknown"}</td>
                <td>
                  {t.detail}
                  <br />
                  <span className="muted small wrap">{t.location}</span>
                </td>
                <td>{t.confidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function describeEvent(kind: string, d: Record<string, unknown>) {
  if (kind === "finding_changed") return alertCopy(`${d.advisory}: ${d.from ? `${d.from} → ` : "new finding: "}${d.to} (${d.reason})`);
  if (kind === "monitoring_changed") return `Monitoring ${d.from} → ${d.to} (subscription ${d.subscription_status})`;
  if (kind === "monitoring_paused") return "Monitoring paused";
  if (kind === "system_added") return "System added";
  if (kind === "evidence_added") return `Administrator evidence added: ${d.product} ${d.version}`;
  return kind.replace(/_/g, " ");
}
