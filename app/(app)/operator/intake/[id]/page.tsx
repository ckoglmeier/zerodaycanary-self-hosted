import Link from "next/link";
import { notFound } from "next/navigation";
import { requireOperator } from "@/lib/auth";
import { one, q } from "@/lib/db";
import { draftProblems, type AdvisoryDraft } from "@/intel/schema";
import { EXPLOIT_LABEL, Badge } from "@/components/badges";
import { abs } from "@/components/time";
import { Submit } from "@/components/submit";

export const metadata = { title: "Review drafts" };

export default async function IntakeReview({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ error?: string; msg?: string }> }) {
  await requireOperator();
  const { id } = await params;
  const sp = await searchParams;
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const intake = await one<{ id: string; created_at: Date; brief: string; status: string; is_test: boolean; error: string | null; attribution: string | null; model: string | null }>("select * from feed_intakes where id = $1", [id]);
  if (!intake) notFound();
  const drafts = await q<{ id: string; draft: AdvisoryDraft; status: string; target_advisory_id: string | null; review_note: string | null; published_advisory_id: string | null;source_id:string|null }>(
    "select * from advisory_drafts where intake_id = $1 order by status, created_at",
    [id],
  );
  const open = drafts.filter((d) => d.status === "draft");
  return (
    <div className="stack" style={{ ["--gap" as string]: "24px" }}>
      <p className="small">
        <Link href="/operator">← Intake</Link>
      </p>
      <div className="stack" style={{ ["--gap" as string]: "6px" }}>
        <h1 className="h-page">Review drafts</h1>
        <p className="small muted">
          Brief received {abs(intake.created_at)}
          {intake.attribution ? ` · ${intake.attribution}` : ""} · status {intake.status}
          {intake.model ? ` · extracted by ${intake.model}` : ""}
        </p>
      </div>
      {intake.is_test ? <p className="notice small">Test intake. Its outcome is kept for audit and does not change public feed review health.</p> : null}
      {sp.error ? <p className="notice n-danger" role="alert">{sp.error}</p> : null}
      {sp.msg ? <p className="notice n-success">{sp.msg}</p> : null}
      {intake.status === "failed" ? (
        <p className="notice n-danger">Extraction failed: {intake.error}. Published records are unchanged.{intake.is_test ? " This test does not change public review health." : " The public feed shows the incomplete review."} Fix the input and submit it again.</p>
      ) : null}

      <details className="panel">
        <summary>Original brief</summary>
        <pre className="code" style={{ whiteSpace: "pre-wrap" }}>{intake.brief}</pre>
      </details>

      {open.length ? (
        <form method="post" action={`/api/operator/intake/${id}/publish`} id="publish" className="panel stack" style={{ ["--gap" as string]: "8px" }}>
          <h2 className="h-section">Publish</h2>
          <p className="small">Selected drafts become one catalog revision. The public page and API update together, and all systems are re-matched.</p>
          <p className="small">New alerts are available for matching after publication. Select priority placement separately in the operator catalog.</p>
          {open.some(d=>d.source_id)?<label className="row small"><input type="checkbox" name="source_review_confirmed" required style={{width:20,height:20}}/>I checked primary sources, corrected the summary and confirmed the available version, condition and exploitation evidence. Remaining gaps are explicit.</label>:null}
          <div>
            <label htmlFor="note">Revision note</label>
            <input id="note" name="note" type="text" defaultValue={`Brief review ${new Date().toISOString().slice(0, 10)}`} />
          </div>
          <Submit className="btn btn-brand" busy="Publishing and re-matching…">Publish selected</Submit>
        </form>
      ) : intake.status !== "failed" && intake.status !== "reviewed" ? (
        <form method="post" action={`/api/operator/intake/${id}/no-changes`} className="panel stack">
          <p className="small">No drafts are open. Record that this brief was reviewed with no changes?</p>
          <Submit className="btn btn-secondary" busy="Saving…">Record &ldquo;reviewed, no changes&rdquo;</Submit>
        </form>
      ) : null}

      <ul className="list">
        {drafts.map((d) => {
          const problems = d.status === "draft" ? draftProblems(d.draft) : [];
          const x = d.draft;
          return (
            <li key={d.id} className="stack">
              <div className="spread">
                <div className="row">
                  {d.status === "draft" ? (
                    <>
                      <input type="checkbox" id={`sel-${d.id}`} name="draft" value={d.id} form="publish" disabled={problems.length > 0} style={{ width: 20, height: 20 }} />
                      <label htmlFor={`sel-${d.id}`} style={{ margin: 0 }}>
                        {x.product}: {x.title}
                      </label>
                    </>
                  ) : (
                    <strong>
                      {x.product}: {x.title}
                    </strong>
                  )}
                </div>
                <Badge tone={d.status === "published" ? "success" : d.status === "rejected" ? "neutral" : "warning"}>{d.status}</Badge>
              </div>
              {d.target_advisory_id ? <p className="small">Updates existing record <Link href={`/advisory/${d.target_advisory_id}`} className="mono">{d.target_advisory_id}</Link>.</p> : null}
              {d.review_note ? <p className="small muted">{d.review_note}</p> : null}
              <div className="split">
                <dl className="facts">
                  <dt>Identifiers</dt>
                  <dd className="mono">{x.identifiers.join(", ") || "none"}</dd>
                  <dt>Severity</dt>
                  <dd>
                    {x.severity} {x.cvss_score ?? ""} {x.severity_source ? `(${x.severity_source})` : ""}
                  </dd>
                  <dt>Exploitation</dt>
                  <dd>
                    {EXPLOIT_LABEL[x.exploitation.category]} {x.exploitation.source_url ? <a href={x.exploitation.source_url}>source</a> : <em>no source</em>} {x.exploitation.as_of ?? ""}
                  </dd>
                  <dt>Ranges</dt>
                  <dd className="mono">
                    {x.affected.map((p) => `${p.product}: ` + p.ranges.map((r) => `[${r.introduced ?? "…"}, ${r.fixed ?? r.last_affected ?? "?"})${r.ambiguous ? " ambiguous" : ""}`).join(" ")).join("; ") || "none"}
                  </dd>
                  <dt>Conditions</dt>
                  <dd>{x.conditions.map((c) => c.description).join("; ") || "none"}</dd>
                  <dt>Sources</dt>
                  <dd className="wrap small">
                    {x.sources.map((s) => (
                      <a key={s.url} href={s.url} style={{ display: "block" }}>
                        {s.kind}: {s.url}
                      </a>
                    ))}
                  </dd>
                  <dt>Uncertainty</dt>
                  <dd>{x.uncertainty.join(" · ") || "none"}</dd>
                </dl>
                <blockquote className="small muted" style={{ margin: 0, borderLeft: "3px solid var(--color-line)", paddingLeft: 12 }}>
                  From the brief: {x.brief_excerpt}
                </blockquote>
              </div>
              {problems.length ? (
                <ul className="notice n-warning small">
                  {problems.map((p) => (
                    <li key={p}>{p}</li>
                  ))}
                </ul>
              ) : null}
              {d.status === "draft" ? (
                <details>
                  <summary>Edit draft</summary>
                  <form method="post" action={`/api/operator/drafts/${d.id}/save`} className="stack" style={{ marginTop: 8 }}>
                    <label htmlFor={`json-${d.id}`}>Draft record (JSON)</label>
                    <textarea id={`json-${d.id}`} name="draft" className="mono" rows={18} defaultValue={JSON.stringify(x, null, 2)} />
                    <label htmlFor={`target-${d.id}`}>Update existing record id (optional)</label>
                    <input id={`target-${d.id}`} name="target" type="text" defaultValue={d.target_advisory_id ?? ""} />
                    <div className="row">
                      <Submit className="btn btn-secondary" busy="Saving…">Save draft</Submit>
                    </div>
                  </form>
                  <form method="post" action={`/api/operator/drafts/${d.id}/reject`} className="row" style={{ marginTop: 8 }}>
                    <label htmlFor={`rej-${d.id}`} className="sr-only">
                      Reason
                    </label>
                    <input id={`rej-${d.id}`} name="note" type="text" placeholder="Reason for rejecting" style={{ maxWidth: 320 }} />
                    <Submit className="btn btn-danger" busy="Rejecting…">Reject draft</Submit>
                  </form>
                </details>
              ) : null}
            </li>
          );
        })}
        {drafts.length === 0 && intake.status !== "failed" ? <li className="muted">No drafts were extracted from this brief.</li> : null}
      </ul>
    </div>
  );
}
