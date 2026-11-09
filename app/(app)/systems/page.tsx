import Link from "next/link";
import { listSystems } from "@/lib/portfolio";
import { ClaimBadge, ExploitBadge, MonitoringBadge, StatusBadge } from "@/components/badges";
import { When } from "@/components/time";
import { TechnologyOverviewForm } from "@/components/technology-overview";
import { allAdvisories } from "@/lib/catalog";
import { STATUS_RANK,type AssessmentStatus } from "@/intel/match";

export const metadata = { title: "Your systems" };

const FILTERS = [
  { key: "", label: "All" },
  { key: "attention", label: "Needs attention" },
  { key: "verify", label: "Needs an answer" },
  { key: "upgrade", label: "Owner reported upgrade" },
  { key: "fixed", label: "Fixed, with evidence" },
] as const;

const ATTENTION: AssessmentStatus[] = ["affected_version_matched", "applicability_confirmed"];

export default async function Systems({ searchParams }: { searchParams: Promise<{ f?: string; error?: string; added?: string }> }) {
  const sp = await searchParams;
  const [rows, advisories] = await Promise.all([listSystems(), allAdvisories()]);
  const exploit = new Map(advisories.map((a) => [a.id, a.exploitation.category]));

  const has = (r: (typeof rows)[number], s: AssessmentStatus[]) => (r.assessment?.results ?? []).some((x) => s.includes(x.status)) || r.review.findings.some(x=>s.includes(x.assessment_status as AssessmentStatus)&&!["withdrawn","owner_not_affected","no_match_in_report"].includes(x.workflow_status));
  const match = (r: (typeof rows)[number], f: string) =>
    f === "attention" ? r.review.answer?.outcome==='affected'||has(r, ATTENTION) :
    f === "verify" ? r.review.waiting>0 || r.review.findings.some(x=>["check_required","unknown"].includes(x.workflow_status)) || (!r.review.answer && (has(r, ["needs_verification"]) || r.assessment?.summary.observation.outcome == null)) :
    f === "upgrade" ? !!r.claim && ["reported", "checking"].includes(r.claim.state) :
    f === "fixed" ? has(r, ["fix_verified"]) : true;
  const f = FILTERS.some((x) => x.key === sp.f) ? sp.f ?? "" : "";
  const shown = rows.filter((r) => match(r, f));
  const n = (k: string) => rows.filter((r) => match(r, k)).length;

  return (
    <div className="stack" style={{ ["--gap" as string]: "24px" }}>
      <div className="spread">
        <div className="stack" style={{ ["--gap" as string]: "6px" }}>
          <h1 className="h-page">Your systems</h1>
          {rows.length ? (
            <p className="small muted">
              {n("attention")} need attention · {n("verify")} waiting for an answer · {rows.filter((r) => r.system.monitoring === "active").length} monitored
            </p>
          ) : null}
        </div>
      </div>

      <TechnologyOverviewForm/>
        {sp.error ? (
          <p className="field-error" role="alert">
            {sp.error}
          </p>
        ) : null}

      {rows.length === 0 ? (
        <div className="panel empty stack" style={{ ["--gap" as string]: "12px" }}>
          <img src="/brand/canary-160.png" alt="" width={72} height={72} style={{ margin: "0 auto" }} />
          <p>Check a system to see whether a reviewed vulnerability might affect it.</p>
          <p className="small muted">You get a specific question to send its owner or developer, and a place to keep their answer and the evidence.</p>
        </div>
      ) : (
        <>
          <nav className="filters" aria-label="Filter systems">
            {FILTERS.map((x) => (
              <Link key={x.key} href={x.key ? `/systems?f=${x.key}` : "/systems"} className="filter" aria-current={f === x.key ? "page" : undefined}>
                {x.label} <span className="muted">({x.key ? n(x.key) : rows.length})</span>
              </Link>
            ))}
          </nav>
          <p className="small muted">These are the systems you added, not a complete inventory of your organization. Related alerts for the same software are grouped as one concern.</p>
          <div>
            <div className="list-head grid-sys" aria-hidden="true">
              <span>System</span>
              <span>Concern</span>
              <span>Evidence</span>
              <span>Next step</span>
            </div>
            <ul className="list">
              {shown.map(({ system: s, assessment: a, claim, review }) => {
                const tracked=review.findings.filter(f=>f.workflow_status!=='withdrawn').sort((x,y)=>STATUS_RANK[y.assessment_status as AssessmentStatus]-STATUS_RANK[x.assessment_status as AssessmentStatus])[0];
                const strongest=tracked&&(!a?.summary.strongest||STATUS_RANK[tracked.assessment_status as AssessmentStatus]>STATUS_RANK[a.summary.strongest.status])?{status:tracked.assessment_status as AssessmentStatus,advisory:tracked.evidence.primary_identifier,title:tracked.evidence.title,next_step:tracked.evidence.next_step}:a?.summary.strongest;
                const techs = a ? [...new Set(a.results.map((r) => `${r.product}${r.version_used ? " " + r.version_used : ""}`))] : [];
                const top = a?.results[0];
                return (
                  <li key={s.id} className="grid-sys">
                    <div className="stack" style={{ ["--gap" as string]: "4px" }}>
                      <span className="cell-label">System</span>
                      <Link href={`/systems/${s.id}`} style={{ fontWeight: 600 }} className="wrap">
                        {s.label}
                      </Link>
                      <span className="mono muted">{s.scope?.scope_key}</span>
                      {s.business_use ? <span className="small muted">{s.business_use}</span> : null}
                      <div className="row">
                        <MonitoringBadge state={s.monitoring} />
                      </div>
                    </div>
                    <div className="stack" style={{ ["--gap" as string]: "6px" }}>
                      <span className="cell-label">Concern</span>
                      {!a&&!strongest ? (
                        <StatusBadge status="not_assessed" />
                      ) : strongest ? (
                        <>
                          <div className="row">
                            <StatusBadge status={strongest.status} />
                          </div>
                          <span className="small">
                            <span className="mono">{strongest.advisory}</span>
                          </span>
                          {top && exploit.get(top.advisory_id) && exploit.get(top.advisory_id) !== "none_confirmed" ? <ExploitBadge category={exploit.get(top.advisory_id)!} /> : null}
                        </>
                      ) : (
                        <span className="small">
                          {a?.summary.observation.outcome === "failed" ? "The check did not complete." : "No reviewed alert matches what we can see."}{" "}
                          <span className="muted">{a?.summary.gaps.length ? `${a?.summary.gaps.length} evidence gap${a?.summary.gaps.length > 1 ? "s" : ""}.` : ""}</span>
                        </span>
                      )}
                      {claim ? <ClaimBadge state={claim.state} /> : null}{review.answer?<span className="small">Owner: {review.answer.outcome==='not_affected'?'not affected by the requested alert':review.answer.outcome==='affected'?'affected':'not sure'} · <When at={review.answer.created_at}/></span>:null}{review.findings.some(f=>f.workflow_status==='check_required')?<span className="small">New or changed evidence needs a check.</span>:null}
                    </div>
                    <div className="stack small" style={{ ["--gap" as string]: "4px" }}>
                      <span className="cell-label">Evidence</span>
                      <span className="wrap">{techs.length ? techs.join(", ") : "No covered software identified publicly"}</span>
                      <span className="muted">
                        Public check: <When at={a?.summary.observation.observed_at ?? null} />
                      </span><span>{review.reports?`${review.reports} shared developer report${review.reports>1?'s':''} · source inventory, production unverified`:"No developer report shared"}</span>
                    </div>
                    <div className="stack small" style={{ ["--gap" as string]: "6px" }}>
                      <span className="cell-label">Next step</span>
                      <span>{review.waiting?"Follow up on the owner request.":review.findings.some(f=>["check_required","unknown"].includes(f.workflow_status))?"Review the evidence and ask the owner to confirm.":review.answer?.outcome==='affected'?"Follow the owner’s fix plan.":strongest && strongest.status !== "not_affected" && !review.answer ? strongest.next_step : a?.summary.observation.outcome === "failed" ? "Retry the check or ask the owner to check." : "Review the current evidence and coverage."}</span>
                      <Link href={`/systems/${s.id}`}>
                        Open<span className="sr-only"> {s.label}</span>
                      </Link>
                    </div>
                  </li>
                );
              })}
              {shown.length === 0 ? <li className="muted">No systems match this filter.</li> : null}
            </ul>
          </div>
        </>
      )}
    </div>
  );
}
