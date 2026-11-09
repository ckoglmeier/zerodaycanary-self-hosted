import {advisoryHref} from '@/intel/packages';
import {CveReviewView} from "@/components/cve-review";
import type {CveReview} from "@/lib/developer/cve-report";
import { BuildReport } from "@/components/build-report";
import { reportRequestContext } from "@/lib/review/presentation";
import { RequestContext } from "@/components/request-context";
import { reviewData } from "@/lib/review/requests";
import { alertCopy } from "@/lib/alert-copy";
import Link from "next/link";
import { cookies } from "next/headers";
import { notFound } from "next/navigation";
import { requireViewer } from "@/lib/auth";
import { userQ } from "@/lib/db";
import { ownProject } from "@/lib/developer/projects";
import { q } from "@/lib/db";
import { Badge, StatusBadge, EXPLOIT_LABEL } from "@/components/badges";
import { When, abs } from "@/components/time";
import { Submit } from "@/components/submit";
import { CopyButton } from "@/components/copy";
import { env } from "@/lib/env";
import type { DevResult } from "@/lib/developer/evaluate";
import type { ExploitationCategory } from "@/intel/schema";

export const metadata = { title: "Developer project" };

const UNKNOWN_LABEL: Record<string, string> = {
  missing_inventory: "No inventory supplied",
  unsupported_inventory: "Unsupported inventory format",
  ambiguous_identity: "Package identity unclear",
  ambiguous_version: "Version not exact",
  linked_or_workspace_component: "Linked or workspace package (not a registry identity)",
  missing_root_manifest: "Root manifest missing from lockfile",
  missing_direct_entry: "Direct dependency missing from lockfile",
  non_registry_component: "Resolved outside registry.npmjs.org",
};

export default async function DevProject({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ msg?: string; error?: string; rev?: string; request?: string }> }) {
  const { id } = await params;
  const sp = await searchParams;
  const v = await requireViewer(`/developer/${id}`);
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const p=await ownProject(v,id).catch(()=>null);
  if (!p) notFound();
  const requestContext=sp.request?await reviewData(v,sp.request):null;
  if(!p.latest_evidence_id)return <div className="stack" style={{maxWidth:840,marginInline:'auto'}}><p><Link href={sp.request?`/reviews/${sp.request}`:'/developer'}>← {sp.request?'Back to the request':'Developer projects'}</Link></p><h1 className="h-page">Build a report for {p.name}</h1><p>Download the skill, give your agent the prompt, then upload the report below. Everything stays private until you review and share it.</p>{sp.error?<p className="notice n-danger" role="alert">{sp.error}</p>:null}<BuildReport name={p.name} projectId={p.id} requestId={sp.request} context={requestContext?reportRequestContext(requestContext):undefined}/></div>;

  type Revision={cve_review:CveReview|null;id:string;received_at:string;bundle_sha256:string;submitted_via:string;repository_id:string;repository_commit:string|null;repository_dirty:boolean;deployment:unknown;inventory_format:string;unknowns:unknown;audit_summary:unknown;has_detailed_findings:boolean};
  const [revisions,events,tokens]=await Promise.all([
    userQ<Revision>(v,'select * from developer_evidence where project_id=$1 and workspace_id=$2 order by received_at desc',[id,v.workspaceId]),
    userQ<{id:string;created_at:string;seen_at:string|null;kind:string;current_status:string|null;detail:unknown;advisory_id:string}>(v,'select * from developer_events where project_id=$1 and workspace_id=$2 order by created_at desc limit 50',[id,v.workspaceId]),
    q<{ id: string; token_hint: string; scopes: string[]; label: string | null; expires_at: Date; revoked_at: Date | null; last_used_at: Date | null }>(
      'select id,token_hint,scopes,label,expires_at,revoked_at,last_used_at from developer_project_tokens where project_id=$1 and workspace_id=$2 order by created_at desc',[id,v.workspaceId]),
  ]);
  const revs = revisions ?? [];
  const current = revs.find((r) => r.id === sp.rev) ?? revs.find((r) => r.id === p.latest_evidence_id) ?? null;
  const [comps,evals]=current?await Promise.all([
    userQ<{instance:number;name:string;exact_version:string|null;relationship:string;development:boolean|null;optional:boolean}>(v,'select instance,name,exact_version,relationship,development,optional from developer_components where evidence_id=$1 and workspace_id=$2 order by name limit 2000',[current.id,v.workspaceId]),
    userQ<{state:string;catalog_revision:number;results:unknown;coverage:unknown;error:string|null;completed_at:string|null;created_at:string}>(v,'select * from developer_evaluations where evidence_id=$1 and workspace_id=$2 order by created_at desc limit 5',[current.id,v.workspaceId]),
  ]):[[],[]];
  const lastOk = (evals ?? []).find((e) => e.state === "completed");
  const latestEval = (evals ?? [])[0];
  const results = ((lastOk?.results ?? []) as DevResult[]).filter((r) => r.status !== "not_affected");
  const clear = ((lastOk?.results ?? []) as DevResult[]).filter((r) => r.status === "not_affected");
  const unseen = (events ?? []).filter((e) => !e.seen_at);
  const newToken = (await cookies()).get("zdc_new_token")?.value;
  const audit = current?.audit_summary as { verdict_counts: Record<string, number>; total_records: number; context: { run_status: string; audited_at: string | null } } | undefined;
  const endpoint = `${env.siteUrl()}/api/v1/developer/projects/${p.id}/evidence`;

  return (
    <div className="stack" style={{ ["--gap" as string]: "24px" }}>
      <p className="small">
        <Link href={sp.request?`/reviews/${sp.request}`:"/developer"}>← {sp.request?"Back to the request":"Developer projects"}</Link>
      </p>
      {sp.error ? <p className="notice n-danger" role="alert">{sp.error}</p> : null}
      {sp.msg ? <p className="notice n-success" role="status">{sp.msg}</p> : null}
      <header className="spread">
        <div className="stack" style={{ ["--gap" as string]: "6px" }}>
          <h1 className="h-page wrap">{p.name}</h1>
          <div className="row">
            <Badge tone={p.state === "active" ? "brand" : "neutral"}>{p.state === "active" ? "Free monitoring on" : p.state === "paused" ? "Paused" : "Not enrolled"}</Badge>
            <span className="small muted">Free · private until explicitly shared · not a billable system</span>
          </div>
        </div>
        <div className="row no-print">
          {p.state === "pending" && current ? (
            <form method="post" action={`/api/app/developer/${p.id}/enroll`}>
              <Submit className="btn btn-brand" busy="Starting…">Start free monitoring</Submit>
            </form>
          ) : null}
          {p.state === "active" ? (
            <form method="post" action={`/api/app/developer/${p.id}/pause`}>
              <Submit className="btn btn-secondary" busy="Pausing…">Pause</Submit>
            </form>
          ) : null}
          {p.state === "paused" && p.enrolled_at ? (
            <form method="post" action={`/api/app/developer/${p.id}/resume`}>
              <Submit className="btn btn-secondary" busy="Resuming…">Resume</Submit>
            </form>
          ) : null}
        </div>
      </header>

      {requestContext?<RequestContext context={reportRequestContext(requestContext)}/>:null}
      <section className="panel stack" id="review-share"><h2 className="h-section">Share a reviewed report</h2><p className="small">Review the exact component inventory, alert matches and limits before creating your free reusable report page. Your raw uploads and detailed audit notes remain private.</p>{current&&lastOk?<Link className="btn btn-brand" href={`/developer/${id}/share${sp.request?'?request='+encodeURIComponent(sp.request):''}`}>Review report before sharing</Link>:<p className="small muted">Upload an inventory and complete evaluation first.</p>}{sp.request?<Link href={`/reviews/${sp.request}`}>Back to the client’s request</Link>:null}<Link href={`/developer/skill?project=${id}${sp.request?`&request=${sp.request}`:''}`}>Get the Canary companion skill</Link></section>

      {unseen.length ? (
        <section className="panel stack" aria-labelledby="notices">
          <div className="spread">
            <h2 id="notices" className="h-section">New notices</h2>
            <form method="post" action={`/api/app/developer/${p.id}/seen`}>
              <Submit className="btn btn-secondary" busy="Saving…">Mark all read</Submit>
            </form>
          </div>
          <ul className="small">
            {unseen.map((e) => (
              <li key={e.id}>
                <strong>{e.kind === "newly_relevant" ? "Newly relevant" : e.kind === "advisory_withdrawn" ? "Alert withdrawn" : e.kind === "no_longer_relevant" ? "No longer relevant" : "Status changed"}:</strong>{" "}
                <Link href={advisoryHref(e.advisory_id)} className="mono">{(e.detail as { identifier: string }).identifier}</Link> for {(e.detail as { package: string }).package}{" "}
                <span className="mono">{(e.detail as { version: string | null }).version ?? "version unknown"}</span>
                {e.current_status ? ` → ${e.current_status.replace(/_/g, " ")}` : ""} · {abs(e.created_at)}
              </li>
            ))}
          </ul>
          <p className="small muted">Delivered in this app only. Checked when a reviewed alert is published and daily; you only get a notice when one matches a package you uploaded.</p>
        </section>
      ) : null}


      {current?.cve_review?<details className="panel"><summary>Advisory-specific source checks ({current.cve_review.assessments.length})</summary><CveReviewView review={current.cve_review} labels={Object.fromEntries(((lastOk?.results||[]) as DevResult[]).map(r=>[r.advisory_id,r.identifier]))}/></details>:null}
      <div className="split">
        <div className="stack" style={{ ["--gap" as string]: "24px" }}>
          <section className="panel stack">
            <h2 className="h-section">Possible concerns</h2>
            {!current ? (
              <p className="muted">Upload an inventory to see matches.</p>
            ) : !lastOk ? (
              <p className="notice n-warning">
                {latestEval?.state === "failed" ? `The last evaluation failed (${latestEval.error}). Earlier results, if any, are kept; it will be retried.` : "Evaluation pending."}
              </p>
            ) : (
              <>
                <p className="small muted">
                  Compared <When at={lastOk.completed_at} /> with Canary alerts (catalog revision {lastOk.catalog_revision}) and stored package checks. These compare the versions declared in your
                  lockfile with affected ranges. They do not show what production runs, and a version match alone does not mean the vulnerability applies.
                </p>
                {results.length === 0 ? (
                  <p>No reviewed alert matched the packages we cover. That answers only for those alerts; it does not mean the project has no vulnerabilities.</p>
                ) : (
                  <details><summary>{results.length} vulnerability version results — review evidence</summary>
                  <ul className="list">
                    {results.map((r, i) => (
                      <li key={i} className="stack" style={{ ["--gap" as string]: "4px" }}>
                        <div className="row">
                          <StatusBadge status={r.status} />
                          <Link href={advisoryHref(r.advisory_id)} className="mono">{r.identifier}</Link>
                          {r.exploitation !== "none_confirmed" ? <Badge tone={r.exploitation === "known_exploited" ? "danger" : "warning"}>{EXPLOIT_LABEL[r.exploitation as ExploitationCategory]}</Badge> : null}
                        </div>
                        <p style={{ fontWeight: 600 }}>{r.title}</p>
                        <p className="small">
                          {r.component.name} <span className="mono">{r.component.version ?? "unknown"}</span> ({r.component.relationship}
                          {r.component.development ? ", development" : ""}). {alertCopy(r.reason)}
                        </p>
                        <p className="small"><strong>Next step:</strong> {alertCopy(r.next_step)}</p>
                      </li>
                    ))}
                  </ul>
                  </details>
                )}
                {clear.length ? <p className="small muted">Unaffected by these vulnerabilities, based on the declared version: {clear.map((r) => `${r.identifier} (${r.component.name} ${r.component.version})`).join("; ")}.</p> : null}
                <p className="small muted">
                  Coverage: {(lastOk.coverage as { components_covered: number; components_total: number }).components_covered} of {(lastOk.coverage as { components_total: number }).components_total} components have an available package check. The rest are not assessed, which does not mean they are unaffected.
                </p>
              </>
            )}
          </section>

          {current ? (
            <section className="panel stack">
              <h2 className="h-section">Inventory review</h2>
              <dl className="facts">
                <dt>Revision</dt>
                <dd className="mono">{current.id}</dd>
                <dt>Received</dt>
                <dd>{abs(current.received_at)} via {current.submitted_via === "api" ? "Canary CLI (API)" : current.submitted_via === "web_bundle" ? "bundle upload" : "file upload"}</dd>
                <dt>Repository</dt>
                <dd className="wrap">
                  {current.repository_id} · commit {current.repository_commit ?? "not supplied"}
                  {current.repository_dirty ? " (uncommitted changes)" : ""} · developer-supplied
                </dd>
                <dt>Deployment claim</dt>
                <dd>{current.deployment ? `${(current.deployment as { identity: string; version: string }).identity} ${(current.deployment as { version: string }).version} (developer-supplied, unverified)` : "none"}</dd>
                <dt>Inventory</dt>
                <dd>{current.inventory_format} · {comps?.length ?? 0} components</dd>
                <dt>Bundle SHA-256</dt>
                <dd className="mono">{current.bundle_sha256}</dd>
                <dt>Audit (as supplied)</dt>
                <dd>
                  {audit?.total_records ? `${audit.total_records} records: ${audit.verdict_counts.confirmed} confirmed, ${audit.verdict_counts.needs_validation} need validation, ${audit.verdict_counts.rejected} rejected (run ${audit.context.run_status})` : "no audit report"}
                  {current.has_detailed_findings ? " · detailed findings stored privately" : " · detailed findings not stored"}
                </dd>
              </dl>
              <p className="small muted">Audit verdicts are the auditor&rsquo;s, kept exactly as supplied. They are separate from alert matches and say nothing about the deployed system.</p>
              {(current.unknowns as { reason: string; entry: number | null }[]).length ? (
                <details>
                  <summary>Unknowns ({(current.unknowns as unknown[]).length})</summary>
                  <ul className="small">
                    {Object.entries(
                      (current.unknowns as { reason: string }[]).reduce<Record<string, number>>((a, u) => ((a[u.reason] = (a[u.reason] ?? 0) + 1), a), {}),
                    ).map(([k, n]) => (
                      <li key={k}>
                        {UNKNOWN_LABEL[k] ?? k}: {n}
                      </li>
                    ))}
                  </ul>
                </details>
              ) : null}
              <details>
                <summary>Components ({comps?.length ?? 0})</summary>
                <div className="table-wrap">
                  <table className="t">
                    <thead>
                      <tr>
                        <th scope="col">Package</th>
                        <th scope="col">Version</th>
                        <th scope="col">Relationship</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(comps ?? []).map((c) => (
                        <tr key={c.instance}>
                          <td className="mono">{c.name}</td>
                          <td className="mono">{c.exact_version ?? "unknown"}</td>
                          <td className="small">
                            {c.relationship}
                            {c.development ? ", dev" : ""}
                            {c.optional ? ", optional" : ""}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            </section>
          ) : null}

          <section className="panel stack">
            <h2 className="h-section">History</h2>
            {revs.length === 0 ? <p className="small muted">No revisions yet.</p> : (
              <ol className="small">
                {revs.map((r) => (
                  <li key={r.id}>
                    <Link href={`/developer/${p.id}?rev=${r.id}`}>{abs(r.received_at)}</Link> · {r.repository_id} {r.repository_commit ? r.repository_commit.slice(0, 10) : ""} ·{" "}
                    <span className="mono">{r.bundle_sha256.slice(0, 12)}</span>
                    {r.id === p.latest_evidence_id ? " · current" : ""}
                  </li>
                ))}
              </ol>
            )}
            <p className="small muted">Revisions are immutable. A refreshed upload becomes a new revision; earlier ones and their results are kept.</p>
            {(events ?? []).length ? (
              <details>
                <summary>All notices</summary>
                <ul className="small">
                  {(events ?? []).map((e) => (
                    <li key={e.id}>
                      {abs(e.created_at)}: {e.kind.replace(/_/g, " ")} — {(e.detail as { identifier: string }).identifier} ({(e.detail as { package: string }).package})
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
          </section>
        </div>

        <aside className="stack" style={{ ["--gap" as string]: "24px" }}><details className="panel"><summary>Update inventory and settings</summary>
          <section className="panel stack">
            <h2 className="h-section">Upload inventory</h2>
            <form method="post" action={`/api/app/developer/${p.id}/upload`} encType="multipart/form-data" className="stack" style={{ ["--gap" as string]: "12px" }}>
              <div>
                <label htmlFor="bundle">Canary evidence bundle</label>
                <input id="bundle" name="bundle" type="file" accept="application/json,.json" />
                <p className="hint">From the Canary companion (canary-evidence/1).</p>
              </div>
              <p className="small muted">— or —</p>
              <div>
                <label htmlFor="repository">Repository name</label>
                <input type="hidden" name="return_to_request" value={sp.request||''}/><input id="repository" name="repository" type="text" placeholder="org/app" maxLength={200} />
              </div>
              <div>
                <label htmlFor="lockfile">npm package-lock.json (v2 or v3)</label>
                <input id="lockfile" name="lockfile" type="file" accept="application/json,.json" />
              </div>
              <div>
                <label htmlFor="findings">Cloudflare audit findings JSON (optional)</label>
                <input id="findings" name="findings" type="file" accept="application/json,.json" />
              </div>
              <label className="row" style={{ fontWeight: 400 }}>
                <input type="checkbox" name="include_findings" style={{ width: 20, height: 20 }} /> Store detailed findings privately (otherwise only verdict counts are kept)
              </label>
              <label className="row small"><input type="checkbox" name="public_package_lookups" defaultChecked /> Check public packages with OSV.dev. Only public names, ecosystems and versions are sent.</label><p className="hint">Max 5 MiB per file. Files are read as data only; nothing in them is run or sent to an AI model. Uploads stay private to your account.</p>
              <Submit busy="Validating…">Upload for review</Submit>
            </form>
          </section>

          <section className="panel stack">
            <h2 className="h-section">CLI access</h2>
            {newToken ? (
              <div className="notice n-warning stack" style={{ ["--gap" as string]: "8px" }}>
                <strong>New token (shown once):</strong>
                <span className="mono wrap">{newToken}</span>
                <CopyButton text={newToken} label="Copy token" />
              </div>
            ) : null}
            <p className="small">
              Endpoint: <span className="mono wrap">{endpoint}</span>
            </p>
            <form method="post" action={`/api/app/developer/${p.id}/token`} className="stack" style={{ ["--gap" as string]: "8px" }}>
              <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
                <legend className="small" style={{ fontWeight: 600 }}>Scopes</legend>
                <label className="row" style={{ fontWeight: 400 }}><input type="checkbox" name="evidence:write" defaultChecked style={{ width: 20, height: 20 }} /> Upload evidence</label>
                <label className="row" style={{ fontWeight: 400 }}><input type="checkbox" name="evidence:read" style={{ width: 20, height: 20 }} /> Read evidence</label>
              </fieldset>
              <div>
                <label htmlFor="days">Expires after (days)</label>
                <select id="days" name="days" defaultValue="90">
                  <option value="7">7</option>
                  <option value="30">30</option>
                  <option value="90">90</option>
                  <option value="365">365</option>
                </select>
              </div>
              <div>
                <label htmlFor="label">Label</label>
                <input id="label" name="label" type="text" maxLength={80} placeholder="e.g. CI" />
              </div>
              <Submit className="btn btn-secondary" busy="Creating…">Create token</Submit>
            </form>
            {tokens.length ? (
              <ul className="small">
                {tokens.map((t) => (
                  <li key={t.id} className="spread">
                    <span>
                      …{t.token_hint} · {t.scopes.join(", ")} {t.label ? `· ${t.label}` : ""} ·{" "}
                      {t.revoked_at ? "revoked" : t.expires_at.getTime() < Date.now() ? "expired" : `expires ${abs(t.expires_at).slice(0, 10)}`}
                    </span>
                    {!t.revoked_at ? (
                      <form method="post" action={`/api/app/developer/${p.id}/revoke-token`}>
                        <input type="hidden" name="token_id" value={t.id} />
                        <button className="linkbtn small" type="submit">Revoke</button>
                      </form>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : null}
          </section>

          <section className="panel stack">
            <h2 className="h-section">Your data</h2>
            <a className="btn btn-secondary" href={`/api/app/developer/${p.id}/export`}>Export all revisions (JSON)</a>
            <form method="post" action={`/api/app/developer/${p.id}/delete`}>
              <Submit className="btn btn-danger" busy="Deleting…" confirm="Delete this project? Tokens are revoked and monitoring stops.">Delete project</Submit>
            </form>
          </section>
        </details></aside>
      </div>
    </div>
  );
}
