import { alertCopy } from "@/lib/alert-copy";
import { notFound } from "next/navigation";
import { claimsForScope, scopeForToken, txtName, txtValue, CONTROL_FRESH_MINUTES } from "@/lib/host";
import { one } from "@/lib/db";
import { ClaimBadge } from "@/components/badges";
import { abs } from "@/components/time";
import { Submit } from "@/components/submit";
import { CopyButton } from "@/components/copy";

export const metadata = { title: "Answer a question about your system", robots: { index: false } };
export const dynamic = "force-dynamic";

// Shows only the public address being checked. The requesting buyer is never identified here.
export default async function HostPage({ params, searchParams }: { params: Promise<{ token: string }>; searchParams: Promise<{ c?: string; error?: string; msg?: string }> }) {
  const { token } = await params;
  const sp = await searchParams;
  const scope = await scopeForToken(token);
  if (!scope) notFound();
  const ch = sp.c && /^[0-9a-f-]{36}$/.test(sp.c)
    ? await one<{ id: string; token: string; expires_at: Date; verified_at: Date | null; consumed_at: Date | null; scope_id: string }>("select * from host_challenges where id = $1 and scope_id = $2", [sp.c, scope.scope_id])
    : null;
  const claims = await claimsForScope(scope.scope_id);
  const controlFresh = ch?.verified_at && !ch.consumed_at && Date.now() - ch.verified_at.getTime() < CONTROL_FRESH_MINUTES * 60_000 && ch.expires_at.getTime() > Date.now();

  return (
    <div className="stack prose" style={{ ["--gap" as string]: "24px" }}>
      <header className="stack" style={{ ["--gap" as string]: "8px" }}>
        <h1 className="h-page">Answer a question about your system</h1>
        <p>
          Someone who relies on <span className="mono wrap">{scope.url}</span> asked whether it might be affected by a recently published vulnerability. If you
          own or develop this system and have updated it, report the version here and we will run a fresh check of its public signals. No account is needed.
        </p>
        <p className="small muted">
          What you enter here and the result of the fresh check are shown to the person who sent you this link. Nothing else about you or your system is
          shared. If you build it with npm, you can also check your lockfile privately in a <a href="/developer">free developer project</a>; those results
          stay in your own account.
        </p>
      </header>
      {sp.error ? <p className="notice n-danger" role="alert">{sp.error}</p> : null}
      {sp.msg ? <p className="notice n-success" role="status">{sp.msg}</p> : null}

      <section className="panel stack">
        <h2 className="h-section">1. Verify control of {scope.host}</h2>
        <p className="small">
          Add a DNS TXT record to show you control this domain. This shows who is reporting the upgrade; it does not show that anything is fixed. You can
          remove the record after you submit.
        </p>
        {!ch || ch.consumed_at || ch.expires_at.getTime() < Date.now() ? (
          <form method="post" action={`/api/host/${token}/challenge`}>
            <Submit className="btn btn-primary" busy="Creating record…">Get DNS record</Submit>
          </form>
        ) : (
          <div className="stack" style={{ ["--gap" as string]: "12px" }}>
            <dl className="facts">
              <dt>Type</dt>
              <dd className="mono">TXT</dd>
              <dt>Name</dt>
              <dd className="mono">{txtName(scope.host)}</dd>
              <dt>Value</dt>
              <dd className="mono">{txtValue(ch.token)}</dd>
              <dt>Expires</dt>
              <dd>{abs(ch.expires_at)}</dd>
            </dl>
            <CopyButton text={txtValue(ch.token)} label="Copy TXT value" />
            {ch.verified_at ? (
              <p className="notice n-neutral">Domain control verified {abs(ch.verified_at)}.</p>
            ) : (
              <form method="post" action={`/api/host/${token}/verify`}>
                <input type="hidden" name="challenge" value={ch.id} />
                <Submit className="btn btn-primary" busy="Checking DNS…">Check verification</Submit>
                <p className="hint">DNS changes can take a few minutes to appear.</p>
              </form>
            )}
          </div>
        )}
      </section>

      <section className="panel stack" aria-disabled={!controlFresh}>
        <h2 className="h-section">2. Report the upgrade</h2>
        {!controlFresh ? (
          <p className="small muted">Available after domain control is verified (valid for {CONTROL_FRESH_MINUTES} minutes).</p>
        ) : (
          <form method="post" action={`/api/host/${token}/upgrade`} className="stack">
            <input type="hidden" name="challenge" value={ch!.id} />
            <div>
              <label htmlFor="product">Product</label>
              <select id="product" name="product" required>
                {["php", "nextjs", "wordpress", "gitlab", "nodejs", "plex", "nginx", "apache", "drupal"].map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="claimed_version">Version or build now running</label>
              <input id="claimed_version" name="claimed_version" type="text" required placeholder="8.2.35" />
            </div>
            <div>
              <label htmlFor="upgraded_at">When was it upgraded? (optional)</label>
              <input id="upgraded_at" name="upgraded_at" type="datetime-local" />
            </div>
            <div>
              <label htmlFor="reference_url">Release notes, vendor advisory or change ticket (optional)</label>
              <input id="reference_url" name="reference_url" type="url" placeholder="https://" />
            </div>
            <Submit className="btn btn-primary" busy="Reporting and checking public signals…">Report upgrade and re-analyze</Submit>
          </form>
        )}
      </section>

      <section className="panel stack">
        <h2 className="h-section">Status</h2>
        <p className="small muted">Upgrade reported → fresh public check → fixed with evidence, still affected, or unable to confirm from public signals. A claim alone is never marked fixed.</p>
        {claims.length === 0 ? (
          <p className="small">No upgrade reports yet.</p>
        ) : (
          <ol className="timeline small">
            {claims.map((c) => (
              <li key={c.id} className="stack" style={{ ["--gap" as string]: "4px" }}>
                <div className="row">
                  <ClaimBadge state={c.state} />
                  <span>
                    {c.product} <span className="mono">{c.claimed_version}</span> reported {abs(c.created_at)}
                  </span>
                </div>
                {c.outcome_detail ? <span>{alertCopy(c.outcome_detail)}</span> : null}
                {c.state === "check_failed" ? (
                  <form method="post" action={`/api/host/${token}/retry`}>
                    <input type="hidden" name="claim" value={c.id} />
                    <Submit className="btn btn-secondary" busy="Checking…">Retry check</Submit>
                  </form>
                ) : null}
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}
