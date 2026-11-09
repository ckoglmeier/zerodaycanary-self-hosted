import Link from "next/link";
import { requireOperator } from "@/lib/auth";
import { q } from "@/lib/db";
import { catalogMeta } from "@/lib/catalog";
import { abs } from "@/components/time";
import { Submit } from "@/components/submit";
import { Badge, ExploitBadge } from "@/components/badges";
import type { AdvisoryRecord } from "@/intel/schema";

export const metadata = { title: "Intake" };

export default async function Operator({ searchParams }: { searchParams: Promise<{ error?: string; msg?: string }> }) {
  await requireOperator();
  const sp = await searchParams;
  const [intakes, meta, records] = await Promise.all([
    q<{ id: string; created_at: Date; status: string; attribution: string | null; error: string | null; drafts: string; published: string }>(
      `select i.id, i.created_at, i.status, i.attribution, i.error,
        (select count(*) from advisory_drafts d where d.intake_id = i.id and d.status = 'draft') drafts,
        (select count(*) from advisory_drafts d where d.intake_id = i.id and d.status = 'published') published
       from feed_intakes i order by created_at desc limit 20`,
    ),
    catalogMeta(),
    q<{ record: AdvisoryRecord;featured:boolean }>("select record,featured from advisories order by updated_at desc limit 100"),
  ]);
  return (
    <div className="stack" style={{ ["--gap" as string]: "24px" }}>
      <div className="stack" style={{ ["--gap" as string]: "6px" }}>
        <h1 className="h-page">Feed intake</h1>
        <p className="small muted">
          Paste brief → Review drafts → Publish. Catalog revision {meta.catalog_revision} · last successful review {abs(meta.last_successful_review_at)}
          {meta.last_failure_at ? ` · last failure ${abs(meta.last_failure_at)}` : ""}
        </p>
      </div>
      {sp.error ? <p className="notice n-danger" role="alert">{sp.error}</p> : null}
      {sp.msg ? <p className="notice n-success">{sp.msg}</p> : null}
      <p><Link className="btn btn-secondary" href="/operator/feed">Import the full CSV feed and review priority candidates</Link></p>

      <form method="post" action="/api/operator/intake" className="panel stack">
        <h2 className="h-section">1. Paste tonight&rsquo;s brief</h2>
        <div>
          <label htmlFor="brief">Brief text and links</label>
          <textarea id="brief" name="brief" required rows={14} className="mono" placeholder="Paste the full brief, including source links." />
          <p className="hint">The brief is treated as untrusted input. Extraction proposes drafts only; nothing is published until you review it.</p>
        </div>
        <div>
          <label htmlFor="attribution">Attribution (optional)</label>
          <input id="attribution" name="attribution" type="text" placeholder="e.g. CK nightly brief, Oct 22" />
        </div>
        <Submit busy="Extracting drafts… (this can take a minute)">Extract drafts</Submit>
      </form>

      <section className="stack">
        <h2 className="h-section">Recent intakes</h2>
        <ul className="list">
          {intakes.map((i) => (
            <li key={i.id} className="spread">
              <div className="stack" style={{ ["--gap" as string]: "4px" }}>
                <Link href={`/operator/intake/${i.id}`}>
                  {abs(i.created_at)} {i.attribution ? `· ${i.attribution}` : ""}
                </Link>
                {i.error ? <span className="small field-error">{i.error}</span> : null}
              </div>
              <div className="row small">
                <Badge tone={i.status === "failed" ? "danger" : i.status === "reviewed" ? "success" : "neutral"}>{i.status}</Badge>
                <span>
                  {i.drafts} to review · {i.published} published
                </span>
              </div>
            </li>
          ))}
          {intakes.length === 0 ? <li className="muted">No intakes yet.</li> : null}
        </ul>
      </section>

      <section className="stack">
        <h2 className="h-section">Catalog</h2>
        <ul className="list">
          {records.map(({ record: r,featured }) => (
            <li key={r.id} className="spread">
              <div className="stack" style={{ ["--gap" as string]: "4px" }}>
                <Link href={`/advisory/${r.id}`}>
                  {r.product}: {r.title}
                </Link>
                <span className="mono muted">
                  {r.identifiers.join(" · ")} · rev {r.revision}
                </span>
              </div>
              <div className="row">
                <form method="post" action={`/api/operator/advisories/${r.id}/feature`} className="row">
                  <input type="hidden" name="featured" value={featured?'false':'true'}/>
                  <label className="sr-only" htmlFor={`feature-${r.id}`}>Priority selection reason for {r.id}</label>
                  <input id={`feature-${r.id}`} name="reason" required maxLength={500} placeholder="Priority selection reason" style={{width:180}}/>
                  <Submit className="btn btn-secondary" busy="Saving…">{featured?'Remove from priority':'Feature alert'}</Submit>
                </form>
                <ExploitBadge category={r.exploitation.category} withdrawn={r.status !== "published" ? r.status : undefined} />
                <form method="post" action={`/api/operator/advisories/${r.id}/status`} className="row">
                  <label htmlFor={`st-${r.id}`} className="sr-only">
                    Status change for {r.id}
                  </label>
                  <select id={`st-${r.id}`} name="status" defaultValue="" style={{ width: 150 }}>
                    <option value="" disabled>
                      Change status…
                    </option>
                    {r.status !== "withdrawn" ? <option value="withdrawn">Withdraw</option> : null}
                    {r.status !== "superseded" ? <option value="superseded">Superseded</option> : null}
                    {r.status !== "published" ? <option value="published">Restore</option> : null}
                  </select>
                  <label htmlFor={`note-${r.id}`} className="sr-only">
                    Reason
                  </label>
                  <input id={`note-${r.id}`} name="note" type="text" placeholder="Reason" required style={{ width: 180 }} />
                  <Submit className="btn btn-secondary" busy="Saving…">Apply</Submit>
                </form>
              </div>
            </li>
          ))}
          {records.length === 0 ? <li className="muted">No published records yet.</li> : null}
        </ul>
      </section>
    </div>
  );
}
