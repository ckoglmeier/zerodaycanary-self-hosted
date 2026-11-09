import { jsonLd, publicMetadata, publicUrl } from '@/lib/discovery';
import Link from "next/link";
import { notFound } from "next/navigation";
import { getAdvisory } from "@/lib/catalog";
import { ExploitBadge, EXPLOIT_LABEL, SeverityText } from "@/components/badges";
import { abs } from "@/components/time";

export const revalidate = 300;
// Rendered on first request, then cached and revalidated on publication.
export async function generateStaticParams() {
  return [];
}

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  const a = await getAdvisory((await params).id);
  return a ? publicMetadata(`/advisory/${a.record.id}`, `${a.record.identifiers[0] ?? a.record.id}: ${a.record.product}`, a.record.summary) : { title: "Alert", robots: { index: false, follow: false } };
}

export default async function AdvisoryPage({ params }: { params: Promise<{ id: string }> }) {
  const a = await getAdvisory((await params).id);
  if (!a) notFound();
  const r = a.record;
  return (
    <article className="stack" style={{ ["--gap" as string]: "24px" }}>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLd({ "@context": "https://schema.org", "@type": "Article", headline: `${r.product}: ${r.title}`, description: r.summary, url: publicUrl(`/advisory/${r.id}`), datePublished: r.published_at ?? undefined, dateModified: r.updated_at, author: { "@type": "Organization", name: "Zero Day Canary", url: publicUrl("/") }, citation: r.sources.map(s => s.url) }) }} />
      <p className="small">
        <Link href="/advisories">← Alerts</Link>
      </p>
      <header className="stack prose" style={{ ["--gap" as string]: "8px" }}>
        <p className="mono muted">{r.identifiers.join(" · ")}</p>
        <h1 className="h-page">
          {r.product}: {r.title}
        </h1>
        <div className="row">
          <ExploitBadge category={r.exploitation.category} withdrawn={r.status !== "published" ? r.status : undefined} />
          <span className="small">
            <SeverityText severity={r.severity} score={r.cvss_score} source={r.severity_source} />
          </span>
        </div>
        {r.status !== "published" ? (
          <p className="notice n-neutral">
            This record is {r.status}. It is kept for history and is not an active finding.{r.status_note ? ` Note: ${r.status_note}` : ""}
          </p>
        ) : null}
        <p>{r.summary}</p>
      </header>

      <div className="split">
        <div className="stack" style={{ ["--gap" as string]: "24px" }}>
          <section className="panel stack">
            <h2 className="h-section">Affected and fixed versions</h2>
            {r.affected.length === 0 ? (
              <p className="muted">No structured version ranges were reviewed for this record.</p>
            ) : (
              r.affected.map((p) => (
                <div key={p.product} className="table-wrap" role="region" aria-label={`Version ranges for ${p.product}`} tabIndex={0}>
                  <table className="t">
                    <caption className="sr-only">Version ranges for {p.product}</caption>
                    <thead>
                      <tr>
                        <th scope="col">Product</th>
                        <th scope="col">Affected from</th>
                        <th scope="col">Fixed in</th>
                        <th scope="col">Notes</th>
                      </tr>
                    </thead>
                    <tbody>
                      {p.ranges.map((x, i) => (
                        <tr key={i}>
                          <td className="mono">{p.product}</td>
                          <td className="mono">{x.introduced ?? (x.ambiguous ? "Not established" : "earliest")}</td>
                          <td className="mono">{x.fixed ?? (x.last_affected ? `after ${x.last_affected}` : "not established")}</td>
                          <td className="small">
                            {x.ambiguous ? <strong>Boundary needs verification. </strong> : null}
                            {x.note}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <p className="small muted">Versions on branches not listed here: {p.other_branches === "not_affected" ? "not affected per the source" : "unknown; treat as needing verification"}.</p>
                </div>
              ))
            )}
          </section>
          <section className="panel stack">
            <h2 className="h-section">Conditions</h2>
            {r.conditions.length === 0 ? <p className="muted">No additional prerequisites were recorded.</p> : (
              <ul>
                {r.conditions.map((c, i) => (
                  <li key={i}>{c.description}</li>
                ))}
              </ul>
            )}
          </section>
          {r.uncertainty.length ? (
            <section className="panel stack">
              <h2 className="h-section">Open questions</h2>
              <ul>
                {r.uncertainty.map((u, i) => (
                  <li key={i}>{u}</li>
                ))}
              </ul>
            </section>
          ) : null}
        </div>
        <aside className="stack">
          <section className="panel stack" style={{ ["--gap" as string]: "8px" }}>
            <h2 className="h-section">Exploitation evidence</h2>
            <p>{EXPLOIT_LABEL[r.exploitation.category]}</p>
            {r.exploitation.source_url ? (
              <p className="small wrap">
                Source: <a href={r.exploitation.source_url}>{r.exploitation.source_url}</a>
                {r.exploitation.as_of ? ` (as of ${r.exploitation.as_of})` : ""}
              </p>
            ) : null}
            {r.exploitation.category === "none_confirmed" ? <p className="small muted">This describes evidence in this catalog, not proof that attacks are absent.</p> : null}
            {r.exploitation.category === "public_poc" ? <p className="small muted">A public proof of concept does not by itself show attacks in the wild.</p> : null}
          </section>
          <section className="panel stack" style={{ ["--gap" as string]: "8px" }}>
            <h2 className="h-section">Sources</h2>
            <ul className="small wrap">
              {r.sources.map((s) => (
                <li key={s.url}>
                  <a href={s.url}>{s.title ?? s.url}</a> <span className="muted">({s.kind})</span>
                </li>
              ))}
            </ul>
          </section>
          <section className="panel">
            <dl className="facts">
              <dt>Published</dt>
              <dd>{r.published_at ?? "unknown"}</dd>
              <dt>Reviewed</dt>
              <dd>{abs(r.reviewed_at)}</dd>
              <dt>Revision</dt>
              <dd>
                {r.revision} (catalog {r.catalog_revision})
              </dd>
              <dt>ID</dt>
              <dd className="mono">{r.id}</dd>
              <dt>JSON</dt>
              <dd>
                <a href={`/api/v1/advisories/${r.id}`}>/api/v1/advisories/{r.id}</a>
              </dd>
            </dl>
          </section>
          <section className="panel stack" style={{ ["--gap" as string]: "8px" }}>
            <h2 className="h-section">History</h2>
            <ol className="small">
              {a.history.map((h) => (
                <li key={h.revision}>
                  Revision {h.revision}, {abs(h.created_at)}: {h.change_note}
                </li>
              ))}
            </ol>
          </section>
        </aside>
      </div>
    </article>
  );
}
