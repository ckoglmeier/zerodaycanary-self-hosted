import Link from "next/link";
import type { AdvisoryRecord } from "@/intel/schema";
import type { CatalogMeta } from "@/lib/catalog";
import { ExploitBadge, SeverityText } from "./badges";
import { abs } from "./time";
import { FeedFilter } from "./feed-filter";

export type FeedView = "priority" | "known_exploited" | "public_poc" | "all";

const VIEWS: { key: FeedView; href: string; label: string }[] = [
  { key: "priority", href: "/advisories", label: "Priority alerts" },
  { key: "known_exploited", href: "/advisories/exploited", label: "Known exploited" },
  { key: "public_poc", href: "/advisories/poc", label: "Public exploit / PoC" },
  { key: "all", href: "/advisories/all", label: "All reviewed alerts" },
];

export function Feed({ view, records, meta, counts,sourceTotal }: { view: FeedView; records: AdvisoryRecord[]; meta: CatalogMeta; counts: Record<FeedView, number>;sourceTotal:number }) {
  return (
    <div className="stack" style={{ ["--gap" as string]: "24px" }}>
      <section className="stack prose" style={{ ["--gap" as string]: "8px" }}>
        <h1 className="h-page">Vulnerability alerts</h1>
        <p className="small"><Link href="/advisories/feed">{sourceTotal.toLocaleString()} in the full feed</Link> · {counts.all} reviewed alerts</p>
        <p>
          A focused selection of significant vulnerabilities, reviewed against primary sources. Priority is an editorial selection; your app checks still use every supported reviewed alert.
        </p>
        <p className="small muted">
          Feed reviewed {meta.last_successful_review_at ? abs(meta.last_successful_review_at) : "— no review yet"} · Catalog revision {meta.catalog_revision} ·{" "}
          <Link prefetch={false} href="/about">How checks work and what is covered</Link> · <Link prefetch={false} href="/docs/api">Reviewed alerts and the full source-feed API</Link>
        </p>
        {meta.last_failure_at ? (
          <p className="notice n-warning small">The most recent feed update ({abs(meta.last_failure_at)}) did not complete. The records below are from the last successful review.</p>
        ) : null}
      </section>

      <nav className="filters" aria-label="Alert views">
        {VIEWS.map((v) => (
          <Link prefetch={false} key={v.key} href={v.href} className="filter" aria-current={v.key === view ? "page" : undefined}>
            {v.label} <span className="muted">({counts[v.key]})</span>
          </Link>
        ))}
        <Link prefetch={false} href="/advisories/feed" className="filter">Full feed <span className="muted">({sourceTotal.toLocaleString()})</span></Link>
      </nav>

      <FeedFilter>
        {records.length === 0 ? (
          <div className="panel empty stack" style={{ ["--gap" as string]: "8px" }}>
            <p>No reviewed records match this view.</p>
            <p className="small muted">This means none are in this catalog, not that none exist.</p>
          </div>
        ) : (
          <div>
            <div className="list-head grid-feed" aria-hidden="true">
              <span>Product / alert</span>
              <span>Severity · Exploit evidence · Reviewed</span>
              <span />
            </div>
            <ul className="list" data-feed>
              {records.map((r) => (
                <li key={r.id} className="grid-feed" data-search={[r.product, r.title, ...r.identifiers, ...r.affected.map((a) => a.product)].join(" ").toLowerCase()} data-severity={r.severity}>
                  <div className="stack" style={{ ["--gap" as string]: "4px" }}>
                    <p style={{ fontWeight: 600 }}>
                      {r.product}: {r.title}
                    </p>
                    <p className="mono muted">{r.identifiers.join(" · ")}</p>
                    <p className="small">{r.summary}</p>
                  </div>
                  <div className="stack small" style={{ ["--gap" as string]: "6px" }}>
                    <div className="row">
                      <ExploitBadge category={r.exploitation.category} withdrawn={r.status !== "published" ? r.status : undefined} />
                    </div>
                    <p>
                      <SeverityText severity={r.severity} score={r.cvss_score} source={r.severity_source} />
                    </p>
                    <p className="muted">
                      {r.exploitation.category !== "none_confirmed" && r.exploitation.as_of ? <>Evidence dated {r.exploitation.as_of} · </> : null}
                      Reviewed {abs(r.reviewed_at).slice(0, 10)}
                    </p>
                  </div>
                  <div>
                    <Link prefetch={false} href={`/advisory/${r.id}`} className="btn btn-secondary">
                      View alert<span className="sr-only">: {r.identifiers[0]}</span>
                    </Link>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </FeedFilter>
    </div>
  );
}
