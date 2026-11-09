import { publicMetadata } from '@/lib/discovery';
import { catalogMeta, allAdvisories } from "@/lib/catalog";
import { catalogCoverage } from "@/intel/match";
import { abs } from "@/components/time";

export const metadata = publicMetadata('/about', 'How it works', 'How Zero Day Canary helps local businesses and nonprofits check possible vulnerability exposure and get evidence-backed answers from developers.');
export const revalidate = 300;

export default async function About() {
  const [meta, records] = await Promise.all([catalogMeta(), allAdvisories()]);
  const coverage = catalogCoverage(records);
  return (
    <div className="stack prose" style={{ ["--gap" as string]: "24px" }}>
      <h1 className="h-page">How it works</h1>

      <section className="stack">
        <p>
          Zero Day Canary helps local businesses, nonprofits, and other small teams find out whether a newly published vulnerability might affect the systems they look after, and get a clear answer
          from the person who runs each one.
        </p>
        <ol>
          <li>We compare reviewed alerts with what a system shows publicly, or with the npm packages its developer uploads. Related alerts for the same software are grouped into one concern; a new CVE on its own does not create a concern for your systems.</li>
          <li>Each concern comes with one specific question, such as which version is running or whether a feature is in use. You provide the owner's email and create a tracked request. Canary shows whether an invitation was emailed or a link needs to be shared. Replies stay inside the app.</li>
          <li>The owner or developer can give a quick answer or use the free Canary skill to build a deeper report. Uploads stay private until the developer reviews and explicitly shares the report. A reported upgrade still needs fresh evidence.</li>
          <li>The outcome is specific: unaffected by this vulnerability, still affected, or fixed with evidence. An owner&rsquo;s report alone is recorded as a claim, not a fix.</li>
          <li>Each system keeps its dated evidence and outcomes, with a printable report.</li>
        </ol>
        <p className="small muted">
          Privacy: anything a developer uploads stays private to their own account. What an owner submits on the link you send them, and the result of the fresh
          check, is shown to you.
        </p>
      </section>

      <section className="stack">
        <h2 className="h-section">What the catalog contains</h2>
        <p>
          Each record is drafted from a nightly analyst brief, checked against primary sources (vendor and GitHub advisories, CVE records, the CISA Known
          Exploited Vulnerabilities catalog) and published by an operator. Unsupported claims stay unpublished. Records are corrected or withdrawn in place
          with their history kept.
        </p>
        <dl className="facts">
          <dt>Catalog revision</dt>
          <dd>{meta.catalog_revision}</dd>
          <dt>Last successful review</dt>
          <dd>{meta.last_successful_review_at ? abs(meta.last_successful_review_at) : "none yet"}</dd>
          <dt>Software covered by public checks</dt>
          <dd>{coverage.length ? coverage.join(", ") : "none yet"}</dd>
        </dl>
        <p className="muted">
          The catalog is a selective, reviewed set, not a complete vulnerability database. Developer reports check confirmed public package names and exact versions across supported OSV ecosystems, alongside Canary-reviewed alerts. Any CVE can receive a targeted source check; missing package/runtime/vendor evidence remains unknown. &ldquo;No matching alert&rdquo; never means &ldquo;no vulnerabilities&rdquo;, and lockfile uploads describe source
          dependencies, not what production runs.
        </p>
      </section>

      <section className="stack">
        <h2 className="h-section">What a public check looks at</h2>
        <p>
          We fetch the address you give us and a small number of same-origin resources (selected scripts and, for some products, a public version endpoint).
          We read ordinary response headers, page metadata, asset paths and cookie names. We never send exploit requests, log in, run downloaded code, or store
          cookie values.
        </p>
        <ul>
          <li>Only public addresses on standard ports are fetched. Private, loopback, link-local and cloud metadata addresses are refused, including after redirects.</li>
          <li>Each fetch is limited in time and size. Failures, denials, redirects to other hosts and hidden versions are shown as gaps, never as a sign that the system is unaffected.</li>
          <li>A version is shown as seen only when it appears in the evidence. Detecting a CMS or framework never implies a server runtime version, and a matching version is a reason to check, not proof that the vulnerability applies.</li>
          <li>A result is cached and reused; it always shows when it was observed. Re-analysis fetches again and keeps the earlier result.</li>
          <li>Monitored systems are re-checked whenever a reviewed alert is published and daily. Public evidence is refreshed when you ask, when an owner reports an upgrade, and weekly for monitored systems (a few per day).</li>
        </ul>
      </section>

      <section className="stack">
        <h2 className="h-section">Free use limits</h2>
        <p>Checking is free. Signed-in administrators can check up to 30 addresses per hour, with up to 10 new scans per hour; earlier results do not count as new scans. Developer projects are free.</p>
      </section>
    </div>
  );
}
