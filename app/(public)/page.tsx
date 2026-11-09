import Link from "next/link";
import { allAdvisories, catalogMeta } from "@/lib/catalog";
import { catalogCoverage } from "@/intel/match";
import { techName } from "@/lib/scan/detect";
import { disclosureDate, recentAdvisories } from "@/lib/recent-advisories";
import { AdvisoryTicker } from "@/components/advisory-ticker";
import { ExploitBadge } from "@/components/badges";
import { jsonLd, PRODUCT_DESCRIPTION, PUBLIC_ORIGIN, publicMetadata } from '@/lib/discovery';

export const revalidate = 300;
export const metadata = publicMetadata('/', 'Vulnerability alerts for local businesses and nonprofits | Zero Day Canary', PRODUCT_DESCRIPTION);

export default async function Landing() {
  const [records, featured, meta] = await Promise.all([allAdvisories(), allAdvisories({featuredOnly:true}), catalogMeta()]);
  const recent = recentAdvisories(featured);
  const preview = recent[0];
  const coverage = catalogCoverage(records).map(techName);
  return (
    <div className="landing landing-doors">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLd({ '@context': 'https://schema.org', '@type': 'SoftwareApplication', name: 'Zero Day Canary', url: PUBLIC_ORIGIN, description: PRODUCT_DESCRIPTION, applicationCategory: 'SecurityApplication', operatingSystem: 'Web', image: `${PUBLIC_ORIGIN}/brand/canary-logo.png` }) }} />
      <AdvisoryTicker records={recent.map(({ id, product, title, severity, published_at, exploitation }) => ({ id, product, title, severity, published_at, exploitation }))} reviewedAt={meta.last_successful_review_at} revision={meta.catalog_revision} />
      {meta.last_failure_at ? <p className="notice n-warning small" role="status">The last catalog review did not complete. Showing the last published records; review time is shown above.</p> : null}
      <section className="hero">
        <p className="landing-eyebrow"><span aria-hidden="true" />Security clarity for small teams.</p>
        <h1 className="h-public">Know when a security alert needs your attention.</h1>
        <p className="hero-lede">Zero Day Canary helps local businesses and nonprofits understand which software vulnerabilities could affect their websites and apps—and get the right person to check and fix them.</p>
        <p className="small muted">We check open-source packages for known vulnerabilities. Start with a public check, then ask the developer for a deeper package report.</p>
      </section>
      <div className="doors" aria-label="Choose how you use Canary">
        <section className="door" aria-labelledby="builder-door">
          <span className="door-icon" aria-hidden="true">&lt;/&gt;</span>
          <h2 id="builder-door" className="h-section">I build software</h2>
          <p>Check your app. See what needs fixing. Keep an eye on new vulnerabilities for free.</p>
          <div className="door-action"><Link prefetch={false} href="/developer" data-site-action="builder_start" className="btn btn-brand">Check my app <span aria-hidden="true">→</span></Link></div>
          <p className="small muted">Free for builders. Your reports stay private.</p>
          <p className="small"><Link href="/for-builders">How builder checks work</Link></p>
        </section>
        <section className="door" aria-labelledby="buyer-door">
          <span className="door-icon" aria-hidden="true">▤</span>
          <h2 id="buyer-door" className="h-section">I buy or manage software</h2>
          <p>See which systems might be affected. Get the right person to check and confirm the answer.</p>
          <div className="door-action"><Link prefetch={false} href="/systems" data-site-action="buyer_start" className="btn btn-secondary">Check my systems <span aria-hidden="true">→</span></Link></div>
          <p className="small muted">Start with a URL. <Link prefetch={false} href="/pricing">Monitor your first system free.</Link></p>
          <p className="small"><Link href="/for-buyers">How buyer monitoring works</Link></p>
        </section>
      </div>
      <section className="open-intelligence" aria-labelledby="public-h">
        <div className="stack" style={{ ["--gap" as string]: "16px" }}>
          <p className="landing-eyebrow">Free for everyone</p>
          <h2 id="public-h" className="h-section">Read the alerts.<br />Build with the API.</h2>
          <p>Read focused, reviewed alerts. Developers can also pull the full source feed through the free API, with review status and coverage gaps clearly marked.</p>
          <div className="row"><Link prefetch={false} href="/advisories" data-site-action="browse_alerts" className="btn btn-secondary">Browse alerts <span aria-hidden="true">→</span></Link><Link prefetch={false} href="/docs/api" data-site-action="view_api" className="btn btn-secondary">Explore the API <span aria-hidden="true">→</span></Link></div>
          <p className="small muted">No account. No API key. Public access is free.</p>
        </div>
        <div className="panel intelligence-preview">
          <div className="stack" style={{ ["--gap" as string]: "8px" }}>
            <p className="small muted">For people</p>
            {preview ? <><Link prefetch={false} href={`/advisory/${preview.id}`} className="preview-advisory">{preview.product}: {preview.title}</Link><p className="small muted">{disclosureDate(preview.published_at) ? `Disclosed ${disclosureDate(preview.published_at)}` : "Disclosure date not provided"}</p><ExploitBadge category={preview.exploitation.category} /></> : <p>No reviewed alerts yet.</p>}
          </div>
          <hr />
          <div className="stack" style={{ ["--gap" as string]: "8px" }}><p className="small muted">For agents and developers</p><Link prefetch={false} href="/api/v1/vulnerabilities" className="mono">GET /api/v1/vulnerabilities</Link><p className="small muted">The full source feed. Reviewed alerts remain available separately.</p></div>
        </div>
      </section>
      <div className="landing-bottom"><p className="small">Specific concerns. Clear next steps. Evidence-backed answers.</p><Link prefetch={false} href="/about" className="small">How it works and what we can check</Link></div>
      <details className="landing-coverage">
        <summary>What can Canary check today?</summary>
        <div className="stack small" style={{ marginTop: 12 }}>
          <p>Public checks cover reviewed alerts for {coverage.length ? coverage.join(", ") : "a small set of products"}. They cannot see internal packages, authenticated areas or hidden versions.</p>
          <p>Developer reports check confirmed public package names and exact versions across supported OSV ecosystems. Any CVE can receive a targeted source check, including runtime and vendor issues. Missing inventory, unsupported matches and deployment facts stay unknown. Source dependencies do not prove what production runs.</p>
          <p>A matching alert is a reason to check. It does not establish that a vulnerability applies, or that a system was compromised. <Link prefetch={false} href="/about">See coverage and limits</Link>.</p>
        </div>
      </details>
    </div>
  );
}
