import { publicMetadata } from '@/lib/discovery';
import Link from "next/link";
import { getPrice, money } from "@/lib/billing";
import { VOLUME_THRESHOLD } from "@/lib/contact";

export const revalidate = 300;
export const metadata = { ...publicMetadata('/pricing', "Zero Day Canary", "Vulnerability alerts and evidence-backed answers for your apps and vendors."),
  title: "Pricing",
  description: "Free checks and monitoring for builders. Free alerts and API for everyone. Your first system free. Team covers up to 25 systems.",
};

export default async function Pricing() {
  const [price,nonprofit] = await Promise.all([getPrice().catch(() => null),getPrice(true).catch(() => null)]);
  return (
    <div className="stack pricing-page" style={{ ["--gap" as string]: "32px" }}>
      <header className="stack prose"><h1 className="h-page">Your first system is free.</h1><p>Start with one system. Monitor up to 25 across your organization with Team.</p></header>
      {price&&!price.livemode?<p className="notice n-warning" role="status">Payment test mode. No real charges. Launch pricing is not yet active.</p>:null}
      <div className="pricing-plans">
        <section className="panel pricing-plan"><h2 className="h-section">Free</h2><p className="price">$0</p><p>One monitored system. No card required.</p><ul><li>Ongoing checks against reviewed alerts</li><li>Questions and follow-up with the system owner</li><li>Dated evidence and reports</li></ul><Link href="/systems" className="btn btn-brand">Start free monitoring</Link></section>
        <section className="panel pricing-plan"><h2 className="h-section">Team</h2><p className="price">{price?money(price.unit_amount,price.currency):'$49'}<span className="muted"> per workspace per month</span></p>{!price?<p className="small muted">Proposed price. Paid checkout is not configured yet.</p>:null}<p>Up to 25 monitored systems in total.</p><p><strong>Nonprofits: {nonprofit?money(nonprofit.unit_amount,nonprofit.currency):"$29"}/month.</strong> Check “We’re a nonprofit” at checkout. Same allowance; self-reported.</p><ul><li>The same monitoring and owner follow-up across your portfolio</li><li>One monthly workspace price</li><li>Add or pause systems within your allowance without changing your bill</li></ul><Link href="/billing/checkout" className="btn btn-primary">Choose systems</Link></section>
      </div>
      <section className="panel"><h2 className="h-section">Free for builders</h2><p>Private dependency checks, developer projects, reports and builder monitoring stay free.</p><Link href="/developer">Check what you build</Link></section>
      <section className="pricing-public" aria-labelledby="free-public">
        <div className="stack" style={{ ["--gap" as string]: "8px" }}><p className="landing-eyebrow">Free for everyone</p><h2 id="free-public" className="h-section">The alerts and API stay public.</h2><p>Read the reviewed records or use the same data in your own tools. No account or API key needed.</p></div>
        <div className="row"><Link href="/advisories" className="btn btn-secondary">Browse alerts</Link><Link href="/docs/api" className="btn btn-secondary">Explore the API</Link></div>
      </section>
      <aside className="volume" aria-labelledby="volume-h">
        <div className="stack" style={{ ["--gap" as string]: "4px" }}><h2 id="volume-h" className="h-section">Buying for a lot of systems?</h2><p className="small">For more than 25 systems, contact us for portfolio pricing and invoicing.</p></div>
        <Link href="/contact?topic=volume" className="btn btn-secondary">Get in touch</Link>
      </aside>
      <section className="split-2">
        <div className="stack" style={{ ["--gap" as string]: "8px" }}><h2 className="h-section">What counts as a system?</h2><p className="small">One exact web address and path you choose to monitor, such as <span className="mono">portal.example.edu/research</span>. Other subdomains or paths are separate systems. Checking an address is free; it counts toward your plan only when you choose monitoring.</p></div>
        <div className="stack" style={{ ["--gap" as string]: "8px" }}><h2 className="h-section">Manage what you monitor</h2><p className="small">Add, pause or remove systems within your allowance. Team stays the same price. To return to Free, cancel in Billing; Team continues until the paid period ends. Your oldest requested system stays monitored and all evidence history is kept.</p><p className="small"><Link href="/billing">Manage billing and invoices</Link></p></div>
      </section>
    </div>
  );
}
