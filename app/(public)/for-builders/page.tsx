import Link from 'next/link';
import { publicMetadata } from '@/lib/discovery';
export const metadata = publicMetadata('/for-builders', 'Check your app. Share the evidence.', 'Use the free Canary skill with your coding agent to check known vulnerability targets and share a private report with clients.');
export default function Builders() {
  return <article className="stack prose" style={{ maxWidth: 800 }}>
    <p className="landing-eyebrow">For builders</p><h1 className="h-page">Your client has a vulnerability question. Give them a specific answer.</h1>
    <p>The free Zero Day Canary skill checks your app against known reviewed CVE and GHSA targets. Your coding agent inspects the relevant source and configuration, records the evidence and leaves unresolved facts unknown.</p>
    <ol className="stack"><li><strong>Download one skill.</strong> Extract it and open your source project in Claude Code or Codex. The public guide includes a prompt and the steps to create the report.</li><li><strong>Build and review your report locally.</strong> The helper matches supported dependency versions; your agent then checks the advisory’s prerequisites and mitigations. It does not run exploits, patch production or upload automatically.</li><li><strong>Share only when you choose.</strong> Create a free private project, upload <code>canary-report.json</code>, review it, then share with your client. Free monitoring checks supported uploaded dependencies against future reviewed alerts. Your client can read a directly shared report for free.</li></ol>
    <div className="row"><Link href="/docs/skill" className="btn btn-brand">Get the skill and build a report</Link><Link href="/developer">Open my projects</Link></div>
    <h2 className="h-section">Specific evidence, with clear limits</h2><p>Public package versions are matched across supported OSV ecosystems. Any CVE can receive a targeted source check, including runtime, OS and vendor issues. Private or unsupported inventory and unobserved deployments remain explicit unknowns. A source report is a dated developer-supplied assessment of the reviewed revision; it does not certify production safety.</p>
    <p>Building your own tooling? The <Link href="/docs/api">free API and MCP connector</Link> expose reviewed alerts and the full source feed separately. No account or API key.</p>
  </article>;
}
