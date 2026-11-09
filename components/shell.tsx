import Link from "next/link";
import { Navigation } from "./navigation";
import type { NavigationViewer } from "@/lib/navigation";

export function Lockup({ href = "/" }: { href?: string }) {
  return (
    <Link href={href} prefetch={false} className="lockup">
      {/* Decorative beside the live wordmark (design.md §2). */}
      <img src="/brand/canary-160.png" alt="" width={40} height={40} />
      <span>Zero Day Canary</span>
    </Link>
  );
}

export function Header({ viewer }: { viewer?: NavigationViewer }) {
  return (
    <header className="site-header">
      <a href="#main-content" className="skip-link">Skip to content</a>
      <div className="container">
        <Lockup />
        <Navigation initialViewer={viewer} />
      </div>
    </header>
  );
}

export function Footer() {
  return (
    <footer className="footer">
      <div className="container stack" style={{ ["--gap" as string]: "6px" }}>
        <p>
          Zero Day Canary flags possible concerns from reviewed alerts and records dated, sourced evidence. It does not discover unknown
          vulnerabilities, show that a system has no vulnerabilities, or exploit, patch or change anyone&rsquo;s systems.
        </p>
        <p>
          <Link href="/about" prefetch={false}>How it works, coverage and sources</Link> · <Link href="/advisories" prefetch={false}>Alerts</Link> · <Link href="/docs/api">API</Link> · <Link href="/docs/skill">Canary skill</Link> · <Link href="/for-education">For education</Link> · <Link href="/contact">Support</Link>
        </p>
      </div>
    </footer>
  );
}
