// SYNTHETIC TEST FIXTURES. Shaped after the reference set in REQUIREMENTS.md §10 so
// matching rules can be regression-tested. Not a source of published data: the live
// catalog only contains records an operator reviewed and published.
import { SCHEMA_VERSION, type AdvisoryRecord } from "../schema";

const base = {
  schema_version: SCHEMA_VERSION,
  revision: 1,
  catalog_revision: 1,
  status: "published" as const,
  reviewed_at: "2026-10-22T06:00:00Z",
  updated_at: "2026-10-22T06:00:00Z",
  status_note: null,
  uncertainty: [],
  published_at: "2026-10-21",
};

export const PHP_OOM: AdvisoryRecord = {
  ...base,
  id: "fx-php-oom",
  title: "PHP out-of-memory issue (fixture)",
  product: "PHP",
  summary: "Fixture.",
  identifiers: ["CVE-2026-109618", "GHSA-w8hw-w9fx-j79w"],
  severity: "critical",
  cvss_score: 9.2,
  severity_source: "vendor",
  exploitation: { category: "none_confirmed", source_url: null, as_of: null },
  affected: [
    {
      product: "php",
      other_branches: "unknown",
      ranges: [
        { introduced: "8.2.0", fixed: "8.2.35", ambiguous: false },
        { introduced: "8.3.0", fixed: "8.3.36", ambiguous: false },
        { introduced: "8.4.0", fixed: "8.4.27", ambiguous: false },
        { introduced: "8.5.0", fixed: "8.5.12", ambiguous: false },
      ],
    },
  ],
  conditions: [],
  sources: [{ url: "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w", kind: "ghsa" }],
};

export const NEXT_CACHE: AdvisoryRecord = {
  ...base,
  id: "fx-next-cache",
  title: "Next.js cache issue (fixture)",
  product: "Next.js",
  summary: "Fixture.",
  identifiers: ["GHSA-673q-mjm6-r5xr"],
  severity: "critical",
  cvss_score: 9.5,
  severity_source: "GitHub",
  exploitation: { category: "none_confirmed", source_url: null, as_of: null },
  affected: [{ product: "nextjs", other_branches: "not_affected", ranges: [{ introduced: "16.0.0", fixed: "16.4.1", ambiguous: false }] }],
  conditions: [{ description: "Uses the App Router", fact: "nextjs.app_router" }],
  sources: [{ url: "https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr", kind: "ghsa" }],
};

export const NEXT_SVG: AdvisoryRecord = {
  ...base,
  id: "fx-next-svg",
  title: "Next.js SVG image processing (fixture)",
  product: "Next.js",
  summary: "Fixture.",
  identifiers: ["CVE-2026-96889", "GHSA-2464-fhr4-w9xw"],
  severity: "critical",
  cvss_score: 9.5,
  severity_source: "GitHub",
  exploitation: { category: "none_confirmed", source_url: null, as_of: null },
  affected: [
    {
      product: "nextjs",
      other_branches: "unknown",
      ranges: [
        { introduced: "16.0.0", last_affected: "16.0.0", fixed: null, ambiguous: true, note: "Official page says >16.0.0; summaries say 16.x" },
        { introduced: "16.0.1", fixed: "16.4.1", ambiguous: false },
        { introduced: null, fixed: "15.5.28", ambiguous: false },
      ],
    },
  ],
  conditions: [{ description: "Runs on Linux with glibc and processes images", fact: null }],
  sources: [{ url: "https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw", kind: "ghsa" }],
};

export const PLEX_KEV: AdvisoryRecord = {
  ...base,
  id: "fx-plex",
  title: "Plex Media Server issues (fixture)",
  product: "Plex Media Server",
  summary: "Fixture.",
  identifiers: ["CVE-2026-96652"],
  severity: "high",
  cvss_score: null,
  severity_source: null,
  exploitation: {
    category: "known_exploited",
    source_url: "https://www.cisa.gov/news-events/alerts/2026/10/20/cisa-adds-six-known-exploited-vulnerabilities-catalog",
    as_of: "2026-10-20",
  },
  affected: [{ product: "plex", other_branches: "unknown", ranges: [{ introduced: null, fixed: null, last_affected: null, ambiguous: true, note: "Fixed build not established" }] }],
  conditions: [],
  sources: [{ url: "https://www.cisa.gov/news-events/alerts/2026/10/20/cisa-adds-six-known-exploited-vulnerabilities-catalog", kind: "kev" }],
};
