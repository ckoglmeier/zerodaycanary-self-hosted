# Third-party attribution

Cloudflare security-audit-skill, commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`:
https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8

Copyright (c) 2025-2026 Cloudflare, Inc. MIT license; complete notice in [vendor/cloudflare/LICENSE](vendor/cloudflare/LICENSE).

The unchanged `report-schema.json`, `validate-findings.cjs`, `validate-coverage-ledger.cjs` and their two test suites are retained under `vendor/cloudflare/security-audit` only for optional legacy report compatibility. Pinned hashes: [docs/UPSTREAM.json](docs/UPSTREAM.json). Synthetic `examples/findings.json` derives from that upstream validator's example fixture functions and is not an actual vulnerability claim.

The single Canary skill adapts Cloudflare's evidence-first method: trace relevant source, check the strongest preventing control, use bounded validation and keep unresolved facts explicit. It redirects that discipline to known advisory targets from Canary's API. The full reconnaissance/hunting workflow and separate Cloudflare SKILL.md are not installed or invoked. Earlier full-audit integration material remains historical, outside the active skill and in Git history.

This companion is independently developed; Cloudflare has not endorsed it. Original Canary code is MIT licensed; see the repository root LICENSE. The MIT license applies to the attributed upstream material. The app's advisory field names/range semantics inform a separately written conservative adapter; app implementation files were not copied.
