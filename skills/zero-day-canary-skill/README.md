# Zero Day Canary skill

One skill inventories open-source packages across ecosystems, matches exact public package versions through OSV, and investigates specifically requested CVEs using source and configuration evidence. It creates a private report for you to review before sharing.

The workflow borrows Cloudflare's source tracing and evidence discipline. No separate Cloudflare skill is needed. Missing source, runtime or deployment evidence stays unknown.

## Use

Requires macOS/Linux, Python 3.9+, `jsonschema` 4.25+, Git, and Node 22+ for optional legacy report validation. Install into your project without overwriting an existing Canary installation:

```sh
python scripts/install.py --project /absolute/consumer-project
```

Open your app's source in Claude Code or Codex and paste Canary's **Copy report-building prompt**, or ask: **“Use $zero-day-canary-skill to check this app's open-source packages and these CVEs.”** The agent should follow [SKILL.md](SKILL.md), including all available package ecosystems and transitive dependencies.

The agent first prepares `components-input.json` from lockfiles, SBOMs and configuration. Exact public package names, versions and ecosystems may be sent to OSV only with your approval. Source code, private package names, app URLs and credentials stay local.

```sh
python scripts/broad.py run --repo /absolute/app --repo-id owner/app \
  --components /absolute/private/components-input.json \
  --allow-public-lookups --out /absolute/new-private-run \
  --cve CVE-2021-44228
```

`--cve` is repeatable and optional; it accepts requested CVEs outside package ecosystems too. Omit `--allow-public-lookups` when you have not approved package disclosure. Unassessed packages and unavailable public records remain explicit gaps. The command does not execute application code, exploit a target, change dependencies or upload results.

## Finish and share the report

Preparation is not a completed source check. The agent must review the relevant source/configuration prerequisites and preventing controls, then complete `condition-checks.json` from the generated template and write private `REPORT.md`. Cite repository-relative evidence, retain unknowns and distinguish affected versions from actual deployment exposure.

```sh
python scripts/broad.py report --run /absolute/new-private-run \
  --checks /absolute/new-private-run/condition-checks.json \
  --out /absolute/new-private-run/canary-report.json
```

Review `canary-report.json`, upload it to your free private Canary project, then review the report in the app before choosing to share it with a client. The JSON contains package identities, version results and source-check conclusions. Source files and the full private `REPORT.md` are not uploaded. A source check does not establish the deployed version, prove exploitability or certify that an app is safe.

## Coverage

`broad.py` supports exact public packages across OSV ecosystems and explicit CVE source-review targets. Runtime/vendor products, private packages, unresolved versions and unsupported identities remain unassessed when evidence is missing. Package matching alone cannot answer all CVEs. The older `cve.py` workflow is retained for compatibility and is limited to the original Next.js catalog mapping; use `broad.py` for new checks.

## Optional helpers

`canary.py` still supports private inventory packaging, local matching, reviewed submission, upgrade comparison and explicitly supplied legacy source-audit reports. Those operations preserve their existing wire format and separate source findings from CVE applicability. Read [docs/WORKFLOWS.md](docs/WORKFLOWS.md) and [docs/API-CONTRACT.md](docs/API-CONTRACT.md) for them. Upload requires approval of the exact bytes/destination; detailed findings require separate approval. A local check creates no monitoring enrollment or billable system.

The unchanged Cloudflare report schema, two validators and their tests remain only for optional report compatibility. Its full hunting workflow is not part of this install. [Attribution](THIRD-PARTY-NOTICES.md) and [pinned hashes](docs/UPSTREAM.json).

## Validation

```sh
python -m unittest discover -s tests -v
node --test vendor/cloudflare/security-audit/validate-findings.test.cjs vendor/cloudflare/security-audit/validate-coverage-ledger.test.cjs
python scripts/build_package.py
python tests/package_smoke.py --archive dist/zero-day-canary-skill.zip
```

Tests exercise catalog pagination/scope/revision, conservative range matching, single-skill installation, privacy, consent, retry and legacy import contracts. The packaged smoke uses disposable files and a local API fixture; it does not launch a model or assess a real deployed system. Actual CVE workflow evidence is reported separately.
