# Zero Day Canary — self-hosted reference

**Unmaintained. The original hosted service is retired.** This is a source snapshot, released November 9, 2026, for people who want to run or adapt it themselves. There are no promised updates, support, hosted API, or vulnerability-feed maintenance. Fork it if you want to continue development.

Canary combines public website observations, developer-supplied dependency reports, reviewed vulnerability alerts, and buyer/developer follow-up. Public observations are clues, not proof that a system is vulnerable or safe. Reports only establish what their evidence supports.

## What is included

- Next.js application with Supabase authentication and Postgres storage.
- CSV source intake and a separate operator review/publication workflow.
- Public read-only API and MCP endpoint for your own catalog.
- Local developer skill, report validation and sharing flows.
- Original optional Stripe billing implementation and email templates.

No production database, customer reports, credentials, private release evidence or historical Git commits are included. Test fixtures are synthetic examples, not a current vulnerability database. You must supply and maintain your own advisory data. No license to third-party advisory content is granted by this repository.

## Run the app

Use Node.js 24 and Python 3 for the companion skill. Create **your own** Supabase project and configure its Auth site URL and allowed redirect URLs for your instance. Configure SMTP if you need real sign-in email delivery.

```sh
npm ci
cp .env.example .env.local
# Fill in your own site URL, Supabase URL, anon key and database connection.
# Set OPERATOR_EMAILS to the email you will use to sign in.
npm run db:migrate
npm run dev
```

Migrations require a Supabase-backed database, including its auth schema. The migration script targets `public`; use a new dedicated project, never someone else's production database. The database connection uses SSL.

For a production Node host, set the same environment variables, then run `npm run build` and `npm start`. Use HTTPS. Vercel can host a fork, but no deployment or scheduled jobs are provisioned here. Keep server credentials out of public/client variables. Review the code and update dependencies before exposing it to the internet.

### Optional integrations

- **Advisories:** Sign in as an operator and use `/operator/feed` to import source CSVs. Review selected records before publishing. The public catalog starts empty. The former nightly feed is not included as a service.
- **Matching:** OSV requests may transmit public package names and versions; inspect `intel/osv.ts` and your privacy requirements. Missing coverage is not evidence of safety.
- **AI extraction:** The optional extraction flow uses your own `ANTHROPIC_API_KEY` and incurs your provider's charges. Deterministic CSV intake does not require it.
- **Email:** Configure your own Resend sender and Supabase email delivery. Default invitation mode should remain `hold` until you have tested delivery.
- **Billing:** The archived application still contains the original one-free-system/paid-workspace model. Billing beyond that requires your own Stripe configuration; it does not pay the original author. Start with test keys. See `scripts/stripe-workspace-setup.mjs` and `scripts/stripe-nonprofit-setup.mjs`. This snapshot does not implement an unlimited, billing-free monitoring edition.
- **Scheduling:** `/api/cron/daily` requires your own `CRON_SECRET` and scheduler. Review the route before enabling it. Nothing runs automatically from this repository.
- **Analytics:** Disabled unless you explicitly supply your own PostHog configuration.

## Developer skill

See `skills/zero-day-canary-skill/`. Set `CANARY_API_ORIGIN=https://your-canary-host.example` before running the CVE workflow, or use a locally supplied catalog snapshot as described by the script's `--help`. No request should depend on the former hosted Canary API. HTTPS is required for remote catalog reads. The targeted adapter has narrower coverage than the broader package inventory/OSV path; inspect the skill's limitations before relying on it.

## Verification

```sh
npm test
npm run typecheck
npm run build
```

These are source-level checks; they do not establish that your database, email, Stripe, scheduler or deployment is configured correctly. Test with disposable accounts before using real reports. This software does not provide a security certification or ongoing assurance.

## License and support

Original code: [MIT](LICENSE). Cloudflare-derived validators retain their MIT notices in `vendor/canary/LICENSE` and `skills/zero-day-canary-skill/vendor/cloudflare/LICENSE`; see the companion's third-party notices. Other dependencies retain their own licenses.

This repository is archived and accepts no support requests or security-fix commitments. Do not send private reports, credentials or vulnerability disclosures to the former hosted service. Maintain your fork and its dependencies yourself.
