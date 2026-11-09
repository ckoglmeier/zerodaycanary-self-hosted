<p align="center">
  <img src="public/brand/canary-logo.png" alt="Zero Day Canary — yellow canary mascot" width="200">
</p>

# Zero Day Canary

**Find possible open-source vulnerabilities in the apps you build and buy. Get the evidence you need to act.**

New vulnerabilities keep coming. Knowing which ones matter to your organization starts with knowing what your apps run. Canary brings your app inventory, vulnerability alerts, developer reports, and follow-up into one place.

## Why use Canary

- **Know what needs attention.** Add your applications and check their public websites for technology clues. Use those clues to start a specific conversation with the people who maintain them.
- **Go deeper with developer evidence.** Run the companion skill against your own project, check public dependencies against known vulnerabilities, and share a report with your buyers.
- **Keep the follow-up together.** Request a deeper check, review the developer's report, and track remediation in the app.
- **Build on your own vulnerability catalog.** Import advisory data, review the alerts you want to highlight, and make your catalog available to people and agents through the API and MCP endpoint.
- **Run it on your terms.** Self-host the app, keep reports in your own database, and adapt the code to your workflow.

Canary is useful for teams managing a mix of vendor products and homegrown software, especially when the person responsible for an app isn't its developer.

A public website check can identify possible exposure. A dependency report provides deeper evidence. Neither proves an application is secure; Canary keeps those distinctions visible so you can decide what to investigate next.

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

- **Advisories:** Sign in as an operator and use `/operator/feed` to import source CSVs. Review selected records before publishing. The public catalog starts empty. Supply your own feed and refresh it on your schedule.
- **Matching:** OSV requests may transmit public package names and versions; inspect `intel/osv.ts` and your privacy requirements. Missing coverage is not evidence of safety.
- **AI extraction:** The optional extraction flow uses your own `ANTHROPIC_API_KEY` and incurs your provider's charges. Deterministic CSV intake does not require it.
- **Email:** Configure your own Resend sender and Supabase email delivery. Default invitation mode should remain `hold` until you have tested delivery.
- **Billing:** The application includes a one-free-system/paid-workspace model. Billing beyond that requires your own Stripe configuration; it does not pay the original author. Start with test keys. See `scripts/stripe-workspace-setup.mjs` and `scripts/stripe-nonprofit-setup.mjs`. This snapshot does not implement an unlimited, billing-free monitoring edition.
- **Scheduling:** `/api/cron/daily` requires your own `CRON_SECRET` and scheduler. Review the route before enabling it. Nothing runs automatically from this repository.
- **Analytics:** Disabled unless you explicitly supply your own PostHog configuration.

## Developer skill

See `skills/zero-day-canary-skill/`. Set `CANARY_API_ORIGIN=https://your-canary-host.example` before running the CVE workflow, or use a locally supplied catalog snapshot as described by the script's `--help`. Point catalog requests at your own instance. HTTPS is required for remote catalog reads. The targeted adapter has narrower coverage than the broader package inventory/OSV path; inspect the skill's limitations before relying on it.

## Verification

```sh
npm test
npm run typecheck
npm run build
```

These are source-level checks; they do not establish that your database, email, Stripe, scheduler or deployment is configured correctly. Test with disposable accounts before using real reports. This software does not provide a security certification or ongoing assurance.

## License and support

Original code: [MIT](LICENSE). Cloudflare-derived validators retain their MIT notices in `vendor/canary/LICENSE` and `skills/zero-day-canary-skill/vendor/cloudflare/LICENSE`; see the companion's third-party notices. Other dependencies retain their own licenses.

**Maintenance:** This is an archived, unmaintained project. Fork it to make changes; you are responsible for dependency updates, advisory data, and operating your instance. No support or security updates are promised.
