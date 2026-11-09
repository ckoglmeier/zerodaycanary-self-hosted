import "server-only";

function req(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing environment variable ${name}`);
  return v;
}

export const env = {
  siteUrl: () => ((process.env.SUPABASE_DB_SCHEMA&&process.env.VERCEL_URL?`https://${process.env.VERCEL_URL}`:process.env.NEXT_PUBLIC_SITE_URL) ?? (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "http://localhost:3000")).replace(/\/$/, ""),
  supabaseUrl: () => req("NEXT_PUBLIC_SUPABASE_URL"),
  supabaseAnon: () => req("NEXT_PUBLIC_SUPABASE_ANON_KEY"),
  dbUrl: () => req("SUPABASE_DB_URL"),
  stripeKey: () => req("STRIPE_SECRET_KEY"),
  stripeWebhookSecret: () => req("STRIPE_WEBHOOK_SECRET"),
  anthropicKey: () => req("ANTHROPIC_API_KEY"),
  cronSecret: () => req("CRON_SECRET"),
  operatorEmails: () =>
    (process.env.OPERATOR_EMAILS ?? "")
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  // Free analysis limits (configurable, documented on /docs/limits).
  analyzePerHour: () => Number(process.env.ANALYZE_PER_HOUR ?? 30),
  newScansPerHour: () => Number(process.env.NEW_SCANS_PER_HOUR ?? 10),
  freshnessHours: () => Number(process.env.OBSERVATION_FRESHNESS_HOURS ?? 24),
};
