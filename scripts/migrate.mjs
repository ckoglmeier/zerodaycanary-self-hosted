// Applies supabase/migrations/*.sql in order to SUPABASE_DB_URL, tracking applied files.
// Usage: node --env-file=.env.local scripts/migrate.mjs
import { readdir, readFile } from "node:fs/promises";
import pg from "pg";

const url = process.env.SUPABASE_DB_URL;
if (!url) throw new Error("SUPABASE_DB_URL is not set");
// This command intentionally targets public. A preview-configured shell must
// never silently migrate production instead of its isolated schema.
if (process.env.VERCEL_ENV === 'preview' || (process.env.SUPABASE_DB_SCHEMA && process.env.SUPABASE_DB_SCHEMA !== 'public'))
  throw new Error('Refusing public migrations from an isolated preview environment. Use the guarded preview migration workflow.');
const client = new pg.Client({ connectionString: url, ssl: { rejectUnauthorized: false } });
await client.connect();
await client.query("create table if not exists public._migrations (name text primary key, applied_at timestamptz default now())");
await client.query("alter table public._migrations enable row level security");
const done = new Set((await client.query("select name from public._migrations")).rows.map((r) => r.name));
const dir = new URL("../supabase/migrations/", import.meta.url);
for (const f of (await readdir(dir)).filter((f) => f.endsWith(".sql")).sort()) {
  if (done.has(f)) continue;
  const sql = await readFile(new URL(f, dir), "utf8");
  await client.query("begin");
  try {
    // Transaction pooling may reuse a backend whose session search_path was
    // changed by a diagnostic script. Pin the actual DDL target explicitly.
    await client.query('set local search_path = public');
    await client.query(sql);
    await client.query("insert into public._migrations (name) values ($1)", [f]);
    await client.query("commit");
    console.log("applied", f);
  } catch (e) {
    await client.query("rollback");
    console.error("failed", f, e.message);
    process.exitCode = 1;
    break;
  }
}
await client.end();
