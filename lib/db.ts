import "server-only";
// Server-side Postgres access for trusted operations (scans, matching, publication,
// billing). This connection bypasses RLS, so every caller authorizes first.
import pg from "pg";
import { env } from "./env";

const g = globalThis as unknown as { __zdcPool?: pg.Pool };

function pool(): pg.Pool {
  databaseSchema(); // Fail closed before connecting when preview isolation is missing.
  if (!g.__zdcPool) {
    g.__zdcPool = new pg.Pool({
      connectionString: env.dbUrl(),
      ssl: { rejectUnauthorized: false },
      max: 3,
      idleTimeoutMillis: 10_000,
    });
  }
  return g.__zdcPool;
}

export function databaseSchema() {
  if(process.env.VERCEL_ENV==='preview'&&!process.env.SUPABASE_DB_SCHEMA)throw new Error('Preview deployments require an isolated database schema.');
  const schema = process.env.SUPABASE_DB_SCHEMA ?? "public";
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(schema)) throw new Error("Invalid database schema");
  return schema;
}

// Authenticated reads retain Postgres RLS as well as explicit workspace predicates.
// This also permits an isolated preview schema without exposing it through PostgREST.
export async function userQ<T extends pg.QueryResultRow>(viewer: { id: string }, sql: string, params: unknown[] = []): Promise<T[]> {
  return tx(async (c) => {
    await c.query("select set_config('request.jwt.claims', $1, true)", [JSON.stringify({ sub: viewer.id, role: "authenticated" })]);
    await c.query("set local role authenticated");
    const rows = (await c.query<T>(sql, params)).rows;
    return JSON.parse(JSON.stringify(rows)) as T[];
  });
}

export async function q<T extends pg.QueryResultRow = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<T[]> {
  return tx(async c => (await c.query<T>(sql, params)).rows);
}

export async function one<T extends pg.QueryResultRow = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<T | null> {
  return (await q<T>(sql, params))[0] ?? null;
}

export async function tx<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const c = await pool().connect();
  try {
    await c.query("begin");
    await c.query("select set_config('search_path',$1,true)", [databaseSchema()]);
    const r = await fn(c);
    await c.query("commit");
    return r;
  } catch (e) {
    await c.query("rollback").catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}
