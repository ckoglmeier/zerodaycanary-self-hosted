import "server-only";
// Scan jobs persisted in Postgres. One active job per scope (unique index); concurrent
// requests reuse it. A job holds a lease; an expired lease means the worker died and the
// next request reclaims it. Scans run inside the request with bounded time - never
// fire-and-forget after the response.
import { canonicalize, type Canonical } from "./scan/canonical";
import { scanUrl } from "./scan/scan";
import { validateUrl, FetchBlocked } from "./scan/net";
import { q, one } from "./db";
import { latestSuccessfulObservation, latestObservation, type ObservationRow } from "./assess";

import {recordError} from "./monitoring/server";

export type Scope = { id: string; scope_key: string; url: string; host: string };
type Job = { id: string; scope_id: string; status: string; attempts: number; lease_until: Date | null; observation_id: string | null; error: string | null; trigger: string };

const LEASE_SECONDS = 50;
const MAX_ATTEMPTS = 3;

export function parseTarget(input: string): Canonical {
  let c: Canonical;
  try {
    c = canonicalize(input);
  } catch {
    throw new FetchBlocked("bad_url", "Enter a web address such as https://portal.example.edu.");
  }
  validateUrl(c.url);
  return c;
}

export async function ensureScope(c: Canonical): Promise<Scope> {
  const row = await one<Scope>(
    `insert into scan_scopes (scope_key, url, host) values ($1,$2,$3)
     on conflict (scope_key) do update set scope_key = excluded.scope_key returning id, scope_key, url, host`,
    [c.scopeKey, c.url, c.host],
  );
  return row!;
}

async function activeJob(scopeId: string): Promise<Job | null> {
  return one<Job>("select * from scan_jobs where scope_id = $1 and status in ('queued','running')", [scopeId]);
}

export async function enqueue(scopeId: string, trigger: string): Promise<{ job: Job; reused: boolean }> {
  const existing = await activeJob(scopeId);
  if (existing) return { job: existing, reused: true };
  const ins = await one<Job>(
    "insert into scan_jobs (scope_id, status, trigger) values ($1,'queued',$2) on conflict do nothing returning *",
    [scopeId, trigger],
  );
  if (ins) return { job: ins, reused: false };
  const raced = await activeJob(scopeId);
  if (raced) return { job: raced, reused: true };
  throw new Error("Could not create scan job");
}

// Claim: queued, or running with an expired lease (abandoned). Returns null if another
// worker holds a live lease.
async function claim(jobId: string): Promise<Job | null> {
  return one<Job>(
    `update scan_jobs set status = 'running', attempts = attempts + 1, lease_until = now() + ($2 || ' seconds')::interval, updated_at = now()
     where id = $1 and (status = 'queued' or (status = 'running' and lease_until < now())) returning *`,
    [jobId, String(LEASE_SECONDS)],
  );
}

export async function runJob(jobId: string): Promise<Job> {
  const job = await claim(jobId);
  if (!job) return (await one<Job>("select * from scan_jobs where id = $1", [jobId]))!;
  if (job.attempts > MAX_ATTEMPTS) {
    return (await one<Job>("update scan_jobs set status = 'failed', error = 'Gave up after repeated attempts', updated_at = now() where id = $1 returning *", [jobId]))!;
  }
  const scope = (await one<Scope>("select * from scan_scopes where id = $1", [job.scope_id]))!;
  try {
    const r = await scanUrl(scope.url);
    const obs = await one<{ id: string }>(
      `insert into observations (scope_id, outcome, final_url, evidence, gaps, fetch_log, trigger) values ($1,$2,$3,$4,$5,$6,$7) returning id`,
      [scope.id, r.outcome, r.final_url, JSON.stringify(r.evidence), JSON.stringify(r.gaps), JSON.stringify(r.fetch_log), job.trigger],
    );
    return (await one<Job>(
      "update scan_jobs set status = $2, observation_id = $3, error = $4, lease_until = null, updated_at = now() where id = $1 returning *",
      [jobId, r.outcome === "failed" ? "failed" : "done", obs!.id, r.outcome === "failed" ? r.gaps[0]?.detail ?? "Scan failed" : null],
    ))!;
  } catch (e) {
    await recordError("scan");
    // Leave the job reclaimable rather than silently done.
    return (await one<Job>(
      "update scan_jobs set status = 'queued', lease_until = null, error = $2, updated_at = now() where id = $1 returning *",
      [jobId, (e as Error).message],
    ))!;
  }
}

async function waitFor(jobId: string, ms: number): Promise<Job> {
  const until = Date.now() + ms;
  for (;;) {
    const j = (await one<Job>("select * from scan_jobs where id = $1", [jobId]))!;
    if (j.status === "done" || j.status === "failed") return j;
    if (j.status === "running" && j.lease_until && j.lease_until.getTime() < Date.now()) return runJob(jobId); // abandoned: recover
    if (j.status === "queued") return runJob(jobId);
    if (Date.now() > until) return j;
    await new Promise((r) => setTimeout(r, 750));
  }
}

export type AnalyzeResult = {
  scope: Scope;
  observation: ObservationRow | null;
  cached: boolean; // true: persisted evidence returned without a new scan
  requested_refresh: boolean;
  refresh_failed: boolean; // a requested refresh did not complete; prior evidence retained
  job: { id: string; status: string } | null;
};

export async function analyze(c: Canonical, opts: { force?: boolean; trigger?: string } = {}): Promise<AnalyzeResult> {
  const scope = await ensureScope(c);
  if (!opts.force) {
    const prior = await latestSuccessfulObservation(scope.id);
    if (prior) return { scope, observation: prior, cached: true, requested_refresh: false, refresh_failed: false, job: null };
    // A previous attempt that failed is still returned as-is (with its gaps) rather than rescanned on every view.
    const failed = await latestObservation(scope.id);
    if (failed && Date.now() - failed.observed_at.getTime() < 10 * 60_000)
      return { scope, observation: failed, cached: true, requested_refresh: false, refresh_failed: false, job: null };
  }
  const { job, reused } = await enqueue(scope.id, opts.trigger ?? (opts.force ? "reanalysis" : "initial"));
  const done = reused ? await waitFor(job.id, 28_000) : await runJob(job.id);
  if (done.status !== "done" && done.status !== "failed") {
    return { scope, observation: await latestSuccessfulObservation(scope.id), cached: true, requested_refresh: !!opts.force, refresh_failed: false, job: { id: done.id, status: done.status } };
  }
  const obs = done.observation_id ? await one<ObservationRow>("select * from observations where id = $1", [done.observation_id]) : null;
  const failed = !obs || obs.outcome === "failed";
  return {
    scope,
    observation: obs,
    cached: false,
    requested_refresh: !!opts.force,
    refresh_failed: !!opts.force && failed,
    job: { id: done.id, status: done.status },
  };
}
