import "server-only";
import { one, q } from "./db";
import { HttpError, type Viewer } from "./auth";
import { analyze, parseTarget } from "./scanjobs";
import { assessSystem } from "./assess";
import { rateLimit } from "./rate";
import { env } from "./env";
import { recordOperation } from "./usage";

export type OwnedSystem = { id: string; workspace_id: string; scope_id: string; label: string; monitoring: string };

// Authorization for every service-side system operation: the system must belong to the
// caller's workspace. Unknown and foreign ids are indistinguishable (404).
export async function ownSystem(v: Viewer, id: string): Promise<OwnedSystem> {
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new HttpError(404, "System not found.");
  const s = await one<OwnedSystem>("select id, workspace_id, scope_id, label, monitoring from systems where id = $1 and workspace_id = $2 and removed_at is null", [id, v.workspaceId]);
  if (!s) throw new HttpError(404, "System not found.");
  return s;
}

export async function addAndAnalyze(v: Viewer, rawUrl: string) {
  const t0 = performance.now();
  const target = parseTarget(rawUrl);
  await rateLimit(`analyze:${v.id}`, env.analyzePerHour(), 3600);
  const existingScope = await one<{ id: string }>("select id from scan_scopes where scope_key = $1", [target.scopeKey]);
  const hasObs = existingScope ? await one("select 1 from observations where scope_id = $1 limit 1", [existingScope.id]) : null;
  if (!hasObs) await rateLimit(`newscan:${v.id}`, env.newScansPerHour(), 3600);
  const r = await analyze(target);
  let sys = await one<{ id: string }>("select id from systems where workspace_id = $1 and scope_id = $2 and removed_at is null", [v.workspaceId, r.scope.id]);
  if (!sys) {
    const label = target.host + (target.scopeKey.includes("/") ? target.scopeKey.slice(target.scopeKey.indexOf("/")) : "");
    sys = await one<{ id: string }>(
      "insert into systems (workspace_id, scope_id, label) values ($1,$2,$3) on conflict do nothing returning id",
      [v.workspaceId, r.scope.id, label],
    );
    sys ??= await one<{ id: string }>("select id from systems where workspace_id = $1 and scope_id = $2 and removed_at is null", [v.workspaceId, r.scope.id]);
    await q("insert into system_events (workspace_id, system_id, kind, detail) values ($1,$2,'system_added',$3)", [v.workspaceId, sys!.id, JSON.stringify({ url: target.url })]);
  }
  await assessSystem(sys!.id, r.cached ? "cached evidence" : "new analysis");
  await recordOperation(r.cached ? "cached_lookup" : "initial_analysis", "per_customer", r.observation?.outcome ?? "pending", performance.now() - t0, 0);
  return { systemId: sys!.id, cached: r.cached, observedAt: r.observation?.observed_at ?? null };
}

export async function reanalyze(v: Viewer, s: OwnedSystem) {
  const t0 = performance.now();
  await rateLimit(`newscan:${v.id}`, env.newScansPerHour(), 3600);
  const scope = (await one<{ url: string }>("select url from scan_scopes where id = $1", [s.scope_id]))!;
  const r = await analyze(parseTarget(scope.url), { force: true });
  await assessSystem(s.id, "re-analysis");
  await recordOperation("reanalysis", "per_customer", r.refresh_failed ? "failed" : r.observation?.outcome ?? "pending", performance.now() - t0, 0);
  return r;
}
