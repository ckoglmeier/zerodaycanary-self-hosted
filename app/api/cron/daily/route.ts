import { NextResponse } from "next/server";
import { env } from "@/lib/env";
import { q } from "@/lib/db";
import { rematchAll, assessSystem } from "@/lib/assess";
import { analyze } from "@/lib/scanjobs";
import { canonicalize } from "@/lib/scan/canonical";
import { rematchDevelopers } from "@/lib/developer/evaluate";
import { rematchSharedSystems } from "@/lib/review/reports";

import { trackedDaily } from "@/lib/monitoring/server";

export const maxDuration = 300;

// Daily: re-match every system against the current catalog, then refresh a bounded number
// of the oldest public observations for actively monitored systems. Same logic as the app.
export async function GET(req: Request) {
  if (req.headers.get("authorization") !== `Bearer ${env.cronSecret()}`) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  return trackedDaily(async () => {
  const rematch = await rematchAll("daily re-match");
  const developer = await rematchDevelopers("daily re-evaluation");
  const shared = await rematchSharedSystems();
  const stale = await q<{ system_id: string; url: string }>(
    `select s.id system_id, sc.url from systems s join scan_scopes sc on sc.id = s.scope_id
     left join lateral (select observed_at from observations o where o.scope_id = s.scope_id order by observed_at desc limit 1) o on true
     where s.monitoring = 'active' and s.removed_at is null and (o.observed_at is null or o.observed_at < now() - interval '7 days')
     order by o.observed_at nulls first limit 5`,
  );
  const refreshed: { system_id: string; outcome: string }[] = [];
  for (const s of stale) {
    const r = await analyze(canonicalize(s.url), { force: true, trigger: "scheduled" });
    await assessSystem(s.system_id, "scheduled refresh");
    refreshed.push({ system_id: s.system_id, outcome: r.observation?.outcome ?? "pending" });
  }
  return NextResponse.json({ rematch, developer, shared, refreshed });
  });
}
