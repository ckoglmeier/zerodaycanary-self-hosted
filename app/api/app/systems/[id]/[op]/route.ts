import { action, formOf } from "@/lib/http";
import { apiViewer, HttpError } from "@/lib/auth";
import { ownSystem, reanalyze } from "@/lib/systems";
import { releaseMonitoring, requestMonitoring } from "@/lib/billing";
import { assessSystem } from "@/lib/assess";
import { q } from "@/lib/db";
import { userQ } from "@/lib/db";
import { parseVersion } from "@/intel/version";

export const maxDuration = 60;

const PRODUCTS = new Set(["php", "nextjs", "wordpress", "gitlab", "nodejs", "plex", "nginx", "apache", "drupal"]);

export const POST = action(async (req, { params }) => {
  const v = await apiViewer();
  const s = await ownSystem(v, params.id);
  const back = `/systems/${s.id}`;
  switch (params.op) {
    case "reanalyze": {
      const r = await reanalyze(v, s);
      const msg = r.refresh_failed
        ? "The fresh check could not complete. Earlier evidence is kept and labeled with its date."
        : r.cached
          ? "The check is still running. Reload in a moment."
          : "Fresh public check complete.";
      return { redirect: `${back}?msg=${encodeURIComponent(msg)}`, json: { refresh_failed: r.refresh_failed, still_running: r.cached } };
    }
    case "monitor": {
      return { redirect: `/billing/checkout?system=${s.id}`, json: { cartUrl: `/billing/checkout?system=${s.id}` } };
    }
    case "pause":
      await releaseMonitoring(s.workspace_id, s.id, "pause");
      return { redirect: `${back}?msg=${encodeURIComponent("Monitoring paused. History is kept.")}` };
    case "remove":
      await releaseMonitoring(s.workspace_id, s.id, "remove");
      return { redirect: "/systems" };
    case "update": {
      const f = await formOf(req);
      const label = (f.label ?? "").trim().slice(0, 120);
      if (!label) throw new HttpError(400, "Name is required.");
      await userQ(v,'update systems set label=$3,business_use=$4,owner_vendor=$5 where id=$1 and workspace_id=$2 returning id',[s.id,v.workspaceId,label,f.business_use?.trim().slice(0,160)||null,f.owner_vendor?.trim().slice(0,160)||null]);
      return { redirect: `${back}?msg=${encodeURIComponent("Details saved.")}` };
    }
    case "evidence": {
      const f = await formOf(req);
      if (!PRODUCTS.has(f.product)) throw new HttpError(400, "Choose a product.");
      const version = (f.version ?? "").trim();
      if (!parseVersion(version)) throw new HttpError(400, "Enter an exact version such as 8.2.35.");
      await q("insert into system_evidence (workspace_id, system_id, product, version, note) values ($1,$2,$3,$4,$5)", [s.workspace_id, s.id, f.product, version, f.note?.trim().slice(0, 300) || null]);
      await q("insert into system_events (workspace_id, system_id, kind, detail) values ($1,$2,'evidence_added',$3)", [s.workspace_id, s.id, JSON.stringify({ product: f.product, version })]);
      await assessSystem(s.id, "administrator evidence");
      return { redirect: `${back}?msg=${encodeURIComponent("Evidence saved and assessment updated.")}` };
    }
    default:
      throw new HttpError(404, "Unknown action.");
  }
});
