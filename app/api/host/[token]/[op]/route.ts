import { action, formOf } from "@/lib/http";
import { HttpError } from "@/lib/auth";
import { checkClaim, createChallenge, reportUpgrade, scopeForToken, verifyChallenge } from "@/lib/host";
import { one } from "@/lib/db";
import { rateLimit } from "@/lib/rate";
import { parseVersion } from "@/intel/version";

export const maxDuration = 60;
const PRODUCTS = new Set(["php", "nextjs", "wordpress", "gitlab", "nodejs", "plex", "nginx", "apache", "drupal"]);

export const POST = action(async (req, { params }) => {
  const scope = await scopeForToken(params.token);
  if (!scope) throw new HttpError(404, "This link is not valid.");
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "anon";
  await rateLimit(`host-ip:${ip}`, 60, 3600);
  const base = `/host/${params.token}`;
  const f = await formOf(req);
  switch (params.op) {
    case "challenge": {
      const ch = await createChallenge(scope.scope_id, scope.host);
      return { redirect: `${base}?c=${ch!.id}` };
    }
    case "verify": {
      const r = await verifyChallenge(f.challenge, scope.scope_id);
      return {
        redirect: `${base}?c=${f.challenge}&${r.verified ? "msg=" + encodeURIComponent("Domain control verified.") : "error=" + encodeURIComponent("The TXT record was not found yet. DNS changes can take a few minutes; check the name and value and try again.")}`,
      };
    }
    case "upgrade": {
      if (!PRODUCTS.has(f.product)) throw new HttpError(400, "Choose a product.");
      const version = (f.claimed_version ?? "").trim();
      if (!parseVersion(version)) throw new HttpError(400, "Enter the exact version or build, such as 8.2.35.");
      let ref: string | null = null;
      if (f.reference_url) {
        try {
          const u = new URL(f.reference_url);
          if (!/^https?:$/.test(u.protocol)) throw new Error();
          ref = u.href;
        } catch {
          throw new HttpError(400, "The reference must be an http(s) link.");
        }
      }
      const upgradedAt = f.upgraded_at && !Number.isNaN(Date.parse(f.upgraded_at)) ? new Date(f.upgraded_at).toISOString() : null;
      await reportUpgrade(f.challenge, scope.scope_id, { product: f.product, claimed_version: version, upgraded_at: upgradedAt, reference_url: ref });
      return { redirect: `${base}?msg=${encodeURIComponent("Upgrade reported. The fresh check result is shown below.")}` };
    }
    case "retry": {
      const c = await one<{ id: string; state: string }>("select id, state from host_claims where id = $1 and scope_id = $2", [f.claim, scope.scope_id]);
      if (!c) throw new HttpError(404, "Report not found.");
      if (c.state !== "check_failed") throw new HttpError(409, "This report already has an outcome.");
      await rateLimit(`retry:${c.id}`, 5, 3600);
      await checkClaim(c.id);
      return { redirect: base };
    }
    default:
      throw new HttpError(404, "Unknown action.");
  }
});
