// Technology detection from bounded public evidence. Every finding records where it came
// from and whether a version was directly observed. Nothing here infers a server runtime
// version from a CMS or frontend framework.
import type { EvidenceGap, TechObservation } from "@/intel/evidence";

type H = Record<string, string | string[] | undefined>;
const hv = (h: H, k: string) => {
  const v = h[k];
  return Array.isArray(v) ? v.join(", ") : v ?? "";
};

export type DetectInput = {
  url: string;
  headers: H;
  html: string;
  cookieNames: string[];
  observedAt: string;
};

export type Detection = { techs: TechObservation[]; facts: Record<string, boolean>; hints: { nextScripts: string[]; plex: boolean } };

const NAMES: Record<string, string> = {
  php: "PHP", nextjs: "Next.js", wordpress: "WordPress", gitlab: "GitLab", nodejs: "Node.js",
  plex: "Plex Media Server", nginx: "nginx", apache: "Apache HTTP Server", drupal: "Drupal", iis: "Microsoft IIS",
};

export function techName(product: string) {
  return NAMES[product] ?? product;
}

export function detect(i: DetectInput): Detection {
  const techs: TechObservation[] = [];
  const facts: Record<string, boolean> = {};
  const add = (t: Omit<TechObservation, "name" | "observed_at" | "version_basis" | "limitations"> & { limitations?: string[]; version_basis?: TechObservation["version_basis"] }) =>
    techs.push({
      name: techName(t.product),
      observed_at: i.observedAt,
      limitations: [],
      ...t,
      version_basis: t.version ? t.version_basis ?? "observed" : null,
    });

  // ── Headers
  const powered = hv(i.headers, "x-powered-by");
  const server = hv(i.headers, "server");
  for (const m of powered.matchAll(/PHP\/(\d+\.\d+(?:\.\d+)?[\w.+~-]*)/gi))
    add({ product: "php", version: m[1], evidence_type: "header", location: `${i.url} (X-Powered-By)`, detail: `X-Powered-By: ${powered}`, confidence: "high" });
  if (/\bPHP\b/i.test(powered) && !/PHP\//i.test(powered))
    add({ product: "php", version: null, evidence_type: "header", location: `${i.url} (X-Powered-By)`, detail: `X-Powered-By: ${powered}`, confidence: "high" });
  if (/next\.js/i.test(powered))
    add({ product: "nextjs", version: null, evidence_type: "header", location: `${i.url} (X-Powered-By)`, detail: `X-Powered-By: ${powered}`, confidence: "high" });
  if (/express/i.test(powered))
    add({
      product: "nodejs", version: null, evidence_type: "header", location: `${i.url} (X-Powered-By)`, detail: `X-Powered-By: ${powered}`, confidence: "medium",
      limitations: ["Express runs on Node.js; the Node.js version is not exposed."],
    });
  const sv = /^(nginx|Apache)\/(\d+\.\d+(?:\.\d+)?)/i.exec(server);
  if (sv)
    add({ product: sv[1].toLowerCase() === "nginx" ? "nginx" : "apache", version: sv[2], evidence_type: "header", location: `${i.url} (Server)`, detail: `Server: ${server}`, confidence: "medium", limitations: ["A proxy in front of the application may set this header."] });
  for (const m of server.matchAll(/PHP\/(\d+\.\d+(?:\.\d+)?[\w.+~-]*)/gi))
    add({ product: "php", version: m[1], evidence_type: "header", location: `${i.url} (Server)`, detail: `Server: ${server}`, confidence: "medium" });
  if (/Microsoft-IIS\/([\d.]+)/i.test(server))
    add({ product: "iis", version: /Microsoft-IIS\/([\d.]+)/i.exec(server)![1], evidence_type: "header", location: `${i.url} (Server)`, detail: `Server: ${server}`, confidence: "medium" });
  if (["x-nextjs-cache", "x-nextjs-prerender", "x-nextjs-stale-time", "x-nextjs-matched-path"].some((k) => i.headers[k] !== undefined))
    add({ product: "nextjs", version: null, evidence_type: "header", location: i.url, detail: "Next.js response headers present", confidence: "high" });
  if (i.headers["x-plex-protocol"] !== undefined) {
    add({ product: "plex", version: null, evidence_type: "header", location: i.url, detail: "X-Plex-Protocol header present", confidence: "high" });
  }
  if (i.headers["x-gitlab-meta"] !== undefined)
    add({ product: "gitlab", version: null, evidence_type: "header", location: i.url, detail: "X-Gitlab-Meta header present", confidence: "high" });

  // ── HTML
  const html = i.html.slice(0, 1_500_000);
  const gen = /<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)["']/i.exec(html) ?? /<meta[^>]+content=["']([^"']+)["'][^>]*name=["']generator["']/i.exec(html);
  if (gen) {
    const g = gen[1];
    const wp = /WordPress\s*(\d+(?:\.\d+)*(?:-[\w.-]+)?)?/i.exec(g);
    if (wp) add({ product: "wordpress", version: wp[1] ?? null, evidence_type: "html", location: `${i.url} (meta generator)`, detail: `Generator: ${g}`, confidence: "medium", limitations: ["Generator tags can be stale or removed by plugins."] });
    const dr = /Drupal\s*(\d+)/i.exec(g);
    if (dr) add({ product: "drupal", version: null, evidence_type: "html", location: `${i.url} (meta generator)`, detail: `Generator: ${g} (major version only)`, confidence: "medium" });
  }
  if (/\/wp-content\/|\/wp-includes\//i.test(html) && !techs.some((t) => t.product === "wordpress"))
    add({ product: "wordpress", version: null, evidence_type: "html", location: i.url, detail: "WordPress asset paths in page", confidence: "high" });
  if (techs.some((t) => t.product === "wordpress") && !techs.some((t) => t.product === "php"))
    add({
      product: "php", version: null, evidence_type: "html", location: i.url, detail: "WordPress runs on PHP", confidence: "medium",
      limitations: ["PHP presence is implied by WordPress. The PHP version is not visible, and upgrading WordPress does not upgrade PHP."],
    });
  if (/\/_next\/static\//.test(html) && !techs.some((t) => t.product === "nextjs"))
    add({ product: "nextjs", version: null, evidence_type: "html", location: i.url, detail: "Next.js static asset paths in page", confidence: "high" });
  if (/self\.__next_f\b|\/_next\/static\/chunks\/app\//.test(html)) facts["nextjs.app_router"] = true;
  if (/id=["']__NEXT_DATA__["']/.test(html)) facts["nextjs.pages_router"] = true;
  if (/<meta[^>]+content=["']GitLab["']/i.test(html) || /gon\.gitlab_url|window\.gon\s*=/.test(html))
    if (!techs.some((t) => t.product === "gitlab"))
      add({ product: "gitlab", version: null, evidence_type: "html", location: i.url, detail: "GitLab page markers", confidence: "high", limitations: ["GitLab does not publish its version to anonymous visitors."] });
  if (/<title>\s*Plex\s*<\/title>|plex\.tv\/web/i.test(html) && !techs.some((t) => t.product === "plex"))
    add({ product: "plex", version: null, evidence_type: "html", location: i.url, detail: "Plex web app markers", confidence: "medium" });

  // ── Cookies (names only)
  const ck = new Set(i.cookieNames.map((c) => c.toLowerCase()));
  if ((ck.has("phpsessid") || ck.has("laravel_session")) && !techs.some((t) => t.product === "php"))
    add({ product: "php", version: null, evidence_type: "cookie", location: i.url, detail: `Cookie name ${ck.has("phpsessid") ? "PHPSESSID" : "laravel_session"}`, confidence: "medium" });
  if (ck.has("_gitlab_session") && !techs.some((t) => t.product === "gitlab"))
    add({ product: "gitlab", version: null, evidence_type: "cookie", location: i.url, detail: "Cookie name _gitlab_session", confidence: "high" });
  if (ck.has("connect.sid") && !techs.some((t) => t.product === "nodejs"))
    add({ product: "nodejs", version: null, evidence_type: "cookie", location: i.url, detail: "Cookie name connect.sid (Express session)", confidence: "medium" });

  // Hints for bounded follow-up requests.
  const nextScripts = [...html.matchAll(/<script[^>]+src=["']([^"']*\/_next\/static\/(?:immutable\/)?chunks\/[^"']+\.js)["']/gi)].map((m) => m[1]);
  return { techs, facts, hints: { nextScripts, plex: techs.some((t) => t.product === "plex") } };
}

// Next.js publishes `window.next = { version: "x.y.z", appDir: ... }` in a client chunk.
export function nextVersionFromScript(js: string): { version: string | null; appDir: boolean | null } {
  const m = /window\.next\s*=\s*\{\s*version:\s*"([^"]+)"(?:\s*,\s*appDir:\s*(!0|!1|true|false))?/.exec(js) ?? /\bversion:\s*"(\d+\.\d+\.\d+[^"]*)"\s*,\s*appDir:\s*(!0|!1|true|false)/.exec(js);
  if (!m) return { version: null, appDir: null };
  return { version: m[1], appDir: m[2] === undefined ? null : m[2] === "!0" || m[2] === "true" };
}

// Plex /identity: <MediaContainer ... version="1.41.3.9314-a0bfb8370">
export function plexVersionFromIdentity(xml: string): string | null {
  const m = /<MediaContainer[^>]*\sversion="([\d.]+)(?:-[0-9a-f]+)?"/i.exec(xml);
  return m ? m[1] : null;
}

export function gapsForTechs(techs: TechObservation[]): EvidenceGap[] {
  const seen = new Set<string>();
  const out: EvidenceGap[] = [];
  for (const t of techs) {
    if (seen.has(t.product)) continue;
    const hasVersion = techs.some((x) => x.product === t.product && x.version && x.version_basis === "observed");
    seen.add(t.product);
    if (!hasVersion) out.push({ kind: "version_hidden", detail: `${t.name} detected, version not visible in public evidence.`, location: t.location });
  }
  return out;
}
