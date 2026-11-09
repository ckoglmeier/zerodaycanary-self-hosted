// One bounded public scan of a canonical URL. Returns evidence plus every gap; a failed
// or partial fetch is reported as such and is never a clean result.
import type { EvidenceGap, TechObservation } from "@/intel/evidence";
import { detect, gapsForTechs, nextVersionFromScript, plexVersionFromIdentity, techName } from "./detect";
import { FetchBlocked, safeFetch, type FetchOptions } from "./net";

export type ScanOutcome = {
  outcome: "complete" | "partial" | "failed";
  final_url: string | null;
  evidence: { techs: TechObservation[]; facts: Record<string, boolean> };
  gaps: EvidenceGap[];
  fetch_log: { url: string; status: number | null; ms: number; note?: string }[];
};

const BUDGET_MS = 25_000;

export async function scanUrl(url: string, opts: FetchOptions = {}): Promise<ScanOutcome> {
  const started = Date.now();
  const observedAt = new Date().toISOString();
  const gaps: EvidenceGap[] = [];
  const log: ScanOutcome["fetch_log"] = [];
  const fail = (g: EvidenceGap): ScanOutcome => ({ outcome: "failed", final_url: null, evidence: { techs: [], facts: {} }, gaps: [g, ...gaps], fetch_log: log });

  let main;
  try {
    main = await safeFetch(url, opts);
    log.push({ url, status: main.status, ms: main.elapsedMs, note: main.redirects.length ? `${main.redirects.length} redirect(s)` : undefined });
  } catch (e) {
    log.push({ url, status: null, ms: Date.now() - started, note: (e as Error).message });
    if (e instanceof FetchBlocked) return fail({ kind: "blocked_target", detail: e.message, location: url });
    const msg = (e as Error).name === "TimeoutError" || /timeout/i.test((e as Error).message) ? "timeout" : "fetch_failed";
    return fail({ kind: msg, detail: msg === "timeout" ? "The site did not respond in time." : `Could not fetch the page: ${(e as Error).message}`, location: url });
  }

  if (main.offScopeRedirect) {
    return fail({ kind: "redirect_out_of_scope", detail: `Redirected to ${main.offScopeRedirect}, which is a different host. Add that URL as its own system if it is the same application.`, location: main.offScopeRedirect });
  }
  if (main.status === 401 || main.status === 403)
    return { ...fail({ kind: "access_denied", detail: `The server refused access (HTTP ${main.status}).`, location: main.url }), final_url: main.url };
  if (main.status >= 400)
    return { ...fail({ kind: "fetch_failed", detail: `The server returned HTTP ${main.status}.`, location: main.url }), final_url: main.url };

  const isHtml = /html|xml/i.test(main.contentType);
  if (!isHtml) gaps.push({ kind: "not_html", detail: `Response was ${main.contentType || "of unknown type"}, not a web page; page-level evidence is unavailable.`, location: main.url });
  if (main.truncated) gaps.push({ kind: "too_large", detail: "The page exceeded the size limit and was only partly examined.", location: main.url });

  const d = detect({ url: main.url, headers: main.headers, html: isHtml ? main.body : "", cookieNames: main.setCookieNames, observedAt });
  const techs = d.techs;
  const facts = d.facts;

  // Bounded follow-ups: up to 5 same-origin Next.js chunks to read the published version.
  const origin = new URL(main.url).origin;
  if (techs.some((t) => t.product === "nextjs")) {
    const candidates = d.hints.nextScripts
      .map((s) => new URL(s, main.url))
      .filter((u) => u.origin === origin)
      .sort((a, b) => score(b.pathname) - score(a.pathname))
      .slice(0, 5);
    let found = false;
    for (const u of candidates) {
      if (Date.now() - started > BUDGET_MS) {
        gaps.push({ kind: "partial", detail: "Time budget reached before all scripts were checked." });
        break;
      }
      try {
        const r = await safeFetch(u.href, { ...opts, maxBytes: 800_000, accept: "*/*" });
        log.push({ url: u.href, status: r.status, ms: r.elapsedMs });
        const nv = nextVersionFromScript(r.body);
        if (nv.appDir === true) facts["nextjs.app_router"] = true;
        if (nv.version) {
          techs.push({
            product: "nextjs", name: techName("nextjs"), version: nv.version, version_basis: "observed", evidence_type: "script",
            location: u.href, detail: `Client bundle declares Next.js ${nv.version}`, confidence: "medium", observed_at: observedAt,
            limitations: ["Read from the shipped client bundle; a CDN may serve an older cached build."],
          });
          found = true;
          break;
        }
      } catch (e) {
        log.push({ url: u.href, status: null, ms: 0, note: (e as Error).message });
      }
    }
    if (!found && candidates.length === 0 && d.hints.nextScripts.length > 0)
      gaps.push({ kind: "partial", detail: "Next.js scripts are served from another origin and were not fetched." });
  }

  if (d.hints.plex && Date.now() - started < BUDGET_MS) {
    const idUrl = new URL("/identity", origin).href;
    try {
      const r = await safeFetch(idUrl, { ...opts, maxBytes: 50_000, accept: "application/xml,text/xml,*/*" });
      log.push({ url: idUrl, status: r.status, ms: r.elapsedMs });
      const v = r.status === 200 ? plexVersionFromIdentity(r.body) : null;
      if (v)
        techs.push({
          product: "plex", name: techName("plex"), version: v, version_basis: "observed", evidence_type: "endpoint", location: idUrl,
          detail: `Plex /identity reports version ${v}`, confidence: "high", observed_at: observedAt, limitations: [],
        });
    } catch (e) {
      log.push({ url: idUrl, status: null, ms: 0, note: (e as Error).message });
    }
  }

  // CDN / static hosting: the backend runtime is not observed.
  const server = String(main.headers["server"] ?? "");
  if (/vercel|cloudflare|cloudfront|netlify|akamai|fastly/i.test(server) || main.headers["x-vercel-cache"] || main.headers["cf-ray"]) {
    for (const t of techs) t.limitations.push("Served through a CDN; this reflects the delivered response, not necessarily the backend runtime.");
  }

  gaps.push(...gapsForTechs(techs));
  if (techs.length === 0) gaps.push({ kind: "unsupported", detail: "No technology covered by the reviewed alerts was identified from public evidence. This does not mean the system is unaffected; it may use software we cannot see or do not cover.", location: main.url });

  const hardGap = gaps.some((g) => ["not_html", "too_large", "partial"].includes(g.kind));
  return { outcome: hardGap ? "partial" : "complete", final_url: main.url, evidence: { techs, facts }, gaps, fetch_log: log };
}

function score(p: string) {
  // The chunk defining window.next is usually main-app / main / framework.
  if (/main-app/.test(p)) return 3;
  if (/\/main-/.test(p)) return 2;
  if (/framework/.test(p)) return 1;
  return 0;
}
