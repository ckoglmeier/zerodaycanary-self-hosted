// Cache key / assessment scope for a submitted URL.
// Keeps the path (tenant paths on shared SaaS hosts are different systems), drops query
// and fragment, lowercases the host and removes default ports. `www.` is NOT merged with
// the apex: equivalence must be observed through redirects, not assumed.
export type Canonical = { url: string; scopeKey: string; host: string };

export function canonicalize(input: string): Canonical {
  let s = input.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "https://" + s;
  const u = new URL(s);
  u.hash = "";
  u.search = "";
  u.hostname = u.hostname.toLowerCase().replace(/\.$/, "");
  if ((u.protocol === "https:" && u.port === "443") || (u.protocol === "http:" && u.port === "80")) u.port = "";
  let path = u.pathname.replace(/\/{2,}/g, "/");
  if (path.length > 1) path = path.replace(/\/+$/, "");
  u.pathname = path || "/";
  const scopeKey = `${u.hostname}${u.port ? ":" + u.port : ""}${path === "/" ? "" : path}`;
  return { url: u.href, scopeKey, host: u.hostname };
}
