// Safe outbound fetching for public evidence collection.
// - http/https only, ports 80/443, no credentials in URLs
// - every hostname resolved and checked against private/reserved ranges
// - the connection is pinned to the checked address (DNS-rebinding protection)
// - redirects are followed manually and revalidated hop by hop
// - response size and time are bounded; TLS is validated by default
import { BlockList, isIP } from "node:net";
import { lookup as dnsLookup } from "node:dns/promises";
import { Agent, request } from "undici";

const blocked = new BlockList();
for (const [net, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(net, bits, "ipv4");
for (const [net, bits] of [
  ["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32], ["100::", 64], ["2001::", 23],
] as const) blocked.addSubnet(net, bits, "ipv6");

export function isPublicAddress(addr: string): boolean {
  const fam = isIP(addr);
  if (fam === 4) return !blocked.check(addr, "ipv4");
  if (fam === 6) {
    const lower = addr.toLowerCase();
    // IPv4-mapped / NAT64 forms carry an IPv4 address that must itself be public.
    const mapped = /^(?:::ffff:|64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
    if (mapped) return isPublicAddress(mapped[1]);
    if (/^(?:::ffff:|64:ff9b::)/.test(lower)) return false;
    return !blocked.check(addr, "ipv6");
  }
  return false;
}

export class FetchBlocked extends Error {
  constructor(public kind: "blocked_target" | "bad_url", message: string) {
    super(message);
  }
}

export type Resolver = (host: string) => Promise<string[]>;
export const systemResolver: Resolver = async (host) => (await dnsLookup(host, { all: true, verbatim: true })).map((a) => a.address);

export function validateUrl(raw: string, t?: FetchOptions["testOverrides"]): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new FetchBlocked("bad_url", "Not a valid URL.");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new FetchBlocked("bad_url", "Only http and https URLs are supported.");
  if (u.username || u.password) throw new FetchBlocked("bad_url", "URLs with credentials are not accepted.");
  if (u.port && u.port !== "80" && u.port !== "443" && !t?.allowAnyPort) throw new FetchBlocked("bad_url", "Only standard ports (80, 443) are scanned.");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host)) {
    if (!(t?.addressPolicy ?? isPublicAddress)(host)) throw new FetchBlocked("blocked_target", "Private, loopback and reserved addresses are not scanned.");
  } else if (!host.includes(".") || /\.(local|localhost|internal|lan|home|corp|test|invalid|example)$/i.test(host) || host === "localhost") {
    throw new FetchBlocked("blocked_target", "Only public hostnames are scanned.");
  }
  return u;
}

async function resolvePublic(host: string, resolve: Resolver, allowed: (a: string) => boolean = isPublicAddress): Promise<string> {
  if (isIP(host)) {
    if (!allowed(host)) throw new FetchBlocked("blocked_target", "Private, loopback and reserved addresses are not scanned.");
    return host;
  }
  let addrs: string[];
  try {
    addrs = await resolve(host);
  } catch {
    throw new FetchBlocked("blocked_target", `Could not resolve ${host}.`);
  }
  if (addrs.length === 0) throw new FetchBlocked("blocked_target", `Could not resolve ${host}.`);
  // Reject if ANY address is private: a mixed answer is a classic rebinding setup.
  if (addrs.some((a) => !allowed(a))) throw new FetchBlocked("blocked_target", `${host} resolves to a private or reserved address.`);
  return addrs[0];
}

export type FetchResult = {
  url: string; // final URL after in-scope redirects
  status: number;
  headers: Record<string, string | string[]>;
  setCookieNames: string[];
  body: string;
  truncated: boolean;
  contentType: string;
  redirects: { from: string; to: string; status: number }[];
  offScopeRedirect: string | null;
  elapsedMs: number;
};

export type FetchOptions = {
  resolve?: Resolver;
  maxBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
  sameHostOnly?: boolean; // follow redirects only within the starting host
  accept?: string;
  // Test seam only: lets the controlled-fixture tests reach a loopback server on a random port.
  testOverrides?: { addressPolicy?: (addr: string) => boolean; allowAnyPort?: boolean };
};

const UA = "ZeroDayCanary/0.1 (+https://zerodaycanary.com/about-scanning; public evidence only)";

export async function safeFetch(raw: string, opts: FetchOptions = {}): Promise<FetchResult> {
  const resolve = opts.resolve ?? systemResolver;
  const maxBytes = opts.maxBytes ?? 1_500_000;
  const timeoutMs = opts.timeoutMs ?? 8000;
  const maxRedirects = opts.maxRedirects ?? 5;
  const started = Date.now();
  let url = validateUrl(raw, opts.testOverrides);
  const startHost = url.hostname;
  const redirects: FetchResult["redirects"] = [];

  for (let hop = 0; ; hop++) {
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const pinned = await resolvePublic(host, resolve, opts.testOverrides?.addressPolicy);
    const agent = new Agent({
      connect: {
        timeout: timeoutMs,
        // Pin the socket to the address we validated; TLS still verifies the hostname.
        lookup: (_h, _o, cb) => cb(null, [{ address: pinned, family: isIP(pinned) }] as never),
      },
      headersTimeout: timeoutMs,
      bodyTimeout: timeoutMs,
    });
    try {
      const res = await request(url, {
        method: "GET",
        dispatcher: agent,
        headers: { "user-agent": UA, accept: opts.accept ?? "text/html,application/xhtml+xml,*/*;q=0.5" },
        signal: AbortSignal.timeout(timeoutMs),
        maxRedirections: 0,
      } as Parameters<typeof request>[1]);
      const loc = res.headers["location"];
      if (res.statusCode >= 300 && res.statusCode < 400 && loc) {
        await res.body.dump();
        const next = new URL(Array.isArray(loc) ? loc[0] : loc, url);
        redirects.push({ from: url.href, to: next.href, status: res.statusCode });
        if (hop >= maxRedirects) throw new FetchBlocked("blocked_target", "Too many redirects.");
        if ((opts.sameHostOnly ?? true) && next.hostname !== startHost) {
          return {
            url: url.href, status: res.statusCode, headers: res.headers as FetchResult["headers"], setCookieNames: [],
            body: "", truncated: false, contentType: "", redirects, offScopeRedirect: next.href, elapsedMs: Date.now() - started,
          };
        }
        url = validateUrl(next.href, opts.testOverrides);
        continue;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      let truncated = false;
      for await (const chunk of res.body) {
        size += chunk.length;
        if (size > maxBytes) {
          truncated = true;
          chunks.push(chunk.subarray(0, Math.max(0, chunk.length - (size - maxBytes))));
          res.body.destroy();
          break;
        }
        chunks.push(chunk);
      }
      const sc = res.headers["set-cookie"];
      const cookies = (Array.isArray(sc) ? sc : sc ? [sc] : []).map((c) => c.split("=")[0].trim()).filter(Boolean);
      const ct = res.headers["content-type"];
      return {
        url: url.href,
        status: res.statusCode,
        headers: res.headers as FetchResult["headers"],
        setCookieNames: cookies,
        body: Buffer.concat(chunks).toString("utf8"),
        truncated,
        contentType: (Array.isArray(ct) ? ct[0] : ct) ?? "",
        redirects,
        offScopeRedirect: null,
        elapsedMs: Date.now() - started,
      };
    } finally {
      agent.close().catch(() => {});
    }
  }
}
