// A11: fetch safety and error handling against a controlled local fixture server.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { FetchBlocked, isPublicAddress, safeFetch, validateUrl } from "../lib/scan/net";
import { scanUrl } from "../lib/scan/scan";
import { canonicalize } from "../lib/scan/canonical";

let server: http.Server;
let base = "";
const loopbackOnly = { addressPolicy: (a: string) => a === "127.0.0.1", allowAnyPort: true };

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const u = req.url ?? "/";
    if (u === "/slow") return void setTimeout(() => res.end("late"), 3000);
    if (u === "/big") {
      res.setHeader("content-type", "text/html");
      return void res.end("<html>" + "a".repeat(3_000_000));
    }
    if (u === "/denied") return void res.writeHead(403).end("no");
    if (u === "/offsite") return void res.writeHead(302, { location: "https://elsewhere.example.org/" }).end();
    if (u === "/to-metadata") return void res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" }).end();
    if (u === "/loop") return void res.writeHead(302, { location: "/loop" }).end();
    if (u === "/json") {
      res.setHeader("content-type", "application/json");
      return void res.end("{}");
    }
    if (u === "/wp") {
      res.setHeader("content-type", "text/html");
      res.setHeader("set-cookie", ["PHPSESSID=secretvalue; Path=/"]);
      return void res.end('<html><meta name="generator" content="WordPress 6.8.1"><link href="/wp-content/x.css"></html>');
    }
    res.setHeader("content-type", "text/html");
    res.setHeader("x-powered-by", "PHP/8.2.20");
    res.end("<html><body>ok</body></html>");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => server.close());

describe("address policy", () => {
  it.each(["127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"])(
    "blocks %s",
    (a) => expect(isPublicAddress(a)).toBe(false),
  );
  it.each(["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"])("allows %s", (a) => expect(isPublicAddress(a)).toBe(true));
});

describe("URL validation", () => {
  it.each([
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",
    "https://user:pass@example.com/",
    "ftp://example.com/",
    "https://example.com:8443/",
    "http://intranet/",
    "https://printer.local/",
    "file:///etc/passwd",
  ])("rejects %s", (u) => expect(() => validateUrl(u)).toThrow(FetchBlocked));
});

describe("DNS rebinding and private resolution", () => {
  it("rejects a public-looking name that resolves to a private address", async () => {
    await expect(safeFetch("https://rebind.attacker.net/", { resolve: async () => ["10.0.0.5"] })).rejects.toThrow(/private or reserved/);
  });
  it("rejects a mixed public/private answer", async () => {
    await expect(safeFetch("https://mixed.attacker.net/", { resolve: async () => ["93.184.216.34", "127.0.0.1"] })).rejects.toThrow(/private or reserved/);
  });
  it("scan of a private target is a failed scan, not a clean one", async () => {
    const r = await scanUrl("https://rebind.attacker.net/", { resolve: async () => ["192.168.0.10"] });
    expect(r.outcome).toBe("failed");
    expect(r.gaps[0].kind).toBe("blocked_target");
    expect(r.evidence.techs).toEqual([]);
  });
});

describe("controlled fixture responses", () => {
  it("times out safely", async () => {
    const r = await scanUrl(`${base}/slow`, { timeoutMs: 500, testOverrides: loopbackOnly });
    expect(r.outcome).toBe("failed");
    expect(["timeout", "fetch_failed"]).toContain(r.gaps[0].kind);
  });
  it("bounds oversized bodies and reports partial evidence", async () => {
    const r = await scanUrl(`${base}/big`, { testOverrides: loopbackOnly });
    expect(r.outcome).toBe("partial");
    expect(r.gaps.map((g) => g.kind)).toContain("too_large");
  });
  it("reports access denied as a gap", async () => {
    const r = await scanUrl(`${base}/denied`, { testOverrides: loopbackOnly });
    expect(r.outcome).toBe("failed");
    expect(r.gaps[0].kind).toBe("access_denied");
  });
  it("stops at an off-scope redirect", async () => {
    const r = await scanUrl(`${base}/offsite`, { testOverrides: loopbackOnly });
    expect(r.gaps[0].kind).toBe("redirect_out_of_scope");
  });
  it("revalidates redirect targets (metadata endpoint)", async () => {
    const r = await scanUrl(`${base}/to-metadata`, { testOverrides: { ...loopbackOnly }, sameHostOnly: false });
    expect(r.outcome).toBe("failed");
    expect(r.gaps[0].kind).toBe("blocked_target");
  });
  it("caps redirect loops", async () => {
    const r = await scanUrl(`${base}/loop`, { testOverrides: loopbackOnly });
    expect(r.outcome).toBe("failed");
  });
  it("non-HTML responses are partial with a gap", async () => {
    const r = await scanUrl(`${base}/json`, { testOverrides: loopbackOnly });
    expect(r.gaps.map((g) => g.kind)).toContain("not_html");
  });
  it("records header evidence with location and observed version", async () => {
    const r = await scanUrl(`${base}/`, { testOverrides: loopbackOnly });
    const php = r.evidence.techs.find((t) => t.product === "php")!;
    expect(php.version).toBe("8.2.20");
    expect(php.version_basis).toBe("observed");
    expect(php.location).toContain("X-Powered-By");
  });
  it("WordPress implies PHP without inventing a PHP version; cookie values are never stored", async () => {
    const r = await scanUrl(`${base}/wp`, { testOverrides: loopbackOnly });
    const php = r.evidence.techs.filter((t) => t.product === "php");
    expect(php.every((t) => t.version === null)).toBe(true);
    expect(r.evidence.techs.find((t) => t.product === "wordpress")?.version).toBe("6.8.1");
    expect(JSON.stringify(r)).not.toContain("secretvalue");
    expect(r.gaps.some((g) => g.kind === "version_hidden" && /PHP/.test(g.detail))).toBe(true);
  });
});

describe("canonical scope", () => {
  it("keeps tenant paths, drops query/fragment, does not merge www", () => {
    expect(canonicalize("Example.COM/").scopeKey).toBe("example.com");
    expect(canonicalize("https://www.example.com").scopeKey).toBe("www.example.com");
    expect(canonicalize("https://saas.example.com/tenant-a/?x=1#y").scopeKey).toBe("saas.example.com/tenant-a");
    expect(canonicalize("https://saas.example.com/tenant-b").scopeKey).not.toBe(canonicalize("https://saas.example.com/tenant-a").scopeKey);
    expect(canonicalize("https://example.com:443/a/").url).toBe("https://example.com/a");
  });
});
