import "server-only";
import { createHash } from "node:crypto";
import { NextResponse } from "next/server";
import { SCHEMA_VERSION } from "@/intel/schema";
import { catalogMeta } from "./catalog";

// JSON response with catalog-revision validators so clients and the CDN can revalidate cheaply.
export async function cachedJson(req: Request, body: unknown, status = 200) {
  const meta = await catalogMeta();
  const payload = JSON.stringify({ schema_version: SCHEMA_VERSION, catalog_revision: meta.catalog_revision, ...(body as object) });
  const etag = `"${createHash("sha256").update(payload).digest("base64url").slice(0, 27)}"`;
  const lastModified = new Date(meta.catalog_updated_at ?? 0).toUTCString();
  const headers = {
    "content-type": "application/json; charset=utf-8",
    etag,
    "last-modified": lastModified,
    // No shared CDN cache: publication must be visible immediately and match the page.
    // Clients still get cheap 304s through ETag / Last-Modified.
    "cache-control": "public, max-age=0, must-revalidate",
    "x-catalog-revision": String(meta.catalog_revision),
    "access-control-allow-origin": "*",
  };
  const inm = req.headers.get("if-none-match");
  const ims = req.headers.get("if-modified-since");
  if (status === 200 && (inm === etag || (!inm && ims && meta.catalog_updated_at && new Date(ims).getTime() >= Math.floor(new Date(meta.catalog_updated_at).getTime() / 1000) * 1000)))
    return new NextResponse(null, { status: 304, headers });
  return new NextResponse(payload, { status, headers });
}

export function apiError(status: number, code: string, message: string) {
  return NextResponse.json({ error: { code, message } }, { status, headers: { "access-control-allow-origin": "*" } });
}
