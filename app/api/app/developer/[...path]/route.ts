// Browser (cookie) routes for free developer projects. No route here touches billing.
import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { action, formOf } from "@/lib/http";
import { apiViewer, HttpError } from "@/lib/auth";
import { createProject, ownProject, setProjectState } from "@/lib/developer/projects";
import { issueToken, revokeToken, ApiError, type Scope } from "@/lib/developer/tokens";
import { acceptEvidence } from "@/lib/developer/evidence";
import {upgradeNpmInventory} from '@/lib/developer/upgrade-inventory';
import { packFromUpload, sha256 } from "@/lib/developer/bundle";
import { canonical, decodeUtf8, parseStrict, JsonRejected, MAX_BYTES } from "@/lib/developer/json";
import { q } from "@/lib/db";
import { rateLimit } from "@/lib/rate";
import { conversationAccess } from "@/lib/review/requests";

export const maxDuration = 60;

async function fileBytes(f: FormDataEntryValue | null): Promise<Uint8Array | null> {
  if (!f || typeof f === "string" || f.size === 0) return null;
  if (f.size > MAX_BYTES) throw new HttpError(413, "Each file must be at most 5 MiB.");
  return new Uint8Array(await f.arrayBuffer());
}
const parseFile = (b: Uint8Array, what: string) => {
  try {
    return parseStrict(decodeUtf8(b));
  } catch (e) {
    throw new HttpError(400, `${what} is not valid JSON within limits: ${(e as Error).message}`);
  }
};

export const POST = action<{ path: string[] }>(async (req, { params }) => {
  const v = await apiViewer();
  const [first, op] = params.path;
  if (first === "projects" && !op) {
    const f = await formOf(req);
    if(f.return_to_request)await conversationAccess(v,f.return_to_request);
    const id = await createProject(v, f.name ?? "");
    return { redirect: `/developer/${id}${f.return_to_request?'?request='+f.return_to_request:''}${f.from_guide?'#upload':''}`, json: { id } };
  }
  const p = await ownProject(v, first);
  const base = `/developer/${p.id}`;
  switch (op) {
    case "token": {
      const f = await formOf(req);
      const scopes = (["evidence:write", "evidence:read"] as Scope[]).filter((s) => f[s] === "on" || f.scopes?.includes(s));
      if (!scopes.length) throw new HttpError(400, "Choose at least one scope.");
      const t = await issueToken(v.workspaceId, p.id, scopes, Number(f.days ?? 90), f.label?.trim().slice(0, 80) || null);
      // Shown once: handed to the next page view in a short-lived, httpOnly, path-scoped cookie.
      (await cookies()).set("zdc_new_token", t.token, { httpOnly: true, secure: true, sameSite: "strict", path: base, maxAge: 120 });
      return { redirect: `${base}?msg=${encodeURIComponent("Token created. Copy it now; it will not be shown again.")}`, json: { id: t.id, token: t.token, expires_at: t.expires_at } };
    }
    case "revoke-token": {
      const f = await formOf(req);
      await revokeToken(v.workspaceId, f.token_id);
      return { redirect: `${base}?msg=${encodeURIComponent("Token revoked.")}` };
    }
    case "upload": {
      await rateLimit(`dev-web-upload:${v.id}`, 30, 3600);
      const form = await req.formData();
      const returnTo=String(form.get("return_to_request")||"");
      if(returnTo)await conversationAccess(v,returnTo);
      const bundleBytes = await fileBytes(form.get("bundle"));
      let bytes: Uint8Array;
      let via: "web_bundle" | "web_files";
      if (bundleBytes) {
        // A companion bundle: accepted only if already canonical (same rules as the API).
        bytes = bundleBytes;
        via = "web_bundle";
      } else {
        const lock = await fileBytes(form.get("lockfile"));
        const findings = await fileBytes(form.get("findings"));
        if (!lock && !findings) throw new HttpError(400, "Choose a Canary bundle, or an npm lockfile and/or a Cloudflare findings file.");
        try {
          const bundle = packFromUpload({
            repositoryId: String(form.get("repository") ?? "").trim() || "unnamed",
            lock: lock ? { value: parseFile(lock, "The lockfile"), bytes: lock } : null,
            findings: findings ? { value: parseFile(findings, "The findings file"), bytes: findings } : null,
            includeFindings: form.get("include_findings") === "on",
          });
          bytes = new TextEncoder().encode(canonical(upgradeNpmInventory(bundle,lock?parseFile(lock,'The lockfile'):null,form.get('public_package_lookups')==='on')));
        } catch (e) {
          if (e instanceof JsonRejected) throw new HttpError(400, `The files were not accepted: ${e.message}`);
          throw e;
        }
        via = "web_files";
      }
      try {
        const r = await acceptEvidence({ workspaceId: v.workspaceId, projectId: p.id, key: sha256(bytes), bytes, via, by: `user:${v.id}` });
        if(form.get('start_monitoring')==='on'&&p.state==='pending')await setProjectState(v,p.id,'enroll');
        return { redirect: `${base}?${returnTo?'request='+returnTo+'&':''}msg=${encodeURIComponent(r.created ? "Report received privately. Review it before sharing." : "This exact report was already uploaded; showing the existing revision.")}#review-share`, json: r.receipt };
      } catch (e) {
        if (e instanceof ApiError) throw new HttpError(e.status === 422 ? 400 : e.status, e.code === "invalid_evidence" ? "The report did not pass validation. Use the current Canary skill to generate a canonical report with supported, current advisory targets." : `Upload refused (${e.code}).`);
        throw e;
      }
    }
    case "enroll":
    case "pause":
    case "resume":
    case "delete":
      await setProjectState(v, p.id, op);
      return { redirect: op === "delete" ? "/developer" : `${base}?msg=${encodeURIComponent(op === "enroll" ? "Free monitoring started." : op === "pause" ? "Monitoring paused." : "Monitoring resumed.")}` };
    case "seen":
      await q("update developer_events set seen_at = now() where project_id = $1 and workspace_id = $2 and seen_at is null", [p.id, v.workspaceId]);
      return { redirect: base };
    default:
      throw new HttpError(404, "Unknown action.");
  }
});

// Private export of every revision the owner uploaded (account-owned data control).
export async function GET(_req: Request, { params }: { params: Promise<{ path: string[] }> }) {
  try {
    const v = await apiViewer();
    const [id, op] = (await params).path;
    if (op !== "export") throw new HttpError(404, "Not found.");
    const p = await ownProject(v, id);
    const rows = await q<{ id: string; received_at: Date; receipt: unknown; canonical_body: string }>(
      "select id, received_at, receipt, canonical_body from developer_evidence where project_id = $1 and workspace_id = $2 order by received_at",
      [p.id, v.workspaceId],
    );
    const body = JSON.stringify({ project: { id: p.id, name: p.name, state: p.state }, revisions: rows.map((r) => ({ evidence_id: r.id, received_at: r.received_at, receipt: r.receipt, bundle: JSON.parse(r.canonical_body) })) }, null, 2);
    return new NextResponse(body, {
      headers: { "content-type": "application/json", "cache-control": "private, no-store", "content-disposition": `attachment; filename="zdc-project-${p.id}.json"` },
    });
  } catch (e) {
    const status = e instanceof HttpError ? e.status : 500;
    return NextResponse.json({ error: { message: e instanceof HttpError ? e.message : "error" } }, { status });
  }
}
