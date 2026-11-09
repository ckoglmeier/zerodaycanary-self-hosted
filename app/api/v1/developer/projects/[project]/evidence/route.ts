// POST /api/v1/developer/projects/{project_id}/evidence — companion CLI submission.
// Contract: zero-day-canary-skill/docs/API-CONTRACT.md. Auth and scope are checked before
// the body is read; the body is validated without executing anything in it.
import { authorizeBearer, ApiError } from "@/lib/developer/tokens";
import { acceptEvidence } from "@/lib/developer/evidence";
import { apiFail, apiJson, readBounded, UUID } from "@/lib/developer/http";
import { rateLimit } from "@/lib/rate";

export const maxDuration = 60;

export async function POST(req: Request, { params }: { params: Promise<{ project: string }> }) {
  try {
    const { project } = await params;
    if (!UUID.test(project)) {
      // Still authenticate first so an unauthenticated probe cannot distinguish routes.
      if (!/^Bearer /.test(req.headers.get("authorization") ?? "")) throw new ApiError(401, "unauthorized");
      throw new ApiError(404, "not_found");
    }
    const token = await authorizeBearer(req.headers.get("authorization"), project, "evidence:write");
    if (!/^application\/json(\s*;\s*charset=utf-8)?$/i.test(req.headers.get("content-type") ?? "")) throw new ApiError(415, "unsupported_media_type");
    const key = req.headers.get("idempotency-key") ?? "";
    if (!/^[a-f0-9]{64}$/.test(key)) throw new ApiError(400, "invalid_idempotency_key");
    await rateLimit(`dev-upload:${token.id}`, 60, 3600);
    const bytes = await readBounded(req);
    const r = await acceptEvidence({ workspaceId: token.workspace_id, projectId: project, key, bytes, via: "api", by: `token:${token.id}` });
    return apiJson(r.receipt, r.created ? 201 : 200);
  } catch (e) {
    return apiFail(e);
  }
}
