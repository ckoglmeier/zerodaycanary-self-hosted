// GET /api/v1/developer/projects/{project_id}/evidence/{evidence_id} — private, no-store.
import { authorizeBearer, ApiError } from "@/lib/developer/tokens";
import { orderedReceipt, readEvidence } from "@/lib/developer/evidence";
import { apiFail, apiJson, UUID } from "@/lib/developer/http";

export async function GET(req: Request, { params }: { params: Promise<{ project: string; evidence: string }> }) {
  try {
    const { project, evidence } = await params;
    if (!UUID.test(project)) {
      if (!/^Bearer /.test(req.headers.get("authorization") ?? "")) throw new ApiError(401, "unauthorized");
      throw new ApiError(404, "not_found");
    }
    const token = await authorizeBearer(req.headers.get("authorization"), project, "evidence:read");
    const row = await readEvidence(token.workspace_id, project, evidence);
    if (!row) throw new ApiError(404, "not_found");
    return apiJson({ receipt: orderedReceipt(row.receipt), bundle: JSON.parse(row.canonical_body) }, 200);
  } catch (e) {
    return apiFail(e);
  }
}
