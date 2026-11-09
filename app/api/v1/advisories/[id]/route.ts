import { getAdvisory } from "@/lib/catalog";
import { apiError, cachedJson } from "@/lib/api-public";

// Accepts the stable id or any alias (CVE, GHSA, vendor id).
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const a = await getAdvisory(id);
  if (!a) return apiError(404, "not_found", "No alert with that id or alias.");
  return cachedJson(req, { data: a.record, history: a.history });
}
