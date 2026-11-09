import { NextResponse } from "next/server";
import { action } from "@/lib/http";
import { apiViewer, HttpError } from "@/lib/auth";
import { portalUrl, subscriptionFor, startMonitoringCart } from "@/lib/billing";
import { q } from "@/lib/db";

export const POST = action(async (_req, { params }) => {
  const v = await apiViewer();
  if(params.op==='checkout'){
    const data=await _req.json().catch(()=>null);
    if(!data||!Array.isArray(data.systems)||typeof data.nonprofit!=='boolean'||typeof data.client_key!=='string')throw new HttpError(400,'Choose apps and confirm the monitoring plan.');
    const result=await startMonitoringCart(v.workspaceId,v.id,v.email,data.systems,data.nonprofit,data.client_key);
    return {redirect:result.checkoutUrl||'/billing',json:result};
  }
  if (params.op !== "portal") throw new HttpError(404, "Unknown action.");
  const url = await portalUrl(v.workspaceId);
  if (!url) throw new HttpError(400, "No billing account yet. Start monitoring a system first.");
  return { redirect: url };
});

// Polled by the confirmation page. Reflects webhook-written state only.
export async function GET(_req: Request, { params }: { params: Promise<{ op: string }> }) {
  if ((await params).op !== "status") return NextResponse.json({ error: "not found" }, { status: 404 });
  try {
    const v = await apiViewer();
    const [sub, systems] = await Promise.all([
      subscriptionFor(v.workspaceId),
      q<{ id: string; label: string; monitoring: string }>("select id, label, monitoring from systems where workspace_id = $1 and removed_at is null and monitoring <> 'none' order by created_at", [v.workspaceId]),
    ]);
    return NextResponse.json({ subscription: sub ? { status: sub.status, quantity: sub.quantity } : null, systems }, { headers: { "cache-control": "no-store" } });
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: e instanceof HttpError ? e.status : 500 });
  }
}
