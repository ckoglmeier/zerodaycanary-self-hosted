import { NextResponse } from "next/server";
import { getViewer } from "@/lib/auth";
import { userQ } from "@/lib/db";

export const dynamic = "force-dynamic";
export async function GET() {
  const v = await getViewer();
  const [workspace] = v ? await userQ<{name:string}>(v,"select name from workspaces where id=$1",[v.workspaceId]) : [];
  return NextResponse.json({ viewer: v ? { email:v.email, organization:workspace?.name||"Your workspace", isOperator:v.isOperator } : null }, {
    headers: { "cache-control":"private, no-store, max-age=0", "vary":"Cookie, Authorization" },
  });
}
