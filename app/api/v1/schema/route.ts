import { z } from "zod";
import { NextResponse } from "next/server";
import { AdvisoryRecord, SCHEMA_VERSION } from "@/intel/schema";

export const dynamic = "force-static";

export function GET() {
  return NextResponse.json(
    { schema_version: SCHEMA_VERSION, advisory: z.toJSONSchema(AdvisoryRecord, { io: "output" }) },
    { headers: { "access-control-allow-origin": "*", "cache-control": "public, s-maxage=3600" } },
  );
}
