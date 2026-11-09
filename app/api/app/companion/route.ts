import { readFile } from "node:fs/promises";
import { apiViewer,HttpError } from "@/lib/auth";
export const runtime='nodejs';
export async function GET(){try{await apiViewer();const bytes=await readFile(`${process.cwd()}/vendor/companion/zero-day-canary-skill.zip`);return new Response(bytes,{headers:{'content-type':'application/zip','content-disposition':'attachment; filename="zero-day-canary-skill.zip"','cache-control':'private, no-store','x-content-type-options':'nosniff'}});}catch(e){return Response.json({error:e instanceof HttpError?e.message:'Download unavailable'},{status:e instanceof HttpError?e.status:500});}}
