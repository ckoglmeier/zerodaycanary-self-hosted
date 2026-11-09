import { action } from "@/lib/http";
import { apiViewer, HttpError } from "@/lib/auth";
import { addAndAnalyze } from "@/lib/systems";
import {overviewForm,parseOverview,saveOverview} from '@/lib/system-overview';
import {rateLimit} from '@/lib/rate';

export const maxDuration = 60;

export const POST = action(async (req) => {
  const v = await apiViewer();
  const f = await overviewForm(req);
  if (!f.url?.trim()) throw new HttpError(400, "Enter a web address.");
  if(f.file?.size||f.notes)await rateLimit(`overview:${v.id}`,20,3600);
  const overview=await parseOverview(f.notes,f.file);
  const r = await addAndAnalyze(v, f.url);
  if(overview)await saveOverview(v,r.systemId,overview);
  return { redirect: `/systems/${r.systemId}${r.cached ? "?msg=" + encodeURIComponent("Showing a previous check of this address. Re-analyze for a fresh check.") : ""}`, json: r };
});
