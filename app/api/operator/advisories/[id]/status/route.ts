import { action, formOf } from "@/lib/http";
import { apiViewer, HttpError } from "@/lib/auth";
import { changeStatus } from "@/lib/intake";

export const maxDuration = 120;

export const POST = action(async (req, { params }) => {
  const v = await apiViewer({ operator: true });
  const f = await formOf(req);
  if (!["withdrawn", "superseded", "published"].includes(f.status)) throw new HttpError(400, "Choose a status.");
  if (!f.note?.trim()) throw new HttpError(400, "Give a reason for the change.");
  const rev = await changeStatus(params.id, f.status as "withdrawn" | "superseded" | "published", f.note.trim(), v.email);
  return { redirect: `/operator?msg=${encodeURIComponent(`${params.id} → ${f.status} (catalog revision ${rev}).`)}` };
});
