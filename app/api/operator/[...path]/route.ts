import { action, formOf } from "@/lib/http";
import { apiViewer, HttpError } from "@/lib/auth";
import { createIntake, publishDrafts, recordNoChanges, rejectDraft, updateDraft } from "@/lib/intake";
import { rateLimit } from "@/lib/rate";
import { q } from "@/lib/db";

export const maxDuration = 300;

const UUID = /^[0-9a-f-]{36}$/;

export const POST = action<{ path: string[] }>(async (req, { params }) => {
  const v = await apiViewer({ operator: true });
  const [kind, id, op] = params.path;

  if (kind === "intake" && !id) {
    const f = await formOf(req);
    const brief = (f.brief ?? "").trim();
    if (brief.length < 40) throw new HttpError(400, "Paste the full brief (at least a few sentences).");
    if (brief.length > 200_000) throw new HttpError(400, "The brief is too long; split it into parts.");
    await rateLimit(`intake:${v.id}`, 20, 3600);
    const r = await createIntake(brief, f.attribution?.trim() || null, v.email);
    return { redirect: `/operator/intake/${r.id}${r.duplicate ? "?msg=" + encodeURIComponent("This brief was already submitted; showing the existing intake.") : ""}`, json: r };
  }
  if (!id || !UUID.test(id)) throw new HttpError(404, "Not found.");

  if (kind === "intake" && op === "publish") {
    const f = await req.formData();
    const ids = f.getAll("draft").map(String).filter((x) => UUID.test(x));
    const r = await publishDrafts(id, ids, v.email, String(f.get("note") ?? ""),f.get('source_review_confirmed')==='on');
    if (!r.ok) throw new HttpError(400, r.problems.join(" "));
    return { redirect: `/operator/intake/${id}?msg=${encodeURIComponent(`Published catalog revision ${r.catalog_revision}. Re-matched ${r.rematch.systems} systems (${r.rematch.changed} changed).`)}`, json: r };
  }
  if (kind === "intake" && op === "no-changes") {
    const result = await recordNoChanges(id);
    if (!result.ok) throw new HttpError(400, result.problem);
    return { redirect: `/operator/intake/${id}?msg=${encodeURIComponent("Recorded: reviewed, no changes.")}` };
  }
  if (kind === "drafts" && op === "save") {
    const f = await formOf(req);
    let parsed: unknown;
    try {
      parsed = JSON.parse(f.draft ?? "");
    } catch {
      throw new HttpError(400, "The draft is not valid JSON.");
    }
    try {
      await updateDraft(id, parsed, f.target?.trim() || null);
    } catch (e) {
      throw new HttpError(400, `Draft does not match the schema: ${(e as Error).message.slice(0, 300)}`);
    }
    return { redirect: req.headers.get("referer") ?? "/operator" };
  }
  if (kind === "contacts" && op === "handled") {
    await q("update contact_requests set status = 'handled', handled_at = now() where id = $1 and status = 'new'", [id]);
    return { redirect: "/operator/contacts" };
  }
  if (kind === "drafts" && op === "reject") {
    const f = await formOf(req);
    await rejectDraft(id, f.note?.trim() ?? "");
    return { redirect: req.headers.get("referer") ?? "/operator" };
  }
  throw new HttpError(404, "Unknown action.");
});
