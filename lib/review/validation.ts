import { z } from "zod";

export const idSchema = z.string().uuid();
export const emailSchema = z.string().trim().toLowerCase().max(254).email();
export const answerSchema = z.object({
  outcome: z.enum(["not_affected", "affected", "unknown"]),
  reason: z.string().trim().min(1, "Give a brief reason or describe what is still unknown.").max(2000),
  remediation_plan: z.string().trim().max(2000).optional().default(""),
  target_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).or(z.literal("")).optional().default(""),
  date_pending: z.boolean().default(false),
  evidence_note: z.string().trim().max(4000).optional().default(""),
  client_key: idSchema,
}).superRefine((v, ctx) => {
  if (v.outcome === "affected" && !v.remediation_plan) ctx.addIssue({ code: "custom", path: ["remediation_plan"], message: "Add a fix plan." });
  if (v.outcome === "affected" && !v.target_date && !v.date_pending) ctx.addIssue({ code: "custom", path: ["target_date"], message: "Choose a target date or say it is being determined." });
  if (v.target_date && (Number.isNaN(Date.parse(v.target_date)) || new Date(`${v.target_date}T12:00:00Z`).toISOString().slice(0, 10) !== v.target_date))
    ctx.addIssue({ code: "custom", path: ["target_date"], message: "Use a valid date." });
});

export const WORKFLOW_LABEL: Record<string, string> = {
  check_required: "Check required", owner_not_affected: "Owner confirmed: not affected by this alert",
  owner_affected: "Owner confirmed: affected", unknown: "Needs more evidence", fix_reported: "Fix reported · Evidence needed",
  no_match_in_report: "No match in the checked evidence", withdrawn: "Alert withdrawn",
};
