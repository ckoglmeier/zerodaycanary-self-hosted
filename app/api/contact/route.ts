import { action, formOf } from "@/lib/http";
import { saveContact } from "@/lib/contact";
import { rateLimit } from "@/lib/rate";

// Public: no sign-in needed. Rate limited per client address; stores the request only.
export const POST = action(async (req) => {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "anon";
  await rateLimit(`contact:${ip}`, 5, 3600);
  const f = await formOf(req);
  await saveContact({ topic: f.topic, name: f.name, email: f.email, organization: f.organization, systems: f.systems, message: f.message, website: f.website });
  return { redirect: "/contact?sent=1", json: { ok: true } };
});
