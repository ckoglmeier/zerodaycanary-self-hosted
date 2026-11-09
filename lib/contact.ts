import "server-only";
import { q } from "./db";
import { HttpError } from "./auth";

export const VOLUME_THRESHOLD = 26;

export type ContactInput = { topic: string; name: string; email: string; organization?: string; systems?: string; message?: string; website?: string };

// Validates and stores a contact request. `website` is a honeypot field humans never see.
export async function saveContact(f: ContactInput) {
  if (f.website) return { stored: false }; // bot: accept silently, store nothing
  const name = (f.name ?? "").trim();
  const email = (f.email ?? "").trim();
  const organization = (f.organization ?? "").trim();
  const message = (f.message ?? "").trim();
  const topic = f.topic === "volume" ? "volume" : "general";
  if (!name || name.length > 120) throw new HttpError(400, "Enter your name.");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 254) throw new HttpError(400, "Enter a valid email address so we can reply.");
  if (organization.length > 160) throw new HttpError(400, "Organization name is too long.");
  if (message.length > 4000) throw new HttpError(400, "Message is too long (4,000 characters max).");
  let systems: number | null = null;
  if (f.systems && f.systems.trim()) {
    systems = Number(f.systems);
    if (!Number.isInteger(systems) || systems < 1 || systems > 100000) throw new HttpError(400, "Enter the number of systems as a whole number.");
  }
  await q("insert into contact_requests (topic, name, email, organization, systems_estimate, message) values ($1,$2,$3,$4,$5,$6)", [
    topic, name, email, organization || null, systems, message || null,
  ]);
  return { stored: true };
}
