import { publicMetadata } from '@/lib/discovery';
import Link from "next/link";
import { Submit } from "@/components/submit";
import { VOLUME_THRESHOLD } from "@/lib/contact";

export const metadata = { ...publicMetadata('/contact', "Zero Day Canary", "Vulnerability alerts and evidence-backed answers for your apps and vendors."), title: "Contact", description: "Get in touch about volume pricing or anything else." };

export default async function Contact({ searchParams }: { searchParams: Promise<{ topic?: string; sent?: string; error?: string }> }) {
  const sp = await searchParams;
  const volume = sp.topic === "volume";
  if (sp.sent)
    return (
      <div className="stack prose" style={{ ["--gap" as string]: "12px", maxWidth: 640 }}>
        <h1 className="h-page">Thanks, we have your message</h1>
        <p>We&rsquo;ll reply to the email address you gave us.</p>
        <p>
          <Link href="/pricing">Back to pricing</Link>
        </p>
      </div>
    );
  return (
    <div className="stack" style={{ ["--gap" as string]: "24px", maxWidth: 640 }}>
      <header className="stack prose" style={{ ["--gap" as string]: "8px" }}>
        <h1 className="h-page">{volume ? "Volume pricing" : "Contact us"}</h1>
        <p>
          {volume
            ? `Tell us roughly how many systems you look after. For ${VOLUME_THRESHOLD} or more, or a whole institution, we'll work out volume pricing and invoicing with you.`
            : "Send us a question and we'll reply by email."}
        </p>
      </header>
      {sp.error ? (
        <p className="notice n-danger" role="alert">
          {sp.error}
        </p>
      ) : null}
      <form method="post" action="/api/contact" className="panel stack" style={{ ["--gap" as string]: "16px" }}>
        <input type="hidden" name="topic" value={volume ? "volume" : "general"} />
        <div className="honeypot" aria-hidden="true">
          <label htmlFor="website">Leave this empty</label>
          <input id="website" name="website" type="text" tabIndex={-1} autoComplete="off" />
        </div>
        <div>
          <label htmlFor="name">Name</label>
          <input id="name" name="name" type="text" required maxLength={120} autoComplete="name" />
        </div>
        <div>
          <label htmlFor="email">Work email</label>
          <input id="email" name="email" type="email" required maxLength={254} autoComplete="email" />
        </div>
        <div>
          <label htmlFor="organization">School or organization</label>
          <input id="organization" name="organization" type="text" maxLength={160} autoComplete="organization" />
        </div>
        <div>
          <label htmlFor="systems">Roughly how many systems?{volume ? "" : " (optional)"}</label>
          <input id="systems" name="systems" type="text" inputMode="numeric" pattern="[0-9]*" required={volume} placeholder="e.g. 40" />
        </div>
        <div>
          <label htmlFor="message">Anything else we should know?</label>
          <textarea id="message" name="message" rows={5} maxLength={4000} placeholder="Departments involved, how you buy software, timing" />
        </div>
        <p className="hint">We use these details only to reply to you.</p>
        <Submit busy="Sending…">Send</Submit>
      </form>
    </div>
  );
}
