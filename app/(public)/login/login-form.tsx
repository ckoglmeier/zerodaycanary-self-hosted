"use client";
import { useState } from "react";
import { createBrowserClient } from "@supabase/ssr";

import {reportBrowserError} from "@/lib/monitoring/client";

export function LoginForm({ next }: { next: string }) {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "sent" | "error">("idle");
  const [error, setError] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setState("sending");
    setError("");
    const sb = createBrowserClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
    try {
    const { error } = await sb.auth.signInWithOtp({
      email,
      options: { emailRedirectTo: `${window.location.origin}/auth/callback?next=${encodeURIComponent(next)}` },
    });
    if (error) {
      reportBrowserError("login");
      setState("error");
      setError(error.message);
    } else setState("sent");
    } catch {
      reportBrowserError("login");
      setState("error");
      setError("Could not send the link. Please try again.");
    }
  }

  if (state === "sent")
    return (
      <div className="notice n-success" role="status">
        Check {email} for a sign-in link. It expires in one hour.
      </div>
    );
  return (
    <form onSubmit={submit} className="panel stack" noValidate={false}>
      <div>
        <label htmlFor="email">Work email</label>
        <input id="email" type="email" required autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} aria-describedby={error ? "email-err" : undefined} />
        {error ? (
          <p id="email-err" className="field-error" role="alert">
            {error}
          </p>
        ) : null}
      </div>
      <button className="btn btn-primary" type="submit" disabled={state === "sending"}>
        {state === "sending" ? "Sending link…" : "Email me a sign-in link"}
      </button>
    </form>
  );
}
