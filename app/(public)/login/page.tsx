import { LoginForm } from "./login-form";
import { getViewer } from "@/lib/auth";
import { safeReturnTo } from "@/lib/navigation";
import Link from "next/link";

export const metadata = { title: "Sign in" };

export default async function Login({ searchParams }: { searchParams: Promise<{ next?: string; error?: string }> }) {
  const sp = await searchParams;
  const next = safeReturnTo(sp.next);
  const viewer = await getViewer();
  if (viewer) return <section className="stack panel prose" style={{margin:"32px auto"}}><h1 className="h-page">You’re signed in</h1><p>Continue as <strong className="wrap">{viewer.email}</strong>.</p><div><Link href={next === "/login" ? "/systems" : next} className="btn btn-brand">Continue</Link></div><form method="post" action="/auth/signout"><button className="btn btn-secondary">Sign out to use another account</button></form></section>;
  return (
    <div className="stack" style={{ maxWidth: 440, margin: "32px auto", ["--gap" as string]: "16px" }}>
      <h1 className="h-page">Sign in</h1>
      <p className="muted">We&rsquo;ll email you a sign-in link. New addresses get a workspace automatically.</p>
      {sp.error ? <p className="notice n-danger">That sign-in link is invalid or has expired. Request a new one.</p> : null}
      <LoginForm next={next} />
    </div>
  );
}
