import { requireViewer } from "@/lib/auth";
import {userQ} from "@/lib/db";
import {Submit} from "@/components/submit";
import Link from "next/link";

export const metadata = { title: "Account" };

export default async function Account({searchParams}:{searchParams:Promise<{error?:string;saved?:string}>}) {
  const v = await requireViewer("/account");
  const sp=await searchParams;
  const workspace=(await userQ<{name:string}>(v,'select name from workspaces where id=$1',[v.workspaceId]))[0];
  return (
    <div className="stack" style={{ maxWidth: 640, ["--gap" as string]: "16px" }}>
      <h1 className="h-page">Account</h1>
      <p>Signed in as <strong className="wrap">{v.email}</strong></p>
      <nav className="nav" aria-label="Account"><Link href="/billing">Billing and credits</Link><Link href="/pricing">Pricing</Link>{v.isOperator?<Link href="/operator/accounts">Administration</Link>:null}</nav>
      {sp.error?<p className="notice n-danger" role="alert">{sp.error}</p>:null}
      {sp.saved==='1'?<p className="notice n-success" role="status">Organization name saved.</p>:null}
      <form method="post" action="/api/app/account" className="panel stack">
        <div><label htmlFor="workspace-name">Organization name</label><input id="workspace-name" name="name" required minLength={2} maxLength={120} defaultValue={workspace?.name||''} autoComplete="organization" aria-describedby="workspace-name-hint"/><p id="workspace-name-hint" className="hint">Shown to developers when you request a check.</p></div>
        <Submit busy="Saving…">Save name</Submit>
      </form>
      <section className="panel stack">
        <details><summary>Account details for support</summary><dl className="facts"><dt>Workspace ID</dt><dd className="mono">{v.workspaceId}</dd><dt>Role</dt><dd>Owner{v.isOperator ? " · administrator" : ""}</dd></dl></details>
        <form method="post" action="/auth/signout">
          <button className="btn btn-secondary" type="submit">
            Sign out
          </button>
        </form>
      </section>
    </div>
  );
}
