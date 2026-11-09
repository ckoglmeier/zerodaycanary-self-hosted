import Link from "next/link";
import { requireOperator } from "@/lib/auth";
import { accounts } from "@/lib/admin";
import { abs } from "@/components/time";

export const metadata = { title: "Accounts · Admin" };
export default async function Accounts({searchParams}:{searchParams:Promise<{q?:string;page?:string}>}) {
  const v=await requireOperator(),sp=await searchParams,page=Math.max(1,Math.min(10000,Number(sp.page)||1));
  const rows=await accounts(v,sp.q,page),next=rows.length>50;
  return <div className="stack" style={{["--gap" as string]:"24px"}}>
    <div><h1 className="h-page">Accounts</h1><p className="small muted">Review accounts and monitoring. Billing credits apply to future invoices.</p></div>
    <form method="get" className="panel inline-form"><div><label htmlFor="account-search">Find an account</label><input id="account-search" name="q" type="search" maxLength={200} defaultValue={sp.q||''} placeholder="Email, workspace or account ID"/></div><button className="btn btn-secondary">Search</button></form>
    <div className="table-wrap"><table className="t"><caption className="sr-only">Accounts, newest first</caption><thead><tr><th scope="col">Account</th><th scope="col">Workspace</th><th scope="col">Apps / projects</th><th scope="col">Subscription</th><th scope="col">Last sign-in</th></tr></thead><tbody>
      {rows.slice(0,50).map(a=><tr key={a.id}><td><Link href={`/operator/accounts/${a.id}`} className="wrap">{a.email||a.id}</Link><div className="small muted">{a.verified?'Email verified':'Email not verified'}</div></td><td>{a.name||'Not opened'}</td><td>{a.systems} / {a.projects}</td><td>{a.status||'None'}</td><td>{a.last_sign_in_at?abs(a.last_sign_in_at):'Never'}</td></tr>)}
      {!rows.length?<tr><td colSpan={5}>No accounts found.</td></tr>:null}
    </tbody></table></div>
    <nav className="row" aria-label="Account pages">{page>1?<Link href={`?q=${encodeURIComponent(sp.q||'')}&page=${page-1}`}>Previous</Link>:null}{next?<Link href={`?q=${encodeURIComponent(sp.q||'')}&page=${page+1}`}>Next</Link>:null}</nav>
    <p className="small"><Link href="/operator/communications">Email and billing branding</Link></p>
  </div>;
}
