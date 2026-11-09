import { requireOperator } from "@/lib/auth";
import { q } from "@/lib/db";
import { abs } from "@/components/time";
import { Badge } from "@/components/badges";
import { Submit } from "@/components/submit";

export const metadata = { title: "Contact requests" };

type Row = { id: string; created_at: Date; topic: string; name: string; email: string; organization: string | null; systems_estimate: number | null; message: string | null; status: string };

export default async function Contacts() {
  await requireOperator();
  const rows = await q<Row>("select * from contact_requests order by status = 'new' desc, created_at desc limit 200");
  const open = rows.filter((r) => r.status === "new").length;
  return (
    <div className="stack" style={{ ["--gap" as string]: "24px" }}>
      <div className="stack" style={{ ["--gap" as string]: "6px" }}>
        <h1 className="h-page">Contact requests</h1>
        <p className="small muted">
          {open} new · Submitted through the website. You are not notified by email; check here and reply from your own inbox.
        </p>
      </div>
      <ul className="list">
        {rows.map((r) => (
          <li key={r.id} className="stack" style={{ ["--gap" as string]: "6px" }}>
            <div className="spread">
              <div style={{ display: "grid", gap: 2, minWidth: 0 }}>
                <strong className="wrap">
                  {r.name}
                  {r.organization ? `, ${r.organization}` : ""}
                </strong>
                <span className="small mono wrap">{r.email}</span>
              </div>
              <div className="row">
                <Badge tone={r.topic === "volume" ? "brand" : "neutral"}>{r.topic === "volume" ? "Volume" : "General"}</Badge>
                <Badge tone={r.status === "new" ? "warning" : "neutral"}>{r.status === "new" ? "New" : "Handled"}</Badge>
              </div>
            </div>
            <p className="small muted">
              {abs(r.created_at)}
              {r.systems_estimate ? ` · about ${r.systems_estimate.toLocaleString()} systems` : ""}
            </p>
            {r.message ? <p className="small wrap" style={{ whiteSpace: "pre-wrap" }}>{r.message}</p> : null}
            {r.status === "new" ? (
              <form method="post" action={`/api/operator/contacts/${r.id}/handled`}>
                <Submit className="btn btn-secondary" busy="Saving…">Mark handled</Submit>
              </form>
            ) : null}
          </li>
        ))}
        {rows.length === 0 ? <li className="muted">No requests yet.</li> : null}
      </ul>
    </div>
  );
}
