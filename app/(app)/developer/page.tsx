import Link from "next/link";
import { requireViewer } from "@/lib/auth";
import { userQ } from "@/lib/db";
import { Badge } from "@/components/badges";
import { When } from "@/components/time";
import { Submit } from "@/components/submit";


export const metadata = { title: "Developer projects", description: "Free, private checks of your app's npm dependencies against reviewed vulnerability alerts." };

export default async function Developer({ searchParams }: { searchParams: Promise<{ error?: string; request?: string }> }) {
  const v=await requireViewer("/developer");
  const sp = await searchParams;
  const [projects,events]=await Promise.all([
    userQ<{id:string;name:string;state:string;created_at:string;latest_evidence_id:string|null}>(v,'select id,name,state,created_at,latest_evidence_id from developer_projects where workspace_id=$1 and deleted_at is null order by created_at',[v.workspaceId]),
    userQ<{project_id:string}>(v,'select project_id from developer_events where workspace_id=$1 and seen_at is null',[v.workspaceId]),
  ]);
  const unseen = new Map<string, number>();
  for (const e of events ?? []) unseen.set(e.project_id, (unseen.get(e.project_id) ?? 0) + 1);
  return (
    <div className="stack" style={{ ["--gap" as string]: "24px" }}>
      <div className="stack prose" style={{ ["--gap" as string]: "8px" }}>
        <h1 className="h-page">Developer projects</h1>
        <p>Check known open-source package vulnerabilities, then share a reviewed report with clients. Your source and uploads stay private.</p>
        <p className="small muted">Free checks and monitoring across supported OSV ecosystems. Missing package, runtime and deployment evidence stays unknown. Notices appear here when your uploaded inventory has a new relevant finding.</p>
      </div>
      {sp.error ? <p className="notice n-danger" role="alert">{sp.error}</p> : null}
      <p><Link href={sp.request?`/developer/skill?request=${sp.request}`:"/developer/skill"}>Get the Canary companion skill</Link></p>
      <form method="post" action="/api/app/developer/projects" className="panel inline-form">
        <input type="hidden" name="return_to_request" value={sp.request||''}/><div>
          <label htmlFor="name">App or project name</label>
          <input id="name" name="name" type="text" required maxLength={120} placeholder="e.g. course-portal frontend" />
        </div>
        <Submit busy="Creating…">Build a report</Submit>
      </form>
      {(projects ?? []).length === 0 ? (
        <div className="panel empty stack" style={{ ["--gap" as string]: "12px" }}>
          <img src="/brand/canary-160.png" alt="" width={72} height={72} style={{ margin: "0 auto" }} />
          <p>Name your app to get the skill and build its first report.</p>
        </div>
      ) : (
        <ul className="list">
          {(projects ?? []).map((p) => (
            <li key={p.id} className="spread">
              <div className="stack" style={{ ["--gap" as string]: "4px" }}>
                <Link href={`/developer/${p.id}${sp.request?`?request=${sp.request}`:''}`} style={{ fontWeight: 600 }}>
                  {p.name}
                </Link>
                <span className="small muted">
                  Created <When at={p.created_at} /> · {p.latest_evidence_id ? "inventory uploaded" : "no inventory yet"}
                </span>
              </div>
              <div className="row">
                {unseen.get(p.id) ? <Badge tone="warning">{unseen.get(p.id)} new notice{unseen.get(p.id)! > 1 ? "s" : ""}</Badge> : null}
                <Badge tone={p.state === "active" ? "brand" : "neutral"}>{p.state === "active" ? "Free monitoring on" : p.state === "paused" ? "Paused" : "Not enrolled"}</Badge>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
