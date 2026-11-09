import "server-only";
import { one, q } from "../db";
import { HttpError, type Viewer } from "../auth";

export type Project = { id: string; workspace_id: string; name: string; state: "pending" | "active" | "paused"; latest_evidence_id: string | null; created_at: Date; enrolled_at: Date | null };

export async function ownProject(v: Viewer, id: string): Promise<Project> {
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new HttpError(404, "Project not found.");
  const p = await one<Project>("select * from developer_projects where id = $1 and workspace_id = $2 and deleted_at is null", [id, v.workspaceId]);
  if (!p) throw new HttpError(404, "Project not found.");
  return p;
}

export async function createProject(v: Viewer, name: string) {
  const n = name.trim().slice(0, 120);
  if (!n) throw new HttpError(400, "Name the project.");
  const count = await one<{ n: string }>("select count(*) n from developer_projects where workspace_id = $1 and deleted_at is null", [v.workspaceId]);
  // Free quota is a soft limit only; it never creates a charge.
  if (Number(count?.n ?? 0) >= Number(process.env.DEVELOPER_PROJECT_LIMIT ?? 25)) throw new HttpError(400, "Free project limit reached. Delete a project or contact us.");
  return (await one<{ id: string }>("insert into developer_projects (workspace_id, name) values ($1,$2) returning id", [v.workspaceId, n]))!.id;
}

export async function setProjectState(v: Viewer, id: string, action: "enroll" | "pause" | "resume" | "delete") {
  const p = await ownProject(v, id);
  if (action === "enroll") {
    if (!p.latest_evidence_id) throw new HttpError(400, "Upload and review an inventory before starting monitoring.");
    await q("update developer_projects set state = 'active', enrolled_at = coalesce(enrolled_at, now()) where id = $1 and workspace_id = $2", [id, v.workspaceId]);
  } else if (action === "pause") await q("update developer_projects set state = 'paused' where id = $1 and workspace_id = $2", [id, v.workspaceId]);
  else if (action === "resume") await q("update developer_projects set state = 'active' where id = $1 and workspace_id = $2 and enrolled_at is not null", [id, v.workspaceId]);
  else {
    await q("update developer_project_tokens set revoked_at = coalesce(revoked_at, now()) where project_id = $1 and workspace_id = $2", [id, v.workspaceId]);
    await q("update developer_projects set deleted_at = now(), state = 'paused' where id = $1 and workspace_id = $2", [id, v.workspaceId]);
  }
}
