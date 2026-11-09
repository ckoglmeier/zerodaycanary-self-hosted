import "server-only";
// Project-scoped bearer credentials for the companion CLI. Only a SHA-256 hash of a
// high-entropy token is stored; the raw token is shown once at issuance.
import { randomBytes } from "node:crypto";
import { one, q } from "../db";
import { sha256 } from "./bundle";

export type Scope = "evidence:read" | "evidence:write";
export type TokenRow = { id: string; project_id: string; workspace_id: string; scopes: Scope[]; expires_at: Date; revoked_at: Date | null };

export class ApiError extends Error {
  constructor(public status: number, public code: string) {
    super(code);
  }
}

export async function issueToken(workspaceId: string, projectId: string, scopes: Scope[], days: number, label: string | null) {
  const raw = "zdc_dev_" + randomBytes(32).toString("base64url");
  const row = await one<{ id: string; expires_at: Date }>(
    `insert into developer_project_tokens (project_id, workspace_id, token_hash, token_hint, scopes, label, expires_at)
     select $1, $2, $3, $4, $5, $6, now() + ($7 || ' days')::interval
     where exists (select 1 from developer_projects where id = $1 and workspace_id = $2 and deleted_at is null)
     returning id, expires_at`,
    [projectId, workspaceId, sha256(raw), raw.slice(-4), scopes, label, String(Math.min(Math.max(days, 1), 365))],
  );
  if (!row) throw new ApiError(404, "project_not_found");
  return { id: row.id, token: raw, expires_at: row.expires_at };
}

export async function revokeToken(workspaceId: string, tokenId: string) {
  await q("update developer_project_tokens set revoked_at = now() where id = $1 and workspace_id = $2 and revoked_at is null", [tokenId, workspaceId]);
}

// Validates before any body is read: 401 for missing/invalid/expired/revoked/wrong-scope
// credentials, 404 when a valid credential names a different project.
export async function authorizeBearer(header: string | null, projectId: string, scope: Scope): Promise<TokenRow> {
  const m = /^Bearer (zdc_dev_[A-Za-z0-9_-]{43})$/.exec(header ?? "");
  if (!m) throw new ApiError(401, "unauthorized");
  const t = await one<TokenRow>(
    `select t.id, t.project_id, t.workspace_id, t.scopes, t.expires_at, t.revoked_at from developer_project_tokens t
     join developer_projects p on p.id = t.project_id and p.workspace_id = t.workspace_id and p.deleted_at is null
     where t.token_hash = $1`,
    [sha256(m[1])],
  );
  if (!t || t.revoked_at || t.expires_at.getTime() <= Date.now()) throw new ApiError(401, "unauthorized");
  if (!t.scopes.includes(scope)) throw new ApiError(401, "insufficient_scope");
  if (t.project_id !== projectId) throw new ApiError(404, "not_found");
  await q("update developer_project_tokens set last_used_at = now() where id = $1", [t.id]);
  return t;
}
