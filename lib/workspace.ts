import "server-only";
import {z} from "zod";
import {HttpError,type Viewer} from "./auth";
import {userQ} from "./db";

export const workspaceName=z.string().trim().min(2,"Enter your team or organization name.").max(120,"Use at most 120 characters.").refine(s=>!/[\u0000-\u001f\u007f]/.test(s),"Use a single line for the organization name.");

export async function renameWorkspace(v:Viewer,input:unknown){
  const result=workspaceName.safeParse(input);
  if(!result.success)throw new HttpError(400,result.error.issues[0].message);
  const rows=await userQ<{id:string}>(v,"update workspaces set name=$2 where id=$1 returning id",[v.workspaceId,result.data]);
  if(!rows.length)throw new HttpError(404,"Workspace not found.");
}
