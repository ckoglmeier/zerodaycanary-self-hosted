import {apiViewer,HttpError} from "@/lib/auth";
import {action,formOf} from "@/lib/http";
import {renameWorkspace} from "@/lib/workspace";
import {rateLimit} from "@/lib/rate";

export const POST=action(async req=>{
  const v=await apiViewer();
  const f=await formOf(req).catch(()=>{throw new HttpError(400,"Enter your organization name.");});
  await rateLimit(`workspace-name:${v.id}`,30,3600);
  await renameWorkspace(v,f?.name);
  return {redirect:"/account?saved=1"};
});
