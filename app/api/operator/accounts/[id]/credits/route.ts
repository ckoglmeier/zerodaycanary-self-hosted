import { apiViewer,HttpError } from "@/lib/auth";
import { action,formOf } from "@/lib/http";
import { grantCredit } from "@/lib/admin";
import { rateLimit } from "@/lib/rate";

export const POST=action<{id:string}>(async(req,{params})=>{
  const v=await apiViewer({operator:true});
  await rateLimit(`admin-credit:${v.id}`,30,3600);
  const input=await formOf(req).catch(()=>{throw new HttpError(400,"Enter a valid credit request.");});
  const result=await grantCredit(v,params.id,input);
  return {json:{id:result.id,state:result.state,amount_cents:result.amount_cents,currency:result.currency,livemode:result.livemode}};
});
