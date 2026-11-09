import {action} from '@/lib/http';
import {apiViewer} from '@/lib/auth';
import {sourceReviewDraft} from '@/lib/source-feed';
export const POST=action<{id:string}>(async(_req,{params})=>{
  const v=await apiViewer({operator:true}),id=await sourceReviewDraft(params.id,v.email);
  return {redirect:`/operator/intake/${id}`,json:{intake_id:id}};
});
