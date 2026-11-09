import {action,formOf} from '@/lib/http';
import {apiViewer,HttpError} from '@/lib/auth';
import {setFeatured} from '@/lib/source-feed';
export const POST=action<{id:string}>(async(req,{params})=>{
  const v=await apiViewer({operator:true}),f=await formOf(req);
  if(!['true','false'].includes(f.featured))throw new HttpError(400,'Choose whether to feature this alert.');
  await setFeatured(params.id,f.featured==='true',f.reason??'',v.email);
  return {redirect:'/operator?msg='+encodeURIComponent('Priority selection saved. Matching coverage is unchanged.'),json:{ok:true}};
});
