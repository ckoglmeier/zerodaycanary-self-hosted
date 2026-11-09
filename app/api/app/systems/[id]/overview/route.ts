import {apiViewer,HttpError} from '@/lib/auth';
import {action} from '@/lib/http';
import {ownSystem} from '@/lib/systems';
import {overviewForm,parseOverview,saveOverview,removeOverview,systemOverview} from '@/lib/system-overview';
import {rateLimit} from '@/lib/rate';

export const maxDuration=60;
export const POST=action(async(req,{params})=>{
  const v=await apiViewer();await ownSystem(v,params.id);
  await rateLimit(`overview:${v.id}`,20,3600);
  const f=await overviewForm(req),input=await parseOverview(f.notes,f.file);
  if(!input)throw new HttpError(400,'Add a document or paste some notes.');
  await saveOverview(v,params.id,input);
  return {redirect:`/systems/${params.id}?msg=Technology+overview+saved.#technology-overview`,json:{overview:await systemOverview(v,params.id)}};
});
export const DELETE=action(async(_req,{params})=>{
  const v=await apiViewer();await removeOverview(v,params.id);
  return {json:{ok:true}};
});
