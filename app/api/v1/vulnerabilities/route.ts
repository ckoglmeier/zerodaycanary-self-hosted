import {listSources} from '@/lib/source-feed';
import {sourceGet,sourceJson,sourceQuery} from '@/lib/source-api';
export {sourceOptions as OPTIONS} from '@/lib/source-api';
export async function GET(req:Request){return sourceGet(req,async()=>{
  const u=new URL(req.url),p=sourceQuery(u),r=await listSources(p);
  const next=r.next_cursor?(()=>{const n=new URL(u);n.searchParams.set('cursor',r.next_cursor!);return n.pathname+n.search;})():null;
  return sourceJson(req,{...r,next});
});}
