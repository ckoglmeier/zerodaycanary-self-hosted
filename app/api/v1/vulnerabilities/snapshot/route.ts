import {listSources} from '@/lib/source-feed';
import {sourceGet,sourceJson} from '@/lib/source-api';
import {HttpError} from '@/lib/auth';
export {sourceOptions as OPTIONS} from '@/lib/source-api';
export async function GET(req:Request){return sourceGet(req,async()=>{
  if(new URL(req.url).search)throw new HttpError(400,'Snapshot takes no parameters. Use the paginated endpoint for filters.');
  const r=await listSources({},true);const response=sourceJson(req,{...r,count:r.data.length,next:null});
  response.headers.set('content-disposition','attachment; filename="canary-source-feed.json"');return response;
});}
