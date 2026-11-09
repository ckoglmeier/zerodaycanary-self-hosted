import {getSource} from '@/lib/source-feed';
import {sourceGet,sourceJson} from '@/lib/source-api';
import {HttpError} from '@/lib/auth';
export {sourceOptions as OPTIONS} from '@/lib/source-api';
export async function GET(req:Request,{params}:{params:Promise<{id:string}>}){return sourceGet(req,async()=>{
  const {id}=await params;if(id.length>100)throw new HttpError(400,'Identifier too long.');
  const r=await getSource(id);if(!r)throw new HttpError(404,'Source record not found.');
  return sourceJson(req,{feed_revision:r.record.feed_revision,sync_until:r.record.received_at,data:r.record});
});}
