import {NextResponse} from 'next/server';
import {ERROR_AREAS} from '@/lib/monitoring/policy';
import {recordError} from '@/lib/monitoring/server';
import {rateLimit} from '@/lib/rate';
export const maxDuration=10;
const reply=(status:number)=>new NextResponse(null,{status,headers:{'cache-control':'private, no-store'}});
export async function POST(req:Request){
  // Anonymous diagnostics are untrusted; they never grant access or mark a system safe.
  if(req.headers.get('origin')!==new URL(req.url).origin)return reply(403);
  if(!req.headers.get('content-type')?.startsWith('application/json'))return reply(415);
  const reader=req.body?.getReader();if(!reader)return reply(400);
  let bytes=0,body='';const decoder=new TextDecoder();
  for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.length;if(bytes>128){await reader.cancel();return reply(413);}body+=decoder.decode(value,{stream:true});}
  let data;try{data=JSON.parse(body);}catch{return reply(400);}
  if(!data||typeof data!=="object"||Array.isArray(data))return reply(400);
  try {
    if(Object.keys(data).length!==1||!ERROR_AREAS.includes(data.area))return reply(400);
    // Aggregate cap bounds storage without collecting IP addresses or identifiers.
    await rateLimit('browser-error-ingest',30,60);
    await recordError(data.area,'browser');return reply(204);
  }catch{return reply(429);}
}
