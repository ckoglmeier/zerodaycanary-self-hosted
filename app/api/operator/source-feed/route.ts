import {action} from '@/lib/http';
import {apiViewer,HttpError} from '@/lib/auth';
import {rateLimit} from '@/lib/rate';
import {importSourceCsv} from '@/lib/source-feed';
import {MAX_SOURCE_BYTES,SourceInputError} from '@/intel/source-feed';
export const maxDuration=300;
export const POST=action(async(req)=>{
  const v=await apiViewer({operator:true});await rateLimit(`source-import:${v.id}`,20,3600);
  // Bound a chunked request too, before parsing multipart data into memory.
  const reader=req.body?.getReader();if(!reader)throw new HttpError(400,'Choose a CSV file.');
  const chunks:Uint8Array[]=[];let size=0;
  while(true){const r=await reader.read();if(r.done)break;size+=r.value.length;if(size>MAX_SOURCE_BYTES+65536){await reader.cancel();throw new HttpError(413,'CSV must be at most 5 MiB.');}chunks.push(r.value);}
  const f=await new Request(req.url,{method:'POST',headers:{'content-type':req.headers.get('content-type')??''},body:Buffer.concat(chunks)}).formData().catch(()=>{throw new HttpError(400,'Upload a CSV file.');});
  const file=f.get('file');if(!(file instanceof File)||!file.size)throw new HttpError(400,'Choose a nonempty CSV file.');
  if(file.size>MAX_SOURCE_BYTES)throw new HttpError(413,'CSV must be at most 5 MiB.');
  try{const r=await importSourceCsv(await file.text(),file.name,v.email);return {json:r,redirect:'/operator/feed?msg='+encodeURIComponent(`${r.rows} rows received; ${r.changed} new or changed. ${r.duplicate?'This file was already imported. ':''}Priority alerts and matching are unchanged until review.`)};}
  catch(e){if(e instanceof SourceInputError)throw new HttpError(400,e.message);throw e;}
});
