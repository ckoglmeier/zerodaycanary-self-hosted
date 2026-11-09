// A targeted public CVE lookup; never a private-system query. The record is pinned
// by the companion and checked on authenticated report intake, not public reads.
import { z } from 'zod';
import { sha256 } from './developer/bundle';
const metadata=z.object({cveMetadata:z.object({cveId:z.string(),state:z.string()}).passthrough()}).passthrough();
export const cveUrl=(id:string)=>`https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`;
export async function cveRecord(id:string,fetcher=fetch,deadline=Date.now()+10000){
 if(!/^CVE-[0-9]{4}-[0-9]{4,}$/.test(id)||id.length>100)throw Error('Invalid CVE identifier');
 const response=await fetcher('https://cveawg.mitre.org/api/cve/'+id,{headers:{accept:'application/json'},redirect:'error',signal:AbortSignal.timeout(Math.max(1,Math.min(10000,deadline-Date.now()))),cache:'no-store'});
 if(response.status===404)return null;
 if(!response.ok)throw Error('CVE source unavailable');
 const reader=response.body?.getReader();if(!reader)throw Error('CVE empty body');let size=0;const chunks:Uint8Array[]=[];try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>2*1024*1024)throw Error('CVE source exceeds bound');chunks.push(value);}}finally{await reader.cancel();}const text=Buffer.concat(chunks).toString('utf8');
 const record=metadata.parse(JSON.parse(text));if(record.cveMetadata.cveId!==id)throw Error('CVE identity mismatch');
 return {record,sha256:sha256(Buffer.concat(chunks)),published:record.cveMetadata.state==='PUBLISHED'};
}
