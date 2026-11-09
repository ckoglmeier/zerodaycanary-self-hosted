// Only fixed public OSV endpoints. The request body contains public package
// ecosystem/name/version (or an opaque provider cursor); never URLs or account data.
import { z } from 'zod';
import { OsvRecordSchema,type OsvRecord,type PackageIdentity,type PackageCheck } from '@/intel/osv';
const item=z.object({vulns:z.array(z.object({id:OsvRecordSchema.shape.id,modified:z.string()})).max(5000).optional(),next_page_token:z.string().max(4096).optional()}).strict();
async function json(path:string,body:unknown,fetcher:typeof fetch,deadline:number) {
 if(Date.now()>=deadline)throw Error('OSV deadline reached');
 const response=await fetcher('https://api.osv.dev/v1/'+path,{method:body===undefined?'GET':'POST',headers:{accept:'application/json',...(body===undefined?{}:{'content-type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(Math.max(1,Math.min(12000,deadline-Date.now()))),cache:'no-store'});
 if(!response.ok||!response.headers.get('content-type')?.includes('application/json'))throw Error('OSV lookup unavailable');
 const reader=response.body?.getReader();if(!reader)throw Error('OSV empty body');
 const chunks:Uint8Array[]=[];let total=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>8*1024*1024)throw Error('OSV response exceeds bound');chunks.push(value);}}finally{await reader.cancel();}
 return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
export async function queryPackages(packages:PackageIdentity[],fetcher=fetch,deadline=Date.now()+30000):Promise<PackageCheck[]> {
 if(packages.length>50)throw Error('OSV batch exceeds 50 packages');
 const ids=packages.map(()=>new Map<string,string>()),tokens=packages.map(()=>new Set<string>());
 let pending=packages.map((p,i)=>({p,i,token:undefined as string|undefined}));
 for(let page=0;pending.length;page++){
  if(page>=10)throw Error('OSV pagination exceeds bound');
  const response=z.object({results:z.array(item)}).parse(await json('querybatch',{queries:pending.map(({p,token})=>({package:{ecosystem:p.ecosystem,name:p.name},version:p.version,...(token?{page_token:token}:{})}))},fetcher,deadline));
  if(response.results.length!==pending.length)throw Error('OSV batch length mismatch');
  const next:typeof pending=[];
  response.results.forEach((r,j)=>{const {i,p}=pending[j];for(const v of r.vulns||[]){ids[i].set(v.id,v.modified);if(ids[i].size>5000)throw Error('OSV result exceeds bound');}if(r.next_page_token){if(tokens[i].has(r.next_page_token))throw Error('OSV pagination loop');tokens[i].add(r.next_page_token);next.push({i,p,token:r.next_page_token});}});
  pending=next;
 }
 const unique=[...new Set(ids.flatMap(m=>[...m.keys()]))];if(unique.length>1000)throw Error('OSV detail bound exceeded');
 const records=new Map<string,OsvRecord>();let index=0;
 await Promise.all(Array.from({length:Math.min(5,unique.length)},async()=>{while(index<unique.length){const id=unique[index++];const record=OsvRecordSchema.parse(await json('vulns/'+encodeURIComponent(id),undefined,fetcher,deadline));if(record.id!==id)throw Error('OSV record identity mismatch');records.set(id,record);}}));
 const checked_at=new Date().toISOString();
 return packages.map((p,i)=>({...p,checked_at,records:[...ids[i].keys()].sort().map(id=>records.get(id)!)}));
}
