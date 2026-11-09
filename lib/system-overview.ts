import 'server-only';
import {type Viewer,HttpError} from './auth';
import {userQ} from './db';
import {ownSystem} from './systems';
import {allAdvisories} from './catalog';
import {OVERVIEW_BODY_BYTES,OverviewError,extractOverview,overviewClues,type OverviewInput} from './overview';

export async function overviewForm(req:Request) {
  // Enforce a bound even when Content-Length is absent or dishonest.
  if(Number(req.headers.get('content-length'))>OVERVIEW_BODY_BYTES)throw new HttpError(413,'Use an overview file smaller than 2 MB.');
  const reader=req.body?.getReader(),chunks:Uint8Array[]=[];let size=0;
  if(reader)try{for(;;){const part=await reader.read();if(part.done)break;size+=part.value.length;if(size>OVERVIEW_BODY_BYTES){await reader.cancel();throw new HttpError(413,'Use an overview file smaller than 2 MB.');}chunks.push(part.value);}}finally{reader.releaseLock();}
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  try {
    if(req.headers.get('content-type')?.includes('application/json')) {
      const data=JSON.parse(new TextDecoder().decode(bytes));
      if(!data||typeof data!=='object'||Array.isArray(data))throw Error();
      return {url:typeof data.url==='string'?data.url:'',notes:data.overview,file:null};
    }
    const form=await new Response(bytes,{headers:{'content-type':req.headers.get('content-type')||''}}).formData();
    const file=form.get('overview_file');
    return {url:String(form.get('url')||''),notes:form.get('overview'),file:typeof file==='object'?file:null};
  }catch{throw new HttpError(400,'Could not read this form. Please try again.');}
}

export async function parseOverview(notes:unknown,file?:File|null) {
  try{return await extractOverview(notes,file);}catch(e){if(e instanceof OverviewError)throw new HttpError(400,e.message);throw e;}
}

export async function saveOverview(v:Viewer,id:string,input:OverviewInput) {
  await ownSystem(v,id);
  await userQ(v,`insert into system_overviews(system_id,workspace_id,source,kind,pages,extracted_text,added_by)
    values($1,$2,$3,$4,$5,$6,$7) on conflict(system_id) do update set source=excluded.source,kind=excluded.kind,pages=excluded.pages,extracted_text=excluded.extracted_text,added_by=excluded.added_by,updated_at=now()`,
    [id,v.workspaceId,input.source,input.kind,input.pages,input.text,v.id]);
}

export async function removeOverview(v:Viewer,id:string) {
  await ownSystem(v,id);
  await userQ(v,'delete from system_overviews where system_id=$1 and workspace_id=$2',[id,v.workspaceId]);
}

export async function systemOverview(v:Viewer,id:string) {
  await ownSystem(v,id);
  const [row]=await userQ<{source:string;kind:string;pages:number|null;extracted_text:string;updated_at:string}>(v,'select source,kind,pages,extracted_text,updated_at from system_overviews where system_id=$1 and workspace_id=$2',[id,v.workspaceId]);
  if(!row)return null;
  const advisories=await allAdvisories();
  const products=advisories.flatMap(a=>a.affected.map(p=>({key:p.product,name:a.affected.length===1?a.product:p.product})));
  // Re-extract against today's reviewed products. Text never changes an assessment.
  const clues=overviewClues(row.extracted_text,products).map(c=>({...c,alerts:advisories.filter(a=>a.affected.some(p=>p.product===c.product)).map(a=>({id:a.id,title:a.title,identifier:a.identifiers[0]}))}));
  return {source:row.source,kind:row.kind,pages:row.pages,updated_at:row.updated_at,clues};
}
