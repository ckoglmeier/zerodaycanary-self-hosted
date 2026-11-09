import 'server-only';
import {randomUUID} from 'node:crypto';
import {revalidatePath} from 'next/cache';
import {one,q,tx} from './db';
import {HttpError} from './auth';
import {digest,parseSourceCsv,sourceRecord,type SourceRecord} from '@/intel/source-feed';
import {normalizeIdentifier,type AdvisoryDraft} from '@/intel/schema';

export async function importSourceCsv(text:string,filename:string,by:string){
  const parsed=parseSourceCsv(text),sha=digest(text);
  return tx(async c=>{
    // Serialize imports, including distinct files sharing aliases. No duplicate versions.
    await c.query("select pg_advisory_xact_lock(hashtext('source-feed-import'))");
    const prior=(await c.query<{id:string}>('select id from source_imports where sha256=$1',[sha])).rows[0];
    if(prior)return {id:prior.id,duplicate:true,rows:parsed.length,changed:0};
    const imp=(await c.query<{id:string}>('insert into source_imports(sha256,filename,created_by,row_count) values($1,$2,$3,$4) returning id',[sha,filename.slice(0,160),by,parsed.length])).rows[0];
    const incomingAliases=parsed.flatMap(p=>p.identifiers);
    const aliases=(await c.query<{alias:string;source_id:string}>('select alias,source_id from source_vulnerability_aliases where alias=any($1)',[incomingAliases])).rows;
    const ownersByAlias=new Map(aliases.map(r=>[r.alias,r.source_id]));
    const oldRows=(await c.query<{id:string;content_hash:string;record:SourceRecord}>('select id,content_hash,record from source_vulnerabilities where id=any($1)',[[...new Set(aliases.map(a=>a.source_id))]])).rows;
    const previous=new Map(oldRows.map(r=>[r.id,r]));
    const changes=parsed.flatMap(p=>{
      const owners=[...new Set(p.identifiers.map(a=>ownersByAlias.get(a)).filter((v):v is string=>!!v))];
      if(owners.length>1)throw new HttpError(409,`Aliases for ${p.fields.id} belong to separate records. Resolve the collision before importing; no rows were saved.`);
      const id=owners[0]??'src-'+digest(p.fields.id.toUpperCase()).slice(0,20),old=previous.get(id);
      return old?.content_hash===p.hash?[]:[{p,id,old}];
    });
    const changed=changes.length;
    if(new Set(changes.map(r=>r.id)).size!==changes.length)throw new HttpError(409,'Multiple input rows resolve to the same vulnerability. Combine its aliases into one row; no rows were saved.');
    if(changed){
      const at=new Date().toISOString();
      const rev=Number((await c.query<{id:string}>('insert into source_feed_revisions(import_id,created_at) values($1,$2) returning id',[imp.id,at])).rows[0].id);
      const data=changes.map(({p,id,old})=>{const record=sourceRecord(p,id,rev,at,old?.record.identifiers);return {id,content_hash:p.hash,revision:rev,record,updated_at:at,priority_candidate:p.candidate,search:[...record.identifiers,p.fields.vendor_product,p.fields.ecosystem,p.fields.description].join(' ').toLowerCase()};});
      const json=JSON.stringify(data);
      await c.query(`insert into source_vulnerabilities(id,content_hash,revision,record,updated_at,priority_candidate,search)
        select id,content_hash,revision,record,updated_at,priority_candidate,search from jsonb_to_recordset($1::jsonb) as x(id text,content_hash text,revision bigint,record jsonb,updated_at timestamptz,priority_candidate boolean,search text)
        on conflict(id) do update set content_hash=excluded.content_hash,revision=excluded.revision,record=excluded.record,updated_at=excluded.updated_at,priority_candidate=excluded.priority_candidate,search=excluded.search`,[json]);
      await c.query(`insert into source_vulnerability_aliases(alias,source_id) select jsonb_array_elements_text(x.record->'identifiers'),x.id from jsonb_to_recordset($1::jsonb) as x(id text,record jsonb) on conflict(alias) do nothing`,[json]);
      await c.query(`insert into source_vulnerability_versions(source_id,revision,record) select id,revision,record from jsonb_to_recordset($1::jsonb) as x(id text,revision bigint,record jsonb)`,[json]);
    }
    await c.query('update source_imports set changed_count=$2 where id=$1',[imp.id,changed]);
    return {id:imp.id,duplicate:false,rows:parsed.length,changed};
  });
}

export async function sourceMeta(){
  const r=await one<{id:string;created_at:Date}>('select id,created_at from source_feed_revisions order by id desc limit 1');
  return {feed_revision:Number(r?.id??0),last_changed_at:r?.created_at.toISOString()??null};
}

export async function sourceCount(revision?:number){
 const row=revision===undefined?await one<{n:string}>('select count(*) n from source_vulnerabilities'):await one<{n:string}>('select count(distinct source_id) n from source_vulnerability_versions where revision<=$1',[revision]);
 return Number(row?.n||0);
}

export type SourceQuery={identifier?:string;ecosystem?:string;product?:string;severity?:string;updated_since?:string;after_revision?:number;cursor?:string;limit?:number};
const filterHash=(p:SourceQuery)=>digest(JSON.stringify([p.identifier??'',p.ecosystem??'',p.product??'',p.severity??'',p.updated_since??'',p.after_revision??0]));
export async function listSources(p:SourceQuery,snapshot=false){
  let revision=(await sourceMeta()).feed_revision,after='';
  if(p.cursor){
    try{const v=JSON.parse(Buffer.from(p.cursor,'base64url').toString());if(v.v!==1||!Number.isSafeInteger(v.revision)||v.revision<0||v.revision>revision||typeof v.after!=='string'||!/^src-[a-f0-9]{20}$/.test(v.after)||v.filters!==filterHash(p))throw Error();revision=v.revision;after=v.after;}
    catch{throw new HttpError(400,'Invalid cursor, or cursor filters changed.');}
  }
  const args:unknown[]=[revision];const add=(v:unknown)=>{args.push(v);return '$'+args.length;};
  const where=['source_id > '+add(after)];
  if(p.identifier)where.push(`${add(normalizeIdentifier(p.identifier))} in (select jsonb_array_elements_text(record->'identifiers'))`);
  if(p.ecosystem)where.push(`lower(record->>'ecosystem')=${add(p.ecosystem.toLowerCase())}`);
  if(p.product)where.push(`position(${add(p.product.toLowerCase())} in lower(record->'source'->>'vendor_product'))>0`);
  if(p.severity)where.push(`record->>'severity'=${add(p.severity)}`);
  if(p.updated_since)where.push(`(record->>'received_at')::timestamptz>${add(p.updated_since)}::timestamptz`);
  if(p.after_revision!==undefined)where.push(`(record->>'feed_revision')::bigint>${add(p.after_revision)}`);
  // Read immutable versions at a pinned high-water mark. New imports cannot move
  // records out from under an in-progress traversal or hide corrected old values.
  const limit=p.limit??50;
  if(snapshot){
    const size=await one<{n:string;bytes:string}>(`select count(*) n,coalesce(sum(octet_length(record::text)),0) bytes from (
      select distinct on(source_id) record from source_vulnerability_versions where revision<=$1 order by source_id,revision desc) latest`,[revision]);
    if(Number(size?.n)>10000||Number(size?.bytes)>3*1024*1024)throw new HttpError(413,'Snapshot exceeds its size limit. Use the paginated endpoint to retrieve the complete feed.');
  }
  const rows=await q<{source_id:string;record:SourceRecord}>(`with latest as (
    select distinct on(source_id) source_id,record from source_vulnerability_versions where revision<=$1 order by source_id,revision desc
    ) select * from latest where ${where.join(' and ')} order by source_id limit ${snapshot?10001:limit+1}`,args);
  if(snapshot&&rows.length>10000)throw new HttpError(413,'Snapshot exceeds 10,000 records. Use the paginated endpoint to retrieve the complete feed.');
  let bytes=0;const page=[];
  for(const row of rows.slice(0,snapshot?rows.length:limit)){const size=Buffer.byteLength(JSON.stringify(row.record));if(bytes+size>3*1024*1024)break;page.push(row);bytes+=size;}
  const last=page.at(-1);
  const next=!snapshot&&rows.length>page.length&&last?Buffer.from(JSON.stringify({v:1,revision,after:last.source_id,filters:filterHash(p)})).toString('base64url'):null;
  const mark=await one<{created_at:Date}>('select created_at from source_feed_revisions where id=$1',[revision]);
  return {feed_revision:revision,sync_until:mark?.created_at.toISOString()??null,data:page.map(r=>r.record),next_cursor:next};
}
export async function getSource(identifier:string){
  const alias=normalizeIdentifier(identifier);
  return one<{record:SourceRecord}>(`select record from source_vulnerabilities where id=$1 or id=(select source_id from source_vulnerability_aliases where alias=$2)`,[identifier,alias]);
}

export async function sourceOperatorData(search='',all=false){
  const [totals,imports,records]=await Promise.all([
    one<{total:string;candidates:string}>("select count(*) total,count(*) filter(where priority_candidate) candidates from source_vulnerabilities"),
    q<{id:string;filename:string;row_count:number;changed_count:number;created_at:Date}>('select id,filename,row_count,changed_count,created_at from source_imports order by created_at desc limit 5'),
    q<{id:string;record:SourceRecord;intake_id:string|null}>(`select s.id,s.record,(select d.intake_id from advisory_drafts d where d.source_id=s.id and d.source_hash=s.content_hash limit 1) intake_id
      from source_vulnerabilities s where ($1 or priority_candidate) and position($2 in search)>0
      order by (record->'source'->>'x_flag'<>'') desc,updated_at desc,id limit 100`,[all,search.toLowerCase()]),
  ]);return {totals,imports,records};
}

// Queue only selected rows into the existing review workflow, without inference.
// An operator must complete source review explicitly before publishing these drafts.
export async function sourceReviewDraft(id:string,by:string){
  return tx(async c=>{
    await c.query("select pg_advisory_xact_lock(hashtext('source-feed-review'))");
    const row=(await c.query<{record:SourceRecord;content_hash:string}>('select record,content_hash from source_vulnerabilities where id=$1',[id])).rows[0];
    if(!row)throw new HttpError(404,'Source record not found.');
    const existing=(await c.query<{intake_id:string}>('select intake_id from advisory_drafts where source_id=$1 and source_hash=$2',[id,row.content_hash])).rows[0];if(existing)return existing.intake_id;
    const r=row.record,s=r.source;
    const draft:AdvisoryDraft={title:s.vendor_product?`${s.vendor_product}: ${s.id}`:s.id,product:s.vendor_product||'Unknown product',summary:s.description||'Source description unavailable.',identifiers:r.identifiers,severity:r.severity as AdvisoryDraft['severity'],cvss_score:r.cvss_score,severity_source:s.source||null,
      exploitation:{category:'none_confirmed',source_url:null,as_of:null,note:'Source feed assertions are not verified exploitation evidence.'},affected:[],conditions:[],sources:[{url:s.link,kind:s.link.includes('github.com/advisories/')?'ghsa':'cve'}],published_at:s.published||null,
      uncertainty:['Affected package/version ranges and prerequisites need primary-source review.',...(s.x_flag?[`Unverified source note: ${s.x_flag}`]:[])],brief_excerpt:s.description};
    const intake=randomUUID(),brief=JSON.stringify(r,null,2);
    await c.query("insert into feed_intakes(id,created_by,brief,brief_sha256,attribution,status) values($1,$2,$3,$4,$5,'extracted')",[intake,by,brief,digest(brief),'Source CSV: '+s.id]);
    const target=(await c.query<{advisory_id:string}>('select distinct advisory_id from advisory_aliases where alias=any($1)',[r.identifiers])).rows;
    if(target.length>1)throw new HttpError(409,'Reviewed aliases belong to separate alerts; resolve them before review.');
    await c.query('insert into advisory_drafts(intake_id,draft,target_advisory_id,source_id,source_hash) values($1,$2,$3,$4,$5)',[intake,JSON.stringify(draft),target[0]?.advisory_id??null,id,row.content_hash]);
    return intake;
  });
}

export async function setFeatured(id:string,featured:boolean,reason:string,by:string){
  if(!reason.trim()||reason.length>500)throw new HttpError(400,'Give a brief reason for the priority selection (up to 500 characters).');
  await tx(async c=>{
    const r=(await c.query<{featured:boolean;status:string}>('select featured,status from advisories where id=$1 for update',[id])).rows[0];
    if(!r)throw new HttpError(404,'Reviewed alert not found.');
    if(featured&&r.status!=='published')throw new HttpError(400,'Only a published reviewed alert can be featured.');
    if(r.featured===featured)return;
    await c.query('update advisories set featured=$2 where id=$1',[id,featured]);
    await c.query('insert into alert_feature_history(advisory_id,featured,reason,created_by) values($1,$2,$3,$4)',[id,featured,reason.trim(),by]);
  });
  try{revalidatePath('/(public)','layout');}catch{/* script/test */}
}
