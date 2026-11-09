import 'server-only';
import {createHash} from 'node:crypto';
import {NextResponse} from 'next/server';
import {HttpError} from './auth';
import {rateLimit} from './rate';
import {type SourceQuery} from './source-feed';
import {SOURCE_SCHEMA} from '@/intel/source-feed';
import {apiError} from './api-public';

export function sourceQuery(u:URL):SourceQuery{
  const p=Object.fromEntries(u.searchParams);
  if(Object.keys(p).some(k=>!['identifier','ecosystem','product','severity','updated_since','after_revision','cursor','limit'].includes(k)))throw new HttpError(400,'Unknown query parameter.');
  if(Object.values(p).some(v=>v.length>1000))throw new HttpError(400,'Query parameter too long.');
  if(p.severity&&!['critical','high','medium','low','unknown'].includes(p.severity))throw new HttpError(400,'Invalid severity.');
  if(p.updated_since&&!/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(p.updated_since))throw new HttpError(400,'updated_since must be an ISO timestamp with timezone.');
  if(p.updated_since&&Number.isNaN(Date.parse(p.updated_since)))throw new HttpError(400,'Invalid updated_since timestamp.');
  if(p.limit&&(!/^\d+$/.test(p.limit)||Number(p.limit)<1||Number(p.limit)>200))throw new HttpError(400,'limit must be an integer from 1 to 200.');
  if(p.after_revision&&(!/^\d+$/.test(p.after_revision)||!Number.isSafeInteger(Number(p.after_revision))))throw new HttpError(400,'after_revision must be a nonnegative integer.');
  if(p.cursor&&(!/^[A-Za-z0-9_-]+$/.test(p.cursor)||p.cursor.length>1000))throw new HttpError(400,'Invalid cursor.');
  return {...p,limit:p.limit?Number(p.limit):undefined,after_revision:p.after_revision?Number(p.after_revision):undefined};
}
export function sourceJson(req:Request,body:{feed_revision:number;sync_until:string|null;[key:string]:unknown}){
  const payload=JSON.stringify({schema_version:SOURCE_SCHEMA,dataset:'source_feed',notice:'Source-supplied records, not Canary-reviewed alerts. Exploitation and affected ranges are not independently verified. Missing records or fields do not establish safety.',...body});
  const etag='"'+createHash('sha256').update(payload).digest('base64url')+'"';
  const headers={'content-type':'application/json; charset=utf-8','cache-control':'public, max-age=0, s-maxage=300, stale-while-revalidate=60',etag,'last-modified':new Date(body.sync_until??0).toUTCString(),'x-source-feed-revision':String(body.feed_revision),'access-control-allow-origin':'*','access-control-expose-headers':'ETag, Last-Modified, X-Source-Feed-Revision'};
  // Validate the actual representation, not just its date: another filter/page
  // can have the same modification time but different content.
  const tags=req.headers.get('if-none-match')?.split(',').map(v=>v.trim().replace(/^W\//,''));
  if(tags?.includes(etag)||tags?.includes('*'))return new NextResponse(null,{status:304,headers});
  return new NextResponse(payload,{headers});
}
export function sourceOptions(){return new Response(null,{status:204,headers:{'access-control-allow-origin':'*','access-control-allow-methods':'GET, HEAD, OPTIONS','access-control-allow-headers':'If-None-Match, If-Modified-Since','access-control-max-age':'86400'}});}
export async function sourceGet(req:Request,fn:()=>Promise<Response>){
  try{await rateLimit(`source-api:${req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()??'anon'}`,600,3600);return await fn();}
  catch(e){if(e instanceof HttpError)return apiError(e.status,e.status===429?'rate_limited':e.status===404?'not_found':'invalid_parameter',e.message);throw e;}
}
