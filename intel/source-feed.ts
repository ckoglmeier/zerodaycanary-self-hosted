// Deterministic CSV intake. Source text is data, never agent instructions.
import {createHash} from 'node:crypto';
import {normalizeIdentifier} from './schema';

export const SOURCE_SCHEMA='2026-10-22.source.1';
export const MAX_SOURCE_BYTES=5*1024*1024;
const REQUIRED=['id','aliases','vendor_product','description','cvss','cvss_version','severity','kev','ecosystem','published','source','link','x_flag'];
const ID=/^(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})$/;
export class SourceInputError extends Error {}
export type SourceFields=Record<string,string>;
export type ParsedSource={fields:SourceFields;identifiers:string[];hash:string;candidate:boolean;missing:string[]};
export type SourceRecord={
  id:string;schema_version:typeof SOURCE_SCHEMA;feed_revision:number;identifiers:string[];
  review_status:'source_only';matchable:false;received_at:string;
  source:SourceFields;severity:string;cvss_score:number|null;ecosystem:string|null;
  package_name:null;affected_ranges:null;exploitation_status:'unverified';
  completeness:{missing:string[]};
};
export const digest=(s:string)=>createHash('sha256').update(s).digest('hex');

// RFC 4180 quoting, embedded newlines and BOM. Reject broken rows atomically.
export function csvRows(text:string):string[][]{
  text=text.replace(/^\uFEFF/,'');const rows:string[][]=[];let row:string[]=[],cell='',quoted=false,closed=false;
  const endCell=()=>{row.push(cell);cell='';closed=false;};
  const endRow=()=>{endCell();if(row.some(v=>v.trim()))rows.push(row);row=[];if(rows.length>5001)throw new SourceInputError('Use at most 5,000 rows per import.');};
  for(let i=0;i<text.length;i++){
    const ch=text[i];
    if(quoted){if(ch==='"'){if(text[i+1]==='"'){cell+='"';i++;}else{quoted=false;closed=true;}}else cell+=ch;continue;}
    if(ch==='"'){if(cell||closed)throw new SourceInputError('Unexpected quote in CSV.');quoted=true;}
    else if(ch===',')endCell();
    else if(ch==='\n'||ch==='\r'){if(ch==='\r'&&text[i+1]==='\n')i++;endRow();}
    else{if(closed)throw new SourceInputError('Unexpected text after a quoted field.');cell+=ch;}
  }
  if(quoted)throw new SourceInputError('Unclosed quoted CSV field.');
  if(cell||row.length||closed)endRow();return rows;
}
export function parseSourceCsv(text:string):ParsedSource[]{
  if(Buffer.byteLength(text)>MAX_SOURCE_BYTES)throw new SourceInputError('CSV must be at most 5 MiB.');
  const [headers,...rows]=csvRows(text);if(!headers||!rows.length)throw new SourceInputError('CSV needs a header and at least one record.');
  if(headers.length!==REQUIRED.length||new Set(headers).size!==headers.length||REQUIRED.some(h=>!headers.includes(h)))throw new SourceInputError(`Expected columns: ${REQUIRED.join(', ')}.`);
  const seen=new Set<string>();
  return rows.map((row,i)=>{
    if(row.length!==headers.length)throw new SourceInputError(`Row ${i+2}: wrong number of columns.`);
    const fields=Object.fromEntries(REQUIRED.map(k=>[k,row[headers.indexOf(k)].trim()]));
    if(Object.values(fields).some(v=>v.length>20000||v.includes('\0')))throw new SourceInputError(`Row ${i+2}: invalid or oversized field.`);
    const primary=normalizeIdentifier(fields.id);const identifiers=[...new Set([primary,...fields.aliases.split(/[;,|\s]+/).filter(Boolean).map(normalizeIdentifier)])].sort();
    if(identifiers.some(v=>!ID.test(v)))throw new SourceInputError(`Row ${i+2}: invalid CVE/GHSA identifier.`);
    if(identifiers.some(v=>seen.has(v)))throw new SourceInputError(`Row ${i+2}: repeated identifier or alias; combine the rows before import.`);
    identifiers.forEach(v=>seen.add(v));
    // Exports leave severity blank for records NVD has not scored yet; treat that as unknown.
    if(!['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN',''].includes(fields.severity.toUpperCase()))throw new SourceInputError(`Row ${i+2}: invalid severity.`);
    if(fields.cvss&&(!Number.isFinite(Number(fields.cvss))||Number(fields.cvss)<0||Number(fields.cvss)>10))throw new SourceInputError(`Row ${i+2}: invalid CVSS score.`);
    if(!['yes','no','unknown',''].includes(fields.kev.toLowerCase()))throw new SourceInputError(`Row ${i+2}: KEV must be yes, no or unknown.`);
    try{const u=new URL(fields.link);if(!['https:','http:'].includes(u.protocol)||u.username||u.password)throw Error();}catch{throw new SourceInputError(`Row ${i+2}: invalid source URL.`);}
    if(fields.published&&Number.isNaN(Date.parse(fields.published)))throw new SourceInputError(`Row ${i+2}: invalid publication date.`);
    const missing=['package_name','affected_ranges'];if(!fields.vendor_product)missing.push('product');if(!fields.ecosystem)missing.push('ecosystem');if(!fields.description||fields.description==='No description provided')missing.push('description');
    return {fields,identifiers,hash:digest(JSON.stringify(fields)),candidate:fields.severity.toUpperCase()==='CRITICAL'||fields.kev.toLowerCase()==='yes'||!!fields.x_flag,missing};
  });
}
export function sourceRecord(p:ParsedSource,id:string,revision:number,at:string,previousIdentifiers:string[]=[]):SourceRecord{
  return {id,schema_version:SOURCE_SCHEMA,feed_revision:revision,identifiers:[...new Set([...previousIdentifiers,...p.identifiers])].sort(),review_status:'source_only',matchable:false,received_at:at,source:p.fields,severity:p.fields.severity.toLowerCase()||'unknown',cvss_score:p.fields.cvss?Number(p.fields.cvss):null,ecosystem:p.fields.ecosystem||null,package_name:null,affected_ranges:null,exploitation_status:'unverified',completeness:{missing:p.missing}};
}
