// Documents are untrusted historical context, never deployed inventory or instructions.
// Extraction is local and deterministic: no model call, external URL fetch or HTML rendering.
import {OVERVIEW_FILE_BYTES,OVERVIEW_TEXT_CHARS} from './overview-limits';
export {OVERVIEW_BODY_BYTES} from './overview-limits';

export class OverviewError extends Error {}
export type OverviewInput = { text:string; source:string; kind:'notes'|'pdf'|'docx'|'text'; pages:number|null };
export type TechnologyClue = { product:string; name:string; mentions:{quote:string;location:string;version:string|null}[] };

function checkedText(text:string) {
  if(text.length>OVERVIEW_TEXT_CHARS) throw new OverviewError('Use a shorter overview (up to 120,000 characters).');
  if(/[\u0000]/.test(text)) throw new OverviewError('This file does not contain readable text. Upload a PDF, Word document or UTF-8 text file.');
  if(!text.trim()) throw new OverviewError('No readable text was found. For a scanned document, paste its text or upload a searchable PDF.');
  return text.trim();
}

function xmlText(xml:string) {
  // Read only Word text runs. No entities, relationships, macros or embedded objects execute.
  return [...xml.matchAll(/<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>|<\/w:p>|<w:(?:tab|br)\b[^>]*\/?\s*>/g)].map(m=>m[1]===undefined?'\n':m[1]
    .replace(/&#(x[0-9a-f]+|\d+);/gi,(_,n)=>{const c=n[0].toLowerCase()==='x'?parseInt(n.slice(1),16):Number(n);return c>0&&c<=0x10ffff?String.fromCodePoint(c):'';})
    .replace(/&(amp|lt|gt|quot|apos);/g,(_,n)=>({amp:'&',lt:'<',gt:'>',quot:'"',apos:"'"})[n as 'amp'])).join(' ');
}

export async function extractOverview(notes:unknown,file?:File|null):Promise<OverviewInput|null> {
  if(typeof notes!=='string'&&notes!=null) throw new OverviewError('Paste the overview as text.');
  const pasted=(notes||'') as string;
  if(pasted.length>OVERVIEW_TEXT_CHARS) throw new OverviewError('Use a shorter overview (up to 120,000 characters).');
  if(!file?.size) {
    if(file?.name)throw new OverviewError('This file is empty. Choose a readable document or paste notes.');
    return pasted.trim()?{text:checkedText(pasted),source:'Pasted notes',kind:'notes',pages:null}:null;
  }
  if(file.size>OVERVIEW_FILE_BYTES) throw new OverviewError('Choose a file smaller than 2 MB.');
  const source=file.name.replace(/[\u0000-\u001f\u007f]/g,'').split(/[\\/]/).pop()!.slice(0,180)||'Overview';
  const ext=source.split('.').at(-1)?.toLowerCase();
  if(!['pdf','docx','txt','md','csv','json'].includes(ext||'')) throw new OverviewError('Use PDF, Word (.docx) or a text file (.txt, .md, .csv, .json).');
  const bytes=new Uint8Array(await file.arrayBuffer());
  let text='',pages:number|null=null,kind:OverviewInput['kind']='text';
  try {
    if(ext==='pdf') {
      if(new TextDecoder().decode(bytes.slice(0,5))!=='%PDF-') throw Error('Invalid PDF');
      const {getDocumentProxy}=await import('unpdf');
      const pdf=await getDocumentProxy(bytes,{enableXfa:false,useSystemFonts:false,disableFontFace:true,useWorkerFetch:false});
      try {
        pages=pdf.numPages;kind='pdf';
        if(pages>40) throw new OverviewError('Choose a PDF with at most 40 pages.');
        for(let i=1;i<=pages;i++) {
          const p=await pdf.getPage(i),content=await p.getTextContent();
          text+=`\n[Page ${i}]\n`+content.items.map(item=>'str' in item?item.str+('hasEOL' in item&&item.hasEOL?'\n':' '):'').join('');
          if(text.length>OVERVIEW_TEXT_CHARS) throw new OverviewError('Use a shorter overview (up to 120,000 characters).');
        }
        if(!text.replace(/\[Page \d+\]/g,'').trim()) text='';
      } finally {await pdf.loadingTask.destroy();}
    } else if(ext==='docx') {
      const {unzipSync,strFromU8}=await import('fflate');
      const entries=unzipSync(bytes,{filter:entry=>{
        if(entry.name!=='word/document.xml')return false;
        if(entry.originalSize>1024*1024)throw new OverviewError('The Word document is too large after decompression. Use a shorter document.');
        return true;
      }});
      if(!entries['word/document.xml'])throw Error('Missing Word text');
      text=xmlText(strFromU8(entries['word/document.xml']));kind='docx';
    } else text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  } catch(e) {
    if(e instanceof OverviewError)throw e;
    throw new OverviewError('Could not read this document. Use an unlocked, searchable PDF, a Word (.docx) document or UTF-8 text.');
  }
  checkedText(text);
  return {text:checkedText(text+(pasted.trim()?`\n\n[Additional notes]\n${pasted}`:'')),source,kind,pages};
}

const TECHNOLOGIES:Record<string,[string,string[]]>={
  php:['PHP',['PHP']],nextjs:['Next.js',['Next.js','NextJS']],nodejs:['Node.js',['Node.js','NodeJS']],
  wordpress:['WordPress',['WordPress']],gitlab:['GitLab',['GitLab']],plex:['Plex Media Server',['Plex Media Server']],
  nginx:['nginx',['nginx']],apache:['Apache HTTP Server',['Apache HTTP Server','Apache httpd']],drupal:['Drupal',['Drupal']],
  python:['Python',['Python']],django:['Django',['Django']],flask:['Flask',['Flask']],fastapi:['FastAPI',['FastAPI']],
  laravel:['Laravel',['Laravel']],magento:['Magento',['Magento']],react:['React',['React']],vue:['Vue.js',['Vue.js','VueJS']],
  java:['Java',['Java']],spring:['Spring Framework',['Spring Framework','Spring Boot']],dotnet:['.NET',['.NET','ASP.NET']],
  ruby:['Ruby',['Ruby']],rails:['Ruby on Rails',['Ruby on Rails']],golang:['Go',['Golang']],
  mysql:['MySQL',['MySQL']],postgresql:['PostgreSQL',['PostgreSQL','Postgres']],mongodb:['MongoDB',['MongoDB']],redis:['Redis',['Redis']],
  openssl:['OpenSSL',['OpenSSL']],log4j:['Log4j',['Log4j']],tomcat:['Apache Tomcat',['Apache Tomcat','Tomcat']],
  docker:['Docker',['Docker']],kubernetes:['Kubernetes',['Kubernetes']],linux:['Linux',['Linux']],windows:['Windows Server',['Windows Server']],
  iis:['Microsoft IIS',['Microsoft IIS']],jquery:['jQuery',['jQuery']],litellm:['LiteLLM',['LiteLLM']],sharp:['Sharp',['sharp']],
};

export function overviewClues(text:string,products:{key:string;name:string}[]=[]):TechnologyClue[] {
  const dictionary=new Map(Object.entries(TECHNOLOGIES));
  for(const p of products)if(!dictionary.has(p.key)&&p.name.length>=4)dictionary.set(p.key,[p.name,[p.name,...(p.key.length>=4?[p.key]:[])]]);
  const clues:TechnologyClue[]=[];
  for(const [product,[name,aliases]] of dictionary) {
    const escaped=aliases.map(a=>a.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('|');
    const pattern=new RegExp(`(?<![\\w])(?:${escaped})(?![\\w])(?:[ /:=\\t-]{0,8}(?:version[ \\t]+|v)?(\\d+\\.\\d+(?:\\.\\d+){0,2}(?:[-+][\\w.-]+)?))?`,'gi');
    const mentions:TechnologyClue['mentions']=[];
    for(const m of text.matchAll(pattern)) {
      const start=Math.max(0,m.index!-90),end=Math.min(text.length,m.index!+m[0].length+100);
      const page=[...text.slice(0,m.index).matchAll(/\[Page (\d+)\]/g)].at(-1)?.[1];
      mentions.push({quote:text.slice(start,end).replace(/\s+/g,' ').trim(),location:page?`Page ${page}`:`Character ${m.index!+1}`,version:m[1]||null});
      if(mentions.length===3)break;
    }
    if(mentions.length)clues.push({product,name,mentions});
  }
  return clues.sort((a,b)=>a.name.localeCompare(b.name));
}
