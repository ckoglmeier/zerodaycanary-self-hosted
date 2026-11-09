// Standalone external runner. No application/database credentials required.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {dirname} from 'node:path';
import {randomUUID} from 'node:crypto';

export function transition(old, issues, now=new Date().toISOString()) {
  const state={version:1,failures:0,successes:0,incident:null,notified:false,pending:null,...old};
  state.checkedAt=now;
  if(issues.length){
    state.failures++;state.successes=0;
    if(state.pending?.kind==='recovery')state.pending=null;
    if(state.failures>=2&&!state.incident)state.incident={id:randomUUID(),startedAt:now,issues:[...issues].sort()};
    if(state.incident&&!state.notified&&!state.pending)state.pending={kind:'incident',id:state.incident.id,issues:state.incident.issues,startedAt:state.incident.startedAt};
  }else{
    state.successes++;state.failures=0;
    if(state.successes>=2&&state.incident){
      if(state.notified)state.pending={kind:'recovery',id:state.incident.id,issues:state.incident.issues,startedAt:state.incident.startedAt};
      else {state.incident=null;state.pending=null;}
    }
  }
  return state;
}
export function acknowledged(state){
  if(state.pending?.kind==='recovery')return {...state,incident:null,notified:false,pending:null};
  return {...state,notified:true,pending:null};
}
export async function probe({base,token,fetcher=fetch,extraHeaders={}}){
  if(!/^https:\/\//.test(base))throw Error('HTTPS monitor base required');
  const issues=[];
  await Promise.all([
    ['homepage','/',200],['login','/login',200],['developer_auth','/developer',307],['alerts_api','/api/v1/advisories?limit=1',200],['health','/api/monitor/health',200],
  ].map(async([name,path,status])=>{
    try{
      const headers={...extraHeaders,...(name==='health'?{authorization:`Bearer ${token}`}:{})};
      const r=await fetcher(base+path,{headers,redirect:'manual',signal:AbortSignal.timeout(12_000)});
      if(name==='health'){
        const body=await r.json();
        const allowed=['feed_review_failed','feed_review_overdue','daily_job_failed','daily_job_interrupted','daily_job_overdue','server_errors','browser_errors','health_unavailable'];
        if(r.status===503&&Array.isArray(body.issues)&&body.issues.length&&body.issues.every(i=>allowed.includes(i)))issues.push(...body.issues);
        else if(r.status!==200||body.ok!==true||!Array.isArray(body.issues)||body.issues.length)issues.push('health_contract');
      } else if(r.status!==status)issues.push(name);
      else if(name==='developer_auth'&&!r.headers.get('location')?.startsWith('/login?next='))issues.push(name);
      else if(name==='alerts_api'){
        const body=await r.json();const etag=r.headers.get('etag');
        if(!Array.isArray(body.data)||!body.data.length||!Number.isInteger(body.catalog_revision)||!etag)issues.push(name);
        else {const cached=await fetcher(base+path,{headers:{...extraHeaders,'if-none-match':etag},redirect:'manual',signal:AbortSignal.timeout(12_000)});if(cached.status!==304)issues.push('api_cache');}
      }else if(name==='homepage'){if(!(await r.text()).includes('Zero Day Canary'))issues.push(name);}
      else await r.arrayBuffer();
    }catch{issues.push(name);}
  }));
  return [...new Set(issues)].sort();
}
export async function notify(pending,env,fetcher=fetch){
  if(!env.MONITOR_EMAIL_TO||!env.MONITOR_EMAIL_FROM||!env.MONITOR_RESEND_KEY)throw Error('Monitor notification is not configured');
  const recovery=pending.kind==='recovery';
  const res=await fetcher('https://api.resend.com/emails',{
    method:'POST',signal:AbortSignal.timeout(15000),headers:{authorization:`Bearer ${env.MONITOR_RESEND_KEY}`,'content-type':'application/json','idempotency-key':`canary-monitor-${pending.id}-${pending.kind}`},
    body:JSON.stringify({from:env.MONITOR_EMAIL_FROM,to:[env.MONITOR_EMAIL_TO],subject:`Zero Day Canary: ${recovery?'recovered':'needs attention'}`,
      text:`${recovery?'Two consecutive checks are healthy.':'Two consecutive checks failed.'}\n\nIncident started: ${pending.startedAt}\nChecks: ${pending.issues.join(', ')}\n\nhttps://www.zerodaycanary.com\nInspect the launch-monitor workflow and private Vercel logs. No customer data is included.`}),
  });
  if(!res.ok)throw Error(`Monitor email delivery failed (${res.status})`);
}
async function main(){
  const base=process.env.MONITOR_BASE??'https://www.zerodaycanary.com';
  if(!process.env.MONITOR_TOKEN)throw Error('MONITOR_TOKEN is required');
  const file=process.env.MONITOR_STATE_FILE??'.monitor-state/state.json';
  let old;try{old=JSON.parse(await readFile(file,'utf8'));if(old.version!==1)throw Error('Unsupported monitor state');}catch(e){if(e.code!=='ENOENT')throw e;}
  const issues=await probe({base,token:process.env.MONITOR_TOKEN});
  let state=transition(old,issues);
  await mkdir(dirname(file),{recursive:true});
  await writeFile(file,JSON.stringify(state)); // Retain pending key before attempting mail.
  if(state.pending){await notify(state.pending,process.env);state=acknowledged(state);await writeFile(file,JSON.stringify(state));}
  console.log(JSON.stringify({checkedAt:state.checkedAt,issues,incidentOpen:!!state.incident,notificationPending:!!state.pending}));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(e=>{console.error(e.message);process.exitCode=1;});
