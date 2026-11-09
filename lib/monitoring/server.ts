import 'server-only';
import {timingSafeEqual} from 'node:crypto';
import {q} from '@/lib/db';
import {catalogMeta} from '@/lib/catalog';
import {ERROR_AREAS,healthIssues,type ErrorArea} from './policy';

export function monitorAuthorized(req:Request) {
  const expected=process.env.MONITOR_TOKEN;
  if(!expected||expected.length<32)return false;
  const a=Buffer.from(req.headers.get('authorization')??''),b=Buffer.from(`Bearer ${expected}`);
  return a.length===b.length&&timingSafeEqual(a,b);
}
export async function recordError(area:ErrorArea, source:'server'|'browser'='server') {
  if(!ERROR_AREAS.includes(area))return;
  // No raw exception is accepted by this function. Telemetry cannot disclose it.
  console.error('canary_error',source,area);
  try {
    await q("insert into operation_log(operation,cost_pool,model_calls,outcome) values($1,'shared_feed',0,$2)",[`error_${source}`,area]);
  } catch { console.error('canary_error_storage_unavailable'); }
}
export async function trackedDaily<T>(work:()=>Promise<T>):Promise<T> {
  const start=Date.now();
  const [run]=await q<{id:string}>("insert into operation_log(operation,cost_pool,model_calls,outcome) values('daily_monitor','shared_feed',0,'started') returning id");
  try {
    const result=await work();
    await q("update operation_log set outcome='completed',latency_ms=$2 where id=$1",[run.id,Date.now()-start]);
    return result;
  } catch(e) {
    try {await q("update operation_log set outcome='failed',latency_ms=$2 where id=$1",[run.id,Date.now()-start]);}catch{console.error('daily_heartbeat_write_failed');}
    throw e;
  }
}
export async function monitoringHealth() {
  const [catalog,daily,success,errors]=await Promise.all([
    catalogMeta(),
    q<{created_at:Date;outcome:string}>("select created_at,outcome from operation_log where operation='daily_monitor' and measurement='live' order by id desc limit 1"),
    q<{created_at:Date}>("select created_at from operation_log where operation='daily_monitor' and outcome='completed' and measurement='live' order by id desc limit 1"),
    q<{operation:string;n:string}>("select operation,count(*) n from operation_log where operation in ('error_server','error_browser') and measurement='live' and created_at>now()-interval '15 minutes' group by operation"),
  ]);
  const issues=healthIssues({reviewAt:catalog.last_successful_review_at,reviewFailed:!!catalog.last_failure_at,
    dailySuccessAt:success[0]?.created_at.toISOString()??null,dailyStartedAt:daily[0]?.created_at.toISOString()??null,dailyOutcome:daily[0]?.outcome??null,
    monitoringStartedAt:process.env.MONITOR_STARTED_AT??null,
    serverErrors:Number(errors.find(e=>e.operation==='error_server')?.n??0),clientErrors:Number(errors.find(e=>e.operation==='error_browser')?.n??0)});
  return {ok:issues.length===0,issues,catalog_revision:catalog.catalog_revision};
}
