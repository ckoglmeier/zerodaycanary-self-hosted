import {describe,it,expect,vi,beforeEach} from 'vitest';
vi.mock('server-only',()=>({}));
vi.mock('@/lib/db',()=>({q:vi.fn()}));
vi.mock('@/lib/catalog',()=>({catalogMeta:vi.fn()}));
vi.mock('@/lib/rate',()=>({rateLimit:vi.fn()}));
import {q} from '@/lib/db';
import {rateLimit} from '@/lib/rate';
import {healthIssues,errorArea} from '@/lib/monitoring/policy';
import {trackedDaily,monitorAuthorized,recordError} from '@/lib/monitoring/server';
import {POST} from '@/app/api/monitor/errors/route';
// @ts-expect-error standalone dependency-free Node monitor
import {transition,acknowledged,notify,probe} from '../scripts/monitoring/check.mjs';
const now=Date.parse('2026-10-23T12:00:00Z');
const ago=(h:number)=>new Date(now-h*3600000).toISOString();
const healthy={reviewAt:ago(1),reviewFailed:false,dailySuccessAt:ago(1),dailyStartedAt:ago(1),dailyOutcome:'completed',monitoringStartedAt:ago(2),serverErrors:0,clientErrors:0};
beforeEach(()=>{vi.resetAllMocks();vi.unstubAllEnvs();vi.spyOn(console,'error').mockImplementation(()=>{});});
describe('health policy',()=>{
 it('accepts a reviewed unchanged catalog, no findings are required',()=>expect(healthIssues(healthy,now)).toEqual([]));
 it('detects stale review, failures, missed jobs and interrupted work independently',()=>{
  expect(healthIssues({...healthy,reviewAt:ago(37),reviewFailed:true,dailySuccessAt:ago(28),dailyOutcome:'started',dailyStartedAt:ago(1)},now)).toEqual(['feed_review_failed','feed_review_overdue','daily_job_interrupted','daily_job_overdue']);
  expect(healthIssues({...healthy,dailyOutcome:'failed'},now)).toContain('daily_job_failed');
 });
 it('has explicit bounded first-run grace and fails closed on absent/invalid timestamps',()=>{
  expect(healthIssues({...healthy,dailySuccessAt:null,dailyStartedAt:null,dailyOutcome:null},now)).toEqual([]);
  for(const date of [null,'invalid',ago(28)])expect(healthIssues({...healthy,dailySuccessAt:null,monitoringStartedAt:date},now)).toContain('daily_job_overdue');
 });
 it('requires repeated errors and never classifies a private path as telemetry data',()=>{
  expect(healthIssues({...healthy,serverErrors:3,clientErrors:5},now)).toEqual(['server_errors','browser_errors']);
  expect(errorArea('/developer/private-id/share?token=secret')).toBe('share');
  expect(errorArea('/login?email=private@example.com')).toBe('login');
 });
});
describe('heartbeat and privacy',()=>{
 it('records completed only after work succeeds',async()=>{
  vi.mocked(q).mockResolvedValueOnce([{id:'1'}]).mockResolvedValue([]);
  const work=vi.fn(async()=>42);expect(await trackedDaily(work)).toBe(42);
  expect(vi.mocked(q).mock.calls[1][0]).toContain("outcome='completed'");
 });
 it('records failed and preserves the actual work failure',async()=>{
  vi.mocked(q).mockResolvedValueOnce([{id:'1'}]).mockResolvedValue([]);
  await expect(trackedDaily(async()=>{throw Error('private payload');})).rejects.toThrow('private payload');
  expect(vi.mocked(q).mock.calls[1][0]).toContain("outcome='failed'");
  expect(JSON.stringify(vi.mocked(q).mock.calls)).not.toContain('private payload');
 });
 it('requires a separate strong monitor credential',()=>{
  const req=(token:string)=>new Request('https://x',{headers:{authorization:`Bearer ${token}`}});
  expect(monitorAuthorized(req(''))).toBe(false);vi.stubEnv('MONITOR_TOKEN','a'.repeat(32));
  expect(monitorAuthorized(req('a'.repeat(32)))).toBe(true);expect(monitorAuthorized(req('b'.repeat(32)))).toBe(false);
 });
 it('stores only category, degrades without breaking customer action',async()=>{
  vi.mocked(q).mockRejectedValue(Error('db down'));await expect(recordError('upload')).resolves.toBeUndefined();
  expect(vi.mocked(q).mock.calls[0][1]).toEqual(['error_server','upload']);
 });
 it('bounds and validates browser events without storing payload fields',async()=>{
  vi.mocked(q).mockResolvedValue([]);
  const req=(body:string,origin='https://x')=>new Request('https://x/api/monitor/errors',{method:'POST',headers:{origin,'content-type':'application/json'},body});
  expect((await POST(req('{"area":"upload"}'))).status).toBe(204);
  expect((await POST(req('{"area":"upload","email":"secret"}'))).status).toBe(400);
  expect((await POST(req('x'.repeat(129)))).status).toBe(413);
  expect((await POST(req('{"area":"upload"}','https://evil'))).status).toBe(403);
  vi.mocked(rateLimit).mockRejectedValue(Error('limit'));
  expect((await POST(req('{"area":"upload"}'))).status).toBe(429);
 });
});
describe('external monitor',()=>{
 it('alerts after two failures, stays quiet, recovers after two passes',()=>{
  let state=transition(undefined,['homepage']);expect(state.pending).toBe(null);
  state=transition(state,['homepage']);expect(state.pending.kind).toBe('incident');
  state=acknowledged(state);state=transition(state,['homepage']);expect(state.pending).toBe(null);
  state=transition(state,[]);expect(state.pending).toBe(null);
  state=transition(state,[]);expect(state.pending.kind).toBe('recovery');
  expect(acknowledged(state).incident).toBe(null);
 });
 it('retains the same notification key on retry',()=>{
  const first=transition(transition(undefined,['health']),['health']);
  expect(transition(first,['health']).pending).toEqual(first.pending);
 });
 it('does not announce recovery for an unsent incident',()=>{
  const first=transition(transition(undefined,['health']),['health']);
  expect(transition(transition(first,[]),[]).pending).toBe(null);
 });
 it('reports transport rejection; sends only fixed diagnostic fields',async()=>{
  const fetcher=vi.fn(async(_url:string,_init:RequestInit)=>new Response('',{status:500}));
  await expect(notify({id:'one',kind:'incident',issues:['homepage'],startedAt:'today'}, {MONITOR_EMAIL_TO:'ops@example.com',MONITOR_EMAIL_FROM:'canary@example.com',MONITOR_RESEND_KEY:'key'},fetcher)).rejects.toThrow('500');
  expect(JSON.parse(String(fetcher.mock.calls[0][1].body)).text).toContain('homepage');
 });
 it('validates API cache and health contract and never forwards monitor auth to public paths',async()=>{
  const fetcher=vi.fn(async(url:string,init:RequestInit)=>{
   if(url.includes('/health'))return Response.json({ok:true,issues:[]});
   expect(init.headers).not.toHaveProperty('authorization');
   if(url.includes('/developer'))return new Response(null,{status:307,headers:{location:'/login?next=%2Fdeveloper'}});
   if(url.includes('/advisories'))return (init.headers as Record<string,string>)['if-none-match']?new Response(null,{status:304}):Response.json({data:[{}],catalog_revision:1},{headers:{etag:'"1"'}});
   return new Response('Zero Day Canary');
  });
  expect(await probe({base:'https://x',token:'secret',fetcher})).toEqual([]);
 });
});
