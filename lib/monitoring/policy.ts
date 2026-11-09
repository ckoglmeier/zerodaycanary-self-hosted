// Fixed categories only. Never retain a pathname, error text or customer data.
export const ERROR_AREAS = ['login','mail','scan','upload','share','billing','render','api','browser'] as const;
export type ErrorArea = typeof ERROR_AREAS[number];
export function errorArea(path: string): ErrorArea {
  const p = path.split(/[?#]/,1)[0];
  if (/^\/(auth|login)(\/|$)|^\/api\/auth\//.test(p)) return 'login';
  if (/^\/api\/stripe\/|^\/api\/app\/billing\//.test(p)) return 'billing';
  if (/\/share(?:\/|$)/.test(p)) return 'share';
  if (/\/evidence(?:\/|$)|\/upload(?:\/|$)/.test(p)) return 'upload';
  if (/\/analyze(?:\/|$)|\/recheck(?:\/|$)/.test(p)) return 'scan';
  return p.startsWith('/api/') ? 'api' : 'render';
}
export type HealthFacts = {
  reviewAt: string|null; reviewFailed: boolean;
  dailySuccessAt: string|null; dailyStartedAt: string|null; dailyOutcome: string|null;
  monitoringStartedAt: string|null;
  serverErrors: number; clientErrors: number;
};
export function healthIssues(f: HealthFacts, now=Date.now()): string[] {
  const age=(date:string|null)=>date && Number.isFinite(Date.parse(date)) ? now-Date.parse(date) : Infinity;
  const issues:string[]=[];
  if(f.reviewFailed)issues.push('feed_review_failed');
  if(age(f.reviewAt)>36*3600_000)issues.push('feed_review_overdue');
  if(f.dailyOutcome==='failed')issues.push('daily_job_failed');
  if(f.dailyOutcome==='started'&&age(f.dailyStartedAt)>10*60_000)issues.push('daily_job_interrupted');
  if(age(f.dailySuccessAt)>27*3600_000 && (f.dailySuccessAt!==null || age(f.monitoringStartedAt)>27*3600_000))issues.push('daily_job_overdue');
  if(f.serverErrors>=3)issues.push('server_errors');
  if(f.clientErrors>=5)issues.push('browser_errors');
  return issues;
}
