import {describe,it,expect,vi,afterEach} from 'vitest';
import {createHmac,randomBytes} from 'node:crypto';
vi.mock('server-only',()=>({}));
vi.mock('@/lib/monitoring/server',()=>({recordError:vi.fn()}));
vi.mock('next/server',async(importOriginal)=>({...await importOriginal<typeof import('next/server')>(),after:vi.fn()}));
import {authDeliveries,verifyHookSignature} from '@/lib/auth-email';
import {POST} from '@/app/api/auth/send-email/route';

const key=randomBytes(32),secret=`v1,whsec_${key.toString('base64')}`;
const sign=(body:string,id='msg_1',ts=Math.floor(Date.now()/1000))=>new Headers({'webhook-id':id,'webhook-timestamp':String(ts),
  'webhook-signature':`v1,${createHmac('sha256',key).update(`${id}.${ts}.${body}`).digest('base64')}`});
const SB='https://proj.supabase.co',SITE='https://www.zerodaycanary.com';
const payload=(type:string,extra:object={},user:object={email:'a@example.com'})=>({user,email_data:{token:'123456',token_hash:'pkce_hash',redirect_to:`${SITE}/auth/callback?next=/app`,email_action_type:type,site_url:SB,token_new:'',token_hash_new:'',...extra}});

describe('send email hook signature',()=>{
  const body=JSON.stringify(payload('magiclink'));
  it('accepts a valid signature, including alongside other versions',()=>{
    const h=sign(body);h.set('webhook-signature',`v2,abc ${h.get('webhook-signature')}`);
    expect(()=>verifyHookSignature(secret,h,body)).not.toThrow();
  });
  it('rejects tampered bodies, wrong secrets, stale and missing headers',()=>{
    expect(()=>verifyHookSignature(secret,sign(body),body+' ')).toThrow(/invalid/);
    expect(()=>verifyHookSignature(`v1,whsec_${randomBytes(32).toString('base64')}`,sign(body),body)).toThrow(/invalid/);
    expect(()=>verifyHookSignature(secret,sign(body,'m',Math.floor(Date.now()/1000)-600),body)).toThrow(/stale/);
    expect(()=>verifyHookSignature(secret,new Headers(),body)).toThrow(/missing/);
  });
});

describe('auth deliveries',()=>{
  it('builds the branded sign-in email with a Supabase verify link and plain text',()=>{
    const [m]=authDeliveries(payload('magiclink'),SB,SITE);
    expect(m.to).toBe('a@example.com');expect(m.subject).toBe('Sign in to Zero Day Canary');
    const link=`${SB}/auth/v1/verify?token=pkce_hash&type=magiclink&redirect_to=${encodeURIComponent(`${SITE}/auth/callback?next=/app`)}`;
    expect(m.text).toContain(link);expect(m.html).toContain(link.replace(/&/g,'&amp;'));
    expect(m.html).not.toContain('{{');expect(m.text).not.toContain('<');expect(m.html).not.toContain('123456');
  });
  it('maps every action to the right template',()=>{
    const subject=(t:string)=>authDeliveries(payload(t),SB,SITE)[0].subject;
    expect(subject('signup')).toBe('Confirm your email');expect(subject('email')).toBe('Sign in to Zero Day Canary');
    expect(subject('recovery')).toBe('Reset your password');expect(subject('invite')).toBe('You’re invited to Zero Day Canary');
    expect(subject('password_changed_notification')).toBe('Your password was changed');
    const [r]=authDeliveries(payload('reauthentication'),SB,SITE);expect(r.text).toContain('123456');expect(r.html).toContain(`${SITE}/account`);
    expect(()=>authDeliveries(payload('unknown'),SB,SITE)).toThrow();
  });
  it('pairs secure email change hashes the way Supabase documents',()=>{
    const p=payload('email_change',{token_new:'654321',token_hash:'hash_for_new',token_hash_new:'hash_for_current'},{email:'old@example.com',new_email:'new@example.com'});
    const [current,next]=authDeliveries(p,SB,SITE);
    expect(current.to).toBe('old@example.com');expect(current.text).toContain('token=hash_for_current');
    expect(next.to).toBe('new@example.com');expect(next.text).toContain('token=hash_for_new');
    const single=authDeliveries(payload('email_change',{token_hash:'only'},{email:'old@example.com',new_email:'new@example.com'}),SB,SITE);
    expect(single).toHaveLength(1);expect(single[0].to).toBe('new@example.com');
  });
});

describe('send email route',()=>{
  afterEach(()=>{vi.unstubAllEnvs();vi.unstubAllGlobals();});
  const env=()=>{vi.stubEnv('SUPABASE_SEND_EMAIL_HOOK_SECRET',secret);vi.stubEnv('RESEND_API_KEY','re_test');vi.stubEnv('CANARY_EMAIL_FROM','Canary <auth@zerodaycanary.com>');
    vi.stubEnv('CANARY_REPLY_TO','hello@zerodaycanary.com');vi.stubEnv('NEXT_PUBLIC_SUPABASE_URL',SB);vi.stubEnv('NEXT_PUBLIC_SITE_URL',SITE);};
  it('sends through Resend with reply-to and an idempotency key',async()=>{
    env();const fetch=vi.fn(async()=>new Response('{}'));vi.stubGlobal('fetch',fetch);
    const body=JSON.stringify(payload('magiclink'));
    const res=await POST(new Request('https://x/api/auth/send-email',{method:'POST',headers:sign(body,'msg_9'),body}));
    expect(res.status).toBe(200);expect(await res.json()).toEqual({});
    const [,init]=fetch.mock.calls[0] as unknown as [string,RequestInit];const sent=JSON.parse(String(init.body));
    expect(sent).toMatchObject({from:'Zero Day Canary <auth@zerodaycanary.com>',to:['a@example.com'],reply_to:'hello@zerodaycanary.com',subject:'Sign in to Zero Day Canary'});
    expect(sent.text).toBeTruthy();expect((init.headers as Record<string,string>)['idempotency-key']).toBe('auth-msg_9-0');
  });
  it('rejects unsigned calls and reports provider failures to Supabase',async()=>{
    env();const fetch=vi.fn(async()=>new Response('no',{status:500}));vi.stubGlobal('fetch',fetch);vi.spyOn(console,'error').mockImplementation(()=>{});
    const body=JSON.stringify(payload('magiclink'));
    const bad=await POST(new Request('https://x',{method:'POST',headers:{'webhook-id':'a','webhook-timestamp':'1','webhook-signature':'v1,x'},body}));
    expect(bad.status).toBe(401);expect(fetch).not.toHaveBeenCalled();
    const failed=await POST(new Request('https://x',{method:'POST',headers:sign(body),body}));
    expect(failed.status).toBe(502);expect((await failed.json()).error.http_code).toBe(502);
  });
});
