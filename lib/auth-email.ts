// Supabase Auth email content. The same definitions produce the provider
// templates (SMTP fallback) and the messages sent by the Send Email Hook.
import {createHmac,timingSafeEqual} from 'node:crypto';
import {emailShell,escapeHtml} from './email-brand';

const SAFETY='If you did not request this, you can ignore this email. Never forward sign-in links or codes.';
const NOTICE='This is an account security notification from Zero Day Canary. Never share sign-in links or codes.';
type Action={key:string;title:string;text:string;label:string;code?:boolean};
export const AUTH_ACTIONS:Action[]=[
 {key:'confirmation',title:'Confirm your email',text:'Confirm your email address to open your Zero Day Canary account.',label:'Confirm email'},
 {key:'invite',title:'You’re invited to Zero Day Canary',text:'You have been invited to Zero Day Canary. Continue to set up access.',label:'Accept invitation'},
 {key:'magic_link',title:'Sign in to Zero Day Canary',text:'Use this secure link to sign in. Your app requests, reports and monitoring stay in one place.',label:'Sign in'},
 {key:'email_change',title:'Confirm your new email',text:'Confirm this change to the email address for your Zero Day Canary account.',label:'Confirm email change'},
 {key:'recovery',title:'Reset your password',text:'You requested a password reset for your Zero Day Canary account.',label:'Reset password'},
 {key:'reauthentication',title:'Confirm it’s you',text:'Enter this one-time code in Zero Day Canary:',label:'Open account',code:true},
];
export const NOTIFICATIONS:[string,string][]=[
 ['password_changed_notification','Your password was changed'],['email_changed_notification','Your email address was changed'],
 ['phone_changed_notification','Your phone number was changed'],['identity_linked_notification','A sign-in method was added'],
 ['identity_unlinked_notification','A sign-in method was removed'],['mfa_factor_enrolled_notification','A verification method was added'],
 ['mfa_factor_unenrolled_notification','A verification method was removed'],
];
export type AuthMessage={subject:string;html:string;text:string};

/** Renders one message. `url` and `code` may be Supabase placeholders when preparing provider templates. */
export function renderAuthEmail(key:string,url:string,code=''):AuthMessage{
  const a=AUTH_ACTIONS.find(x=>x.key===key);
  if(a){
    const codeHtml=a.code?` <strong>${code.startsWith('{{')?code:escapeHtml(code)}</strong>.`:'';
    return {subject:a.title,
      html:emailShell(a.title,`<p>${a.text}${codeHtml}</p>`,{label:a.label,url},SAFETY),
      text:`${a.title}\n\n${a.text}${a.code?` ${code}`:''}\n\n${a.label}: ${url}\n\n${SAFETY}\n\nZero Day Canary · https://www.zerodaycanary.com`};
  }
  const n=NOTIFICATIONS.find(([k])=>k===key);
  if(!n)throw Error(`Unsupported auth email ${key}`);
  const body='If you did not make this change, open your account through your usual sign-in method and review access immediately.';
  return {subject:n[1],
    html:emailShell(n[1],`<p>${n[1]} on your Zero Day Canary account.</p><p>${body}</p>`,{label:'Open account',url},NOTICE),
    text:`${n[1]}\n\n${n[1]} on your Zero Day Canary account.\n\n${body}\n\nOpen account: ${url}\n\n${NOTICE}\n\nZero Day Canary · https://www.zerodaycanary.com`};
}

/** Standard Webhooks verification for Supabase Auth hooks. Throws on any failure. */
export function verifyHookSignature(secret:string,headers:Headers,body:string,now=Date.now()){
  const id=headers.get('webhook-id'),ts=headers.get('webhook-timestamp'),sig=headers.get('webhook-signature');
  if(!id||!ts||!sig)throw Error('missing signature');
  const seconds=Number(ts);
  if(!Number.isInteger(seconds)||Math.abs(now/1000-seconds)>300)throw Error('stale signature');
  const key=Buffer.from(secret.replace(/^v1,whsec_/,'').replace(/^whsec_/,''),'base64');
  if(!key.length)throw Error('invalid secret');
  const expected=createHmac('sha256',key).update(`${id}.${ts}.${body}`).digest();
  const ok=sig.split(' ').some(part=>{
    const [version,value]=part.split(',');if(version!=='v1'||!value)return false;
    const given=Buffer.from(value,'base64');
    return given.length===expected.length&&timingSafeEqual(given,expected);
  });
  if(!ok)throw Error('invalid signature');
}

type HookPayload={user:{email?:string;new_email?:string};email_data:{token?:string;token_hash?:string;token_new?:string;token_hash_new?:string;redirect_to?:string;email_action_type:string;site_url?:string}};
export type AuthDelivery=AuthMessage&{to:string};
const TEMPLATE_FOR:Record<string,string>={signup:'confirmation',invite:'invite',magiclink:'magic_link',email:'magic_link',recovery:'recovery',email_change:'email_change',reauthentication:'reauthentication'};

/** Turns a Send Email Hook payload into the emails Supabase expects us to deliver. */
export function authDeliveries(p:HookPayload,supabaseUrl:string,siteUrl:string):AuthDelivery[]{
  const d=p.email_data,type=d?.email_action_type;
  if(!type)throw Error('missing email action');
  const site=siteUrl.replace(/\/$/,'');
  const verify=(hash:string)=>{
    const q=new URLSearchParams({token:hash,type});if(d.redirect_to)q.set('redirect_to',d.redirect_to);
    return `${supabaseUrl.replace(/\/$/,'')}/auth/v1/verify?${q}`;
  };
  if(type.endsWith('_notification')){
    if(!p.user?.email)throw Error('missing recipient');
    return [{to:p.user.email,...renderAuthEmail(type,`${site}/account`)}];
  }
  const key=TEMPLATE_FOR[type];if(!key)throw Error(`Unsupported auth email ${type}`);
  if(type==='reauthentication'){
    if(!p.user?.email||!d.token)throw Error('missing reauthentication code');
    return [{to:p.user.email,...renderAuthEmail(key,`${site}/account`,d.token)}];
  }
  if(type==='email_change'){
    const newEmail=p.user?.new_email;if(!newEmail)throw Error('missing new email');
    if(d.token_hash&&d.token_hash_new&&p.user.email)return [
      {to:p.user.email,...renderAuthEmail(key,verify(d.token_hash_new))},
      {to:newEmail,...renderAuthEmail(key,verify(d.token_hash))},
    ];
    const hash=d.token_hash||d.token_hash_new;if(!hash)throw Error('missing token');
    return [{to:newEmail,...renderAuthEmail(key,verify(hash))}];
  }
  if(!p.user?.email||!d.token_hash)throw Error('missing recipient or token');
  return [{to:p.user.email,...renderAuthEmail(key,verify(d.token_hash))}];
}
