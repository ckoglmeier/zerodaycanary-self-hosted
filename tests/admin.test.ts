import {describe,it,expect,vi} from 'vitest';
vi.mock('server-only',()=>({}));
import {creditInput,assertAdministrator} from '@/lib/admin';
import {brandedSender,invitationEmail} from '@/lib/email-brand';
import {readFileSync} from 'node:fs';
const key='806146c2-075b-47f5-aa9a-47f23b3d0393';
describe('administrator credit boundary',()=>{
 it.each([['29',2900],['19.99',1999],['1.01',101],['1000',100000]])('parses exact USD cents %s',(amount,cents)=>expect(creditInput.parse({amount,reason:'Service credit',client_key:key}).amount).toBe(cents));
 it.each(['0','-29','0.99','1000.01','1e2','NaN','Infinity','19.999','1,000',' 29','29.','+29'])('rejects ambiguous or out-of-bound amount %s',amount=>expect(creditInput.safeParse({amount,reason:'Service credit',client_key:key}).success).toBe(false));
 it('requires a reason and durable request key',()=>{expect(creditInput.safeParse({amount:'29',reason:' ',client_key:key}).success).toBe(false);expect(creditInput.safeParse({amount:'29',reason:'Test credit',client_key:'bad'}).success).toBe(false);});
 it('requires verified server-configured operator identity',()=>{
  vi.stubEnv('OPERATOR_EMAILS','owner@example.com');const v={id:'x',email:'owner@example.com',workspaceId:'w',isOperator:true,emailVerified:true};
  expect(()=>assertAdministrator(v)).not.toThrow();for(const invalid of [{...v,isOperator:false},{...v,emailVerified:false},{...v,email:'other@example.com'}])expect(()=>assertAdministrator(invalid)).toThrow(/Administrator/);vi.unstubAllEnvs();
 });
});
describe('branded transactional communications',()=>{
 it('escapes untrusted app/requester content and brands both formats',()=>{const m=invitationEmail({app:'<script>alert(1)</script>',requester:'Buyer & Co',url:'https://www.zerodaycanary.com/requests/safe?a=1&b=2'});expect(m.subject).toMatch(/^Zero Day Canary:/);expect(m.html).not.toContain('<script>');expect(m.html).toContain('Buyer &amp; Co');expect(m.html).toContain('canary-160.png');expect(m.text).toContain('Replies stay in Zero Day Canary');expect(m.html).toContain('a=1&amp;b=2');});
 it('uses a consistent sender and refuses header injection',()=>{expect(brandedSender('Old Brand <hello@zerodaycanary.com>')).toBe('Zero Day Canary <hello@zerodaycanary.com>');expect(()=>brandedSender('a@b.com\r\nBcc:evil@b.com')).toThrow();expect(()=>invitationEmail({app:'A',requester:'B',url:'javascript:alert(1)'})).toThrow();});
 it('ships all auth and security templates without losing provider variables',()=>{const p=JSON.parse(readFileSync('supabase/email-templates/provider-patch.json','utf8'));const html=Object.entries(p).filter(([k])=>k.endsWith('_content'));expect(html).toHaveLength(13);for(const [k,v]of html){expect(v).toContain('Zero Day Canary');if(k.includes('reauthentication'))expect(v).toContain('{{ .Token }}');else if(!k.includes('_notification_'))expect(v).toContain('{{ .ConfirmationURL }}');}expect(p.mailer_templates_magic_link_content).not.toContain('token_hash=');expect(p.mailer_subjects_magic_link).toContain('Zero Day Canary');});
});
