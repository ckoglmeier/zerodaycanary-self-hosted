// Generate reviewable provider templates without changing any provider settings.
// These are the SMTP fallback; the Send Email Hook renders the same content.
import {mkdir,writeFile} from 'node:fs/promises';
import {AUTH_ACTIONS,NOTIFICATIONS,renderAuthEmail} from '../lib/auth-email';
const root='supabase/email-templates';await mkdir(root,{recursive:true});
const payload:Record<string,string>={};
const keys=[...AUTH_ACTIONS.map(a=>a.key),...NOTIFICATIONS.map(([k])=>k)];
for(const key of keys){
 const url=key==='reauthentication'||key.endsWith('_notification')?'{{ .SiteURL }}/account':'{{ .ConfirmationURL }}';
 const m=renderAuthEmail(key,url,'{{ .Token }}');
 payload[`mailer_subjects_${key}`]=m.subject;payload[`mailer_templates_${key}_content`]=m.html;
 await writeFile(`${root}/${key}.html`,m.html+'\n');
}
await writeFile(`${root}/provider-patch.json`,JSON.stringify(payload,null,2)+'\n');
console.log(`Prepared ${keys.length} branded templates. No provider settings changed or email sent.`);
