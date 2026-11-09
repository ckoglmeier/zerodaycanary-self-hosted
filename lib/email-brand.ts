// Shared, dependency-free email shell. Templates are also usable by self-hosters.
export const BRAND_URL=(process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000").replace(/\/$/, "");
export const escapeHtml=(s:string)=>s.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]!);
export function emailShell(title:string,body:string,action:{label:string;url:string},footer:string) {
  const url=action.url.startsWith('{{')?action.url:escapeHtml(action.url);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} · Zero Day Canary</title></head><body style="margin:0;background:#F7F8F6;color:#172B32;font-family:Arial,Helvetica,sans-serif;line-height:1.6"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#FFFFFF;border:1px solid #DCE2DE;border-radius:12px"><tr><td style="padding:28px"><a href="${BRAND_URL}" style="color:#172B32;text-decoration:none;font-size:20px;font-weight:bold"><img src="${BRAND_URL}/brand/canary-160.png" alt="" width="40" height="40" style="vertical-align:middle;margin-right:8px">Zero Day Canary</a><h1 style="font-size:24px;line-height:1.3;margin:24px 0 16px">${escapeHtml(title)}</h1>${body}<p style="margin:24px 0"><a href="${url}" style="display:inline-block;background:#F2CB4B;color:#172B32;padding:12px 20px;border-radius:8px;font-weight:bold;text-decoration:none">${escapeHtml(action.label)}</a></p><p style="font-size:13px;color:#526168">${footer}</p><hr style="border:0;border-top:1px solid #DCE2DE;margin:24px 0"><p style="font-size:12px;color:#526168">Zero Day Canary · Possible vulnerabilities. Clear next steps.<br><a href="${BRAND_URL}/about" style="color:#172B32">How Canary works</a></p></td></tr></table></td></tr></table></body></html>`;
}
export function brandedSender(config:string) {
  const email=config.match(/<([^<>]+)>/)?.[1]||config.trim();
  if(!/^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/.test(email)||/[\r\n]/.test(config))throw Error('Configure a valid CANARY_EMAIL_FROM address.');
  return `Zero Day Canary <${email}>`;
}
export function replyToAddress(config=process.env.CANARY_REPLY_TO) {
  const address=config?.trim();
  if(!address)return undefined;
  if(!/^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/.test(address)||/[\r\n]/.test(address))throw Error('Configure a valid CANARY_REPLY_TO address.');
  return address;
}
export function invitationEmail(mail:{app:string;requester:string;url:string}) {
  const u=new URL(mail.url);if(!['https:','http:'].includes(u.protocol))throw Error('Invalid invitation URL');
  return {subject:`Zero Day Canary: a check requested for ${mail.app.replace(/[\r\n]/g,' ').slice(0,100)}`,
    text:`${mail.requester} uses Zero Day Canary to monitor possible open source vulnerabilities and has a question about ${mail.app}.\n\nOpen the specific request and sign in as the invited recipient:\n${mail.url}\n\nGive a quick answer or share a reviewed report, free. Replies stay in Zero Day Canary. A forwarded link does not grant access.\n\nZero Day Canary · ${BRAND_URL}`,
    html:emailShell('A check requested for your app',`<p><strong>${escapeHtml(mail.requester)}</strong> uses Zero Day Canary to monitor possible open source vulnerabilities and has a question about <strong>${escapeHtml(mail.app)}</strong>.</p><p>Open the specific request to see what was detected and what the buyer needs you to confirm. Give a quick answer or share a reviewed report, free.</p>`,{label:'Open request',url:mail.url},'Sign in as the invited recipient. Replies and remediation updates stay in Zero Day Canary. A forwarded link does not grant access.')};
}
