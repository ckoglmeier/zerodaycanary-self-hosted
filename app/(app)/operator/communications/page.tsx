import Link from 'next/link';
import {requireOperator} from '@/lib/auth';
import {assertAdministrator} from '@/lib/admin';
import {invitationEmail} from '@/lib/email-brand';
import {env} from '@/lib/env';

export const metadata={title:'Communications · Admin'};
export default async function Communications(){
 const v=await requireOperator();assertAdministrator(v);
 const configured=!!(process.env.RESEND_API_KEY&&process.env.CANARY_EMAIL_FROM),held=process.env.CANARY_INVITATION_MODE==='hold';
 const sample=invitationEmail({requester:'Cedar College',app:'Course portal',url:'https://www.zerodaycanary.com/requests/example'});
 // The app CSP permits local images. Keep the email's real public URL in the
 // delivered template, but use this deployment's asset in its sandboxed preview.
 const preview=sample.html.replace('src="https://www.zerodaycanary.com/brand/',`src="${env.siteUrl()}/brand/`);
 return <div className="stack" style={{['--gap' as string]:'24px',maxWidth:1000}}>
  <p><Link href="/operator/accounts">← Accounts</Link></p><h1 className="h-page">Email and billing branding</h1>
  <section className="panel stack"><h2 className="h-section">Invitations</h2><p>{held?'Delivery held in this environment.':configured?'Sender and email transport configured. Delivery still needs a real inbox check.':'Not configured: invitation emails are not being sent.'}</p><p className="small">Sender display name: Zero Day Canary. Branded HTML and plain text. The app keeps the recipient-bound link when delivery is unavailable.</p><p className="small">Subject: {sample.subject}</p><iframe title="Sample Zero Day Canary invitation email" sandbox="allow-same-origin" srcDoc={preview} style={{width:'100%',height:620,border:'1px solid var(--color-line)',borderRadius:12}}/></section>
  <section className="panel stack"><h2 className="h-section">Sign-in and account emails</h2><p>Branded templates are included for sign-in, confirmation, email changes, account recovery, invitations, reauthentication and security notifications. They must also be installed in Supabase.</p><p className="small">Configure a verified sender named Zero Day Canary and custom SMTP. This page cannot confirm Supabase settings or inbox delivery.</p><Link href="https://supabase.com/dashboard" target="_blank" rel="noreferrer">Open Supabase settings</Link></section>
  <section className="panel stack"><h2 className="h-section">Checkout, invoices and receipts</h2><p>Checkout uses the Canary name and colors. Stripe’s business profile and branding control the billing portal, invoice and receipt emails, and legal business details.</p><p className="small">Review the account name, logo, support contact and sender domain in Stripe before enabling live payments. A checkout display name does not change those account settings.</p><Link href="https://dashboard.stripe.com/settings/branding" target="_blank" rel="noreferrer">Open Stripe branding</Link></section>
 </div>;
}
