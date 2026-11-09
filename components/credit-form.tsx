"use client";
import { useRef,useState } from "react";
import { useRouter } from "next/navigation";

export function CreditForm({accountId,email,clientKey,testMode,balanceAvailable,retry}:{accountId:string;email:string;clientKey:string;testMode:boolean;balanceAvailable:boolean;retry?:{amount:string;reason:string}}) {
  const router=useRouter(),[pending,setPending]=useState(false),[message,setMessage]=useState(''),[done,setDone]=useState(false),[locked,setLocked]=useState(!!retry);
  const request=useRef<{amount:string;reason:string;client_key:string}|null>(retry?{...retry,client_key:clientKey}:null);
  async function submit(e:React.FormEvent<HTMLFormElement>){
    e.preventDefault();if(pending||done)return;
    if(!locked){const f=new FormData(e.currentTarget);request.current={amount:String(f.get('amount')),reason:String(f.get('reason')),client_key:clientKey};}
    setPending(true);setLocked(true);setMessage('');
    try{
      const r=await fetch(`/api/operator/accounts/${accountId}/credits`,{method:'POST',headers:{'content-type':'application/json',accept:'application/json'},body:JSON.stringify(request.current)});
      const result=await r.json();
      if(!r.ok){if(r.status===400||r.status===403||r.status===404)setLocked(false);throw Error(result.error?.message||'Credit outcome unconfirmed. Retry the same request.');}
      setDone(true);setMessage('Credit applied to the account’s invoice balance.');router.refresh();
    }catch(e){setMessage((e as Error).message);}finally{setPending(false);}
  }
  return <form onSubmit={submit} className="panel stack" aria-label="Grant monitoring credit">
    <h2 className="h-section">Grant monitoring credit</h2><p className="small">For <strong className="wrap">{email}</strong>. Applies to the next finalized monitoring invoice; unused credit carries forward. It does not refund a paid invoice or start monitoring.</p>
    {testMode?<p className="notice n-warning">Stripe test mode. These credits have no cash value.</p>:null}
    {!balanceAvailable?<p className="notice n-warning">Billing balance is unavailable. Refresh before granting a credit.</p>:null}
    {retry?<p className="notice n-warning">An adjustment is pending. Retry it before starting another credit.</p>:null}
    <fieldset disabled={pending||done||locked||!balanceAvailable} className="stack" style={{border:0,padding:0,margin:0}}><div><label htmlFor="credit-amount">Credit (USD)</label><input id="credit-amount" name="amount" type="number" min="1" max="1000" step="0.01" required placeholder="29.00" defaultValue={retry?.amount} style={{maxWidth:220}}/></div><div><label htmlFor="credit-reason">Internal reason</label><textarea id="credit-reason" name="reason" rows={2} required minLength={3} maxLength={500} defaultValue={retry?.reason}/></div></fieldset>
    {/* Keep submitted values on uncertain outcomes, for the same durable retry. */}
    <button type="submit" className="btn btn-brand" disabled={pending||done||!balanceAvailable}>{pending?'Applying credit…':done?'Credit applied':locked?'Retry same credit':'Grant credit'}</button>
    {message?<p role="status" className={done?'notice n-success':'notice n-warning'}>{message}</p>:null}
    {done?<p><a href={`/operator/accounts/${accountId}`}>Start another adjustment</a></p>:null}
  </form>;
}
