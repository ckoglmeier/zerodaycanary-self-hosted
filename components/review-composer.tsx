"use client";
import {useState,type ReactNode} from 'react';
import {useRouter} from 'next/navigation';

// One conversation composer. A structured owner answer is an optional addition
// to the same reply, rather than a competing form or a second primary action.
export function ReviewComposer({conversationId,requestId,owner,clientKey,children}:{conversationId:string;requestId?:string;owner:boolean;clientKey:string;children?:ReactNode}){
 const [status,setStatus]=useState(''),[pending,setPending]=useState(false),[body,setBody]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState(''),[sent,setSent]=useState(false),[key,setKey]=useState(clientKey);const router=useRouter();
 async function submit(e:React.FormEvent<HTMLFormElement>){e.preventDefault();setBusy(true);setError('');setSent(false);const form=e.currentTarget;
  try{const response=await fetch(`/api/app/reviews/${conversationId}/respond`,{method:'POST',headers:{accept:'application/json'},body:new FormData(form)});const data=await response.json();if(!response.ok)throw Error(data.error?.message||'Could not save your reply.');form.reset();setBody('');setStatus('');setPending(false);setKey(crypto.randomUUID());setSent(true);router.refresh();}
  catch(e){setError((e as Error).message);}finally{setBusy(false);}
 }
 return <form onSubmit={submit} className="stack no-print"><input type="hidden" name="request_id" value={requestId||''}/><input type="hidden" name="client_key" value={key}/><div><label htmlFor="review-reply">Your reply</label><textarea id="review-reply" name="body" rows={4} required maxLength={2000} value={body} onChange={e=>{setBody(e.target.value);setSent(false);}} placeholder="Share what you found, or ask a question."/></div>
 {owner&&requestId?<details className="composer-option"><summary className="small">Add a status update</summary><div className="stack"><div><label htmlFor="reply-status">Status</label><select id="reply-status" name="outcome" value={status} onChange={e=>setStatus(e.target.value)}><option value="">No status change</option><option value="not_affected">Not affected by this alert</option><option value="affected">Affected — a fix is needed</option><option value="unknown">Not sure — more evidence needed</option><option value="fix_reported">Fix deployed — please recheck</option></select></div>{status==='affected'?<><div><label htmlFor="reply-plan">Fix plan</label><textarea id="reply-plan" name="remediation_plan" rows={2} required maxLength={2000}/></div><div><label htmlFor="reply-date">Target fix date</label><input id="reply-date" name="target_date" type="date" required={!pending} disabled={pending}/></div><label className="row small"><input type="checkbox" name="date_pending" checked={pending} onChange={e=>setPending(e.target.checked)} style={{width:20,height:20}}/>The date is still being determined</label></>:null}{status?<p className="hint">Your reply explains this status. It is your confirmation, not independent verification of the deployed app.</p>:null}</div></details>:null}
 {children}
 {error?<p className="field-error" role="alert">{error}</p>:null}{sent?<p className="small" role="status">Reply sent.</p>:null}<div><button className="btn btn-primary" disabled={busy||!body.trim()}>{busy?'Sending…':'Send reply'}</button></div><p className="hint">Replies stay with this app. Don’t include passwords, tokens or source code.</p></form>;
}
