"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

export function ShareReportForm({projectId,requestId,requester,needsFix}:{projectId:string;requestId?:string;requester?:string;needsFix:boolean}) {
  const router=useRouter(), [pending,setPending]=useState(false), [busy,setBusy]=useState(false), [error,setError]=useState("");
  async function submit(e:React.FormEvent<HTMLFormElement>) {
    e.preventDefault(); setBusy(true); setError("");
    try {
      const r=await fetch(`/api/app/reviews/${projectId}/publish-report`,{method:"POST",headers:{accept:"application/json"},body:new FormData(e.currentTarget)});
      const data=await r.json();
      if(!r.ok) throw Error(data.error?.message||"The report could not be shared. Your entries are kept below.");
      router.push(requestId?`/reviews/${requestId}?msg=Reviewed%20report%20shared%20with%20the%20requester`:`/reports/${data.pageId}?msg=Reviewed%20report%20page%20created`);
      router.refresh();
    } catch(e) {setError((e as Error).message); setBusy(false);}
  }
  return <form id="share-report" onSubmit={submit} className="panel stack">
    <input type="hidden" name="conversation_id" value={requestId||""}/>
    <h2 className="h-section">{requester?`Share with ${requester}`:"Create your reusable report page"}</h2>
    {needsFix?<><p className="small">The report has findings requiring a fix or further confirmation. Describe your plan; you can say the target date is still being determined.</p><div><label htmlFor="share-plan">Fix or investigation plan</label><textarea id="share-plan" name="remediation_plan" required rows={3} maxLength={2000}/></div><div><label htmlFor="share-target">Target date</label><input id="share-target" name="target_date" type="date" required={!pending} disabled={pending}/></div><label className="row"><input type="checkbox" name="date_pending" checked={pending} onChange={e=>setPending(e.target.checked)} style={{width:20,height:20}}/>The date is still being determined</label></>:<p>No remediation timeline is required for this report. Unknown applicability and unassessed components stay explicit.</p>}
    <p className="small muted">Only the reviewed report above is shared. Publishing a newer snapshot updates this report page for clients already granted access. Later private uploads are not shared automatically.</p>
    {error?<p role="alert" className="field-error">{error}</p>:null}
    <div><button className="btn btn-brand" disabled={busy}>{busy?"Sharing reviewed report…":requester?"Share reviewed report":"Create reviewed report page"}</button></div>
    {requester?<p className="hint">Free for you and {requester}. The report and your plan will be attached to this app’s conversation.</p>:null}
  </form>;
}
