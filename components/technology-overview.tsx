"use client";
import {useRef,useState} from 'react';
import {useRouter} from 'next/navigation';
import {OVERVIEW_ACCEPT,OVERVIEW_FILE_BYTES,OVERVIEW_TEXT_CHARS} from '@/lib/overview-limits';

function OverviewFields({id}:{id:string}) {
  return <div className="stack" style={{marginTop:12}}>
    <p className="small muted" id={`${id}-hint`}>Have an old security report, architecture overview or technology list? Add it for clues about what this system may use. Entirely optional.</p>
    <div><label htmlFor={`${id}-file`}>Document</label><input id={`${id}-file`} name="overview_file" type="file" accept={OVERVIEW_ACCEPT} aria-describedby={`${id}-formats ${id}-privacy`}/><p id={`${id}-formats`} className="hint">PDF, Word (.docx) or text · up to 2 MB and 40 PDF pages. Scans and images need pasted text.</p></div>
    <div><label htmlFor={`${id}-notes`}>Or paste notes</label><textarea id={`${id}-notes`} name="overview" rows={4} maxLength={OVERVIEW_TEXT_CHARS} aria-describedby={`${id}-privacy`} placeholder="For example: a 2024 review says the portal uses PHP and MySQL."/></div>
    <p id={`${id}-privacy`} className="hint">Private to your workspace. We keep extracted text for technology clues, not the original file. It is not sent to an AI provider or shared with the developer. Remove secrets before adding it.</p>
  </div>;
}

export function TechnologyOverviewForm({systemId,hasOverview=false}:{systemId?:string;hasOverview?:boolean}) {
  const router=useRouter(),ref=useRef<HTMLFormElement>(null);
  const [error,setError]=useState(''),[busy,setBusy]=useState(false);
  async function submit(e:React.FormEvent<HTMLFormElement>) {
    e.preventDefault();setError('');const form=e.currentTarget,body=new FormData(form),file=body.get('overview_file');
    if(file instanceof File&&file.size>OVERVIEW_FILE_BYTES){setError('Choose a file smaller than 2 MB.');return;}
    setBusy(true);
    try {
      const r=await fetch(systemId?`/api/app/systems/${systemId}/overview`:'/api/app/analyze',{method:'POST',headers:{accept:'application/json'},body});
      const data=await r.json();if(!r.ok)throw Error(data.error?.message||'Could not save this check. Your inputs are kept; try again.');
      if(systemId){form.reset();router.push(`/systems/${systemId}?msg=Technology+overview+saved.#technology-overview`);router.refresh();}
      else {router.push(`/systems/${data.systemId}${data.cached?'?msg=Showing+a+previous+public+check.+Re-analyze+for+a+fresh+check.':''}`);router.refresh();}
    }catch(e){setError((e as Error).message);}finally{setBusy(false);}
  }
  async function remove() {
    if(!window.confirm('Remove this overview and its extracted text? Public checks and developer reports are kept.'))return;
    setBusy(true);setError('');try{const r=await fetch(`/api/app/systems/${systemId}/overview`,{method:'DELETE',headers:{accept:'application/json'}});if(!r.ok)throw Error('Could not remove the overview.');ref.current?.reset();router.push(`/systems/${systemId}?msg=Technology+overview+removed.#technology-overview`);router.refresh();}catch(e){setError((e as Error).message);}finally{setBusy(false);}
  }
  const id=systemId?'replace-overview':'new-overview';
  return <form ref={ref} method="post" encType="multipart/form-data" action={systemId?`/api/app/systems/${systemId}/overview`:'/api/app/analyze'} onSubmit={submit} className={systemId?'stack':'panel stack'} aria-busy={busy}>
    {!systemId?<><div><label htmlFor="url">Check a system</label><input id="url" name="url" type="text" inputMode="url" required placeholder="https://portal.example.edu" aria-describedby="url-hint"/></div><p id="url-hint" className="hint">Enter one app or vendor web address. We check public signals for possible vulnerabilities. Checking is free; monitoring is a separate choice.</p></>:null}
    <details><summary>{hasOverview?'Replace technology overview':'Add a technology overview (optional)'}</summary><OverviewFields id={id}/>{systemId?<button type="submit" disabled={busy} className="btn btn-secondary">{busy?'Reading overview…':'Save overview'}</button>:null}</details>
    {error?<p className="field-error" role="alert">{error}</p>:null}
    {!systemId?<button type="submit" disabled={busy} className="btn btn-primary">{busy?'Checking public signals and overview…':'Check system'}</button>:null}
    {systemId&&hasOverview?<button type="button" disabled={busy} className="linkbtn small" onClick={remove}>Remove overview</button>:null}
    <span role="status" className="sr-only">{busy?'Working. Please wait.':''}</span>
  </form>;
}
