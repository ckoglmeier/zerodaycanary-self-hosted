import Link from 'next/link';
import {requireViewer} from '@/lib/auth';
import {reviewData} from '@/lib/review/requests';
import {ownProject} from '@/lib/developer/projects';
import {BuildReport} from '@/components/build-report';
import {reportRequestContext} from '@/lib/review/presentation';
export const metadata={title:'Build a Canary report'};
export default async function Skill({searchParams}:{searchParams:Promise<{request?:string;project?:string}>}){
 const sp=await searchParams,v=await requireViewer('/developer/skill');const context=sp.request?await reviewData(v,sp.request):null,p=sp.project?await ownProject(v,sp.project):null,name=p?.name||context?.label||'My app';
 return <div className="stack" style={{maxWidth:840,marginInline:'auto'}}><p><Link href={context?`/reviews/${sp.request}`:'/developer'}>← {context?'Back to the request':'Developer projects'}</Link></p><h1 className="h-page">Build a report for {name}</h1><p>Use the skill locally, then bring the report back here. Free for you and the client you share it with.</p><BuildReport name={name} projectId={p?.id} requestId={sp.request} context={context?reportRequestContext(context):undefined}/><p className="hint">Evaluation download. Original-code licensing and public package/store distribution have not been selected; bundled third-party notices are retained.</p></div>;
}
