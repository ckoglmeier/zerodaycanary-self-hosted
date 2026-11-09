import Link from 'next/link';
import {TechnologyOverviewForm} from './technology-overview';
import {abs} from './time';
import type {systemOverview} from '@/lib/system-overview';

export function OverviewClues({systemId,overview}:{systemId:string;overview:Awaited<ReturnType<typeof systemOverview>>}) {
  return <section className="panel stack" id="technology-overview" aria-labelledby="overview-title">
    <h2 className="h-section" id="overview-title">Technology overview</h2>
    {overview?<>
      <p className="small wrap"><strong>{overview.source}</strong> · updated {abs(overview.updated_at)}{overview.pages?` · ${overview.pages} pages`:''}</p>
      <p className="small muted">Historical clues, not a current inventory. Mentions may describe old versions, recommendations or software the vendor does not use. They do not change the public check or confirm a vulnerability.</p>
      {overview.clues.length?<ul className="list">{overview.clues.map(c=><li className="stack" key={c.product}>
        <div className="spread"><strong>{c.name}</strong><span className="badge">Mentioned · needs confirmation</span></div>
        {c.mentions.map((m,i)=><div key={i}><blockquote className="small wrap" style={{margin:'0 0 4px',paddingLeft:12,borderLeft:'2px solid var(--line)'}}>{m.quote}</blockquote><p className="hint">{m.location}{m.version?` · document mentions ${m.version}`:''}</p></div>)}
        {c.alerts.length?<details><summary className="small">{c.alerts.length} related reviewed alert{c.alerts.length===1?'':'s'} · applicability unknown</summary><ul className="small">{c.alerts.map(a=><li key={a.id}><Link href={`/advisory/${a.id}`}>{a.identifier}: {a.title}</Link></li>)}</ul></details>:<p className="hint">No reviewed alert for this technology in Canary’s current catalog. This is not a security clearance.</p>}
        <Link className="small no-print" href={`/systems/${systemId}/request?clue=${encodeURIComponent(c.product)}`}>Ask the owner to confirm {c.name}</Link>
      </li>)}</ul>:<p className="small">No technology names recognized in the readable text. This does not establish what the system uses or whether it is safe. You can add more detail or ask its owner.</p>}
      <p className="hint">Private to your workspace. No automatic alert or message was sent. Related alerts use the current reviewed catalog.</p>
    </>:<p className="small muted">Have a security report or technology notes? Add them for clues the public check may miss.</p>}
    <div className="no-print"><TechnologyOverviewForm systemId={systemId} hasOverview={!!overview}/></div>
  </section>;
}
