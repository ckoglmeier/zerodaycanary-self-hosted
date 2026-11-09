import type { ReportRequestContext } from "@/lib/review/presentation";
import { requestSummary } from "@/lib/review/presentation";

export function RequestContext({ context }: { context: ReportRequestContext }) {
  return <section className="notice n-neutral stack" aria-label="Specific client request">
    <strong>Request from {context.requester} for {context.app}</strong>
    <p className="small mono wrap">{context.url}</p>
    {context.identifiers.length ? <p className="small"><strong>Requested alerts:</strong> {context.identifiers.join(" · ")}</p> : null}
    <p className="small" style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere"}}>{requestSummary(context.question)}</p>
    {requestSummary(context.question)!==context.question?<details><summary>Read the full request</summary><p className="small" style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere"}}>{context.question}</p></details>:null}
  </section>;
}
