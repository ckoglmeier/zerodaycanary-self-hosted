import { describe,it,expect,vi } from "vitest";
vi.mock('server-only',()=>({}));
import { answerSchema } from "@/lib/review/validation";
import { findingSignature,type FindingCandidate } from "@/lib/review/findings";
const key='806146c2-075b-47f5-aa9a-47f23b3d0393';
describe('attributed owner answers',()=>{
 it('accepts a brief not-affected answer without mandatory report or remediation',()=>{expect(answerSchema.parse({outcome:'not_affected',reason:'This app does not use PHP.',client_key:key}).outcome).toBe('not_affected');});
 it('does not turn missing evidence into a fix-plan requirement',()=>{expect(answerSchema.safeParse({outcome:'unknown',reason:'The vendor has not supplied the runtime version.',client_key:key}).success).toBe(true);});
 it('requires a fix plan and a real date or explicit pending date',()=>{const base={outcome:'affected',reason:'Affected deployed version.',client_key:key};expect(answerSchema.safeParse(base).success).toBe(false);expect(answerSchema.safeParse({...base,remediation_plan:'Patch PHP.'}).success).toBe(false);expect(answerSchema.safeParse({...base,remediation_plan:'Patch PHP.',date_pending:true}).success).toBe(true);expect(answerSchema.safeParse({...base,remediation_plan:'Patch PHP.',target_date:'2026-02-30'}).success).toBe(false);});
});
describe('meaningful finding identity',()=>{
 const candidate={componentKey:'php',product:'php',sourceKind:'public',sourceAt:'2026-10-22T12:00:00Z',sourceId:'scan-1',result:{advisory_id:'same-alert',advisory_revision:1,status:'needs_verification',version_used:'8.3.35',version_basis:'observed',matched_range:{introduced:'8.3.0',fixed:'8.3.36'},conditions:[]}} as unknown as FindingCandidate;
 it('does not re-alert merely because a scan or catalog revision is new',()=>{expect(findingSignature(candidate)).toBe(findingSignature({...candidate,sourceId:'scan-2',sourceAt:'2026-10-23T12:00:00Z',result:{...candidate.result,advisory_revision:2}}));});
 it('detects changed affected ranges and version/condition evidence',()=>{expect(findingSignature(candidate)).not.toBe(findingSignature({...candidate,result:{...candidate.result,version_used:'8.3.36'}}));});
});
