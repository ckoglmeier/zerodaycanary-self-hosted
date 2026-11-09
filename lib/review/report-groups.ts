import type { ReportSnapshot, SharedComponent } from "./reports";
import type { DevResult } from "../developer/evaluate";
import type { CveReview } from "../developer/cve-report";

export type ReportGroup = { component:SharedComponent; results:DevResult[]; assessments:CveReview["assessments"]; needsReview:boolean; packageState:string };

// Presentation only: retain every result and each distinct source conclusion.
// Grouping never changes matching, stored snapshots, API data or exposure claims.
export function groupReport(snapshot:ReportSnapshot): ReportGroup[] {
  const coverage=Array.isArray(snapshot.coverage.component_coverage)?snapshot.coverage.component_coverage as {instance:number;status:string}[]:[];
  const groups = new Map<number,ReportGroup>(snapshot.components.map(component=>[component.instance,{component,results:[],assessments:[],needsReview:false,packageState:coverage.find(c=>c.instance===component.instance)?.status||"unknown"}]));
  const ensure=(instance:number, component?:DevResult["component"])=>{
    if (!groups.has(instance)) groups.set(instance,{component:{instance,name:component?.name||`Component ${instance} (inventory missing)`,version:component?.version||null,ecosystem:component?.ecosystem||"unknown",relationship:component?.relationship||"unknown",development:component?.development??null},results:[],assessments:[],needsReview:false,packageState:"unknown"});
    return groups.get(instance)!;
  };
  for (const result of snapshot.results) {
    const group=ensure(result.component.instance,result.component);
    group.results.push(result);
    if (result.status!=="not_affected") group.needsReview=true;
  }
  for (const assessment of snapshot.cve_review?.assessments||[]) {
    const group=ensure(assessment.component_instance);
    group.assessments.push(assessment);
    if (["needs_verification","source_prerequisites_supported"].includes(assessment.conclusion)) group.needsReview=true;
  }
  return [...groups.values()].sort((a,b)=>Number(b.needsReview)-Number(a.needsReview)||a.component.name.localeCompare(b.component.name)||a.component.instance-b.component.instance);
}

export function missingRequestedTargets(snapshot:ReportSnapshot, identifiers:string[]) {
  const present=new Set([
    ...snapshot.results.flatMap(r=>[r.advisory_id,r.identifier,...(r.identifiers||[])]),
    ...(snapshot.cve_review?.assessments.map(a=>a.advisory_id)||[]),
  ].map(id=>id.toUpperCase()));
  return identifiers.filter(id=>!present.has(id.toUpperCase()));
}
