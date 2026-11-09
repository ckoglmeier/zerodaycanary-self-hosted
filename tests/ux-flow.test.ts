import {describe,it,expect} from "vitest";
import {safeReturnTo,sectionActive,workspaceSection} from "@/lib/navigation";
import {requestIdentifiers,reportBuildingPrompt,requestSummary,requestOutcome} from "@/lib/review/presentation";
import {groupReport,missingRequestedTargets} from "@/lib/review/report-groups";
import type {ReportSnapshot} from "@/lib/review/reports";
import type {DevResult} from "@/lib/developer/evaluate";

describe("navigation and account returns",()=>{
  it("preserves the request, project and anchor through sign-in",()=>{
    expect(safeReturnTo("/developer/skill?request=abc&project=def#upload")).toBe("/developer/skill?request=abc&project=def#upload");
  });
  it.each(["https://evil.invalid","//evil.invalid","/\\evil.invalid","/%2fhost","/%5chost","/\nevil.invalid"])("rejects external or ambiguous return destination %s",input=>expect(safeReturnTo(input)).toBe("/systems"));
  it("keeps nested pages in the right section without matching prefixes",()=>{
    expect(sectionActive("/developer/abc/share","/developer")).toBe(true);
    expect(sectionActive("/advisory/abc","/advisories")).toBe(true);
    expect(sectionActive("/operator/feed","/operator")).toBe(false);
    expect(sectionActive("/developer-other","/developer")).toBe(false);
    expect(workspaceSection("/reviews/abc")).toBe(true);
    expect(workspaceSection("/operator/accounts")).toBe(false);
  });
});

describe("specific request handoff",()=>{
  const question="We use Zero Day Canary to monitor our apps.\n\nPlease confirm PHP exposure to CVE-2026-109618 and GHSA-w8hw-w9fx-j79w.\n\nApp: https://courses.example.edu";
  it("pins the substantive question and deduplicates actual targets",()=>{
    expect(requestSummary(question)).toBe("Please confirm PHP exposure to CVE-2026-109618 and GHSA-w8hw-w9fx-j79w.");
    expect(requestIdentifiers(question+" cve-2026-109618")).toEqual(["CVE-2026-109618","GHSA-w8hw-w9fx-j79w"]);
  });
  it("gives a local agent the exact task, explicit runtime target and sharing boundary",()=>{
    const p=reportBuildingPrompt("Course portal",{requester:"Cedar College",app:"Course portal",url:"https://courses.example.edu",question,identifiers:requestIdentifiers(question)});
    expect(p).toContain(JSON.stringify(question));expect(p).toContain("--cve");expect(p).toContain("CVE-2026-109618");expect(p).toContain("Do not upload or share automatically");expect(p).toContain("no app URLs, account IDs or source code");
  });
  it("does not invent a client or CVE for an independent project",()=>{
    const p=reportBuildingPrompt("My app");expect(p).not.toContain("Request context");expect(p).not.toContain("Explicit CVE targets");
  });
  it("does not let an older answer close a new question",()=>{
    const a={request_id:"old",outcome:"not_affected",date_pending:false,target_date:null,created_at:"2026-10-22T12:00Z"};
    expect(requestOutcome({id:"new",state:"waiting"},[a],[])).toBe("Waiting for an answer");
  });
  it("keeps an affected answer and subsequent reported fix distinct from verification",()=>{
    const a={request_id:"new",outcome:"affected",date_pending:true,target_date:null,created_at:"2026-10-22T12:00Z"};
    expect(requestOutcome({id:"new",state:"answered"},[a],[])).toBe("Affected — fix date pending");
    expect(requestOutcome({id:"new",state:"answered"},[a],[{request_id:"new",kind:"progress",created_at:"2026-10-22T13:00Z"}])).toBe("Fix reported — awaiting evidence");
    expect(requestOutcome({id:"new",state:"answered"},[a],[{request_id:"old",kind:"progress",created_at:"2026-10-22T13:00Z"}])).toBe("Affected — fix date pending");
  });
});

describe("complete grouped report presentation",()=>{
  const component={instance:1,name:"Django",version:"4.2.0",ecosystem:"PyPI",relationship:"direct",development:false};
  const result={advisory_id:"a",identifier:"CVE-1",status:"affected_version_matched",component} as DevResult;
  const snapshot={components:[component,{...component,instance:2,version:"5.0.0"},{...component,instance:3,name:"private-lib",version:null}],results:[result,{...result,advisory_id:"b"},{...result,advisory_id:"c",status:"not_affected",component:{...component,instance:2,version:"5.0.0"}}],coverage:{component_coverage:[{instance:3,status:"not_assessed"}]},cve_review:{assessments:[{advisory_id:"a",component_instance:1,conclusion:"needs_verification"}]}} as unknown as ReportSnapshot;
  it("retains every version result and separate source check without merging installed versions",()=>{
    const groups=groupReport(snapshot);
    expect(groups.flatMap(g=>g.results)).toHaveLength(3);expect(groups.flatMap(g=>g.assessments)).toHaveLength(1);
    expect(groups).toHaveLength(3);expect(groups[0].component.version).toBe("4.2.0");expect(groups[0].results).toHaveLength(2);
    expect(groups.find(g=>g.component.instance===2)?.needsReview).toBe(false);expect(groups.find(g=>g.component.instance===3)?.packageState).toBe("not_assessed");
  });
  it("distinguishes checked-no-match from unassessed inventory",()=>{
    const groups=groupReport({...snapshot,coverage:{component_coverage:[{instance:3,status:"checked_no_match"}]}});
    expect(groups.find(g=>g.component.instance===3)?.packageState).toBe("checked_no_match");
  });
  it("does not silently drop historic results absent from the component list",()=>{
    expect(groupReport({...snapshot,components:[]}).flatMap(g=>g.results)).toHaveLength(3);
  });
  it("names requested runtime CVEs missing from a package-only report",()=>{
    expect(missingRequestedTargets(snapshot,["CVE-1","CVE-2026-109618"])).toEqual(["CVE-2026-109618"]);
  });
});
