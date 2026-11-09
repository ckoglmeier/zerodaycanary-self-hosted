import {describe,it,expect} from 'vitest';
import draft from '../intel/reviewed/CVE-2026-91403.json';
import {AdvisoryDraft,draftProblems,type AdvisoryRecord} from '../intel/schema';
import {assessAll} from '../intel/match';
const reviewed=AdvisoryDraft.parse(draft);
const record={...reviewed,id:'zdc-oracle-fixture',schema_version:'2026-10-22',revision:1,catalog_revision:1,status:'published',reviewed_at:'2026-10-22T00:00:00Z',updated_at:'2026-10-22T00:00:00Z',status_note:null} as AdvisoryRecord;
describe('Oracle certificate-trust alert',()=>{
 it('is reviewed, sourced and explicit about unresolved runtime evidence',()=>{expect(draftProblems(reviewed)).toEqual([]);expect(reviewed.cvss_score).toBe(9.1);expect(reviewed.exploitation.category).toBe('none_confirmed');expect(reviewed.sources.every(s=>s.kind==='vendor')).toBe(true);expect(reviewed.conditions.every(c=>c.fact===null)).toBe(true);});
 it.each(['21.0.13','8u511','99.0.0'])('does not automatically clear runtime %s from an unencoded range',version=>{
 const at=new Date().toISOString();const result=assessAll([record],{techs:[{product:'oracle_java_se',name:'Oracle Java SE',version,version_basis:'developer_supplied',evidence_type:'administrator',location:'synthetic inventory',detail:'Declared runtime; deployment not observed',confidence:'medium',observed_at:at,limitations:[]}],facts:{},observed_at:at});
 expect(result).toHaveLength(1);expect(result[0].status).toBe('needs_verification');
 });
});
