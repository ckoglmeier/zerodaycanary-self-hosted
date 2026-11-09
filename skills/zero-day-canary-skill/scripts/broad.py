#!/usr/bin/env python3
"""Multi-ecosystem inventory and any-CVE source-review preparation. Never runs app code."""
import argparse,contextlib,datetime as dt,io,json,re,sys,time,urllib.request,urllib.error
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from jsonschema import Draft202012Validator
from canary import CanaryError,canonical,digest,need,pack,parse_json,read_path,read_bytes,timestamp,write_new,LIMITATIONS,validate_bundle
from cve import NoRedirect,utc
ROOT=Path(__file__).resolve().parents[1]

def request(url,body=None,with_digest=False):
    # Destinations are constructed here, never taken from a report or repository.
    need(url.startswith('https://api.osv.dev/v1/') or re.fullmatch(r'https://cveawg.mitre.org/api/cve/CVE-[0-9]{4}-[0-9]{4,}',url),'Unexpected public source.')
    data=canonical(body) if body is not None else None
    req=urllib.request.Request(url,data=data,headers={'Accept':'application/json','Content-Type':'application/json','User-Agent':'Zero-Day-Canary-Skill/2'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(req,timeout=12) as response:
        raw=response.read(5*1024*1024+1)
        need(len(raw)<=5*1024*1024 and response.headers.get_content_type()=='application/json','Invalid/oversized public response.')
        parsed=parse_json(raw)
        return (parsed,digest(raw)) if with_digest else parsed

def validate_inventory(b):
    return validate_bundle(b)

def make_inventory(args,out,at):
    repo=Path(args.repo).resolve(strict=True);raw=read_path(args.components);value=parse_json(raw)
    need(isinstance(value,dict) and set(value)<= {'components','unknowns'} and isinstance(value.get('components'),list) and len(value['components'])<=20000,'Invalid component input.')
    base=argparse.Namespace(repo=str(repo),repo_id=args.repo_id,inventory=None,audit_root=None,findings=None,audit_context=None,select_finding=None,scope=None,deployment_id=None,deployment_version=None,at=at,out=str(out/'legacy-base.json'))
    with contextlib.redirect_stdout(io.StringIO()):pack(base)
    b=parse_json(read_path(out/'legacy-base.json'));(out/'legacy-base.json').unlink()
    b['schema_version']='canary-evidence/2';b['inventory']={'format':'component-inventory','components':[],'unknowns':[]};b['sources']=[]
    sources={}
    for index,c in enumerate(value['components'],1):
        need(isinstance(c,dict) and set(c)<= {'ecosystem','name','version','public_registry','source','relationship','development','optional'},'Unexpected component fields; omit source code and secrets.')
        need(all(k in c for k in ('ecosystem','name','version','public_registry','source')),'Component identity, exact version/null, public origin and source are required.')
        source=c['source'];need(isinstance(source,str),'Source path required.')
        if source not in sources:
            need(len(sources)<100,'More than 100 inventory sources.')
            sources[source]='inventory-'+str(len(sources)+1)
            b['sources'].append({'id':sources[source],'kind':'component_inventory','sha256':digest(read_bytes(repo,source))})
        b['inventory']['components'].append({'instance':index,'ecosystem':c['ecosystem'],'name':c['name'],'version':c['version'],'public_registry':c['public_registry'],'source_id':sources[source],'purl':None,'relationship':c.get('relationship','unknown'),'development':c.get('development'),'optional':c.get('optional')})
    for reason in value.get('unknowns',[]):
        need(isinstance(reason,str) and 0<len(reason)<=200,'Invalid inventory unknown.')
        b['inventory']['unknowns'].append({'reason':reason,'entry':None})
    # Empty inventory is a real coverage gap, not a blank clean report.
    if not b['sources']:
        b['inventory']['format']='missing';b['inventory']['unknowns'].append({'reason':'missing_inventory','entry':None})
    validate_inventory(b);write_new(out/'inventory.json',canonical(b));return b

def public_query(c,deadline):
    if not c['public_registry'] or c['version'] is None or c['ecosystem']=='product':return {'instance':c['instance'],'state':'not_assessed','reason':'Public origin/exact package version is not established.','records':[]}
    records=[];tokens=set();token=None
    try:
        for page in range(10):
            need(time.monotonic()<deadline,'Lookup deadline reached.')
            body={'package':{'ecosystem':c['ecosystem'],'name':c['name']},'version':c['version']}
            if token:body['page_token']=token
            data=request('https://api.osv.dev/v1/query',body)
            need(isinstance(data,dict) and set(data)<= {'vulns','next_page_token'},'Unrecognized OSV response.')
            found=data.get('vulns',[]);need(isinstance(found,list) and all(isinstance(r,dict) and isinstance(r.get('id'),str) and isinstance(r.get('affected'),list) for r in found),'Invalid OSV records.')
            records.extend(found);need(len(records)<=5000,'OSV result exceeds bound.')
            token=data.get('next_page_token')
            if not token:break
            need(isinstance(token,str) and len(token)<=4096 and token not in tokens,'Invalid OSV pagination.');tokens.add(token)
        else:raise CanaryError('Incomplete OSV pagination.')
        return {'instance':c['instance'],'state':'checked','records':records,'checked_at':utc()}
    except (CanaryError,ValueError,OSError,urllib.error.URLError):
        return {'instance':c['instance'],'state':'not_assessed','reason':'OSV lookup failed, unsupported or incomplete. No clean result is claimed.','records':[]}

def prepare(args):
    repo=Path(args.repo).resolve(strict=True);out=Path(args.out).resolve(strict=False)
    need(out!=repo and repo not in out.parents and not out.exists(),'Use a new private output folder outside the repository.')
    out.mkdir(mode=0o700,parents=True);at=utc()
    try:
        inventory=make_inventory(args,out,at)
        components=inventory['inventory']['components'];checks=[]
        if args.allow_public_lookups:
            deadline=time.monotonic()+90
            with ThreadPoolExecutor(max_workers=5) as executor:checks=list(executor.map(lambda c:public_query(c,deadline),components[:500]))
        else:checks=[{'instance':c['instance'],'state':'not_assessed','reason':'Public lookups were not enabled.','records':[]} for c in components[:500]]
        checks.extend({'instance':c['instance'],'state':'not_assessed','reason':'Per-run limit reached.','records':[]} for c in components[500:])
        write_new(out/'package-checks.json',canonical({'provider':'OSV.dev','checks':checks,'limits':'Declared source versions only. No match never establishes security. Failed/partial lookups are not assessed.'}))
        requested=list(dict.fromkeys(args.cve or []));need(len(requested)<=25 and all(re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}',x) for x in requested),'Supply at most 25 exact CVE IDs.')
        # Auto-prepare a bounded set of CVE targets; retain every version match
        # in package-checks.json. The agent can target any other CVE explicitly.
        for check in checks:
            for record in check['records']:
                for alias in [record['id']]+record.get('aliases',[]):
                    if re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}',alias) and alias not in requested and len(requested)<25:requested.append(alias)
        targets=[]
        for id in requested:
            try:
                record,record_hash=request('https://cveawg.mitre.org/api/cve/'+id,with_digest=True)
                need(record.get('cveMetadata',{}).get('cveId')==id,'CVE identity mismatch.')
                published=record['cveMetadata'].get('state')=='PUBLISHED'
                targets.append({'id':id,'record':record,'sha256':record_hash if published else None})
            except (CanaryError,ValueError,OSError,urllib.error.URLError):targets.append({'id':id,'record':None,'sha256':None})
        write_new(out/'targets.json',canonical(targets))
        assessments=[]
        for target in targets:
            ids={check['instance'] for check in checks if any(target['id'] in [r['id']]+r.get('aliases',[]) for r in check['records'])}
            # For explicitly requested runtime/vendor CVEs the agent selects the
            # relevant asset/component after reading the public target. Start unknown.
            if not ids and args.cve and target['id'] in args.cve:ids={c['instance'] for c in components}
            for instance in sorted(ids):assessments.append({'advisory_id':target['id'],'advisory_revision':1,'component_instance':instance,'target_sha256':target['sha256'],'conclusion':'needs_verification','summary':'Advisory prerequisites and deployment have not been confirmed.','conditions':[]})
        need(len(assessments)<=500,'More than 500 targeted comparisons; narrow explicit CVE/asset scope.')
        review={'schema_version':'canary-cve-review/2','checked_at':utc(),'catalog_revision':0,'catalog_sha256':digest(canonical(targets)),'deployment_status':'not_verified','assessments':assessments}
        write_new(out/'condition-checks.template.json',canonical(review))
        write_new(out/'verification-plan.json',canonical({'targets':targets,'inventory_sha256':digest(canonical(inventory)),'next':'Read each CVE record. Check only its source/configuration prerequisites. Complete condition-checks.json and REPORT.md; missing facts stay unknown. No app code was executed, uploaded or enrolled.'}))
        print(json.dumps({'state':'prepared','components':len(components),'package_lookups':sum(c['state']=='checked' for c in checks),'targeted_comparisons':len(assessments),'output':str(out),'source_checks_completed':False,'uploaded':False}))
    except BaseException:
        write_new(out/'INCOMPLETE.json',canonical({'state':'incomplete','source_checks_completed':False,'uploaded':False}));raise

def report(args):
    from source_report import validate_review
    folder=Path(args.run);inventory=validate_inventory(parse_json(read_path(folder/'inventory.json')));targets=parse_json(read_path(folder/'targets.json'))
    review=validate_review(parse_json(read_path(args.checks)),inventory)
    need(review['schema_version']=='canary-cve-review/2' and review['catalog_sha256']==digest(canonical(targets)),'Review does not pin these public targets.')
    target_map={t['id']:t for t in targets};instances={c['instance'] for c in inventory['inventory']['components']}
    template=parse_json(read_path(folder/'condition-checks.template.json'))
    need({(a['advisory_id'],a['component_instance']) for a in review['assessments']}=={(a['advisory_id'],a['component_instance']) for a in template['assessments']},'Retain every prepared comparison, including unknowns.')
    for a in review['assessments']:need(a['advisory_id'] in target_map and a['target_sha256']==target_map[a['advisory_id']]['sha256'] and a['component_instance'] in instances,'Unknown/changed report target.')
    write_new(Path(args.out),canonical({'schema_version':'canary-cve-report/2','inventory':inventory,'review':review}))
    print('Created private canary-report.json. No upload, sharing or enrollment occurred.')

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(required=True)
    run=sub.add_parser('run');run.add_argument('--repo',required=True);run.add_argument('--repo-id',required=True);run.add_argument('--components',required=True);run.add_argument('--out',required=True);run.add_argument('--allow-public-lookups',action='store_true');run.add_argument('--cve',action='append');run.set_defaults(func=prepare)
    done=sub.add_parser('report');done.add_argument('--run',required=True);done.add_argument('--checks',required=True);done.add_argument('--out',required=True);done.set_defaults(func=report)
    args=parser.parse_args()
    try:args.func(args)
    except (CanaryError,OSError,ValueError) as e:print('ERROR: '+str(e),file=sys.stderr);return 1
    return 0
if __name__=='__main__':sys.exit(main())
