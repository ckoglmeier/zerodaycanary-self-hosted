#!/usr/bin/env python3
"""Prepare a private, CVE-targeted Canary check. No app execution or evidence upload.
The coding agent completes only the API targets' source-condition checks afterward.
"""
import argparse
import os
import collections
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from canary import CanaryError, MAX_BYTES, canonical, digest, need, pack, parse_json, read_path, timestamp, validate_bundle, write_new
from matching import match_snapshot, validate_snapshot

API_ORIGIN=os.environ.get('CANARY_API_ORIGIN', 'https://canary.example.org').rstrip('/')
API_PATH='/api/v1/advisories'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        return None

def utc():return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def get_page(url):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    request=urllib.request.Request(url,headers={'Accept':'application/json','User-Agent':'Zero-Day-Canary-CVE-Skill/1'})
    with opener.open(request,timeout=10) as response:
        need(response.status==200,'Catalog request did not return HTTP 200.')
        need(response.headers.get_content_type()=='application/json','Catalog did not return JSON.')
        data=response.read(MAX_BYTES+1)
        need(len(data)<=MAX_BYTES,'Catalog page exceeds 5 MiB.')
        return data

def collect_catalog(request_page=get_page):
    """Follow only same-resource pagination, with one pinned revision and bounds."""
    first=API_ORIGIN+API_PATH+'?product=nextjs&status=all&limit=200'
    url=first;seen=set();records=[];revision=None;schema=None;total=0;pages=[]
    while url:
        need(url not in seen and len(seen)<20,'Catalog pagination loops or exceeds 20 pages.')
        parsed=urllib.parse.urlsplit(url)
        need(parsed.scheme=='https' and parsed.netloc==urllib.parse.urlsplit(API_ORIGIN).netloc and parsed.path==API_PATH and not parsed.fragment,'Catalog pagination changed destination.')
        params=urllib.parse.parse_qs(parsed.query,keep_blank_values=True)
        need(set(params)<= {'product','status','limit','cursor'} and all(len(v)==1 for v in params.values()) and params.get('product')==['nextjs'] and params.get('status')==['all'] and params.get('limit')==['200'],'Catalog pagination changed scope.')
        if 'cursor' in params:need(re.fullmatch(r'[A-Za-z0-9_-]{1,512}',params['cursor'][0]) is not None,'Invalid catalog cursor.')
        seen.add(url);raw=request_page(url);total+=len(raw);need(total<=MAX_BYTES,'Combined catalog exceeds 5 MiB.')
        page=parse_json(raw)
        need(isinstance(page,dict) and isinstance(page.get('data'),list) and len(page['data'])<=200,'Invalid catalog page.')
        need(type(page.get('catalog_revision')) is int and page['catalog_revision']>=0 and page.get('schema_version')=='2026-10-22','Unsupported catalog schema/revision.')
        if revision is None:revision=page['catalog_revision'];schema=page['schema_version']
        need(page['catalog_revision']==revision and page['schema_version']==schema,'Catalog changed while paging; obtain a fresh consistent snapshot.')
        records.extend(page['data']);need(len(records)<=1000,'Catalog exceeds 1000 records.')
        pages.append({'url':url,'sha256':digest(raw),'records':len(page['data'])})
        cursor=page.get('next_cursor');next_path=page.get('next')
        need((cursor is None)==(next_path is None),'Inconsistent catalog pagination fields.')
        if cursor is not None:
            need(isinstance(cursor,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,512}',cursor) is not None and isinstance(next_path,str),'Invalid next catalog page.')
            following=urllib.parse.urljoin(API_ORIGIN,next_path)
            query=urllib.parse.parse_qs(urllib.parse.urlsplit(following).query)
            need(query.get('cursor')==[cursor],'Next page cursor disagrees.')
            url=following
        else:url=None
    snapshot={'schema_version':schema,'catalog_revision':revision,'data':records,'next_cursor':None,'next':None}
    validate_snapshot(snapshot)
    return snapshot,{'source':'live_canary_api','retrieved_at':utc(),'public_product_filter':'nextjs','pages':pages,'complete_for_filter':True,'disclosure':'Only public product/filter/cursor parameters; no app source, versions, inventory or credentials.'}

def prepare(args):
    repo=Path(args.repo).resolve(strict=True);out=Path(args.out).resolve(strict=False)
    need(repo.is_dir() and out!=repo and repo not in out.parents,'Use a new output directory outside the app.')
    need(not out.exists(),'Output directory already exists; use a new path.')
    at=args.at or utc();timestamp(at)
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    pack_args=argparse.Namespace(repo=str(repo),repo_id=args.repo_id,inventory=args.inventory,audit_root=None,findings=None,audit_context=None,select_finding=None,scope=None,deployment_id=None,deployment_version=None,at=at,out=str(out/'inventory.json'))
    try:
        with contextlib.redirect_stdout(io.StringIO()):pack(pack_args)
        inventory=parse_json(read_path(out/'inventory.json'));validate_bundle(inventory)
        if args.snapshot:
            raw=read_path(args.snapshot);snapshot=parse_json(raw);validate_snapshot(snapshot)
            source={'source':'supplied_snapshot','retrieved_at':None,'input_sha256':digest(raw),'complete_for_filter':'caller_declared','notice':'Retrieval date and catalog freshness are unknown; do not label this a live API fetch.'}
        else:snapshot,source=collect_catalog()
        matches=match_snapshot(inventory,snapshot,at)
        source['snapshot_sha256']=digest(canonical(snapshot))
        # Live retrieval provenance replaces only the matcher's supplied-snapshot warning.
        if not args.snapshot:matches['warnings'][0]='Live Canary API snapshot collected at '+source['retrieved_at']+'; complete for product=nextjs at one catalog revision.'
        by_id={a['id']:a for a in snapshot['data']}
        targets=[]
        for row in matches['matches']:
            if row['status']=='not_affected':continue
            advisory=by_id[row['advisory_id']]
            targets.append({'advisory_id':advisory['id'],'advisory_revision':advisory['revision'],'identifiers':advisory['identifiers'],'component':row['component'],'version_status':row['status'],'conditions':advisory['conditions'],'uncertainty':advisory.get('uncertainty',[]),'sources':advisory.get('sources',[]),'instruction':'Check only this advisory’s prerequisites and mitigations. Record source evidence or unknown; do not hunt unrelated bugs or run a PoC.'})
        plan={'schema_version':'canary-cve-plan/1','run_status':'prepared','prepared_at':at,'repository':inventory['repository'],'catalog_revision':snapshot['catalog_revision'],'catalog_sha256':source['snapshot_sha256'],'inventory_sha256':digest(canonical(inventory)),'targets':targets,'version_exclusions':[x for x in matches['matches'] if x['status']=='not_affected'],'coverage':{'supported_mapping':'npm next -> nextjs','unmapped_packages':matches['unmapped_packages'],'inventory_unknowns':inventory['inventory']['unknowns']},'next':'The coding agent must apply SKILL.md to the targets, then write condition-checks.json and REPORT.md. These generated files do not establish completed source checks or deployed verification.'}
        for name,value in [('catalog.json',snapshot),('catalog-source.json',source),('version-matches.json',matches),('verification-plan.json',plan)]:write_new(out/name,canonical(value))
        template={'schema_version':'canary-cve-review/1','checked_at':at,'catalog_revision':snapshot['catalog_revision'],'catalog_sha256':source['snapshot_sha256'],'deployment_status':'not_verified','assessments':[{'advisory_id':row['advisory_id'],'advisory_revision':by_id[row['advisory_id']]['revision'],'component_instance':row['component']['instance'],'conclusion':'version_excluded' if row['status']=='not_affected' else 'needs_verification','summary':'Declared version is outside the affected range.' if row['status']=='not_affected' else 'Source prerequisites have not been checked yet.','conditions':[]} for row in matches['matches']]}
        write_new(out/'condition-checks.template.json',canonical(template))
        print(json.dumps({'result':'prepared','output':str(out),'catalog_revision':snapshot['catalog_revision'],'catalog_source':source['source'],'active_comparisons':len(matches['matches']),'version_status_counts':dict(collections.Counter(x['status'] for x in matches['matches'])),'source_check_targets':len(targets),'unmapped_packages':len(matches['unmapped_packages']),'checks_completed':False,'evidence_uploaded':False,'next':plan['next']},indent=2))
    except BaseException:
        # Preserve partial outputs with explicit status rather than fabricating completion.
        write_new(out/'INCOMPLETE.json',canonical({'status':'incomplete','reason':'CVE preparation failed; inspect the reported error. No applicability report completed or evidence uploaded.'}))
        raise

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(required=True)
    run=sub.add_parser('run');run.add_argument('--repo',required=True);run.add_argument('--repo-id',required=True);run.add_argument('--inventory',default='package-lock.json');run.add_argument('--out',required=True);run.add_argument('--snapshot');run.add_argument('--at');run.set_defaults(func=prepare)
    from source_report import package_report
    report=sub.add_parser('report');report.add_argument('--run',required=True);report.add_argument('--checks',required=True);report.add_argument('--out',required=True);report.set_defaults(func=package_report)
    args=parser.parse_args()
    try:args.func(args)
    except (CanaryError,OSError,ValueError,urllib.error.URLError) as error:
        print('ERROR: '+(str(error) if isinstance(error,CanaryError) else 'CVE preparation failed; no evidence was uploaded.'),file=sys.stderr);return 1
    return 0

if __name__=='__main__':sys.exit(main())
