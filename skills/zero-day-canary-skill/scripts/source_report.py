"""Validate and package explicitly supplied advisory-only source conclusions.
No inference, source execution, upload or automatic sharing.
"""
import datetime as dt
from pathlib import Path
from jsonschema import Draft202012Validator
from canary import canonical,digest,need,parse_json,read_path,timestamp,validate_bundle,write_new

ROOT=Path(__file__).resolve().parents[1]

def validate_review(review,inventory):
    v2=review.get('schema_version')=='canary-cve-review/2'
    schema=parse_json(read_path(ROOT/('schemas/cve-review-v2.schema.json' if v2 else 'schemas/cve-review-v1.schema.json')))
    need(not list(Draft202012Validator(schema).iter_errors(review)),'Invalid canary-cve-review/1 source checks.')
    at=timestamp(review['checked_at']);created=timestamp(inventory['created_at'])
    need(created<=at<=dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5),'Invalid source-check date.')
    seen=set()
    for assessment in review['assessments']:
        key=(assessment['advisory_id'],assessment['component_instance'])
        need(key not in seen,'Duplicate advisory/component source check.');seen.add(key)
        need(any(c['instance']==assessment['component_instance'] and (v2 or c['ecosystem']=='npm' and c['name']=='next') for c in inventory['inventory']['components']),'Source check is outside supported inventory.')
        if v2:
            need(inventory['schema_version']=='canary-evidence/2','Broad review needs broad inventory.')
            need(assessment['target_sha256'] is not None or assessment['conclusion']=='needs_verification','Unverified target must remain unknown.')
            if assessment['conclusion']=='version_excluded':need(any(c['instance']==assessment['component_instance'] and c['version'] is not None for c in inventory['inventory']['components']) and any(c['role']=='prerequisite' and c['state']=='absent' and c['evidence'] for c in assessment['conditions']),'Version exclusion needs an exact version and a cited absent affected-range prerequisite.')
        for condition in assessment['conditions']:
            need(condition['state']=='unknown' or condition['evidence'],'Observed conditions require file and line evidence.')
            for evidence in condition['evidence']:
                path=evidence['path']
                need(not path.startswith('/') and all(x not in ('','.','..') for x in path.split('/')) and not any(ord(c)<32 or 127<=ord(c)<=159 or c in '\u200b\u200c\u200d\u200e\u200f\u2028\u2029\ufeff' for c in path),'Unsafe evidence path.')
        if assessment['conclusion']=='source_prerequisites_excluded':
            need(any(c['role']=='prerequisite' and c['state']=='absent' or c['role']=='mitigation' and c['state']=='present' for c in assessment['conditions']),'Source exclusion requires a preventing control.')
        if assessment['conclusion']=='source_prerequisites_supported':
            need(assessment['conditions'] and all(c['state']==('present' if c['role']=='prerequisite' else 'absent') for c in assessment['conditions']),'Supported prerequisites require resolved conditions without a preventing control.')
    return review

def package_report(args):
    folder=Path(args.run)
    inventory=parse_json(read_path(folder/'inventory.json'));validate_bundle(inventory)
    catalog=parse_json(read_path(folder/'catalog.json'))
    matches=parse_json(read_path(folder/'version-matches.json'))
    review=validate_review(parse_json(read_path(args.checks)),inventory)
    need(review['catalog_revision']==catalog['catalog_revision'] and review['catalog_sha256']==digest(canonical(catalog)),'Source checks do not identify the captured catalog.')
    by_key={(r['advisory_id'],r['component']['instance']):r for r in matches['matches']}
    records={a['id']:a for a in catalog['data']}
    need(set(by_key)=={(a['advisory_id'],a['component_instance']) for a in review['assessments']},'Include exactly the captured advisory/component comparisons.')
    for a in review['assessments']:
        row=by_key[(a['advisory_id'],a['component_instance'])]
        need(a['advisory_revision']==records[a['advisory_id']]['revision'],'Advisory revision disagrees.')
        need((row['status']=='not_affected')==(a['conclusion']=='version_excluded'),'Conclusion conflicts with version comparison.')
    report={'schema_version':'canary-cve-report/1','inventory':inventory,'review':review}
    write_new(Path(args.out),canonical(report))
    print('Created private canary-report.json. Review all summaries, component identities and file/line references before uploading. No upload or sharing occurred.')
