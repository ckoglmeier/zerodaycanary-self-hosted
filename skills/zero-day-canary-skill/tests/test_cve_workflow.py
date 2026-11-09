"""CVE catalog scope, source-check planning and single-skill installation."""
import argparse
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import cve
import install
from source_report import package_report,validate_review
from canary import CanaryError
from matching import assess, catalog_timestamp, validate_snapshot, match_snapshot

class CveWorkflow(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name).resolve();self.repo=self.base/'app';self.repo.mkdir()
        (self.repo/'package-lock.json').write_bytes((ROOT/'examples/package-lock.json').read_bytes())
        self.snapshot=json.loads((ROOT/'examples/advisories.json').read_text())
    def tearDown(self):self.temp.cleanup()
    def page(self,cursor=None,next_path=None,revision=1,records=None):
        return json.dumps(dict(self.snapshot,catalog_revision=revision,next_cursor=cursor,next=next_path,data=records if records is not None else self.snapshot['data'])).encode()
    def test_complete_paging_is_one_revision_and_preserves_withdrawals(self):
        withdrawn=copy.deepcopy(self.snapshot['data'][0]);withdrawn.update(id='withdrawn-1',status='withdrawn')
        replies=[self.page('two','/api/v1/advisories?product=nextjs&status=all&limit=200&cursor=two'),self.page(records=[withdrawn])];urls=[]
        def request(url):urls.append(url);return replies.pop(0)
        data,meta=cve.collect_catalog(request)
        self.assertEqual(len(data['data']),2);self.assertEqual(data['data'][1]['status'],'withdrawn')
        self.assertEqual(meta['source'],'live_canary_api');self.assertEqual(len(meta['pages']),2)
        self.assertTrue(all('product=nextjs' in u and 'version=' not in u for u in urls))
    def test_catalog_revision_change_is_rejected(self):
        replies=[self.page('two','/api/v1/advisories?product=nextjs&status=all&limit=200&cursor=two'),self.page(revision=2,records=[])]
        with self.assertRaises(CanaryError):cve.collect_catalog(lambda url:replies.pop(0))
    def test_scope_or_host_change_never_gets_requested(self):
        for next_path in ['https://other.invalid/api/v1/advisories?cursor=two','/api/v1/advisories?product=php&status=all&limit=200&cursor=two','/api/v1/developer/projects/private?cursor=two']:
            calls=[]
            def request(url):calls.append(url);return self.page('two',next_path)
            with self.assertRaises(CanaryError):cve.collect_catalog(request)
            self.assertEqual(len(calls),1)
    def test_duplicate_cursor_and_record_are_rejected(self):
        page=self.page('two','/api/v1/advisories?product=nextjs&status=all&limit=200&cursor=two')
        with self.assertRaises(CanaryError):cve.collect_catalog(lambda url:page)
        duplicate=copy.deepcopy(self.snapshot);duplicate['data']*=2
        with self.assertRaises(CanaryError):cve.collect_catalog(lambda url:json.dumps(duplicate).encode())
    def test_partial_or_unsupported_catalog_is_rejected(self):
        for mutation in [dict(schema_version='unknown'),dict(next_cursor='two',next=None),dict(catalog_revision=True)]:
            s=dict(self.snapshot,**mutation)
            with self.assertRaises(CanaryError):cve.collect_catalog(lambda url:json.dumps(s).encode())
    def test_single_install_preserves_existing_general_audit_skill(self):
        prior=self.repo/'.agents/skills/security-audit';prior.mkdir(parents=True);(prior/'SKILL.md').write_text('user-owned unrelated skill')
        result=install.install(self.repo);self.assertEqual(len(result['installed']),1)
        self.assertFalse(result['checks_started']);self.assertFalse(result['network_used'])
        installed=self.repo/'.agents/skills/zero-day-canary-skill'
        self.assertEqual(len(list(installed.rglob('SKILL.md'))),1)
        self.assertEqual((prior/'SKILL.md').read_text(),'user-owned unrelated skill')
        self.assertTrue((installed/'vendor/cloudflare/LICENSE').is_file())
        with self.assertRaises(FileExistsError):install.install(self.repo)
    def test_symlink_install_parent_and_recursive_install_are_refused(self):
        external=self.base/'elsewhere';external.mkdir();(self.repo/'.agents').symlink_to(external)
        with self.assertRaises(OSError):install.install(self.repo)
        self.assertFalse(list(external.iterdir()))
        with self.assertRaises(ValueError):install.install(ROOT)
    def prepare(self,snapshot=None,out=None):
        s=self.base/'snapshot.json';s.write_text(json.dumps(snapshot or self.snapshot))
        args=argparse.Namespace(repo=str(self.repo),repo_id='synthetic/cve',inventory='package-lock.json',out=str(out or self.base/'output'),snapshot=str(s),at='2026-10-22T12:00:00Z')
        with contextlib.redirect_stdout(io.StringIO()) as captured:cve.prepare(args)
        return json.loads(captured.getvalue()),Path(args.out)
    def test_only_active_api_targets_and_no_automatic_source_or_deployment_claim(self):
        s=copy.deepcopy(self.snapshot);withdrawn=copy.deepcopy(s['data'][0]);withdrawn.update(id='old-alert',status='withdrawn');s['data'].append(withdrawn)
        summary,out=self.prepare(s);plan=json.loads((out/'verification-plan.json').read_text())
        self.assertEqual({t['advisory_id'] for t in plan['targets']},{s['data'][0]['id']})
        self.assertFalse(summary['checks_completed']);self.assertFalse(summary['evidence_uploaded'])
        self.assertFalse((out/'REPORT.md').exists());self.assertTrue(plan['coverage']['unmapped_packages'])
        self.assertIsNone(json.loads((out/'catalog-source.json').read_text())['retrieved_at'])
    def test_output_cannot_reuse_or_modify_app(self):
        with self.assertRaises(CanaryError):self.prepare(out=self.repo/'report')
        _,out=self.prepare()
        with self.assertRaises(CanaryError):self.prepare(out=out)
    def test_source_report_template_packs_without_inventing_completed_checks(self):
        _,out=self.prepare()
        checks=out/'condition-checks.template.json';destination=self.base/'canary-report.json'
        with contextlib.redirect_stdout(io.StringIO()):package_report(argparse.Namespace(run=str(out),checks=str(checks),out=str(destination)))
        result=json.loads(destination.read_text())
        self.assertEqual(result['schema_version'],'canary-cve-report/1')
        self.assertEqual(result['review']['deployment_status'],'not_verified')
        self.assertTrue(all(a['conclusion']=='needs_verification' for a in result['review']['assessments']))
        self.assertEqual(result['inventory'],json.loads((out/'inventory.json').read_text()))
    def test_source_report_rejects_changed_targets_or_catalog(self):
        _,out=self.prepare();template=json.loads((out/'condition-checks.template.json').read_text())
        for field in ['catalog_sha256','advisory_id','component_instance','advisory_revision']:
            checks=copy.deepcopy(template)
            if field=='catalog_sha256':checks[field]='0'*64
            elif field=='advisory_id':checks['assessments'][0][field]='unrelated-bug'
            else:checks['assessments'][0][field]=900
            file=out/('bad-'+field+'.json');file.write_text(json.dumps(checks))
            with self.assertRaises(CanaryError):package_report(argparse.Namespace(run=str(out),checks=str(file),out=str(self.base/('bad-'+field+'.json'))))
    def test_source_review_does_not_accept_unsupported_claims_or_unsafe_paths(self):
        _,out=self.prepare();template=json.loads((out/'condition-checks.template.json').read_text());inventory=json.loads((out/'inventory.json').read_text())
        for conclusion in ['fix_verified','source_prerequisites_supported','source_prerequisites_excluded']:
            value=copy.deepcopy(template);value['assessments'][0]['conclusion']=conclusion
            with self.assertRaises(CanaryError):validate_review(value,inventory)
        for path in ['/etc/passwd','../source.ts','C:\\secret','safe/../secret','safe\\secret','a\nfile']:
            value=copy.deepcopy(template);value['assessments'][0]['conditions']=[dict(condition='Named feature',role='prerequisite',state='present',explanation='SYNTHETIC fixture only',evidence=[dict(path=path,line=1)])]
            with self.assertRaises(CanaryError):validate_review(value,inventory)
    def product(self,ranges):return {'ranges':ranges,'other_branches':'not_affected'}
    def test_disputed_other_boundary_does_not_hide_clear_affected_range(self):
        ap=self.product([{'introduced':'16.0.0','last_affected':'16.0.0','fixed':None,'ambiguous':True},{'introduced':'16.0.1','last_affected':'16.4.0','fixed':'16.4.1','ambiguous':False}])
        for version,status in [('16.0.0','needs_verification'),('16.3.3','affected_version_matched'),('16.4.1','not_affected'),('16.4.1-beta.1','needs_verification')]:
            self.assertEqual(assess({'version':version},ap)[0],status)
    def test_actual_api_fractional_timestamps_preserved_and_future_checked(self):
        snap=copy.deepcopy(self.snapshot);snap['data'][0]['reviewed_at']='2026-10-22T11:59:59.737Z'
        validate_snapshot(snap)
        self.assertEqual(catalog_timestamp(snap['data'][0]['reviewed_at']).microsecond,737000)
        _,out=self.prepare(snap)
        self.assertEqual(json.loads((out/'catalog.json').read_text())['data'][0]['reviewed_at'],snap['data'][0]['reviewed_at'])
        bundle=json.loads((out/'inventory.json').read_text());snap['data'][0]['reviewed_at']='2026-10-22T12:00:00.001Z'
        with self.assertRaises(CanaryError):match_snapshot(bundle,snap,'2026-10-22T12:00:00Z')
    def test_malformed_api_timestamps_refused(self):
        for value in ['2026-10-22T12:00:00+00:00','2026-13-22T12:00:00.001Z','not-a-date']:
            with self.assertRaises(CanaryError):catalog_timestamp(value)
    def test_contradictory_boundaries_do_not_become_exclusions(self):
        ap=self.product([{'introduced':'16.0.0','fixed':'16.4.1','last_affected':'16.5.0'}])
        self.assertEqual(assess({'version':'16.3.3'},ap)[0],'needs_verification')

if __name__=='__main__':unittest.main()
