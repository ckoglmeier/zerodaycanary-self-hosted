import argparse
import contextlib
import copy
import io
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from canary import *
from matching import match_snapshot
from contract_server import FixtureServer

AT = '2026-10-22T12:00:00Z'

class Consumer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='canary-test-')
        self.root = Path(self.tmp.name).resolve()
        self.repo = self.root / 'consumer'
        self.repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        self.lock = json.loads((ROOT / 'examples/package-lock.json').read_text())
        self.save_lock()
        self.report = json.loads((ROOT / 'examples/findings.json').read_text())
        (self.root / 'findings.json').write_text(json.dumps(self.report))
        self.output = self.root / 'bundle.json'
        self.args = argparse.Namespace(repo=str(self.repo), repo_id='synthetic/consumer', inventory='package-lock.json', audit_root=str(self.root), findings=None, audit_context=None, select_finding=None, scope=None, deployment_id=None, deployment_version=None, at=AT, out=str(self.output))

    def tearDown(self):
        self.tmp.cleanup()

    def save_lock(self):
        (self.repo / 'package-lock.json').write_text(json.dumps(self.lock))

    def packed(self, **kwargs):
        args = copy.copy(self.args)
        for k, v in kwargs.items():
            setattr(args, k, v)
        with contextlib.redirect_stdout(io.StringIO()):
            pack(args)
        return read_bundle(args.out)

    def test_deterministic_and_originals_unchanged(self):
        original = (self.repo / 'package-lock.json').read_bytes()
        first = self.packed()
        self.packed(out=str(self.root / 'second.json'))
        self.assertEqual(self.output.read_bytes(), (self.root / 'second.json').read_bytes())
        self.assertEqual(original, (self.repo / 'package-lock.json').read_bytes())
        self.assertTrue(first['repository']['dirty'])
        self.assertIsNone(first['repository']['commit'])

    def test_direct_transitive_scoped_and_duplicate_versions(self):
        b = self.packed()
        cs = b['inventory']['components']
        self.assertEqual(len(cs), 5)
        self.assertEqual(next(c for c in cs if c['name'] == 'next')['relationship'], 'direct')
        self.assertEqual(sorted(c['version'] for c in cs if c['name'] == 'fixture-child'), ['2.1.0', '3.4.5'])
        self.assertTrue(all(c['relationship'] == 'transitive' for c in cs if c['name'] == 'fixture-child'))
        self.assertEqual(next(c for c in cs if c['name'].startswith('@'))['purl'], 'pkg:npm/%40synthetic/widget@1.2.3')
        self.assertTrue(next(c for c in cs if c['name'] == 'fixture-tool')['development'])

    def test_v2_alias_and_exact_prerelease(self):
        self.lock['lockfileVersion'] = 2
        self.lock['packages']['node_modules/next']['name'] = '@synthetic/real'
        self.lock['packages']['node_modules/next']['version'] = '1.2.3-beta.1+build.1'
        self.save_lock()
        b = self.packed()
        self.assertEqual(b['inventory']['format'], 'npm-lock-v2')
        c = next(c for c in b['inventory']['components'] if c['name'] == '@synthetic/real')
        self.assertEqual(c['purl'], 'pkg:npm/%40synthetic/real@1.2.3-beta.1%2Bbuild.1')

    def test_missing_and_unsupported_inventories(self):
        b = self.packed(inventory=None)
        self.assertEqual(b['inventory']['format'], 'missing')
        self.assertEqual(b['inventory']['unknowns'][0]['reason'], 'missing_inventory')
        self.lock = {'bomFormat': 'CycloneDX', 'components': []}
        self.save_lock()
        b = self.packed(out=str(self.root / 'unsupported.json'))
        self.assertEqual(b['inventory']['format'], 'unsupported')
        self.assertFalse(b['inventory']['components'])

    def test_ambiguous_versions_do_not_escape(self):
        for i, version in enumerate(['^1.2.3', 'latest', 'git+secret://token', '1.2', '1.2.3-01', '1.2.3-beta..1', None]):
            self.lock['packages']['node_modules/next']['version'] = version
            self.save_lock()
            b = self.packed(out=str(self.root / ('bundle' + str(i))))
            c = next(c for c in b['inventory']['components'] if c['name'] == 'next')
            self.assertIsNone(c['version'])
            self.assertIn('ambiguous_version', [u['reason'] for u in b['inventory']['unknowns']])
            self.assertNotIn('git+secret', canonical(b).decode())

    def test_links_workspaces_nonregistry_and_missing_direct(self):
        self.lock['packages']['node_modules/next']['link'] = True
        self.lock['packages']['packages/workspace'] = {'version': '1.0.0'}
        self.lock['packages']['node_modules/local'] = {'version': '1.0.0', 'resolved': 'https://user:password@example.invalid/private.tgz'}
        self.lock['packages']['']['dependencies']['absent'] = '1.0.0'
        self.save_lock()
        b = self.packed()
        reasons = [u['reason'] for u in b['inventory']['unknowns']]
        self.assertIn('linked_or_workspace_component', reasons)
        self.assertIn('non_registry_component', reasons)
        self.assertIn('missing_direct_entry', reasons)
        self.assertNotIn('password', canonical(b).decode())

    def test_no_root_manifest_means_unknown_relationship(self):
        del self.lock['packages']['']
        self.save_lock()
        b = self.packed()
        self.assertTrue(all(c['relationship'] == 'unknown' for c in b['inventory']['components']))

    def test_provenance_uses_actual_git_commit_and_dirty_state(self):
        subprocess.run(['git', '-C', str(self.repo), 'add', 'package-lock.json'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.email=fixture@example.invalid', '-c', 'user.name=Fixture', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture'], check=True)
        clean = self.packed()
        self.assertFalse(clean['repository']['dirty'])
        self.assertRegex(clean['repository']['commit'], '^[a-f0-9]{40}$')
        (self.repo / 'untracked').write_text('synthetic')
        dirty = self.packed(out=str(self.root / 'dirty'))
        self.assertTrue(dirty['repository']['dirty'])
        self.assertEqual(clean['repository']['commit'], dirty['repository']['commit'])

    def test_git_clean_filters_and_fsmonitor_are_never_executed(self):
        tracked = self.repo / 'tracked'
        tracked.write_text('original')
        def g(*args):
            subprocess.run(['git', '-C', str(self.repo), '-c', 'core.hooksPath=/dev/null'] + list(args), check=True, capture_output=True)
        g('add', 'tracked', 'package-lock.json')
        g('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')
        marker = self.root / 'filter-was-executed'
        monitor = self.root / 'monitor-was-executed'
        (self.repo / '.gitattributes').write_text('tracked filter=canaryfixture\n')
        g('config', 'filter.canaryfixture.clean', 'touch ' + str(marker) + '; cat')
        g('config', 'core.fsmonitor', 'touch ' + str(monitor))
        tracked.write_text('modified')  # Same length forces Git's content comparison.
        b = self.packed()
        self.assertTrue(b['repository']['dirty'])
        self.assertFalse(marker.exists())
        self.assertFalse(monitor.exists())

    def test_findings_remain_distinct_and_selected_records_unchanged(self):
        raw = (self.root / 'findings.json').read_bytes()
        minimal = self.packed(findings='findings.json')
        self.assertEqual(minimal['audit']['verdict_counts'], {'confirmed': 1, 'needs_validation': 1, 'rejected': 1})
        self.assertFalse(minimal['audit']['selected_findings'])
        selected = self.packed(out=str(self.root / 'selected'), findings='findings.json', select_finding=[x['fingerprint'] for x in self.report])
        self.assertEqual(selected['audit']['selected_findings'], self.report)
        self.assertEqual(raw, (self.root / 'findings.json').read_bytes())
        self.assertIsNone(selected['audit']['context']['audited_at'])

    def test_upstream_rejects_additional_properties_and_invalid_severity(self):
        for index, mutate in enumerate([lambda f: f[1].update(severity='high'), lambda f: f[0].update(canary='extra')]):
            findings = copy.deepcopy(self.report)
            mutate(findings)
            (self.root / 'findings.json').write_text(json.dumps(findings))
            with self.assertRaises(CanaryError):
                self.packed(findings='findings.json', out=str(self.root / str(index)))

    def test_minimal_excludes_sensitive_fields_unrelated_source_and_environment(self):
        self.lock['token'] = 'SYNTHETIC_SECRET_MARKER'
        self.lock['packages']['node_modules/next']['scripts'] = {'install': 'touch NEVER_EXECUTE'}
        self.lock['packages']['node_modules/next']['integrity'] = 'SYNTHETIC_SECRET_MARKER'
        self.save_lock()
        (self.repo / '.env.local').write_text('SECRET=SYNTHETIC_SECRET_MARKER')
        (self.repo / 'source.py').write_text('proprietary SYNTHETIC_SECRET_MARKER')
        self.report[0]['execution']['payloads'] = ['SYNTHETIC_SECRET_MARKER']
        (self.root / 'findings.json').write_text(json.dumps(self.report))
        b = self.packed(findings='findings.json')
        self.assertNotIn('SYNTHETIC_SECRET_MARKER', canonical(b).decode())
        self.assertFalse((self.repo / 'NEVER_EXECUTE').exists())
        with self.assertRaises(CanaryError):
            self.packed(inventory='.env.local', out=str(self.root / 'env'))

    def test_malformed_duplicate_nonfinite_depth_and_oversize(self):
        for data in [b'{', b'{"a":1,"a":2}', b'{"v":NaN}', b'\xff', b'[' * 80 + b'0' + b']' * 80, b'"' + b'x' * 65537 + b'"']:
            with self.assertRaises(CanaryError):
                parse_json(data)
        with self.assertRaises(CanaryError):
            parse_json(b' ' * (MAX_BYTES + 1))
        large = self.repo / 'large'
        with large.open('wb') as f:
            f.truncate(MAX_BYTES + 1)
        with self.assertRaises(CanaryError):
            read_bytes(self.repo, 'large')

    def test_traversal_and_symlink_hardlink_fifo_inputs_rejected(self):
        for path in ['../findings.json', '/etc/passwd', 'x/../../findings.json', 'x\\secret', 'x//y', '.aws/credentials']:
            with self.assertRaises(CanaryError):
                read_bytes(self.repo, path)
        (self.repo / 'link').symlink_to(self.repo / 'package-lock.json')
        (self.repo / 'dirlink').symlink_to(self.root, target_is_directory=True)
        os.link(self.repo / 'package-lock.json', self.repo / 'hardlink')
        os.mkfifo(self.repo / 'pipe')
        for path in ['link', 'dirlink/findings.json', 'hardlink', 'pipe']:
            with self.assertRaises((CanaryError, OSError)):
                read_bytes(self.repo, path)

    def test_hostile_package_paths_fail_and_names_stay_unknown(self):
        self.lock['packages']['node_modules/foo/../../escape'] = {'version': '1.0.0'}
        self.save_lock()
        with self.assertRaises(CanaryError):
            self.packed()
        del self.lock['packages']['node_modules/foo/../../escape']
        self.lock['packages']['node_modules/next']['name'] = 'https://secret'
        self.save_lock()
        b = self.packed()
        self.assertIn('ambiguous_identity', [u['reason'] for u in b['inventory']['unknowns']])

    def test_output_overwrite_and_symlink_refused(self):
        self.packed()
        with self.assertRaises(FileExistsError):
            self.packed()
        link = self.root / 'outlink'
        link.symlink_to(self.output)
        with self.assertRaises(FileExistsError):
            self.packed(out=str(link))

    def test_schema_and_semantic_tampering_rejected(self):
        original = self.packed()
        for change in [lambda b: b.update(credentials='secret'), lambda b: b['inventory']['components'][0].update(purl='pkg:pypi/next@1.0.0'), lambda b: b['audit']['verdict_counts'].update(confirmed=50), lambda b: b.update(limitations=[]), lambda b: b['sources'].clear()]:
            b = copy.deepcopy(original)
            change(b)
            with self.assertRaises(CanaryError):
                validate_bundle(b)

    def test_inventory_review_does_not_require_general_source_audit(self):
        bundle = self.packed()
        result = review_document(bundle, argparse.Namespace(at=AT, endpoint=None, project=None))
        self.assertIsNone(bundle['audit']['report_sha256'])
        self.assertFalse(any('audit' in warning.lower() for warning in result['warnings']))
        self.assertEqual(result['exact_submission_body'], bundle)

    def test_review_staleness_context_and_terminal_escaping(self):
        shutil.copy(ROOT / 'examples/audit-context.json', self.root / 'context.json')
        b = self.packed(at='2026-10-01T13:00:00Z', findings='findings.json', audit_context='context.json')
        args = argparse.Namespace(at=AT, endpoint=None, project=None)
        r = review_document(b, args)
        self.assertTrue(any('older than 7 days' in w for w in r['warnings']))
        self.assertTrue(any('differ' in w for w in r['warnings']))
        self.assertEqual(r['exact_submission_body'], b)
        self.assertIn('not_performed', canonical(r).decode())
        self.assertNotIn(b'\x1b', canonical({'untrusted': '\x1b[31m'}))

    def test_vendor_provenance_and_numeric_resource_bounds(self):
        provenance = json.loads((ROOT / 'docs/UPSTREAM.json').read_text())
        for name, sha in provenance['files'].items():
            self.assertEqual(digest((ROOT / 'vendor/cloudflare' / name).read_bytes()), sha)
        for data in [b'1e9999', b'1' * 129]:
            with self.assertRaises(CanaryError): parse_json(data)

    def test_invalid_timestamp_and_future_evidence(self):
        for value in ['2026-02-30T00:00:00Z', 'today', '2026-10-22T12:00:00+00:00']:
            with self.assertRaises(CanaryError):
                timestamp(value)
        b = self.packed()
        with self.assertRaises(CanaryError):
            review_document(b, argparse.Namespace(at='2026-10-01T00:00:00Z', endpoint=None, project=None))

    def test_compare_versions_and_missing_findings_are_not_remediation(self):
        before = self.packed()
        self.lock['packages']['node_modules/next']['version'] = '16.0.2'
        self.save_lock()
        self.packed(out=str(self.root / 'after'))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            compare(argparse.Namespace(before=str(self.output), after=str(self.root / 'after')))
        result = json.loads(out.getvalue())
        self.assertEqual(result['added_or_changed'][0]['version'], '16.0.2')
        self.assertIn('do not prove remediation', result['notice'])

class Matching(Consumer):
    # Inherit fixture setup only, not all packaging tests a second time.
    def snapshot(self):
        return json.loads((ROOT / 'examples/advisories.json').read_text())

    def match_version(self, version, mutate=None):
        b = self.packed()
        b['inventory']['components'] = [c for c in b['inventory']['components'] if c['name'] == 'next']
        b['inventory']['components'][0]['version'] = version
        snapshot = self.snapshot()
        if mutate:
            mutate(snapshot['data'][0])
        return match_snapshot(b, snapshot, AT)

    def test_matching_boundaries_unknown_and_prerelease(self):
        for version, expected in [('16.0.0', 'affected_version_matched'), ('16.0.1', 'affected_version_matched'), ('16.0.2', 'not_affected'), ('17.0.0', 'not_affected'), ('15.0.0', 'needs_verification'), (None, 'needs_verification'), ('16.0.1-beta.1', 'affected_version_matched'), ('16.0.1+deb1', 'needs_verification')]:
            # Reuse output path while never overwriting through the product CLI.
            if self.output.exists():
                self.output.unlink()
            result = self.match_version(version)
            self.assertEqual(result['matches'][0]['status'], expected)
            self.assertNotIn(result['matches'][0]['status'], ('fix_verified', 'applicability_confirmed'))
            self.assertEqual(result['matches'][0]['conditions'][0]['state'], 'unknown')

    def test_ambiguous_malformed_and_withdrawn(self):
        for field, value in [('ambiguous', True), ('fixed', 'vendor-release')]:
            if self.output.exists(): self.output.unlink()
            result = self.match_version('16.0.0', lambda a: a['affected'][0]['ranges'][0].update({field: value}))
            self.assertEqual(result['matches'][0]['status'], 'needs_verification')
        self.output.unlink()
        result = self.match_version('16.0.0', lambda a: a.update(status='withdrawn'))
        self.assertFalse(result['matches'])

    def test_snapshot_pagination_schema_and_ecosystem_coverage(self):
        b = self.packed()
        result = match_snapshot(b, self.snapshot(), AT)
        self.assertIn('fixture-child', [c['name'] for c in result['unmapped_packages']])
        for mutate in [lambda s: s.update(next_cursor='more'), lambda s: s.update(schema_version='other'), lambda s: s['data'][0].update(reviewed_at='2027-01-01T00:00:00Z')]:
            snapshot = self.snapshot()
            mutate(snapshot)
            with self.assertRaises(CanaryError):
                match_snapshot(b, snapshot, AT)

# Prevent inherited tests from being collected twice while reusing setup helpers.
for _name in list(Consumer.__dict__):
    if _name.startswith('test_'):
        setattr(Matching, _name, None)

class Contract(Consumer):
    def setUp(self):
        super().setUp()
        self.bundle = self.packed()
        self.server = FixtureServer(('127.0.0.1', 0))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = 'http://127.0.0.1:' + str(self.server.server_port)
        self.token_hash, self.request = approval(self.bundle, self.endpoint, 'project-a', True)
        self.submit_args = argparse.Namespace(bundle=str(self.output), endpoint=self.endpoint, project='project-a', at=AT, approve=self.token_hash, approve_findings=None, attempts=3, allow_loopback_http=True)
        self.env = mock.patch.dict(os.environ, {'CANARY_TOKEN': 'fixture-token-a'})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        super().tearDown()

    def send(self, args=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            submit(args or self.submit_args)
        return json.loads(out.getvalue())

    def direct(self, method='POST', project='project-a', token='fixture-token-a', body=None, key=None, item=''):
        body = canonical(self.bundle) if body is None else body
        url = self.endpoint + '/api/v1/developer/projects/' + project + '/evidence' + item
        req = urllib.request.Request(url, data=body if method == 'POST' else None, headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Idempotency-Key': key or digest(body)}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_explicit_consent_endpoint_project_and_payload_binding(self):
        for key, value in [('approve', 'wrong'), ('project', 'project-b'), ('endpoint', 'http://127.0.0.1:9')]:
            args = copy.copy(self.submit_args)
            setattr(args, key, value)
            with self.assertRaises(CanaryError): self.send(args)
        self.assertEqual(self.server.calls, 0)
        modified = copy.deepcopy(self.bundle)
        modified['repository']['id'] = 'different'
        self.output.write_bytes(canonical(modified))
        with self.assertRaises(CanaryError): self.send()
        self.assertEqual(self.server.calls, 0)

    def test_details_need_separate_consent(self):
        detail = self.packed(out=str(self.root / 'detail'), findings='findings.json', select_finding=[self.report[0]['fingerprint']])
        args = copy.copy(self.submit_args)
        args.bundle = str(self.root / 'detail')
        args.approve = approval(detail, self.endpoint, 'project-a', True)[0]
        with self.assertRaises(CanaryError): self.send(args)
        self.assertEqual(self.server.calls, 0)
        args.approve_findings = args.approve
        self.assertEqual(self.send(args)['receipt']['monitoring_state'], 'integration_fixture_only')

    def test_success_replay_readback_and_no_billing(self):
        a = self.send()
        b = self.send()
        self.assertEqual(a, b)
        self.assertIn('FIXTURE ONLY', a['notice'])
        self.assertEqual(self.server.commits, 1)
        status, result = self.direct('GET', item='/' + digest(canonical(self.bundle)))
        self.assertEqual(status, 200)
        self.assertEqual(result['bundle'], self.bundle)
        self.assertEqual(result['receipt']['billing_mode'], 'developer_inventory_free')

    def test_retry_503_429_then_success(self):
        self.server.failures = [503, 429]
        self.send()
        self.assertEqual(self.server.calls, 3)
        self.assertEqual(self.server.commits, 1)

    def test_lost_response_retries_same_key_without_duplicate_commit(self):
        self.server.drop_after_commit = True
        self.send()
        self.assertEqual(self.server.calls, 2)
        self.assertEqual(self.server.commits, 1)

    def test_permanent_failure_and_redirect_not_retried(self):
        for code in (401, 403, 404, 409, 413, 422, 302):
            self.server.calls = 0
            self.server.failures = [code]
            with self.assertRaises(CanaryError): self.send()
            self.assertEqual(self.server.calls, 1)
            self.assertEqual(self.server.commits, 0)

    def test_retry_exhaustion_no_success(self):
        self.server.failures = [503] * 3
        with self.assertRaises(CanaryError): self.send()
        self.assertEqual(self.server.calls, 3)
        self.assertEqual(self.server.commits, 0)

    def test_wrong_receipt_and_no_credential_in_logs(self):
        self.server.receipt_override = {'token': 'SYNTHETIC_SERVER_SECRET'}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(CanaryError) as error: submit(self.submit_args)
        self.assertNotIn('SYNTHETIC_SERVER_SECRET', str(error.exception) + out.getvalue())
        self.assertNotIn('fixture-token-a', str(error.exception) + out.getvalue())

    def test_tenant_isolation_auth_and_conflicting_idempotency(self):
        self.assertEqual(self.direct(project='project-b')[0], 404)
        self.assertEqual(self.direct(token='invalid')[0], 401)
        self.send()
        key = digest(canonical(self.bundle))
        self.assertEqual(self.direct('GET', project='project-b', item='/' + key)[0], 404)
        self.assertEqual(self.direct('GET', token='fixture-token-b', item='/' + key)[0], 404)
        self.assertEqual(self.direct(project='project-b', token='fixture-token-b')[0], 201)
        changed = copy.deepcopy(self.bundle)
        changed['repository']['id'] = 'changed'
        self.assertEqual(self.direct(body=canonical(changed), key=key)[0], 409)
        self.assertEqual(self.direct(key='a' * 64)[0], 422)
        self.assertEqual(self.server.commits, 2)

    def test_invalid_server_input_and_bounds(self):
        self.assertEqual(self.direct(body=b'{')[0], 422)
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        connection.putrequest('POST', '/api/v1/developer/projects/project-a/evidence')
        connection.putheader('Authorization', 'Bearer fixture-token-a')
        connection.putheader('Content-Length', str(MAX_BYTES + 1))
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 413)
        response.read()
        connection.close()
        bad = copy.deepcopy(self.bundle)
        bad['secret'] = 'never accept'
        self.assertEqual(self.direct(body=canonical(bad))[0], 422)

    def test_transport_timeout_is_bounded_and_never_claims_success(self):
        for error in (urllib.error.URLError(TimeoutError()), http.client.BadStatusLine('SYNTHETIC_SERVER_SECRET')):
            fake = mock.Mock()
            fake.open.side_effect = error
            with mock.patch('canary.urllib.request.build_opener', return_value=fake), mock.patch('canary.time.sleep'):
                with self.assertRaises(CanaryError) as failure: self.send()
            self.assertEqual(fake.open.call_count, 3)
            self.assertNotIn('SYNTHETIC_SERVER_SECRET', str(failure.exception))
            self.assertEqual(self.server.commits, 0)

    def test_receipt_size_project_and_billing_mode_are_checked(self):
        receipt = {'schema_version': 'canary-receipt/1', 'project_id': 'other', 'bundle_sha256': digest(canonical(self.bundle)), 'evidence_id': 'evidence', 'monitoring_state': 'integration_fixture_only', 'billing_mode': 'developer_inventory_free'}
        self.server.receipt_override = receipt
        with self.assertRaises(CanaryError): self.send()
        self.server.rows.clear()
        self.server.receipt_override = {'oversize': 'x' * 65537}
        with self.assertRaises(CanaryError): self.send()

    def test_https_origin_and_plaintext_restrictions(self):
        for endpoint in ['http://localhost:1', 'http://127.0.0.1:1', 'https://user:pass@example.invalid', 'https://example.invalid/path', 'https://example.invalid?token=secret', 'file:///tmp/test']:
            with self.assertRaises(CanaryError):
                endpoint_url(endpoint, 'project-a')
        self.assertTrue(endpoint_url('https://canary.example.invalid', 'project-a').startswith('https://'))

for _name in list(Consumer.__dict__):
    if _name.startswith('test_'):
        setattr(Contract, _name, None)

if __name__ == '__main__':
    unittest.main()
