"""Exercise a copied/installed skill via its public CLI in a clean synthetic consumer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

AT = '2026-10-22T12:00:00Z'

def run(installed, output):
    installed = Path(installed).resolve()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    distribution = installed
    with tempfile.TemporaryDirectory(prefix='canary-consumer-') as tmp:
        root = Path(tmp).resolve()
        repo = root / 'consumer'
        audit = root / 'audit'
        repo.mkdir()
        audit.mkdir()
        for name in ('findings.json', 'audit-context.json'):
            (audit / name).write_bytes((installed / 'examples' / name).read_bytes())
        (repo / 'package-lock.json').write_bytes((installed / 'examples/package-lock.json').read_bytes())
        (repo / '.gitignore').write_text('.agents/\n')
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        subprocess.run(['git', '-C', str(repo), 'add', 'package-lock.json', '.gitignore'], check=True)
        env = dict(os.environ, GIT_AUTHOR_DATE=AT, GIT_COMMITTER_DATE=AT)
        subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Synthetic Canary Consumer', '-c', 'user.email=fixture@example.invalid', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic consumer inventory'], env=env, check=True)
        installation = json.loads(subprocess.check_output([os.sys.executable, str(distribution/'scripts/install.py'), '--project', str(repo)], text=True))
        assert installation['audit_started'] is False and installation['network_used'] is False
        installed = repo/'.agents/skills/zero-day-canary-skill'
        cli = installed/'scripts/canary.py'
        assert not (repo/'.agents/skills/security-audit').exists()
        assert len(list((repo/'.agents/skills').rglob('SKILL.md')))==1
        def command(*args):
            result = subprocess.run([os.sys.executable, str(cli)] + list(args), capture_output=True, text=True, timeout=20, check=True)
            return result.stdout
        base = ['pack', '--repo', str(repo), '--repo-id', 'synthetic/consumer', '--inventory', 'package-lock.json', '--audit-root', str(audit), '--findings', 'findings.json', '--audit-context', 'audit-context.json', '--at', AT]
        bundle = output / 'sample-bundle.json'
        command(*base, '--out', str(bundle))
        command('validate', str(bundle))
        command(*base, '--out', str(root / 'deterministic.json'))
        assert bundle.read_bytes() == (root / 'deterministic.json').read_bytes()
        review = json.loads(command('review', str(bundle), '--endpoint', 'https://canary.example.invalid', '--project', 'synthetic-project', '--at', AT, '--out', str(output / 'sample-review.json')))
        assert review['exact_submission_body'] == json.loads(bundle.read_text())
        assert review['summary']['selected_detailed_findings'] == 0
        assert review['summary']['deployed_system_verification'] == 'not_performed'
        command(*base, '--select-finding', 'src-handler-missing-check', '--out', str(output / 'sample-detail-bundle.json'))
        detail = json.loads((output / 'sample-detail-bundle.json').read_text())
        assert detail['audit']['selected_findings'] == [json.loads((audit / 'findings.json').read_text())[0]]
        result = command('match', str(bundle), '--snapshot', str(installed / 'examples/advisories.json'), '--at', AT)
        (output / 'sample-match.json').write_text(result)
        match = json.loads(result)
        assert match['matches'][0]['status'] == 'affected_version_matched'
        lock = json.loads((repo / 'package-lock.json').read_text())
        lock['packages']['node_modules/next']['version'] = '16.0.2'
        (repo / 'package-lock.json').write_text(json.dumps(lock))
        after = output / 'sample-after-bundle.json'
        command(*base, '--out', str(after))
        result = command('compare', str(bundle), str(after))
        (output / 'sample-compare.json').write_text(result)
        assert json.loads(result)['added_or_changed'][0]['version'] == '16.0.2'
        assert json.loads(after.read_text())['repository']['dirty']
        summary = {'result': 'PASS', 'commands': ['install-one-canary-skill', 'pack', 'validate', 'review', 'compare', 'match'], 'component_instances': 5, 'direct': 3, 'transitive': 2, 'audit_verdict_counts': {'confirmed': 1, 'needs_validation': 1, 'rejected': 1}, 'default_detailed_records': 0, 'selected_detail_records': 1, 'bundle_sha256': hashlib.sha256(bundle.read_bytes()).hexdigest(), 'network_calls': 0, 'note': 'Synthetic consumer only; no audit or deployed-system verification.'}
        print(json.dumps(summary, indent=2))
        return summary

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--installed', required=True)
    p.add_argument('--output', required=True)
    args = p.parse_args()
    run(args.installed, args.output)
