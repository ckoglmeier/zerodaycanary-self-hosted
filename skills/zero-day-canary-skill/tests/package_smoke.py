"""Explicit trusted-release smoke test: install one CVE-focused skill, exercise tools and a local API fixture.
This never launches an LLM/audit; captured agent-run artifacts are checked separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import zipfile


def run(archive):
    with tempfile.TemporaryDirectory(prefix='canary-packaged-') as temporary:
        root=Path(temporary).resolve()
        with zipfile.ZipFile(archive) as package:
            entries=package.infolist()
            assert len(entries)<=1000 and sum(x.file_size for x in entries)<=20*1024*1024
            for entry in entries:
                parts=entry.filename.split('/')
                assert parts[0]=='zero-day-canary-skill' and all(x not in ('','.', '..') for x in parts)
                assert '.DS_Store' not in parts
                assert '\\' not in entry.filename and entry.file_size<=5*1024*1024
                assert (entry.external_attr>>16)&0o170000 != 0o120000
            package.extractall(root)
        distribution=root/'zero-day-canary-skill'
        for line in (distribution/'SHA256SUMS').read_text().splitlines():
            sha,name=line.split('  ',1)
            assert '..' not in Path(name).parts and not Path(name).is_absolute()
            assert hashlib.sha256((distribution/name).read_bytes()).hexdigest()==sha
        def command(*args, env=None):
            result=subprocess.run([sys.executable]+list(map(str,args)),capture_output=True,text=True,timeout=30,check=True,env=env)
            return json.loads(result.stdout)
        consumer=command(distribution/'tests/consumer_smoke.py','--installed',distribution,'--output',root/'outputs')
        assert (root/'outputs/sample-bundle.json').read_bytes()==(distribution/'examples/sample-bundle.json').read_bytes()
        project=root/'installed-project';project.mkdir()
        installation=command(distribution/'scripts/install.py','--project',project)
        installed=project/'.agents/skills/zero-day-canary-skill'
        assert not (project/'.agents/skills/security-audit').exists()
        assert len(list((project/'.agents/skills').rglob('SKILL.md')))==1
        # A disposable CVE consumer, with no app process, using the same installed skill.
        cve_repo=root/'cve-repo';cve_repo.mkdir()
        (cve_repo/'package-lock.json').write_bytes((distribution/'examples/package-lock.json').read_bytes())
        prep=command(installed/'scripts/cve.py','run','--repo',cve_repo,'--repo-id','synthetic/cve-consumer','--snapshot',distribution/'examples/advisories.json','--at','2026-10-22T12:00:00Z','--out',root/'cve-output')
        assert prep['checks_completed'] is False and prep['evidence_uploaded'] is False
        plan=json.loads((root/'cve-output/verification-plan.json').read_text())
        catalog=json.loads((root/'cve-output/catalog.json').read_text())
        assert {t['advisory_id'] for t in plan['targets']} <= {a['id'] for a in catalog['data']}
        assert not (root/'cve-output/REPORT.md').exists()
        sys.path.insert(0,str(distribution/'tests'))
        from contract_server import FixtureServer
        server=FixtureServer(('127.0.0.1',0))
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            origin='http://127.0.0.1:'+str(server.server_port)
            shared=[root/'outputs/sample-bundle.json','--endpoint',origin,'--project','project-a','--at','2026-10-22T12:00:00Z','--allow-loopback-http']
            review=command(installed/'scripts/canary.py','review',*shared)
            env=dict(os.environ,CANARY_TOKEN='fixture-token-a')
            receipt=command(installed/'scripts/canary.py','submit',*shared,'--approve',review['approval_sha256'],env=env)
            replay=command(installed/'scripts/canary.py','submit',*shared,'--approve',review['approval_sha256'],env=env)
            assert receipt==replay and server.commits==1
            assert receipt['receipt']['monitoring_state']=='integration_fixture_only'
        finally:
            server.shutdown();server.server_close();thread.join()
        return {'result':'PASS','package_manifest':'verified','single_canary_skill_installed':True,'upstream_revision':installation['upstream_revision'],'consumer':consumer,
                'cve_preparation':prep,'new_agent_audit_launched':False,'local_api_commits':1,'fixture_receipt':receipt,
                'notice':'Automated trusted-release smoke test; local fixture only, no hosted service or target execution.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',required=True)
    args=parser.parse_args()
    print(json.dumps(run(args.archive),indent=2,sort_keys=True))
