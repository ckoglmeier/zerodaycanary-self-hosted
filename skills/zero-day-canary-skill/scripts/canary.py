#!/usr/bin/env python3
"""Local evidence packaging. No repository code is executed; only submit uses network."""
import argparse
import collections
import datetime as dt
import hashlib
import http.client
import json
import math
import unicodedata
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

HERE = Path(__file__).resolve().parent.parent
PIN = 'c1c8a8c1471069fb0e188eeaff69b8e8db6564a8'
SCHEMA_HASH = '6575c9de4a62255699ea052ebf9a49ebfb373a32891bcd89af6f55cc84b35519'
MAX_BYTES = 5 * 1024 * 1024
NAME = re.compile(r'(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+\Z')
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?\Z')
LIMITATIONS = [
    'Developer-supplied source inventory is not evidence of the deployed system.',
    'Lockfiles describe declared resolution; installed, bundled, runtime, OS and deployment components may differ or be absent.',
    'Source audit verdicts are separate from advisory matches and deployed-system verification.',
    'A clean audit or no matching advisory never proves absence of vulnerabilities.',
    'Inventory scope covers supplied lockfile entries, including development and optional packages; runtime reachability is unknown.',
    'Detailed findings are omitted unless individually selected; schema validity does not certify audit completion or independent verification.',
]

class CanaryError(Exception):
    pass

def need(condition, message):
    if not condition:
        raise CanaryError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def safe_relative(value):
    need(isinstance(value, str) and 0 < len(value) <= 512, 'Invalid relative path.')
    need(not value.startswith(('/', '\\')) and '\\' not in value and ':' not in value, 'Absolute or platform-ambiguous path rejected.')
    need(all(x not in ('', '.', '..') for x in value.split('/')), 'Traversal or empty path component rejected.')
    need(all(unicodedata.category(x) not in ('Cc', 'Cf', 'Cs', 'Zl', 'Zp') for x in value), 'Control character in path.')
    # Input filenames must not select secret/configuration files, even if renamed JSON.
    for part in value.lower().split('/'):
        need(not (part.startswith('.env') or part in ('.git', '.aws', '.ssh', '.npmrc', '.netrc', 'credentials') or part.endswith(('.pem', '.key', '.p12'))), 'Sensitive input path rejected.')
    return value

def open_directory(path):
    """Resolve the caller-selected root once, then walk its real components no-follow."""
    absolute = Path(path).resolve(strict=True)
    fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise

def read_bytes(root, relative):
    """Walk descriptors without symlinks; never read devices, FIFOs or hardlinks."""
    safe_relative(relative)
    directory = open_directory(root)
    try:
        parts = relative.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'Only ordinary non-linked input files are accepted.')
            need(before.st_size <= MAX_BYTES, 'Input exceeds 5 MiB.')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read(MAX_BYTES + 1)
            after = os.fstat(fd)
            need(len(data) == before.st_size and len(data) <= MAX_BYTES and (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Input changed while reading or exceeds limit.')
            return data
        finally:
            os.close(fd)
    finally:
        os.close(directory)

def read_path(path):
    p = Path(path).absolute()
    # Explicit root is the caller-selected parent; leaf still cannot be a symlink.
    return read_bytes(p.parent, p.name)

def parse_json(data):
    need(len(data) <= MAX_BYTES, 'JSON exceeds 5 MiB.')
    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out, 'Duplicate JSON object key.')
            out[k] = v
        return out
    def bounded_integer(raw):
        need(len(raw) <= 128, 'JSON integer exceeds limit.')
        return int(raw)
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_int=bounded_integer, parse_constant=lambda _: (_ for _ in ()).throw(CanaryError('Non-finite JSON number.')))
    except (ValueError, UnicodeError, RecursionError):
        raise CanaryError('Invalid JSON or excessive nesting.') from None
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        need(depth <= 48 and count <= 200000, 'JSON structure exceeds depth/node limits.')
        if isinstance(item, dict):
            need(len(item) <= 30000, 'Too many object properties.')
            stack.extend((x, depth + 1) for x in item.values())
        elif isinstance(item, list):
            need(len(item) <= 20000, 'Too many array entries.')
            stack.extend((x, depth + 1) for x in item)
        elif isinstance(item, float):
            need(math.isfinite(item), 'Non-finite JSON number.')
        elif isinstance(item, str):
            need(len(item) <= 65536, 'JSON string exceeds limit.')
    return value

def load(root, relative):
    data = read_bytes(root, relative)
    return parse_json(data), digest(data)

def write_new(path, data):
    need(len(data) <= MAX_BYTES, 'Output exceeds 5 MiB.')
    p = Path(path).absolute()
    directory = open_directory(p.parent)
    try:
        fd = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(data)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def schema_validate(value, filename):
    schema = json.loads((HERE / 'schemas' / filename).read_text())
    upstream = json.loads((HERE / 'vendor/cloudflare/security-audit/report-schema.json').read_text())
    uri = 'https://zerodaycanary.com/vendor/cloudflare/security-audit/report-schema.json'
    registry = Registry().with_resource(uri, Resource.from_contents(upstream, default_specification=__import__('referencing.jsonschema', fromlist=['DRAFT202012']).DRAFT202012))
    try:
        error = next(Draft202012Validator(schema, registry=registry).iter_errors(value), None)
    except Exception:
        raise CanaryError('Schema validation failed.') from None
    need(error is None, 'Data does not satisfy ' + filename + ' (values suppressed).')

def upstream_validate(findings):
    # Fixed installed validator only. Never load target code, plugins or NODE_OPTIONS.
    node = shutil.which('node')
    need(node is not None, 'Node.js is required to validate imported audit findings.')
    program = "const fs=require('fs');const p=process.argv[1];const v=require(p+'/validate-findings.cjs');const s=require(p+'/report-schema.json');process.exit(v.validateDocument(JSON.parse(fs.readFileSync(0,'utf8')),s).length?1:0)"
    result = subprocess.run([node, '-e', program, str(HERE / 'vendor/cloudflare/security-audit')], input=canonical(findings), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, env={'PATH': os.defpath})
    need(result.returncode == 0, 'Audit records failed the pinned upstream schema/semantic validator (values suppressed).')

def timestamp(value):
    need(isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value), 'Timestamp must be UTC YYYY-MM-DDTHH:MM:SSZ.')
    try:
        return dt.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc)
    except ValueError:
        raise CanaryError('Invalid calendar timestamp.') from None

def exact_version(value):
    if not isinstance(value, str) or len(value) > 128:
        return False
    m = VERSION.fullmatch(value)
    if not m:
        return False
    for group in (m[4], m[5]):
        if group and any(not p for p in group.split('.')):
            return False
    return not (m[4] and any(p.isdigit() and len(p) > 1 and p[0] == '0' for p in m[4].split('.')))

def git_state(root):
    env = {'PATH': os.defpath, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_OPTIONAL_LOCKS': '0', 'GIT_ATTR_NOSYSTEM': '1'}
    git = shutil.which('git') or 'git'
    root = Path(root).resolve()
    base = [git, '--no-optional-locks', '--no-replace-objects', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-C', str(root)]
    def metadata(*args):
        result = subprocess.run(base + list(args), capture_output=True, timeout=5, env=env)
        if result.returncode != 0 or len(result.stdout) > 4096:
            return None
        return result.stdout.decode('utf-8', 'strict').strip()
    commit = metadata('rev-parse', '--verify', 'HEAD')
    if commit and not re.fullmatch('[a-f0-9]{40,64}', commit):
        commit = None
    object_format = metadata('rev-parse', '--show-object-format')
    objects = metadata('rev-parse', '--git-path', 'objects')
    index = metadata('rev-parse', '--git-path', 'index')
    if object_format not in ('sha1', 'sha256') or not objects or not index:
        return commit, None
    objects = (root / objects).resolve()
    index = root / index
    if any(c in str(objects) for c in ('\n', '\r')):
        return commit, None
    # Never run status with the target's Git configuration: clean/process filters
    # can execute commands even when status itself is read-only. A private Git
    # directory has no target hooks, filters, textconv, attributes or submodule config.
    with tempfile.TemporaryDirectory(prefix='canary-git-metadata-') as temporary:
        scratch = Path(temporary).resolve() / 'metadata.git'
        init = subprocess.run([git, 'init', '--bare', '--template=', '--object-format=' + object_format, str(scratch)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, env=env)
        if init.returncode != 0:
            return commit, None
        (scratch / 'objects/info/alternates').write_text(str(objects) + '\n')
        if commit:
            (scratch / 'HEAD').write_text(commit + '\n')
        try:
            (scratch / 'index').write_bytes(read_path(index))
        except FileNotFoundError:
            if commit:
                return commit, None
        except (CanaryError, OSError):
            return commit, None
        safe_base = [git, '--no-optional-locks', '--no-replace-objects', '--git-dir=' + str(scratch), '--work-tree=' + str(root), '-c', 'core.bare=false', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'core.attributesFile=/dev/null']
        process = subprocess.Popen(safe_base + ['status', '--porcelain=v1', '--untracked-files=normal', '--ignore-submodules=all'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        try:
            import selectors
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(5):
                return commit, None
            data = os.read(process.stdout.fileno(), 65536)
            dirty = bool(data)
            if dirty:
                process.terminate()
            process.wait(timeout=5)
            if not dirty and process.returncode != 0:
                return commit, None
            # Nested submodule source is deliberately not inspected. The inventory
            # covers named lockfiles, not a recursive source integrity attestation.
            return commit, dirty
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            if 'selector' in locals():
                selector.close()


def inventory(lock):
    empty = {'format': 'missing', 'components': [], 'unknowns': [{'reason': 'missing_inventory', 'entry': None}]}
    if lock is None:
        return empty
    if not isinstance(lock, dict) or type(lock.get('lockfileVersion')) is not int or lock['lockfileVersion'] not in (2, 3) or not isinstance(lock.get('packages'), dict):
        return {'format': 'unsupported', 'components': [], 'unknowns': [{'reason': 'unsupported_inventory', 'entry': None}]}
    packages = lock['packages']
    need(len(packages) <= 20000, 'Lockfile exceeds 20000 entries.')
    root = packages.get('')
    direct = set()
    unknowns = []
    has_manifest = isinstance(root, dict)
    if has_manifest:
        for key in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
            vals = root.get(key, {})
            need(isinstance(vals, dict), 'Invalid root dependency map.')
            direct.update(vals)
    else:
        unknowns.append({'reason': 'missing_root_manifest', 'entry': None})
    components = []
    for index, (location, meta) in enumerate(sorted(packages.items()), 1):
        if location == '':
            continue
        safe_relative(location)
        need(isinstance(meta, dict), 'Invalid lockfile entry.')
        # Local links/workspaces are not claimed as resolved registry identities.
        if meta.get('link') or not location.startswith('node_modules/'):
            unknowns.append({'reason': 'linked_or_workspace_component', 'entry': index})
            continue
        suffixes = location.split('node_modules/')[1:]
        need(all(x.endswith('/') and NAME.fullmatch(x[:-1]) for x in suffixes[:-1]), 'Invalid nested package locator.')
        derived = suffixes[-1]
        candidate = meta.get('name', derived)
        if not isinstance(candidate, str) or len(candidate) > 214 or not NAME.fullmatch(candidate) or not NAME.fullmatch(derived):
            unknowns.append({'reason': 'ambiguous_identity', 'entry': index})
            continue
        resolved = meta.get('resolved')
        if resolved is not None:
            need(isinstance(resolved, str), 'Invalid resolution metadata.')
            source_url = urllib.parse.urlsplit(resolved)
            if source_url.scheme != 'https' or source_url.hostname != 'registry.npmjs.org' or source_url.username or source_url.password or source_url.query or source_url.fragment:
                unknowns.append({'reason': 'non_registry_component', 'entry': index})
                continue
        value = meta.get('version')
        version = value if exact_version(value) else None
        if version is None:
            unknowns.append({'reason': 'ambiguous_version', 'entry': index})
        relationship = 'unknown' if not has_manifest else ('direct' if location == 'node_modules/' + derived and derived in direct else 'transitive')
        components.append({'ecosystem': 'npm', 'name': candidate, 'version': version,
                           'purl': 'pkg:npm/' + urllib.parse.quote(candidate, safe='/') + '@' + urllib.parse.quote(version, safe='') if version else None,
                           'relationship': relationship, 'development': meta.get('dev') if isinstance(meta.get('dev'), bool) else None,
                           'optional': meta.get('optional') if isinstance(meta.get('optional'), bool) else None,
                           'source_id': 'inventory-1', 'instance': index})
    for name in sorted(direct):
        if 'node_modules/' + name not in packages:
            unknowns.append({'reason': 'missing_direct_entry', 'entry': None})
    return {'format': 'npm-lock-v' + str(lock['lockfileVersion']), 'components': components, 'unknowns': unknowns}

def validate_bundle(bundle):
    v2=bundle.get('schema_version')=='canary-evidence/2'
    schema_validate(bundle, 'canary-evidence-v2.schema.json' if v2 else 'canary-evidence-v1.schema.json')
    timestamp(bundle['created_at'])
    need(bool(bundle['scope']), 'Inventory scope must be explicit.')
    for path in bundle['scope'] + bundle['audit']['context']['scope']:
        if path != '.':
            safe_relative(path)
    for item in bundle['inventory']['components']:
        if v2:
            need(item['version'] is None or item['version'].lower() not in ('latest','unknown','any','head','main','master'),'Use an exact version or null.')
            need(item['ecosystem']!='product' or not item['public_registry'],'Non-package assets cannot be public registry packages.')
            need(item['purl'] is None or not any(c.isspace() or ord(c)<32 or ord(c)==127 for c in item['purl']),'Invalid package URL.')
            continue
        if item['version'] is not None:
            need(exact_version(item['version']), 'Non-exact inventory version.')
        expected = 'pkg:npm/' + urllib.parse.quote(item['name'], safe='/') + '@' + urllib.parse.quote(item['version'], safe='') if item['version'] else None
        need(item['purl'] == expected, 'Component purl does not match identity/version.')
    inv = bundle['inventory']
    if inv['format'] in ('missing', 'unsupported'):
        need(not inv['components'], 'Missing/unsupported inventory cannot contain component claims.')
        reason = 'missing_inventory' if inv['format'] == 'missing' else 'unsupported_inventory'
        need(any(u['reason'] == reason for u in inv['unknowns']), 'Missing/unsupported inventory must retain its coverage unknown.')
    instances = [c['instance'] for c in inv['components']]
    need(len(set(instances)) == len(instances), 'Duplicate inventory instance.')
    context = bundle['audit']['context']
    if context['audited_at']:
        need(timestamp(context['audited_at']) <= timestamp(bundle['created_at']), 'Audit is later than packaging time.')
    audit = bundle['audit']
    need(sum(audit['verdict_counts'].values()) == audit['total_records'], 'Audit counts disagree.')
    if audit['report_sha256'] is None:
        need(audit['total_records'] == 0 and not audit['selected_findings'], 'Findings require report provenance.')
    upstream_validate(audit['selected_findings'])
    counts = collections.Counter(x['verdict'] for x in audit['selected_findings'])
    need(all(n <= audit['verdict_counts'][v] for v, n in counts.items()), 'Selected findings exceed report counts.')
    need(len({x['fingerprint'] for x in audit['selected_findings']}) == len(audit['selected_findings']), 'Duplicate selected finding.')
    sources = {x['id']: x for x in bundle['sources']}
    need(len(sources) == len(bundle['sources']), 'Duplicate evidence source.')
    for component in bundle['inventory']['components']:
        need(component['source_id'] in sources and sources[component['source_id']]['kind'] == ('component_inventory' if v2 else 'npm_lockfile'), 'Missing inventory provenance.')
    if v2 and inv['format']=='component-inventory':
        need(sources.get('inventory-1',{}).get('kind')=='component_inventory','Inventory requires its source.')
    elif inv['format'].startswith('npm-lock-'):
        need(sources.get('inventory-1', {}).get('kind') == 'npm_lockfile', 'Supported inventory requires its lockfile source.')
    elif inv['format'] == 'missing':
        need('inventory-1' not in sources, 'Missing inventory cannot claim an inventory input.')
    elif inv['format'] == 'unsupported':
        need(sources.get('inventory-1', {}).get('kind') == 'unsupported_inventory', 'Unsupported inventory requires its source.')
    if audit['report_sha256']:
        need(sources.get('audit-1', {}).get('sha256') == audit['report_sha256'], 'Missing audit provenance.')
    need(bundle['limitations'] == LIMITATIONS, 'Coverage limitations must be retained unchanged.')
    return bundle

def pack(args):
    timestamp(args.at)
    commit, dirty = git_state(args.repo)
    sources = []
    lock = None
    if args.inventory:
        lock, sha = load(args.repo, args.inventory)
        sources.append({'id': 'inventory-1', 'kind': 'npm_lockfile', 'sha256': sha})
    inv = inventory(lock)
    if sources and inv['format'] == 'unsupported':
        sources[0]['kind'] = 'unsupported_inventory'
    context = dict(upstream_revision=None, source_commit=None, source_dirty=None, audited_at=None, scope=[], run_status='unknown')
    findings = []
    report_sha = None
    if args.findings:
        need(args.audit_root, '--audit-root is required with --findings.')
        findings, report_sha = load(args.audit_root, args.findings)
        upstream_validate(findings)
        sources.append({'id': 'audit-1', 'kind': 'audit_findings', 'sha256': report_sha})
    if args.audit_context:
        need(args.findings, 'Audit context requires findings.')
        context, sha = load(args.audit_root, args.audit_context)
        schema_validate(context, 'audit-context-v1.schema.json')
        sources.append({'id': 'context-1', 'kind': 'audit_context', 'sha256': sha})
    selected = set(args.select_finding or [])
    need(selected <= {x['fingerprint'] for x in findings}, 'Selected finding does not exist.')
    counts = {v: sum(x['verdict'] == v for x in findings) for v in ('confirmed', 'needs_validation', 'rejected')}
    need(bool(args.deployment_id) == bool(args.deployment_version), 'Deployment identity and version must be supplied together.')
    deployment = {'identity': args.deployment_id, 'version': args.deployment_version, 'basis': 'developer_supplied_unverified'} if args.deployment_id else None
    bundle = dict(schema_version='canary-evidence/1', created_at=args.at,
                  repository={'id': args.repo_id, 'commit': commit, 'dirty': dirty, 'basis': 'developer_supplied'}, scope=args.scope or ['.'], deployment=deployment,
                  audit={'context': context, 'compatibility_revision': PIN, 'schema_sha256': SCHEMA_HASH, 'report_sha256': report_sha, 'total_records': len(findings), 'verdict_counts': counts, 'selected_findings': [x for x in findings if x['fingerprint'] in selected]},
                  inventory=inv, sources=sources, limitations=LIMITATIONS)
    validate_bundle(bundle)
    write_new(args.out, canonical(bundle))
    print('Saved local bundle; no data sent. SHA256 ' + digest(canonical(bundle)))


def read_bundle(path):
    return validate_bundle(parse_json(read_path(path)))

def endpoint_url(endpoint, project, allow_http=False):
    need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', project) is not None, 'Invalid private project id.')
    u = urllib.parse.urlsplit(endpoint)
    need(u.hostname is not None and u.username is None and u.password is None and not u.query and not u.fragment and u.path in ('', '/'), 'Endpoint must be an origin without credentials, path, query or fragment.')
    need(u.scheme == 'https' or (allow_http and u.scheme == 'http' and u.hostname == '127.0.0.1'), 'HTTPS is required except explicitly enabled 127.0.0.1 fixtures.')
    need(u.port is None or 1 <= u.port <= 65535, 'Invalid endpoint port.')
    origin = u.scheme + '://' + u.netloc.lower()
    return origin + '/api/v1/developer/projects/' + project + '/evidence'

def approval(bundle, endpoint, project, allow_http=False):
    url = endpoint_url(endpoint, project, allow_http)
    request = {'method': 'POST', 'url': url, 'bundle_sha256': digest(canonical(bundle))}
    return digest(canonical(request)), request

def review_document(bundle, args):
    now = timestamp(args.at)
    created = timestamp(bundle['created_at'])
    need(created <= now, 'Bundle timestamp is in the future.')
    warnings = []
    if (now - created).total_seconds() > 7 * 86400:
        warnings.append('Inventory evidence is older than 7 days; refresh it before relying on it.')
    context = bundle['audit']['context']
    if bundle['repository']['dirty'] is None:
        warnings.append('Git dirty state could not be established safely; source state is unknown.')
    if bundle['audit']['report_sha256'] is not None:
        if context['run_status'] != 'completed':
            warnings.append('Source audit run status is ' + context['run_status'] + '; valid records do not establish complete audit coverage.')
        if not context['scope']:
            warnings.append('Source audit scope is unknown.')
        if context['audited_at'] is None:
            warnings.append('Audit time/source coverage may be unknown; import time is not audit time.')
        elif (now - timestamp(context['audited_at'])).total_seconds() > 7 * 86400:
            warnings.append('Source audit is older than 7 days.')
        if context['source_commit'] != bundle['repository']['commit'] or context['source_dirty'] or bundle['repository']['dirty']:
            warnings.append('Audit and current checkout may differ or contain uncommitted changes; commit alone cannot identify dirty contents.')
        if context['upstream_revision'] is None:
            warnings.append('Actual audit producer revision is unknown; compatibility pin only identifies the import validator.')
    if bundle['inventory']['unknowns']:
        warnings.append('Inventory coverage includes explicit unknowns.')
    if bundle['audit']['verdict_counts']['needs_validation']:
        warnings.append('Source audit retains needs_validation records; those claims are not confirmed.')
    detailed = len(bundle['audit']['selected_findings'])
    if detailed:
        warnings.append('Selected findings may disclose proprietary source, paths, payloads or secrets. Inspect every field; no automatic redaction is promised.')
    result = {'review_version': 'canary-review/1', 'reviewed_at': args.at, 'warnings': warnings,
              'summary': {'component_instances': len(bundle['inventory']['components']), 'inventory_unknowns': len(bundle['inventory']['unknowns']), 'audit_verdict_counts': bundle['audit']['verdict_counts'], 'audit_run_status': context['run_status'], 'selected_detailed_findings': detailed, 'deployed_system_verification': 'not_performed', 'billing': 'No enrollment or charges; developer inventory monitoring is free once implemented.'},
              'exact_submission_body': bundle}
    if args.endpoint or args.project:
        need(args.endpoint and args.project, 'Review requires both endpoint and project.')
        token, request = approval(bundle, args.endpoint, args.project, args.allow_loopback_http)
        result.update({'request': request, 'approval_sha256': token, 'detailed_findings_approval_sha256': token if detailed else None})
    return result

def review(args):
    result = review_document(read_bundle(args.bundle), args)
    data = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True).encode() + b'\n'
    if args.out:
        write_new(args.out, data)
    sys.stdout.write(data.decode())

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def submit(args):
    bundle = read_bundle(args.bundle)
    token_hash, request = approval(bundle, args.endpoint, args.project, args.allow_loopback_http)
    need(args.approve == token_hash, 'Explicit approval must match review hash for exact bundle, endpoint and private project.')
    if bundle['audit']['selected_findings']:
        need(args.approve_findings == token_hash, 'Selected detailed findings require separate explicit approval.')
    review_document(bundle, argparse.Namespace(at=args.at, endpoint=None, project=None))
    credential = os.environ.get('CANARY_TOKEN', '')
    need(bool(credential) and len(credential) <= 4096 and all(32 < ord(c) < 127 for c in credential), 'Set a valid CANARY_TOKEN in the environment; never place it in a bundle or command argument.')
    need(1 <= args.attempts <= 3, 'Attempts must be 1..3.')
    payload = canonical(bundle)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(request['url'], data=payload, headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + credential, 'Idempotency-Key': request['bundle_sha256']}, method='POST')
    deadline = time.monotonic() + 20
    for attempt in range(args.attempts):
        need(time.monotonic() < deadline, 'Submission exceeded its time budget; outcome may be unknown. Retry with the same bundle/project/key.')
        try:
            with opener.open(req, timeout=5) as response:
                need(response.status in (200, 201), 'Unexpected server status; no success claimed.')
                blocks, remaining = [], 65537
                while remaining:
                    need(time.monotonic() < deadline, 'Server receipt exceeded its time budget; no success claimed.')
                    block = response.read1(min(8192, remaining))
                    if not block:
                        break
                    blocks.append(block)
                    remaining -= len(block)
                body = b''.join(blocks)
                need(len(body) <= 65536, 'Server receipt exceeds limit; no success claimed.')
            receipt = parse_json(body)
            schema_validate(receipt, 'canary-receipt-v1.schema.json')
            required = {'schema_version', 'project_id', 'bundle_sha256', 'evidence_id', 'monitoring_state', 'billing_mode'}
            need(isinstance(receipt, dict) and set(receipt) == required, 'Invalid server receipt; no success claimed.')
            need(receipt['schema_version'] == 'canary-receipt/1' and receipt['project_id'] == args.project and receipt['bundle_sha256'] == request['bundle_sha256'] and receipt['billing_mode'] == 'developer_inventory_free', 'Receipt does not match submitted project/evidence/free mode.')
            need(isinstance(receipt['evidence_id'], str) and re.fullmatch(r'[A-Za-z0-9_-]{1,100}', receipt['evidence_id']), 'Invalid receipt identity.')
            fixture = args.allow_loopback_http and urllib.parse.urlsplit(request['url']).scheme == 'http'
            need(receipt['monitoring_state'] in (('integration_fixture_only',) if fixture else ('pending', 'active')), 'Invalid monitoring state.')
            print(json.dumps({'receipt': receipt, 'notice': 'LOCAL CONTRACT FIXTURE ONLY; hosted monitoring is not implemented here.' if fixture else 'Server acknowledged evidence. Monitoring state is server-reported; this client did not verify scheduling or alerts.'}, sort_keys=True))
            return
        except urllib.error.HTTPError as error:
            status_code = error.code
            error.close()
            if status_code not in (408, 429, 500, 502, 503, 504) or attempt + 1 == args.attempts:
                raise CanaryError('Submission failed with HTTP ' + str(status_code) + '; response body suppressed. Retry only with the same bundle/project/key when outcome is uncertain.') from None
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
            if attempt + 1 == args.attempts:
                raise CanaryError('Submission transport failed; outcome may be unknown. Reuse exact bundle and project for an idempotent retry.') from None
        if attempt + 1 < args.attempts:
            time.sleep(0.25 * (2 ** attempt))


def compare(args):
    before, after = read_bundle(args.before), read_bundle(args.after)
    need(before['repository']['id'] == after['repository']['id'], 'Compare requires the same repository identity.')
    def identities(b):
        return collections.Counter((x['ecosystem'], x['name'], x['version'], x['relationship']) for x in b['inventory']['components'])
    old, new = identities(before), identities(after)
    def rows(counter):
        return [{'ecosystem': k[0], 'name': k[1], 'version': k[2], 'relationship': k[3], 'instances': n} for k, n in sorted(counter.items(), key=lambda x: str(x[0]))]
    old_findings = {x['fingerprint']: x['verdict'] for x in before['audit']['selected_findings']}
    new_findings = {x['fingerprint']: x['verdict'] for x in after['audit']['selected_findings']}
    result = {'removed_or_changed': rows(old - new), 'added_or_changed': rows(new - old),
              'selected_verdict_changes': [{'fingerprint': k, 'before': old_findings.get(k), 'after': new_findings.get(k)} for k in sorted(set(old_findings) | set(new_findings)) if old_findings.get(k) != new_findings.get(k)],
              'unknowns_before': before['inventory']['unknowns'], 'unknowns_after': after['inventory']['unknowns'],
              'notice': 'Removed components and absent selected findings do not prove remediation. Refresh audit as requested; deployed-system verification was not performed.'}
    print(json.dumps(result, indent=2, sort_keys=True))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    x = sub.add_parser('pack')
    x.add_argument('--repo', required=True)
    x.add_argument('--repo-id', required=True)
    x.add_argument('--inventory', help='Relative JSON input within repo; npm lockfile v2/v3 supported.')
    x.add_argument('--audit-root')
    x.add_argument('--findings')
    x.add_argument('--audit-context')
    x.add_argument('--select-finding', action='append')
    x.add_argument('--scope', action='append')
    x.add_argument('--deployment-id')
    x.add_argument('--deployment-version')
    x.add_argument('--at', required=True)
    x.add_argument('--out', required=True)
    x.set_defaults(run=pack)
    x = sub.add_parser('validate')
    x.add_argument('bundle')
    x.set_defaults(run=lambda a: (read_bundle(a.bundle), print('PASS: Canary evidence bundle valid.')))
    x = sub.add_parser('review')
    x.add_argument('bundle')
    x.add_argument('--at', required=True)
    x.add_argument('--endpoint')
    x.add_argument('--project')
    x.add_argument('--allow-loopback-http', action='store_true')
    x.add_argument('--out')
    x.set_defaults(run=review)
    x = sub.add_parser('submit')
    x.add_argument('bundle')
    x.add_argument('--endpoint', required=True)
    x.add_argument('--project', required=True)
    x.add_argument('--at', required=True)
    x.add_argument('--approve', required=True)
    x.add_argument('--approve-findings')
    x.add_argument('--attempts', type=int, default=3)
    x.add_argument('--allow-loopback-http', action='store_true')
    x.set_defaults(run=submit)
    x = sub.add_parser('compare')
    x.add_argument('before')
    x.add_argument('after')
    x.set_defaults(run=compare)
    x = sub.add_parser('match')
    x.add_argument('bundle')
    x.add_argument('--snapshot', required=True)
    x.add_argument('--at', required=True)
    def match_command(a):
        from matching import match_snapshot
        print(json.dumps(match_snapshot(read_bundle(a.bundle), parse_json(read_path(a.snapshot)), a.at), indent=2, sort_keys=True))
    x.set_defaults(run=match_command)
    args = p.parse_args()
    try:
        need(all(hasattr(os, name) for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK')), 'POSIX safe-file APIs are required; use macOS or Linux.')
        args.run(args)
    except (CanaryError, OSError, ValueError, subprocess.SubprocessError):
        # Only curated errors may be printed. Input values, payloads, token and server bodies stay out of logs.
        error = sys.exc_info()[1]
        print('ERROR: ' + (str(error) if isinstance(error, CanaryError) else 'Operation failed; check paths, permissions, dependencies and input bounds.'), file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
