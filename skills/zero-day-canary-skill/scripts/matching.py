"""Conservative adapter to the app's reviewed advisory schema, never a deployment verifier."""
import re
import datetime as dt
from canary import CanaryError, need, timestamp, VERSION

# The app's product keys do not carry package ecosystem identity. Only this
# reviewed, exact mapping is enabled; do not fuzzy-match package names or titles.
PACKAGE_PRODUCTS = {('npm', 'next'): 'nextjs'}

def catalog_timestamp(value):
    # The actual API emits ISO timestamps with milliseconds; preserve those bytes
    # rather than rewriting advisory records to fit the stricter bundle timestamp.
    need(isinstance(value,str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z',value), 'Invalid UTC catalog timestamp.')
    try:
        return dt.datetime.fromisoformat(value[:-1]+'+00:00')
    except ValueError:
        raise CanaryError('Invalid catalog calendar timestamp.') from None

def parsed(value):
    if not isinstance(value, str):
        return None
    m = VERSION.fullmatch(value)
    if not m:
        return None
    pre = None if m[4] is None else tuple(int(x) if x.isdigit() else x for x in m[4].split('.'))
    return (tuple(int(m[i]) for i in (1, 2, 3)), pre, m[5])

def cmp(a, b):
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    ap, bp = a[1], b[1]
    if ap is None or bp is None:
        return 0 if ap == bp else (1 if ap is None else -1)
    for x, y in zip(ap, bp):
        if x == y:
            continue
        if isinstance(x, int) != isinstance(y, int):
            return -1 if isinstance(x, int) else 1
        return -1 if x < y else 1
    return (len(ap) > len(bp)) - (len(ap) < len(bp))

def in_range(v, r):
    intro, fixed, last = [parsed(r.get(k)) if r.get(k) is not None else None for k in ('introduced', 'fixed', 'last_affected')]
    if intro and cmp(v, intro) < 0:
        return False
    if fixed:
        return cmp(v, fixed) < 0
    if last:
        return cmp(v, last) <= 0
    return True

def branch_touched(v, r):
    lo = parsed(r['introduced']) if r['introduced'] else None
    hi_raw = r.get('fixed') or r.get('last_affected')
    hi = parsed(hi_raw) if hi_raw else None
    branch = v[0][:2]
    return not ((lo and branch < lo[0][:2]) or (hi and branch > hi[0][:2]))

def validate_snapshot(snapshot):
    need(isinstance(snapshot, dict) and snapshot.get('schema_version') == '2026-10-22' and type(snapshot.get('catalog_revision')) is int and snapshot['catalog_revision'] >= 0 and isinstance(snapshot.get('data'), list), 'Expected a captured app advisory API response (schema_version 2026-10-22, catalog_revision, data).')
    need(len(snapshot['data']) <= 1000, 'Snapshot exceeds 1000 advisories; use a scoped snapshot.')
    need(snapshot.get('next_cursor') is None and snapshot.get('next') is None, 'Snapshot is only one page; collect all pages into a single consistent catalog revision first.')
    ids = set()
    for record in snapshot['data']:
        need(isinstance(record, dict), 'Invalid advisory record.')
        need(isinstance(record.get('id'), str) and 0 < len(record['id']) <= 200 and record['id'] not in ids, 'Duplicate/invalid advisory identity.')
        ids.add(record['id'])
        need(record.get('schema_version') == '2026-10-22' and type(record.get('revision')) is int and record['revision'] > 0 and type(record.get('catalog_revision')) is int and 0 <= record['catalog_revision'] <= snapshot['catalog_revision'], 'Invalid advisory revision/schema.')
        need(record.get('status') in ('published', 'withdrawn', 'superseded'), 'Invalid advisory status.')
        need(isinstance(record.get('affected'), list) and len(record['affected']) <= 100 and isinstance(record.get('conditions'), list) and len(record['conditions']) <= 100, 'Invalid advisory ranges/conditions.')
        need(isinstance(record.get('identifiers'), list) and all(isinstance(x, str) and len(x) <= 200 for x in record['identifiers']), 'Invalid advisory identifiers.')
        catalog_timestamp(record.get('reviewed_at'))
        for condition in record['conditions']:
            need(isinstance(condition, dict) and isinstance(condition.get('description'), str) and (condition.get('fact') is None or isinstance(condition.get('fact'), str)), 'Invalid prerequisite.')
        for ap in record['affected']:
            need(isinstance(ap, dict) and isinstance(ap.get('product'), str) and isinstance(ap.get('ranges'), list) and len(ap['ranges']) <= 100 and ap.get('other_branches', 'unknown') in ('unknown', 'not_affected'), 'Invalid affected product.')
            for r in ap['ranges']:
                need(isinstance(r, dict) and all(k in r for k in ('introduced', 'fixed')) and type(r.get('ambiguous', False)) is bool, 'Invalid version range.')
                for k in ('introduced', 'fixed', 'last_affected'):
                    need(r.get(k) is None or isinstance(r[k], str), 'Invalid range boundary type.')
    return snapshot

def assess(component, ap):
    v = parsed(component['version'])
    ranges = ap['ranges']
    if v is None:
        return 'needs_verification', 'Exact supplied version is unavailable.'
    if v[2]:
        return 'needs_verification', 'Build metadata or vendor backport requires confirmation.'
    if not ranges:
        return 'needs_verification', 'Advisory has no usable affected ranges.'
    # Validate every boundary before reasoning about the union of ranges.
    for r in ranges:
        if not any(r.get(k) for k in ('introduced', 'fixed', 'last_affected')):
            return 'needs_verification', 'Advisory boundary is missing.'
        for k in ('introduced', 'fixed', 'last_affected'):
            if r.get(k) and (parsed(r[k]) is None or parsed(r[k])[2]):
                return 'needs_verification', 'Advisory boundary cannot be interpreted conservatively.'
        if r.get('fixed') and r.get('last_affected') and cmp(parsed(r['last_affected']),parsed(r['fixed'])) >= 0:
            return 'needs_verification', 'Contradictory inclusive/exclusive boundaries need review.'
        end = parsed(r.get('last_affected') or r.get('fixed')) if (r.get('last_affected') or r.get('fixed')) else None
        if r.get('introduced') and end and cmp(parsed(r['introduced']),end) > 0:
            return 'needs_verification', 'Inverted advisory range requires review.'
    uncertain = False
    for r in ranges:
        inside = in_range(v, r)
        if r.get('ambiguous'):
            # A disputed exact 16.0.0 boundary does not obscure an explicit
            # affected 16.0.1..16.4.0 range for an observed 16.3.3 instance.
            uncertain |= inside
            continue
        if inside and r.get('fixed') and r.get('last_affected') and cmp(v,parsed(r['last_affected'])) > 0:
            uncertain = True  # e.g. prerelease between last stable and fixed.
            continue
        if inside:
            return 'affected_version_matched', 'Supplied version falls in an explicit affected range. Deployment and prerequisites are unverified.'
    if uncertain:
        return 'needs_verification', 'The supplied version falls within a disputed or incompletely specified boundary.'
    fixed = [parsed(r['fixed']) for r in ranges if r['fixed']]
    past_all = bool(fixed) and all(cmp(v, f) >= 0 for f in fixed)
    branch_covered = past_all or any(branch_touched(v, r) for r in ranges)
    if not branch_covered and ap.get('other_branches', 'unknown') == 'unknown':
        return 'needs_verification', 'This release branch is outside advisory coverage.'
    return 'not_affected', 'Supplied inventory version is outside these advisory ranges; deployed system was not verified.'

def match_snapshot(bundle, snapshot, at):
    validate_snapshot(snapshot)
    now = timestamp(at)
    need(timestamp(bundle['created_at']) <= now, 'Inventory timestamp is in the future.')
    warnings = ['Snapshot retrieval time and completeness are supplied by the caller; no network synchronization was performed.', 'Only npm next maps to the current app nextjs product key. Other ecosystems/products remain unassessed.', 'No deployment facts are supplied; prerequisite states remain unknown and fix_verified is never emitted.']
    if (now - timestamp(bundle['created_at'])).total_seconds() > 7 * 86400:
        warnings.append('Inventory is older than 7 days.')
    work = len(bundle['inventory']['components']) * sum(len(a['affected']) for a in snapshot['data'])
    need(work <= 200000, 'Snapshot/inventory comparison exceeds 200000 candidate checks; use a narrower snapshot.')
    matches = []
    unmapped = set()
    for component in bundle['inventory']['components']:
        product = PACKAGE_PRODUCTS.get((component['ecosystem'], component['name']))
        if product is None:
            unmapped.add((component['ecosystem'], component['name']))
            continue
        for record in snapshot['data']:
            if record['status'] != 'published':
                continue
            reviewed = catalog_timestamp(record['reviewed_at'])
            need(reviewed <= now, 'Snapshot contains a future review timestamp.')
            for ap in record['affected']:
                if ap['product'] != product:
                    continue
                status, reason = assess(component, ap)
                need(len(matches) < 5000, 'Matching exceeds 5000 results; use a narrower snapshot.')
                matches.append({'advisory_id': record['id'], 'advisory_revision': record['revision'], 'identifiers': record['identifiers'], 'component': component,
                                'status': status, 'reason': reason, 'basis': 'developer_supplied', 'conditions': [{'description': c['description'], 'state': 'unknown'} for c in record['conditions']],
                                'advisory_stale': (now - reviewed).total_seconds() > 7 * 86400})
    return {'catalog_revision': snapshot['catalog_revision'], 'snapshot_schema_version': snapshot['schema_version'], 'matches': matches, 'unmapped_packages': [{'ecosystem': e, 'name': n} for e, n in sorted(unmapped)], 'warnings': warnings,
            'notice': 'No matching advisory means only no match in this snapshot and adapter coverage; source-audit verdicts and deployed verification are separate.'}
