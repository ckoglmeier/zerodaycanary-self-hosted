"""Pin a verified companion ZIP as the app download, retaining upstream bytes."""
import argparse,hashlib,io,json,tarfile,zipfile,gzip
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--archive',required=True);p.add_argument('--expected-sha',required=True);args=p.parse_args()
source=Path(args.archive).read_bytes();sha=hashlib.sha256(source).hexdigest()
if sha!=args.expected_sha:raise SystemExit('Source checksum mismatch; distribution not changed.')
root=Path(__file__).resolve().parents[1]/'vendor/companion'
entries=[]
with zipfile.ZipFile(io.BytesIO(source)) as z:
 for name in z.namelist():
  if name.endswith('/'):continue
  if name.startswith('/') or '..' in Path(name).parts:raise SystemExit('Unsafe archive path.')
  entries.append((name,z.read(name)))
assert any(name.endswith('/scripts/install.py') for name,_ in entries)
assert sum(name.endswith('/SKILL.md') for name,_ in entries)==1
assert any(name.endswith('/scripts/cve.py') for name,_ in entries)
assert any(name.endswith('/scripts/source_report.py') for name,_ in entries)
files=dict(entries);prefix=entries[0][0].split('/')[0]
upstream=json.loads(files[prefix+'/docs/UPSTREAM.json'])
for name,digest in upstream['files'].items():assert hashlib.sha256(files[prefix+'/vendor/cloudflare/'+name]).hexdigest()==digest,name
# Preserve the companion's own source manifest and verify every included entry.
for line in files[prefix+'/SHA256SUMS'].decode().splitlines():
 digest,name=line.split('  ',1)
 if name=='.DS_Store':continue
 assert hashlib.sha256(files[prefix+'/'+name]).hexdigest()==digest,name
out=io.BytesIO()
with gzip.GzipFile(fileobj=out,mode='wb',mtime=0) as compressed:
 with tarfile.open(fileobj=compressed,mode='w') as t:
  for name,content in entries:
   info=tarfile.TarInfo(name);info.mode=0o644;info.size=len(content);info.mtime=0;t.addfile(info,io.BytesIO(content))
tar=out.getvalue();(root/'zero-day-canary-skill.zip').write_bytes(source);(root/'zero-day-canary-skill.tar.gz').write_bytes(tar)
(root/'manifest.json').write_text(json.dumps({'source':'Verified companion builder distribution, 2026-10-22','zip_sha256':sha,'sha256':hashlib.sha256(tar).hexdigest(),'zip_bytes':len(source),'bytes':len(tar),'files':len(entries),'upstream_revision':upstream['revision'],'upstream_files_unchanged':True,'skill_count':1,'workflow':'known_cve_targets_only','license':'MIT; third-party notices retained.'},indent=2)+'\n')
print('Pinned complete companion distribution:',len(entries),'files; source manifests verified; one CVE-targeted skill.')
