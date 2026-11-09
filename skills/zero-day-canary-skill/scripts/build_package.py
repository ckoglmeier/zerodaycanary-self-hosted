#!/usr/bin/env python3
"""Build the local companion ZIP and content checksums. No audit, install or network."""
import hashlib
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def build():
    files=[]
    for path in sorted(ROOT.rglob('*')):
        relative=path.relative_to(ROOT)
        if any(p in ('dist','__pycache__','.venv','.git') for p in relative.parts) or path.name in ('SHA256SUMS','.DS_Store') or path.suffix=='.pyc':
            continue
        if path.is_symlink():
            raise ValueError('Symlink in package source.')
        if path.is_file(): files.append(path)
    manifest=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(ROOT).as_posix()+'\n' for p in files)
    (ROOT/'SHA256SUMS').write_text(manifest)
    files.append(ROOT/'SHA256SUMS')
    (ROOT/'dist').mkdir(exist_ok=True)
    archive=ROOT/'dist/zero-day-canary-skill.zip'
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as output:
        for path in sorted(files):
            info=zipfile.ZipInfo('zero-day-canary-skill/'+path.relative_to(ROOT).as_posix(),(2026,10,22,12,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100644<<16
            output.writestr(info,path.read_bytes())
    sha=hashlib.sha256(archive.read_bytes()).hexdigest()
    (ROOT/'dist/zero-day-canary-skill.zip.sha256').write_text(sha+'  zero-day-canary-skill.zip\n')
    print('Packaged '+str(len(files))+' files; SHA256 '+sha)

if __name__=='__main__': build()
