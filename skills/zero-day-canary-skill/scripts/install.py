#!/usr/bin/env python3
"""Install the single CVE-targeted Canary skill into one project. No checks/network."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parents[1]


def install(project):
    project = Path(project).resolve(strict=True)
    if project == HERE or HERE in project.parents:
        raise ValueError('Install into a consumer project outside the packaged source.')
    if not project.is_dir():
        raise ValueError('Project must be an existing directory.')
    manifest = json.loads((HERE / 'docs/UPSTREAM.json').read_text())
    for name, sha in manifest['files'].items():
        if hashlib.sha256((HERE / 'vendor/cloudflare' / name).read_bytes()).hexdigest() != sha:
            raise ValueError('Bundled upstream integrity check failed.')
    # Walk project-local installation parents no-follow; refuse existing skill names.
    fd = os.open(project, os.O_RDONLY | os.O_DIRECTORY)
    created = []
    try:
        for part in ('.agents', 'skills'):
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        for name in ('zero-day-canary-skill',):
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise FileExistsError('An installation already exists; nothing was overwritten.')
        # Exclusive directory creation reserves names before copying trusted packaged resources.
        for name in ('zero-day-canary-skill',):
            os.mkdir(name, 0o700, dir_fd=fd)
            created.append(name)
        base = project / '.agents/skills'
        def copy_files(source, destination_fd, include_license=False):
            total = 0
            for file in sorted(source.rglob('*')):
                relative = file.relative_to(source)
                if any(part in ('dist', '__pycache__', '.venv', '.git') for part in relative.parts) or file.suffix == '.pyc' or file.name == '.DS_Store':
                    continue
                if file.is_symlink():
                    raise ValueError('Symlink in packaged source.')
                if not file.is_file():
                    continue
                data = file.read_bytes()
                total += len(data)
                if len(data) > 5 * 1024 * 1024 or total > 10 * 1024 * 1024:
                    raise ValueError('Installation payload exceeds bounds.')
                copy_one(destination_fd, relative.parts, data)
            if include_license:
                copy_one(destination_fd, ('LICENSE',), (HERE / 'vendor/cloudflare/LICENSE').read_bytes())
        def copy_one(destination_fd, parts, data):
            current = os.dup(destination_fd)
            try:
                for part in parts[:-1]:
                    try: os.mkdir(part, 0o700, dir_fd=current)
                    except FileExistsError: pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    os.close(current); current = child
                leaf = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=current)
                with os.fdopen(leaf, 'wb') as stream: stream.write(data)
            finally:
                os.close(current)
        for name, source in [('zero-day-canary-skill', HERE)]:
            destination = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try: copy_files(source, destination, include_license=False)
            finally: os.close(destination)
        return {'installed': [str(base / name) for name in created], 'upstream_revision': manifest['revision'],
                'audit_started': False, 'network_used': False, 'checks_started': False,
                'next': 'Ask $zero-day-canary-skill to check this project against CVE/GHSA targets from the Canary API. One skill is installed; no general audit is invoked.'}
    except BaseException:
        # Remove only still-empty reserved directories. Retain partial files for review;
        # never recursively delete through project-controlled directory paths.
        for name in reversed(created):
            try: os.rmdir(name, dir_fd=fd)
            except OSError: pass
        raise
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(install(args.project), indent=2))
    except (OSError, ValueError):
        print('ERROR: Installation failed; check project permissions, existing installations, symlinks and bundled integrity. No audit or network operation was started.', file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
