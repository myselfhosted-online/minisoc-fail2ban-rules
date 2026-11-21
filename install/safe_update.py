#!/usr/bin/env python3
"""Fail-closed MiniSOC/Fail2Ban updater: preflight, merge, backup, rollback.

Requires Python >=3.9, git only for three-way filter merges, and fail2ban-client
for an actual install. --dry-run is non-mutating; tests use isolated fake clients.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass

ROOT = Path(__file__).resolve().parents[1]
FILTERS = ('nginx-skanery.conf', 'nginx-dev-honeypot.conf')
VERSIONS = ('v1.2.1', 'v1.3.0', 'v1.3.1')
RELEASE = 'working-next-release'

class UpdateError(Exception):
    pass

@dataclass
class Change:
    destination: Path
    before: bytes | None
    after: bytes
    reason: str
    logical_name: str


def regular_file(path: Path) -> bytes | None:
    """Do not follow a symlink in a privileged target path."""
    if path.is_symlink():
        raise UpdateError(f'Refusing symlink: {path}')
    if not path.exists():
        return None
    if not path.is_file():
        raise UpdateError(f'Refusing non-regular file: {path}')
    return path.read_bytes()


def no_symlink_parents(path: Path) -> None:
    for parent in [path, *path.parents]:
        if parent.is_symlink():
            raise UpdateError(f'Refusing symlink in destination path: {parent}')


def parse_db(content: bytes, path: Path) -> dict[str, str]:
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise UpdateError(f'Invalid UTF-8 in {path}') from exc
    entries = {}
    for idx, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        parts = line.split('|', 3)
        if len(parts) != 4:
            raise UpdateError(f'Malformed signature {path}:{idx}')
        key, severity, category, pattern = parts
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', key):
            raise UpdateError(f'Invalid signature ID {path}:{idx}')
        if severity not in {'HIGH', 'MEDIUM', 'INFO'} or not category or not pattern:
            raise UpdateError(f'Invalid signature fields {path}:{idx}')
        try:
            re.compile(pattern)
        except re.error as exc:
            raise UpdateError(f'Invalid regex {path}:{idx}: {exc}') from exc
        if key in entries:
            raise UpdateError(f'Duplicate signature ID {key} in {path}')
        entries[key] = line
    return entries


def merge_db(previous: bytes | None, incoming: bytes, destination: Path, source: Path) -> bytes:
    new_entries = parse_db(incoming, source)
    if previous is None:
        return incoming
    old_entries = parse_db(previous, destination)
    collisions = sorted(k for k in old_entries.keys() & new_entries.keys() if old_entries[k] != new_entries[k])
    if collisions:
        raise UpdateError('Signature ID conflicts; no changes made: '+', '.join(collisions))
    additions = [line for key, line in new_entries.items() if key not in old_entries]
    if not additions:
        return previous
    separator = b'' if previous.endswith(b'\n') else b'\n'
    return previous + separator + b'\n# Added by MiniSOC future release\n' + ('\n'.join(additions) + '\n').encode('utf-8')


def filter_merge(current: bytes | None, incoming: bytes, filename: str) -> tuple[bytes, str]:
    if current is None:
        return incoming, 'new filter'
    if current == incoming:
        return current, 'already current'
    known = []
    for version in VERSIONS:
        base = ROOT/'install'/'baselines'/version/filename
        if not base.is_file():
            raise UpdateError(f'Missing bundled baseline {base}')
        if current == base.read_bytes():
            known.append(version)
    if known:
        return incoming, f'update known upstream filter ({known[-1]})'
    # Never attempt to reconcile unknown local files automatically.
    possible = []
    for version in VERSIONS:
        base = (ROOT/'install'/'baselines'/version/filename).read_bytes()
        if filename == 'nginx-skanery.conf':
            fp = (b'/\\.git/(?:config|credentials)' if version == 'v1.2.1' else
                  b'/\\.git/(?:config|credentials|HEAD|index|packed-refs|info/refs)')
            if fp not in current:
                continue
        else:
            if b'/\\.config/aws/credentials' not in current:
                continue
        # Same base may occur in multiple releases; deduplicate.
        if base not in [x[1] for x in possible]:
            possible.append((version, base))
    if not possible or shutil.which('git') is None:
        raise UpdateError(f'Customized {filename}: unknown baseline or git unavailable. Manual review required.')
    outcomes = []
    for version, baseline in possible:
        with tempfile.TemporaryDirectory(prefix='minisoc-merge-') as tmp:
            paths = [Path(tmp)/x for x in ('local', 'base', 'incoming')]
            for p, data in zip(paths, (current, baseline, incoming)):
                p.write_bytes(data)
            proc = subprocess.run(['git','merge-file','-p','--',*[str(p) for p in paths]],
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        if proc.returncode == 0:
            outcomes.append(proc.stdout)
        elif proc.returncode > 1:
            raise UpdateError(f'git merge-file failed ({filename}): {proc.stderr.decode(errors="replace")}')
    if len(set(outcomes)) != 1 or not outcomes:
        raise UpdateError(f'Customized {filename}: ambiguous or conflicting merge. No files changed.')
    result = outcomes[0]
    # A healthy merge must still contain every upstream branch's distinctive indicator.
    if b'/\\.git/(?:config|credentials|HEAD|index|packed-refs|info/refs)' not in result and filename == 'nginx-skanery.conf':
        raise UpdateError(f'Merged filter {filename} lost upstream Git indicators; manual review required.')
    return result, 'non-conflicting three-way merge'


def atomic_write(path: Path, content: bytes, old: bytes | None) -> None:
    no_symlink_parents(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.stat() if old is not None else None
    fd, temp = tempfile.mkstemp(prefix='.minisoc-atomic-', dir=str(path.parent))
    try:
        with os.fdopen(fd,'wb') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, stat.S_IMODE(existing.st_mode) if existing else 0o644)
        if existing and hasattr(os, 'chown'):
            os.chown(temp, existing.st_uid, existing.st_gid)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def f2b(*args: str) -> None:
    try:
        subprocess.run(['fail2ban-client',*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    except (OSError,subprocess.CalledProcessError) as exc:
        raise UpdateError(f'Fail2Ban {" ".join(args)} failed: {exc}') from exc


def targets(f2b_etc: Path, db: Path, nginx_log: str | None, require_minisoc: bool) -> list[Change]:
    changes=[]
    for name in FILTERS:
        destination = f2b_etc/'filter.d'/name
        no_symlink_parents(destination)
        current=regular_file(destination)
        incoming=(ROOT/'fail2ban'/'filter.d'/name).read_bytes()
        content, reason=filter_merge(current,incoming,name)
        override=f2b_etc/'filter.d'/name.replace('.conf','.local')
        if override.exists() or override.is_symlink():
            raise UpdateError(f'Local override {override} detected; review effective rules first')
        if content != current:
            changes.append(Change(destination,current,content,reason,'filter.d/'+name))

    jail=f2b_etc/'jail.d'/'minisoc-fail2ban.local'
    no_symlink_parents(jail)
    old_jail=regular_file(jail)
    if old_jail is None:
        content=(ROOT/'fail2ban'/'jail.d'/'minisoc-fail2ban.local.example').read_bytes()
        if nginx_log is not None:
            if not nginx_log.startswith('/') or '\r' in nginx_log or '\n' in nginx_log:
                raise UpdateError('NGINX_LOG must be an absolute path without newlines')
            content=re.sub(rb'(?m)^logpath = .*$',lambda _:b'logpath = '+nginx_log.encode(),content)
        changes.append(Change(jail,None,content,'new default jail','jail.d/minisoc-fail2ban.local'))
    else:
        print(f'PRESERVED {jail} (jail settings unchanged)')
        if nginx_log:
            print('WARNING: NGINX_LOG ignored: the existing jail was preserved')

    no_symlink_parents(db)
    old_db=regular_file(db)
    if old_db is not None or db.parent.is_dir():
        source=ROOT/'rules'/'signatures-v2.db'
        incoming=source.read_bytes()
        content=merge_db(old_db,incoming,db,source)
        if content != old_db:
            changes.append(Change(db,old_db,content,'add new signature IDs; preserve local rules','minisoc/signatures-v2.db'))
    elif require_minisoc:
        raise UpdateError(f'MiniSOC signature directory missing: {db.parent}')
    else:
        print(f'SKIPPED {db} (MiniSOC directory absent; standalone Fail2Ban installation)')
    return changes


def digest(raw: bytes | None) -> str | None:
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


def backup_changes(changes: list[Change], backup: Path) -> None:
    # Manifest is stored inside a restricted directory, along with path-preserving copies.
    backup.mkdir(mode=0o700)
    records=[]
    for i,item in enumerate(changes):
        record={'path':str(item.destination),'logical_name':item.logical_name,
                'action':'delete' if item.reason.startswith('uninstall') else 'write',
                'was_present':item.before is not None,'sha256_before':digest(item.before),
                'sha256_after':None if item.reason.startswith('uninstall') else digest(item.after)}
        if item.before is not None:
            name=f'{i:02d}.orig'
            target=backup/name
            original_stat=item.destination.stat()
            shutil.copy2(item.destination,target,follow_symlinks=False)
            record['backup_file']=name
            record['mode_before']=stat.S_IMODE(original_stat.st_mode)
            record['uid_before']=original_stat.st_uid
            record['gid_before']=original_stat.st_gid
        records.append(record)
    manifest=backup/'manifest.json'
    manifest.write_text(json.dumps({'schema':1,'release':RELEASE,'changes':records},indent=2)+'\n')
    manifest.chmod(0o600)
    with manifest.open('rb') as f:
        os.fsync(f.fileno())


def restore(changes: list[Change]) -> list[str]:
    errors=[]
    for item in reversed(changes):
        try:
            # Restoration from the captured preflight bytes is independent of backup naming.
            if item.before is None:
                item.destination.unlink(missing_ok=True)
            else:
                atomic_write(item.destination,item.before,item.after)
        except Exception as exc:
            errors.append(f'{item.destination}: {exc}')
    return errors


def run(dry_run: bool=False) -> None:
    if not dry_run and os.geteuid()!=0:
        raise UpdateError('Root privileges required; use sudo or --dry-run')
    base=Path(os.environ.get('F2B_ETC','/etc/fail2ban'))
    db=Path(os.environ.get('MINISOC_SIGNATURES','/etc/minisoc/signatures-v2.db'))
    if not base.is_absolute() or not db.is_absolute():
        raise UpdateError('F2B_ETC and MINISOC_SIGNATURES must be absolute paths')
    changes=targets(base,db,os.environ.get('NGINX_LOG'),os.environ.get('MINISOC_REQUIRED')=='1')
    for item in changes:
        print(f'{"WOULD UPDATE" if dry_run else "PLAN"} {item.destination}: {item.reason}')
    if dry_run:
        print('DRY RUN: no file modifications, reload or lock creation')
        return
    if not shutil.which('fail2ban-client'):
        raise UpdateError('fail2ban-client not found')
    if not changes:
        print('Already up to date; no changes necessary')
        return
    f2b('-t')
    base.mkdir(parents=True,exist_ok=True)
    lock=base/'.minisoc-update.lock'
    no_symlink_parents(lock)
    with lock.open('a+b') as fd:
        fcntl.flock(fd,fcntl.LOCK_EX)
        # Preflight + lock re-check; external editors do not use this lock, so fail closed.
        for item in changes:
            if regular_file(item.destination)!=item.before:
                raise UpdateError(f'File changed during preflight: {item.destination}')
        backup=base/('minisoc-backup-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+f'-{os.getpid()}')
        try:
            backup_changes(changes,backup)
        except Exception as exc:
            raise UpdateError(f'Could not complete backup: {exc}') from exc
        changed=[]
        try:
            for item in changes:
                # Register *before* write so any partial error after replacement is rolled back.
                changed.append(item)
                atomic_write(item.destination,item.after,item.before)
            f2b('-t')
            f2b('reload')
        except BaseException as exc:
            errors=restore(changed)
            try:
                f2b('-t')
                f2b('reload')
            except Exception as reload_exc:
                errors.append(f'Reload of restored configuration failed: {reload_exc}')
            if errors:
                raise UpdateError('UPDATE FAILED; rollback INCOMPLETE: '+'; '.join(errors)+f'. Backup: {backup}') from exc
            raise UpdateError(f'UPDATE FAILED; previous files restored automatically. Backup: {backup}; cause: {exc}') from exc
        print(f'SUCCESS; backup available at {backup}')
        print('NOTICE: MiniSOC application is not restarted. Reload its signature cache separately if necessary.')


def main() -> int:
    parser=argparse.ArgumentParser(description='Safe update of Fail2Ban and MiniSOC rules')
    parser.add_argument('--dry-run',action='store_true',help='preview only, no mutations')
    args=parser.parse_args()
    try:
        run(args.dry_run)
    except (OSError,UpdateError) as exc:
        print('ERROR:',exc,file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':
    raise SystemExit(main())
