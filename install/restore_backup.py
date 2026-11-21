#!/usr/bin/env python3
"""Manual rollback of a verified MiniSOC install/uninstall backup.

Always checks original SHA256, destination whitelist and post-update hashes.
Refuses changed files: manually review instead of accidentally losing data.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from safe_update import UpdateError,atomic_write,f2b,no_symlink_parents,regular_file


def sha(raw):
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


def restore_backup(folder:Path,dry_run:bool=False):
    if not dry_run and os.geteuid()!=0:
        raise UpdateError('Root required for restore; use sudo or --dry-run')
    base=Path(os.environ.get('F2B_ETC','/etc/fail2ban'))
    db=Path(os.environ.get('MINISOC_SIGNATURES','/etc/minisoc/signatures-v2.db'))
    if not base.is_absolute() or not db.is_absolute():
        raise UpdateError('Target directories must be absolute')
    folder=folder.absolute()
    if folder.parent != base or not folder.name.startswith(('minisoc-backup-','minisoc-uninstall-backup-')):
        raise UpdateError('Backup must be a direct known MiniSOC backup under F2B_ETC')
    no_symlink_parents(folder)
    manifest=folder/'manifest.json'
    if manifest.is_symlink() or not manifest.is_file():
        raise UpdateError('Missing or unsafe manifest')
    data=json.loads(manifest.read_text(encoding='utf-8'))
    if data.get('schema')!=1 or not isinstance(data.get('changes'),list):
        raise UpdateError('Unsupported backup schema')
    allowed={base/'filter.d'/'nginx-skanery.conf',base/'filter.d'/'nginx-dev-honeypot.conf',
             base/'jail.d'/'minisoc-fail2ban.local',db}
    plan=[]
    used=set()
    for row in data['changes']:
        path=Path(row['path'])
        if path not in allowed or path in used:
            raise UpdateError(f'Unexpected or duplicate target in manifest: {path}')
        used.add(path)
        no_symlink_parents(path)
        current=regular_file(path)
        if sha(current)!=row.get('sha256_after'):
            raise UpdateError(f'Target changed since backup: {path}. No files restored.')
        if row.get('was_present'):
            name=row.get('backup_file','')
            if not re.fullmatch(r'\d{2}\.orig',name):
                raise UpdateError(f'Unsafe backup filename: {name}')
            original=regular_file(folder/name)
            if original is None or sha(original)!=row.get('sha256_before'):
                raise UpdateError(f'Corrupt or missing backup for {path}')
        else:
            original=None
        plan.append((path,current,original,row))
    for path,current,old,row in plan:
        print(('WOULD RESTORE' if dry_run else 'RESTORE'),path,'->',('remove' if old is None else 'previous bytes'))
    if dry_run:
        print('DRY RUN: no files or services changed')
        return
    f2b('-t')
    lock=base/'.minisoc-update.lock'
    no_symlink_parents(lock)
    with lock.open('a+b') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX)
        for path,current,old,row in plan:
            if regular_file(path)!=current:
                raise UpdateError(f'Target changed during restore preflight: {path}')
        changed=[]
        try:
            for path,current,old,row in plan:
                changed.append((path,current))
                if old is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path,old,current)
                    if 'mode_before' in row:
                        os.chmod(path,int(row['mode_before']))
                    if 'uid_before' in row and 'gid_before' in row:
                        os.chown(path,int(row['uid_before']),int(row['gid_before']))
            f2b('-t')
            f2b('reload')
        except BaseException as exc:
            errors=[]
            for path,current in reversed(changed):
                try:
                    if current is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write(path,current,regular_file(path))
                except Exception as rollback_exc:
                    errors.append(str(rollback_exc))
            try:
                f2b('-t'); f2b('reload')
            except Exception as reload_exc:
                errors.append(str(reload_exc))
            raise UpdateError('Restore failed, latest state '+('not fully restored: '+str(errors) if errors else 'restored')+f'. Details: {exc}') from exc
        print('SUCCESS: restored verified backup. MiniSOC application not restarted.')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('backup_dir',type=Path)
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args()
    try:
        restore_backup(args.backup_dir,args.dry_run)
    except (OSError,ValueError,KeyError,UpdateError) as exc:
        print('ERROR:',exc,file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':
    raise SystemExit(main())
