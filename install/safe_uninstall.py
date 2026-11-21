#!/usr/bin/env python3
"""Conservative, rollback-capable removal of untouched project-owned Fail2Ban files.

Never removes the MiniSOC signature DB. If a file differs from the packaged
known baselines, refuse to delete it and require manual review.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import shutil
import stat
import sys

# Imported from the installed, audited updater in the same release.
from safe_update import (ROOT,FILTERS,VERSIONS,Change,UpdateError,regular_file,
                         no_symlink_parents,atomic_write,backup_changes,f2b)


def removal_plan(base: Path) -> list[Change]:
    result=[]
    for filename in FILTERS:
        path=base/'filter.d'/filename
        no_symlink_parents(path)
        data=regular_file(path)
        if data is None:
            print(f'NOT INSTALLED {path}')
            continue
        approved={(ROOT/'fail2ban'/'filter.d'/filename).read_bytes()}
        for version in VERSIONS:
            base_file=ROOT/'install'/'baselines'/version/filename
            if not base_file.is_file():
                raise UpdateError(f'Missing baseline {base_file}')
            approved.add(base_file.read_bytes())
        if data not in approved:
            raise UpdateError(f'Customized filter detected: {path}. Refusing to remove any files.')
        overlay=base/'filter.d'/filename.replace('.conf','.local')
        if overlay.exists() or overlay.is_symlink():
            raise UpdateError(f'Local overlay {overlay} detected. Review it before uninstalling.')
        result.append(Change(path,data,b'',f'uninstall filter {filename}',f'filter.d/{filename}'))

    jail=base/'jail.d'/'minisoc-fail2ban.local'
    no_symlink_parents(jail)
    previous=regular_file(jail)
    if previous is not None:
        default=(ROOT/'fail2ban'/'jail.d'/'minisoc-fail2ban.local.example').read_bytes()
        if previous != default:
            raise UpdateError(f'Customized jail {jail} detected. Refusing to remove any files.')
        result.append(Change(jail,previous,b'','uninstall unmodified default jail',
                             'jail.d/minisoc-fail2ban.local'))
    return result


def run(dry_run:bool=False) -> None:
    if not dry_run and os.geteuid()!=0:
        raise UpdateError('Root required: use sudo or --dry-run')
    base=Path(os.environ.get('F2B_ETC','/etc/fail2ban'))
    if not base.is_absolute():
        raise UpdateError('F2B_ETC must be absolute')
    plan=removal_plan(base)
    for item in plan:
        print(f'{"WOULD REMOVE" if dry_run else "REMOVE"} {item.destination}')
    print('PRESERVED MiniSOC signature database (intentionally not uninstalled)')
    if dry_run:
        print('DRY RUN: no changes')
        return
    if not plan:
        print('Nothing to remove')
        return
    if not shutil.which('fail2ban-client'):
        raise UpdateError('fail2ban-client not found')
    f2b('-t')
    lock=base/'.minisoc-update.lock'
    no_symlink_parents(lock)
    with lock.open('a+b') as fd:
        fcntl.flock(fd,fcntl.LOCK_EX)
        for item in plan:
            if regular_file(item.destination)!=item.before:
                raise UpdateError(f'File changed during preflight: {item.destination}')
        backup=base/('minisoc-uninstall-backup-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+f'-{os.getpid()}')
        try:
            backup_changes(plan,backup)
        except Exception as exc:
            raise UpdateError(f'Backup failed, no files removed: {exc}') from exc
        old_stats={item.destination: item.destination.stat() for item in plan}
        removed=[]
        try:
            for item in plan:
                removed.append(item)
                item.destination.unlink()
            f2b('-t')
            f2b('reload')
        except BaseException as exc:
            failures=[]
            for item in reversed(removed):
                try:
                    atomic_write(item.destination,item.before,None)
                    original=old_stats[item.destination]
                    os.chmod(item.destination,stat.S_IMODE(original.st_mode))
                    os.chown(item.destination,original.st_uid,original.st_gid)
                except Exception as error:
                    failures.append(f'{item.destination}: {error}')
            try:
                f2b('-t')
                f2b('reload')
            except Exception as error:
                failures.append(f'Reloading restored rules: {error}')
            if failures:
                raise UpdateError('UNINSTALL FAILED, ROLLBACK INCOMPLETE: '+'; '.join(failures)+f'. Backup: {backup}') from exc
            raise UpdateError(f'UNINSTALL FAILED; previous files restored. Backup: {backup}; cause: {exc}') from exc
        print(f'SUCCESS: project-managed Fail2Ban files removed. Backup: {backup}')


def main()->int:
    arg=argparse.ArgumentParser(description='Safe uninstall (preserves custom configuration)')
    arg.add_argument('--dry-run',action='store_true')
    args=arg.parse_args()
    try:
        run(args.dry_run)
    except (OSError,UpdateError) as exc:
        print(f'ERROR: {exc}',file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':
    raise SystemExit(main())
