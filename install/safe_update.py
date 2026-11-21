#!/usr/bin/env python3
"""Fail-closed MiniSOC/Fail2Ban updater: preflight, merge, backup, rollback.

Requires Python >=3.10, git only for three-way filter merges, and fail2ban-client
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
VERSIONS = ('v1.2.1', 'v1.3.0', 'v1.3.1', 'v1.3.2', 'v1.3.3')
RELEASE = 'v1.3.5'
RUNTIME_SEVERITIES = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}

class UpdateError(Exception):
    pass

class SignatureParseError(UpdateError):
    """Existing signature database cannot be parsed without risking data loss."""
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


def parse_db(content: bytes, path: Path, *, validate_regex: bool=True) -> dict[str, str]:
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise SignatureParseError(f'Invalid UTF-8 in {path}') from exc
    entries = {}
    for idx, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        parts = line.split('|', 3)
        if len(parts) != 4:
            raise SignatureParseError(f'Malformed signature {path}:{idx}')
        key, severity, category, pattern = parts
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', key):
            raise SignatureParseError(f'Invalid signature ID {path}:{idx}')
        # The production MiniSOC correlator accepts these four levels, not INFO.
        if severity not in RUNTIME_SEVERITIES or not category or not pattern:
            raise SignatureParseError(f'Invalid signature fields {path}:{idx}')
        if validate_regex:
            try:
                re.compile(pattern, re.I)
            except re.error as exc:
                raise SignatureParseError(f'Invalid regex {path}:{idx}: {exc}') from exc
        if key in entries:
            raise SignatureParseError(f'Duplicate signature ID {key} in {path}')
        entries[key] = line
    return entries


def parse_runtime_db(content: bytes, path: Path, *, public_ids: set[str] | None = None,
                     public_categories: set[str] | None = None) -> set[str]:
    """Read the actual MiniSOC correlator format: kind|severity|regex.

    A regex can contain arbitrary literal `|` alternations. Unlike the public
    source DB, the installed format has no unique ID: repeating `secret` or
    `repository` simply indicates multiple patterns of the same kind.
    All existing bytes are preserved by merge_db, including comments and any
    legacy regex the correlator itself would ignore as invalid.
    """
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise SignatureParseError(f'Invalid UTF-8 in {path}') from exc
    if re.search(r'(?im)^\s*#\s*Format:\s*id\|severity\|category\|regex\s*$', text):
        raise SignatureParseError(f'{path} contains public four-column signature format; '
                                  'do not append legacy rows without reviewing the consumer')
    patterns = set()
    for idx, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        # An accidentally installed public DB may lack its format header.
        # Distinguish known public IDs from repeatable runtime categories
        # before the three-column split swallows the fourth field as regex.
        public_parts = line.strip().split('|', 3)
        if (len(public_parts) == 4 and public_ids and public_categories
                and public_parts[0] in public_ids
                and public_parts[2] in public_categories):
            raise SignatureParseError(f'{path}:{idx} looks like public four-column signature '
                                      'format; manual review required')
        parts = line.strip().split('|', 2)
        if len(parts) != 3:
            raise SignatureParseError(f'Malformed MiniSOC runtime signature {path}:{idx}')
        kind, severity, pattern = (part.strip() for part in parts)
        if not kind or not pattern or severity.upper() not in RUNTIME_SEVERITIES:
            raise SignatureParseError(f'Invalid MiniSOC runtime signature fields {path}:{idx}')
        try:
            re.compile(pattern, re.I)
        except re.error as exc:
            print(f'WARNING EXISTING REGEX {path}:{idx}: ignored by the production '
                  f'MiniSOC correlator ({exc}); original signature retained unchanged')
        patterns.add(pattern)
    return patterns


def bundled_runtime_rows(incoming: bytes, source: Path) -> list[tuple[str, str]]:
    """Convert public id|severity|category|regex rows to runtime rows.

    The ID is metadata of the public rules repository, NOT a runtime column.
    """
    new_entries = parse_db(incoming, source)
    rows = []
    for line in new_entries.values():
        _key, severity, kind, pattern = line.split('|', 3)
        # Avoid line injection or a malformed runtime record from upstream.
        if '|' in kind or '\n' in kind or not kind.strip():
            raise SignatureParseError(f'Invalid runtime category in {source}')
        rows.append((pattern.strip(), f'{kind.strip()}|{severity}|{pattern.strip()}'))
    return rows


def merge_db(previous: bytes | None, incoming: bytes, destination: Path, source: Path) -> bytes:
    rows = bundled_runtime_rows(incoming, source)
    upstream = parse_db(incoming, source)
    upstream_categories = {line.split('|', 3)[2] for line in upstream.values()}
    original = previous or b''
    # The real /opt/minisoc/bin/minisoc-correlator.py loader uses
    # kind,sev,pat = raw.split('|', 2), then re.compile(pat, re.I).
    # Do NOT write public four-column rows into that three-column database.
    existing = parse_runtime_db(original, destination,
                                public_ids=set(upstream), public_categories=upstream_categories)
    additions = []
    skipped = 0
    for pattern, row in rows:
        if pattern in existing:
            skipped += 1
            continue
        additions.append(row)
        existing.add(pattern)
    if skipped and additions:
        print(f'WARNING SKIPPED {skipped} existing signature pattern(s); '
              'local category/severity/regex definitions take precedence')
    if not additions:
        return original
    # Preserve the existing bytes and use its newline convention for additions.
    newline = b'\r\n' if b'\r\n' in original and original.count(b'\n') == original.count(b'\r\n') else b'\n'
    separator = b'' if not original or original.endswith(b'\n') else newline
    prefix = '\n' if original else ''
    suffix = (f'{prefix}# Added by MiniSOC {RELEASE} (runtime kind|severity|regex)\n'
              + '\n'.join(additions) + '\n').encode('utf-8')
    return original + separator + suffix.replace(b'\n', newline)


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
    # The v1.3.2 updater relied on one literal .git regex spelling as a
    # fingerprint. Local filters using equivalent syntax were never considered
    # for merging. Try every authentic bundled baseline instead; never guess
    # which arbitrary local regex should be replaced.
    if shutil.which('git') is None:
        return current, 'preserved customized filter (git unavailable for three-way merge)'

    possible = []
    seen = set()
    for version in VERSIONS:
        base = (ROOT/'install'/'baselines'/version/filename).read_bytes()
        if base not in seen:
            possible.append((version, base))
            seen.add(base)

    # For an automatic upgrade, the new upstream failregex must survive
    # verbatim. A conflict-free merge alone does not prove that an unrelated
    # locally maintained filter is compatible with this project's rules.
    upstream_regexes = [line for line in incoming.splitlines() if line.startswith(b'failregex =')]
    if len(upstream_regexes) != 1:
        raise UpdateError(f'Invalid upstream failregex in {filename}')
    outcomes = []
    for version, baseline in possible:
        with tempfile.TemporaryDirectory(prefix='minisoc-merge-') as tmp:
            paths = [Path(tmp)/x for x in ('local', 'base', 'incoming')]
            for p, data in zip(paths, (current, baseline, incoming)):
                p.write_bytes(data)
            proc = subprocess.run(['git','merge-file','-p','--',*[str(p) for p in paths]],
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        if proc.returncode == 0 and upstream_regexes[0] in proc.stdout:
            outcomes.append(proc.stdout)
        elif proc.returncode > 1:
            raise UpdateError(f'git merge-file failed ({filename}): {proc.stderr.decode(errors="replace")}')
    if len(set(outcomes)) != 1 or not outcomes:
        return current, 'preserved customized filter (unknown baseline or conflicting merge)'
    result = outcomes[0]
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


def preexisting_jails(f2b_etc: Path, managed_file: Path) -> list[Path]:
    """Avoid introducing a second jail definition over a local one.

    Fail2Ban can merge sections from multiple jail files. Creating the bundled
    maxretry=1 defaults in that situation could silently change live policy.
    """
    candidates = [f2b_etc/'jail.conf', f2b_etc/'jail.local']
    for ext in ('*.conf', '*.local'):
        candidates.extend((f2b_etc/'jail.d').glob(ext))
    matches=[]
    target = re.compile(rb'(?m)^\s*\[\s*(?:nginx-skanery|nginx-dev-honeypot)\s*\]')
    for file in sorted(set(candidates)):
        if file == managed_file or not (file.exists() or file.is_symlink()):
            continue
        if file.is_symlink() or not file.is_file():
            matches.append(file)  # An unknown jail source must not be overwritten.
            continue
        try:
            content=file.read_bytes()
        except OSError:
            matches.append(file)
            continue
        if target.search(content):
            matches.append(file)
    return matches


def targets(f2b_etc: Path, db: Path, nginx_log: str | None, require_minisoc: bool) -> tuple[list[Change], list[Path], list[Path]]:
    changes=[]
    preserved=[]
    preserved_databases=[]
    for name in FILTERS:
        destination = f2b_etc/'filter.d'/name
        no_symlink_parents(destination)
        current=regular_file(destination)
        incoming=(ROOT/'fail2ban'/'filter.d'/name).read_bytes()
        content, reason=filter_merge(current,incoming,name)
        override=f2b_etc/'filter.d'/name.replace('.conf','.local')
        if override.exists() or override.is_symlink():
            raise UpdateError(f'Local override {override} detected; review effective rules first')
        if reason.startswith('preserved customized filter'):
            preserved.append(destination)
            print(f'WARNING PRESERVED {destination}: {reason}; bundled {RELEASE} filter rules NOT activated')
        if content != current:
            changes.append(Change(destination,current,content,reason,'filter.d/'+name))

    jail=f2b_etc/'jail.d'/'minisoc-fail2ban.local'
    no_symlink_parents(jail)
    old_jail=regular_file(jail)
    if old_jail is None:
        other_jails=preexisting_jails(f2b_etc,jail)
        if other_jails:
            print('WARNING SKIPPED new default jail: existing custom jail source(s) found: '
                  + ', '.join(str(p) for p in other_jails) +
                  '; preserving existing effective jail settings')
        else:
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
        # Validate shipped patterns even when a legacy local DB has syntax the
        # Python regex engine cannot compile; existing signatures are never rewritten.
        parse_db(incoming,source)
        try:
            content=merge_db(old_db,incoming,db,source)
        except SignatureParseError as exc:
            if old_db is None:
                raise
            preserved_databases.append(db)
            print(f'WARNING PRESERVED {db}: invalid local signature database structure ({exc}); '
                  f'bundled {RELEASE} signatures NOT activated')
        else:
            if content != old_db:
                changes.append(Change(db,old_db,content,'append missing runtime signature patterns; preserve local rules','minisoc/signatures-v2.db'))
    elif require_minisoc:
        raise UpdateError(f'MiniSOC signature directory missing: {db.parent}')
    else:
        print(f'SKIPPED {db} (MiniSOC directory absent; standalone Fail2Ban installation)')
    return changes,preserved,preserved_databases


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


def run(dry_run: bool=False, preserve_custom_filters: bool=False,
        preserve_custom_signatures: bool=False) -> None:
    if not dry_run and os.geteuid()!=0:
        raise UpdateError('Root privileges required; use sudo or --dry-run')
    base=Path(os.environ.get('F2B_ETC','/etc/fail2ban'))
    db=Path(os.environ.get('MINISOC_SIGNATURES','/etc/minisoc/signatures-v2.db'))
    if not base.is_absolute() or not db.is_absolute():
        raise UpdateError('F2B_ETC and MINISOC_SIGNATURES must be absolute paths')
    changes,preserved,preserved_databases=targets(base,db,os.environ.get('NGINX_LOG'),
                                                 os.environ.get('MINISOC_REQUIRED')=='1')
    for item in changes:
        print(f'{"WOULD UPDATE" if dry_run else "PLAN"} {item.destination}: {item.reason}')
    if dry_run:
        if preserved and not preserve_custom_filters:
            print('REQUIRES REVIEW: a real installation will stop unless --preserve-custom-filters is specified')
        if preserved_databases and not preserve_custom_signatures:
            print('REQUIRES REVIEW: a real installation will stop unless --preserve-custom-signatures is specified')
        print('DRY RUN: no file modifications, reload or lock creation')
        return
    if preserved and not preserve_custom_filters:
        raise UpdateError('Customized filters require manual review; no files changed. '
                          'To update other managed files while keeping these filters unchanged, '
                          'rerun with --preserve-custom-filters.')
    if preserved_databases and not preserve_custom_signatures:
        raise UpdateError('Incompatible local MiniSOC signature database requires manual review; no files changed. '
                          'To update other managed files while leaving the database untouched, '
                          'rerun with --preserve-custom-signatures.')
    if not changes:
        if preserved or preserved_databases:
            print('PARTIAL: no managed changes; incompatible filters/databases remain unchanged and unupgraded')
        else:
            print('Already up to date; no changes necessary')
        return
    # MiniSOC's runtime database is consumed by its correlator, not by
    # Fail2Ban. Never reload live jails for a database-only update.
    reload_fail2ban = any(item.logical_name.startswith(('filter.d/', 'jail.d/'))
                          for item in changes)
    if reload_fail2ban:
        if not shutil.which('fail2ban-client'):
            raise UpdateError('fail2ban-client not found')
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
            if reload_fail2ban:
                f2b('-t')
                f2b('reload')
        except BaseException as exc:
            errors=restore(changed)
            if reload_fail2ban:
                try:
                    f2b('-t')
                    f2b('reload')
                except Exception as reload_exc:
                    errors.append(f'Reload of restored configuration failed: {reload_exc}')
            if errors:
                raise UpdateError('UPDATE FAILED; rollback INCOMPLETE: '+'; '.join(errors)+f'. Backup: {backup}') from exc
            raise UpdateError(f'UPDATE FAILED; previous files restored automatically. Backup: {backup}; cause: {exc}') from exc
        print(f'SUCCESS; backup available at {backup}')
        if not reload_fail2ban:
            print('NOTICE: Fail2Ban configuration unchanged; no Fail2Ban reload performed')
        if preserved:
            print('PARTIAL UPDATE: customized filters were preserved; bundled filter rules NOT activated for them')
        if preserved_databases:
            print('PARTIAL UPDATE: incompatible local signature database was preserved; '
                  'bundled signatures NOT activated for it')
        print('NOTICE: MiniSOC application is not restarted. Reload its signature cache separately if necessary.')


def main() -> int:
    parser=argparse.ArgumentParser(description='Safe update of Fail2Ban and MiniSOC rules')
    parser.add_argument('--dry-run',action='store_true',help='preview only, no mutations')
    parser.add_argument('--preserve-custom-filters',action='store_true',
                        help='explicitly allow a partial update while leaving unknown custom filters unchanged')
    parser.add_argument('--preserve-custom-signatures',action='store_true',
                        help='explicitly leave incompatible local MiniSOC signature databases untouched')
    args=parser.parse_args()
    try:
        run(args.dry_run,args.preserve_custom_filters,args.preserve_custom_signatures)
    except (OSError,UpdateError) as exc:
        print('ERROR:',exc,file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':
    raise SystemExit(main())
