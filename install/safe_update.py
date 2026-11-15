#!/usr/bin/env python3
"""Conservative, transactional update of MiniSOC Fail2Ban filters and signature DB.

Default behavior preserves unknown/customized files and aborts on ambiguous merges.
No MiniSOC service restart is attempted; applications may cache the signature DB.
"""

from __future__ import annotations

import argparse
import fcntl
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

ROOT = Path(__file__).resolve().parent.parent
FILTERS = ("nginx-skanery.conf", "nginx-dev-honeypot.conf")
PREVIOUS_VERSIONS = ("v1.2.1", "v1.3.0")

class UpdateError(Exception):
    pass

@dataclass
class Change:
    path: Path
    content: bytes
    description: str
    expected: bytes | None


def read_regular(path: Path) -> bytes | None:
    if path.is_symlink():
        raise UpdateError(f"Refusing to modify symlink: {path}")
    if not path.exists():
        return None
    if not path.is_file():
        raise UpdateError(f"Refusing non-regular path: {path}")
    return path.read_bytes()


def parse_signatures(raw: bytes, source: Path) -> dict[str, str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise UpdateError(f"Signature database is not UTF-8: {source}") from exc
    found: dict[str, str] = {}
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("|", 3)
        if len(parts) != 4 or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", parts[0]):
            raise UpdateError(f"Invalid signature at {source}:{number}")
        ident, severity, category, regex = parts
        if severity not in {"HIGH", "MEDIUM", "INFO"} or not category or not regex:
            raise UpdateError(f"Invalid signature fields at {source}:{number}")
        try:
            re.compile(regex)
        except re.error as exc:
            raise UpdateError(f"Invalid signature regex at {source}:{number}: {exc}") from exc
        if ident in found:
            raise UpdateError(f"Duplicate signature ID {ident} in {source}")
        found[ident] = line
    return found


def merge_signatures(old: bytes | None, new: bytes, old_path: Path, incoming_path: Path) -> bytes:
    incoming = parse_signatures(new, incoming_path)
    if old is None:
        return new
    installed = parse_signatures(old, old_path)
    conflicting = sorted(k for k in installed.keys() & incoming.keys() if installed[k] != incoming[k])
    if conflicting:
        raise UpdateError("MiniSOC signature ID conflicts: " + ", ".join(conflicting) + ". Existing file left untouched.")
    added = [line for key, line in incoming.items() if key not in installed]
    if not added:
        return old
    suffix = b"" if old.endswith(b"\n") else b"\n"
    return old + suffix + b"\n# Added from MiniSOC Fail2Ban Rules v1.3.1\n" + ("\n".join(added) + "\n").encode("utf-8")


def merge_filter(current: bytes | None, new: bytes, filename: str) -> tuple[bytes, str]:
    if current is None:
        return new, "new filter"
    if current == new:
        return current, "already current"
    exact_baselines: list[str] = []
    for version in PREVIOUS_VERSIONS:
        path = ROOT / "install" / "baselines" / version / filename
        if not path.is_file():
            raise UpdateError(f"Missing bundled baseline: {path}")
        if current == path.read_bytes():
            exact_baselines.append(version)
    if exact_baselines:
        return new, "known upstream filter " + exact_baselines[-1]

    # A three-way merge is attempted only with explicitly supported baselines.
    # Ambiguous or conflicting merges always fail closed; never discard custom rules.
    if shutil.which("git") is None:
        raise UpdateError(f"Customized filter {filename}: git is required for safe three-way merge. No files changed.")
    # Pick the baseline only when the installed filter still contains its unique
    # upstream fingerprint. Trying every baseline can silently remove a newer rule.
    if filename == "nginx-skanery.conf":
        if b"/\\.git/(?:config|credentials|HEAD|index|packed-refs|info/refs)" in current:
            versions = ("v1.3.0",)
        elif b"/\\.git/(?:config|credentials)" in current:
            versions = ("v1.2.1",)
        else:
            raise UpdateError("Unknown customized nginx-skanery filter baseline; manual review required. No files changed.")
    else:
        # Identical upstream baseline in v1.2.1 and v1.3.0.
        versions = ("v1.3.0",)
    options: list[bytes] = []
    for version in versions:
        path = ROOT / "install" / "baselines" / version / filename
        with tempfile.TemporaryDirectory(prefix="minisoc-merge-") as temp:
            directory = Path(temp)
            local = directory / "local"
            target = directory / "target"
            local.write_bytes(current)
            target.write_bytes(new)
            merged = subprocess.run(
                ["git", "merge-file", "-p", "--", str(local), str(path), str(target)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        if merged.returncode == 0:
            options.append(merged.stdout)
        elif merged.returncode > 1:
            raise UpdateError(f"Three-way merge error for {filename}: {merged.stderr.decode(errors='replace').strip()}")
    unique = list(dict.fromkeys(options))
    if len(unique) != 1:
        raise UpdateError(
            f"Customized filter {filename} has merge conflicts or ambiguous baselines. "
            "Original kept untouched; merge changes manually before retrying."
        )
    return unique[0], "three-way merge of custom filter"


def atomic_write(path: Path, content: bytes, old_exists: bool) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    previous_stat = path.stat() if old_exists else None
    mode = stat.S_IMODE(previous_stat.st_mode) if previous_stat else 0o644
    fd, name = tempfile.mkstemp(prefix=".minisoc-update-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, mode)
        if previous_stat:
            os.chown(name, previous_stat.st_uid, previous_stat.st_gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def invoke_fail2ban(*args: str) -> None:
    try:
        subprocess.run(["fail2ban-client", *args], check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise UpdateError(f"fail2ban-client {' '.join(args)} failed: {exc}") from exc


def run(dry_run: bool = False) -> None:
    if not dry_run and os.geteuid() != 0:
        raise UpdateError("Run as root with sudo, or use --dry-run to inspect changes")
    f2b = Path(os.environ.get("F2B_ETC", "/etc/fail2ban"))
    mini_db = Path(os.environ.get("MINISOC_SIGNATURES", "/etc/minisoc/signatures-v2.db"))
    nginx_log = os.environ.get("NGINX_LOG")
    if not f2b.is_absolute() or not mini_db.is_absolute():
        raise UpdateError("F2B_ETC and MINISOC_SIGNATURES must be absolute paths")
    if nginx_log is not None and ("\n" in nginx_log or "\r" in nginx_log):
        raise UpdateError("NGINX_LOG must not contain newline characters")

    incoming_db = ROOT / "rules" / "signatures-v2.db"
    if not incoming_db.is_file():
        raise UpdateError(f"Packaged signature database missing: {incoming_db}")
    planned: list[Change] = []
    for filename in FILTERS:
        dest = f2b / "filter.d" / filename
        current = read_regular(dest)
        incoming = (ROOT / "fail2ban" / "filter.d" / filename).read_bytes()
        output, description = merge_filter(current, incoming, filename)
        if output != current:
            planned.append(Change(dest, output, description, current))
        else:
            print(f"UNCHANGED {dest}")
        local_overlay = f2b / "filter.d" / filename.replace(".conf", ".local")
        if local_overlay.exists() or local_overlay.is_symlink():
            # A .local override can mask these .conf updates. Require explicit review.
            raise UpdateError(f"Local Fail2Ban override {local_overlay} detected. Review effective rules first; nothing changed.")

    jail = f2b / "jail.d" / "minisoc-fail2ban.local"
    if read_regular(jail) is None:
        content = (ROOT / "fail2ban" / "jail.d" / "minisoc-fail2ban.local.example").read_bytes()
        if nginx_log is not None:
            if not nginx_log.startswith("/"):
                raise UpdateError("NGINX_LOG must be an absolute path")
            content = re.sub(rb"(?m)^logpath = .*", lambda _: b"logpath = " + nginx_log.encode(), content)
        planned.append(Change(jail, content, "new default jail (no previous jail found)", None))
    else:
        print(f"PRESERVED {jail} (custom jail settings)")
        if nginx_log is not None:
            print("WARNING: NGINX_LOG ignored because jail configuration already exists")

    current_db = read_regular(mini_db)
    if current_db is not None or mini_db.parent.is_dir():
        incoming = incoming_db.read_bytes()
        output = merge_signatures(current_db, incoming, mini_db, incoming_db)
        if output != current_db:
            planned.append(Change(mini_db, output, "merge signature IDs; retain custom signatures", current_db))
        else:
            print(f"UNCHANGED {mini_db}")
    else:
        if os.environ.get("MINISOC_REQUIRED") == "1":
            raise UpdateError(f"MiniSOC signature directory missing: {mini_db.parent}")
        print(f"SKIPPED {mini_db} (MiniSOC directory missing; rule-only install)")

    for change in planned:
        print(f"{'WOULD UPDATE' if dry_run else 'UPDATE'} {change.path}: {change.description}")
    if dry_run:
        print("DRY RUN: no files changed; no services reloaded")
        return
    if not shutil.which("fail2ban-client"):
        raise UpdateError("fail2ban-client command not found")
    if not planned:
        print("Already up to date; no reload needed")
        return

    # Fail before touching files if the running installation is already invalid.
    invoke_fail2ban("-t")
    f2b.mkdir(parents=True, exist_ok=True)
    lock = f2b / ".minisoc-update.lock"
    with lock.open("a+b") as lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        backup = f2b / ("minisoc-backup-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}")
        backup.mkdir(mode=0o700)
        old_data: dict[Path, bytes | None] = {}
        modified: list[Path] = []
        try:
            # Concurrent changes since preflight are treated as a conflict.
            for change in planned:
                if read_regular(change.path) != change.expected:
                    raise UpdateError(f"File changed since preflight: {change.path}")
            for i, change in enumerate(planned):
                old = read_regular(change.path)
                old_data[change.path] = old
                if old is not None:
                    backup_file = backup / (f"{i:02d}-" + change.path.name)
                    shutil.copy2(change.path, backup_file)
                atomic_write(change.path, change.content, old_exists=old is not None)
                modified.append(change.path)
            invoke_fail2ban("-t")
            invoke_fail2ban("reload")
        except BaseException as exc:
            print(f"UPDATE FAILED: {exc}", file=sys.stderr)
            errors = []
            for path in reversed(modified):
                try:
                    old = old_data[path]
                    if old is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write(path, old, old_exists=True)
                except Exception as rollback_exc:
                    errors.append(f"{path}: {rollback_exc}")
            try:
                invoke_fail2ban("reload")
            except Exception as rollback_exc:
                errors.append(f"Fail2Ban reload of restored rules: {rollback_exc}")
            if errors:
                raise UpdateError("Rollback incomplete: " + "; ".join(errors)) from exc
            raise UpdateError(f"Configuration restored automatically. Backup: {backup}") from exc
        print(f"SUCCESS: update applied. Backup: {backup}")
        print("NOTE: MiniSOC application may need its own signature-cache reload; no MiniSOC service was restarted.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely update Fail2Ban filters and MiniSOC signatures")
    parser.add_argument("--dry-run", action="store_true", help="show planned changes without writing or reloading")
    options = parser.parse_args()
    try:
        run(options.dry_run)
    except (UpdateError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
