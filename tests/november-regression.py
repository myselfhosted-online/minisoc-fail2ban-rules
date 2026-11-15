#!/usr/bin/env python3
"""Validate active signatures and review-only candidates independently of production MiniSOC."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
entries = []
for line in (root / "rules/signatures-v2.db").read_text().splitlines():
    if not line.strip() or line.startswith("#"):
        continue
    fields = line.split("|", 3)
    assert len(fields) == 4, line
    ident, severity, category, pattern = fields
    assert severity in ("HIGH", "MEDIUM", "INFO"), ident
    entries.append((ident, severity, category, re.compile(pattern)))
assert len({entry[0] for entry in entries}) == len(entries)

def matched(path):
    return {ident: (severity, category) for ident, severity, category, regex in entries if regex.search(path)}

positive = {
    "/.kube/config": "kube-config",
    "/.git/config": "git-config",
    "/.git/HEAD": "git-head",
    "/.git/index": "git-index",
    "/.git/packed-refs": "git-packed-refs",
    "/.git/info/refs": "git-info-refs",
    "/.env.1": "dotenv-numbered-backup",
    "/.env.2": "dotenv-numbered-backup",
    "/env.bak": "env-backup",
    "/env.old": "env-backup",
    "/wp-content/plugins/hellopress/wp_filemanager.php": "hellopress-filemanager",
}
for path, expected in positive.items():
    assert expected in matched(path), (path, expected)
assert matched("/wp-content/plugins/hellopress/wp_filemanager.php")["hellopress-filemanager"] == ("HIGH", "wordpress-webshell")

benign = ["/favicon.ico", "/robots.txt", "/wp-json/", "/.gitignore", "/.git/HEADERS", "/.kube/configure", "/env.oldstuff"]
for path in benign:
    assert not any(severity == "HIGH" for severity, _ in matched(path).values()), path

candidates = []
for line in (root / "rules/candidates.list").read_text().splitlines():
    if not line.strip() or line.startswith("#"):
        continue
    prefix, notes = line.rsplit("|", 1)
    fields = prefix.split("|", 3)
    assert len(fields) == 4, line
    ident, state, category, pattern = fields
    assert state == "REVIEW", ident
    candidates.append((ident, re.compile(pattern)))
assert len({ident for ident, _ in candidates}) == len(candidates)
assert all(not regex.search("/favicon.ico") for _, regex in candidates)
for path in ["/wp-content/maljum.php", "/wp-track3.php", "/wp-sample.php"]:
    assert any(regex.search(path) for _, regex in candidates), path

print(f"PASS: {len(entries)} active signatures, {len(candidates)} review candidates, {len(positive)} malicious and {len(benign)} benign cases")
