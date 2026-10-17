#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

test -s "$ROOT/README.md"
test -s "$ROOT/rules/signatures-v2.db"
test -s "$ROOT/rules/benign-scanners.list"
test -s "$ROOT/rules/candidates.list"
test -s "$ROOT/fail2ban/filter.d/nginx-skanery.conf"
test -s "$ROOT/fail2ban/filter.d/nginx-dev-honeypot.conf"

grep -q 'Behavior is the indicator' "$ROOT/README.md"
grep -q 'hellopress-filemanager|HIGH' "$ROOT/rules/signatures-v2.db"
grep -q 'wp-content-wuhr9|HIGH' "$ROOT/rules/signatures-v2.db"
grep -q '/wp-content/wuhr9\\.php' "$ROOT/fail2ban/filter.d/nginx-skanery.conf"
grep -q 'agent-readiness-openid|SAFE_DISCOVERY' "$ROOT/rules/benign-scanners.list"
grep -q 'urlscan-secret-watcher-dev-injector|TRUSTED_ONLY' "$ROOT/rules/benign-scanners.list"

echo "PASS: repository structure, active malicious signatures, benign-scanner policy, and review list are valid"
