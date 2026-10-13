#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

test -s "$ROOT/README.md"
test -s "$ROOT/rules/signatures-v2.db"
test -s "$ROOT/fail2ban/filter.d/nginx-skanery.conf"
test -s "$ROOT/fail2ban/filter.d/nginx-dev-honeypot.conf"

grep -q 'Behavior is the indicator' "$ROOT/README.md"
grep -q 'hellopress-filemanager|HIGH' "$ROOT/rules/signatures-v2.db"
grep -q 'wp-css-campaign|HIGH' "$ROOT/rules/signatures-v2.db"

echo "PASS: repository structure and required signatures are present"
