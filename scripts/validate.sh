#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for required in \
  README.md VERSION rules/signatures-v2.db rules/candidates.list rules/benign-scanners.list \
  fail2ban/filter.d/nginx-skanery.conf fail2ban/filter.d/nginx-dev-honeypot.conf \
  install/install.sh install/uninstall.sh install/safe_update.py install/safe_uninstall.py; do
  test -s "$ROOT/$required" || { echo "MISSING $required" >&2; exit 1; }
done
bash -n "$ROOT/install/install.sh" "$ROOT/install/uninstall.sh" "$ROOT/install/test.sh"
python3 -m compileall -q "$ROOT/install" "$ROOT/scripts" "$ROOT/tests"
python3 "$ROOT/tests/november-regression.py"
python3 -m unittest discover -s "$ROOT/tests" -p 'test_safe_update.py' -v
python3 -m unittest discover -s "$ROOT/tests" -p 'test_working_patch.py' -v
if command -v fail2ban-regex >/dev/null; then
  python3 "$ROOT/scripts/verify_fail2ban_filters.py" --filter-dir "$ROOT/fail2ban/filter.d"
elif [[ "${REQUIRE_FAIL2BAN_REGEX:-0}" == "1" ]]; then
  echo 'ERROR: fail2ban-regex is required for release CI' >&2
  exit 1
else
  echo 'SKIP: real fail2ban-regex integration unavailable on this machine'
fi
echo 'PASS: structure, baseline tests, updater rollback tests, signature fixtures'
