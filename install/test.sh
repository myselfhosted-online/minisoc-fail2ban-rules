#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if (( $# > 1 )); then echo 'Usage: test.sh [optional-nginx-log]' >&2; exit 2; fi
if (( $# == 1 )); then
  exec python3 "$ROOT/scripts/verify_fail2ban_filters.py" --log "$1"
else
  exec python3 "$ROOT/scripts/verify_fail2ban_filters.py"
fi
