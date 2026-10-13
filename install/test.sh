#!/usr/bin/env bash
set -euo pipefail

LOG="${1:-/var/log/nginx/access.log}"

command -v fail2ban-regex >/dev/null

fail2ban-regex "$LOG" /etc/fail2ban/filter.d/nginx-skanery.conf --print-all-matched >/dev/null
fail2ban-regex "$LOG" /etc/fail2ban/filter.d/nginx-dev-honeypot.conf --print-all-matched >/dev/null

echo "PASS: Fail2Ban filters parsed successfully against $LOG"
