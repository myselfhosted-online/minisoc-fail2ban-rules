#!/usr/bin/env bash
set -euo pipefail

F2B_ETC="${F2B_ETC:-/etc/fail2ban}"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

rm -f "$F2B_ETC/filter.d/nginx-skanery.conf"
rm -f "$F2B_ETC/filter.d/nginx-dev-honeypot.conf"
rm -f "$F2B_ETC/jail.d/minisoc-fail2ban.local"

fail2ban-client -t
fail2ban-client reload
echo "Removed project-managed files."
