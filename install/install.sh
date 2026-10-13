#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
F2B_ETC="${F2B_ETC:-/etc/fail2ban}"
BACKUP="${F2B_ETC}/minisoc-backup-$(date +%Y%m%d-%H%M%S)"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

mkdir -p "$BACKUP" "$F2B_ETC/filter.d" "$F2B_ETC/jail.d"

for f in nginx-skanery.conf nginx-dev-honeypot.conf; do
  [[ -f "$F2B_ETC/filter.d/$f" ]] && cp -a "$F2B_ETC/filter.d/$f" "$BACKUP/$f"
  install -m 0644 "$ROOT/fail2ban/filter.d/$f" "$F2B_ETC/filter.d/$f"
done

JAIL="$F2B_ETC/jail.d/minisoc-fail2ban.local"
[[ -f "$JAIL" ]] && cp -a "$JAIL" "$BACKUP/minisoc-fail2ban.local"
cp "$ROOT/fail2ban/jail.d/minisoc-fail2ban.local.example" "$JAIL"

if [[ -n "${NGINX_LOG:-}" ]]; then
  sed -i "s#^logpath = .*#logpath = $NGINX_LOG#g" "$JAIL"
fi

if ! fail2ban-client -t; then
  echo "Fail2Ban validation failed. Backups are in: $BACKUP" >&2
  exit 1
fi

fail2ban-client reload
echo "Installed. Backup: $BACKUP"
