#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
F2B_ETC="${F2B_ETC:-/etc/fail2ban}"
BACKUP="${F2B_ETC}/minisoc-backup-$(date +%Y%m%d-%H%M%S)-$$"
FILES=(filter.d/nginx-skanery.conf filter.d/nginx-dev-honeypot.conf jail.d/minisoc-fail2ban.local)

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi
command -v fail2ban-client >/dev/null || { echo "fail2ban-client missing" >&2; exit 1; }

mkdir -p "$BACKUP" "$F2B_ETC/filter.d" "$F2B_ETC/jail.d"
rollback() {
  local f
  trap - ERR
  for f in "${FILES[@]}"; do
    if [[ -f "$BACKUP/$f" ]]; then
      cp -a "$BACKUP/$f" "$F2B_ETC/$f"
    elif [[ -f "$BACKUP/.created/$f" ]]; then
      rm -f "$F2B_ETC/$f"
    fi
  done
  echo "Previous configuration restored. Backup: $BACKUP" >&2
}
for f in "${FILES[@]}"; do
  if [[ -e "$F2B_ETC/$f" ]]; then
    mkdir -p "$BACKUP/$(dirname "$f")"
    cp -a "$F2B_ETC/$f" "$BACKUP/$f"
  else
    mkdir -p "$BACKUP/.created/$(dirname "$f")"
    : > "$BACKUP/.created/$f"
  fi
done
trap rollback ERR

for f in nginx-skanery.conf nginx-dev-honeypot.conf; do
  install -m 0644 "$ROOT/fail2ban/filter.d/$f" "$F2B_ETC/filter.d/$f"
done

JAIL="$F2B_ETC/jail.d/minisoc-fail2ban.local"
if [[ ! -e "$JAIL" ]]; then
  cp "$ROOT/fail2ban/jail.d/minisoc-fail2ban.local.example" "$JAIL"
  if [[ -n "${NGINX_LOG:-}" ]]; then
    sed -i "s#^logpath = .*#logpath = $NGINX_LOG#g" "$JAIL"
  fi
elif [[ -n "${NGINX_LOG:-}" ]]; then
  echo "Existing jail configuration preserved; NGINX_LOG override ignored." >&2
fi

fail2ban-client -t
fail2ban-client reload
trap - ERR
echo "Installed. Backup: $BACKUP"
