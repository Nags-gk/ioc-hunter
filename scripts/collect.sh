#!/usr/bin/env bash
# collect.sh: read-only live-response collection for a Linux host under investigation.
#
#   sudo ./collect.sh /path/to/evidence-dir
#
# Collects volatile state first (processes, sockets, logins), then persistence
# locations and logs. Nothing on the host is modified. Every output file is hashed
# into MANIFEST.sha256 and the bundle is tarred with its own hash, so the evidence
# can be shown to be unchanged later (chain of custody).
set -uo pipefail
OUT=${1:?usage: collect.sh OUTPUT_DIR}
HOST=$(hostname 2>/dev/null || echo unknown)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DIR="$OUT/${HOST}_${STAMP}"
mkdir -p "$DIR"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$DIR/collection.log"; }
run() { # run NAME COMMAND...: save output, never abort the collection on one failure
  local name=$1; shift
  log "run $name: $*"
  { "$@"; } > "$DIR/$name.txt" 2>> "$DIR/errors.txt" || log "exit $? for $name"
}
copy() { # copy readable files, preserving paths
  for f in "$@"; do [[ -r "$f" ]] && { mkdir -p "$DIR/files$(dirname "$f")"; cp -p "$f" "$DIR/files$f" 2>/dev/null && log "copied $f"; }; done
}
log "collector start on $HOST as $(id -un) (uid $(id -u))"
# 1. volatile
run date            date -u
run uptime          uptime
run whoami          id
run who             who -a
run last            last -Fai -n 200
run processes       ps auxwwf
run sockets         ss -tunap
run listening       ss -tlnp
run routes          ip route
run interfaces      ip -br addr
run arp             ip neigh
run mounts          findmnt -l
run loaded_modules  lsmod
# 2. accounts and persistence
# shellcheck disable=SC2016  # the awk and sh programs below are meant to be single-quoted
run passwd_uid0     awk -F: '$3 == 0 {print}' /etc/passwd
# shellcheck disable=SC2016
run recent_users    awk -F: '$3 >= 1000 || $3 == 0 {print $1":"$3":"$6":"$7}' /etc/passwd
run cron_system     sh -c 'ls -la /etc/cron.* /var/spool/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null'
run systemd_units   sh -c 'systemctl list-unit-files --type=service --state=enabled 2>/dev/null'
# shellcheck disable=SC2016
run authorized_keys sh -c 'for h in /root /home/*; do [ -f "$h/.ssh/authorized_keys" ] && { echo "== $h"; cat "$h/.ssh/authorized_keys"; }; done'
run tmp_listing     sh -c 'ls -laR /tmp /var/tmp /dev/shm 2>/dev/null | head -2000'
run hidden_bins     sh -c 'find /usr/local/bin /usr/bin /bin /opt -maxdepth 2 -name ".*" -type f 2>/dev/null'
run recent_etc      sh -c 'find /etc -xdev -type f -mtime -7 2>/dev/null | head -500'
run suid_files      sh -c 'find / -xdev -perm -4000 -type f 2>/dev/null'
# 3. logs and configs (copies)
copy /etc/passwd /etc/group /etc/sudoers /etc/ssh/sshd_config /etc/crontab
copy /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/cron
for h in /root /home/*; do copy "$h/.bash_history" "$h/.ssh/authorized_keys"; done
log "collector done"
# manifest and bundle
( cd "$DIR" && find . -type f -print0 | sort -z | xargs -0 sha256sum > "$OUT/.manifest.tmp" && mv "$OUT/.manifest.tmp" MANIFEST.sha256 )
tar -C "$OUT" -czf "$DIR.tar.gz" "$(basename "$DIR")"
sha256sum "$DIR.tar.gz" | tee "$DIR.tar.gz.sha256"
echo "evidence: $DIR.tar.gz"
