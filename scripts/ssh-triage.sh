#!/usr/bin/env bash
# ssh-triage.sh: first-look triage of an OpenSSH auth log with standard tools only
# (works on any Linux box during an incident, no Python needed).
#
#   usage: ssh-triage.sh /var/log/auth.log [min_failures]
#
# Prints: totals, top guessing sources, top usernames, successful logins, and the
# key question: did any source that guessed passwords then log in?
set -uo pipefail   # no -e: a closed pipe from `head` must not abort the report
LOG=${1:?usage: ssh-triage.sh LOGFILE [min_failures]}
MIN=${2:-20}
[[ -r "$LOG" ]] || { echo "cannot read $LOG" >&2; exit 2; }
TMP=${TRIAGE_TMP:-$(mktemp -d)}; [[ -z "${TRIAGE_TMP:-}" ]] && trap 'rm -rf "$TMP"' EXIT

# Some exported logs carry CRLF line endings; strip CR once so fields compare cleanly.
tr -d '\r' < "$LOG" > "$TMP/log"
LOG="$TMP/log"
# failure lines -> "ip user" (user "-" when absent)
grep -E 'sshd.*(Failed password|Invalid user|authentication failure;.*rhost=)' "$LOG" | awk '
  /Failed password for invalid user/ { for (i=1;i<=NF;i++) if ($i=="from") { print $(i+1), $(i-1); next } }
  /Failed password for/              { for (i=1;i<=NF;i++) if ($i=="from") { print $(i+1), $(i-1); next } }
  /Invalid user/                     { for (i=1;i<=NF;i++) if ($i=="from") { print $(i+1), ($(i-1)=="user" ? "-" : $(i-1)); next } }
  /authentication failure;/          { ip="-"; u="-"; for (i=1;i<=NF;i++) { if ($i ~ /^rhost=/) ip=substr($i,7); if ($i ~ /^user=/) u=substr($i,6) }
                                       if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print ip, u }' > "$TMP/fail"
# success lines -> "ip user"
grep -E 'sshd.*Accepted (password|publickey) for' "$LOG" | awk '{ for (i=1;i<=NF;i++) if ($i=="from") print $(i+1), $(i-1) }' > "$TMP/ok"

echo "== totals"
printf 'failed auth events : %s\n' "$(wc -l < "$TMP/fail")"
printf 'failing sources    : %s\n' "$(cut -d' ' -f1 "$TMP/fail" | sort -u | wc -l)"
printf 'successful logins  : %s\n' "$(wc -l < "$TMP/ok")"
echo; echo "== top 10 guessing sources (attempts ip)"
cut -d' ' -f1 "$TMP/fail" | sort | uniq -c | sort -rn | head -10
echo; echo "== top 10 usernames tried"
awk '$2 != "-" {print $2}' "$TMP/fail" | sort | uniq -c | sort -rn | head -10
echo; echo "== successful logins (count ip user)"
sort "$TMP/ok" | uniq -c | sort -rn
echo; echo "== sources with >= $MIN failures that later logged in (brute force then success)"
cut -d' ' -f1 "$TMP/fail" | sort | uniq -c | awk -v m="$MIN" '$1 >= m {print $2}' | sort > "$TMP/heavy"
cut -d' ' -f1 "$TMP/ok" | sort -u > "$TMP/okips"
HITS=$(comm -12 "$TMP/heavy" "$TMP/okips" | wc -l)
comm -12 "$TMP/heavy" "$TMP/okips" | while read -r ip; do
  echo "!! $ip: $(grep -c "^$ip " "$TMP/fail") failures, logged in as: $(awk -v ip="$ip" '$1==ip {print $2}' "$TMP/ok" | sort -u | tr '\n' ' ')"
done
[[ "$HITS" -eq 0 ]] && echo "none"
echo; echo "== sources logging in to 3+ different accounts"
awk '{print $1, $2}' "$TMP/ok" | sort -u | awk '{c[$1]++; u[$1]=u[$1] " " $2} END {for (ip in c) if (c[ip] >= 3) print ip ":" u[ip]}' | sort
exit 0
