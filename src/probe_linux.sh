#!/usr/bin/env bash
# security-watch remote probe. Read-only: it changes nothing on the host.
# Usage: bash -s -- <since_unix_epoch>
# Output: one record per line, "<KEY> <fields...>", parsed by security-watch.
export LC_ALL=C
SINCE="${1:-$(( $(date +%s) - 86400 ))}"
PRIV='^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|169\.254\.)'
S=""; sudo -n true 2>/dev/null && S="sudo -n"
R() { if [ -n "$S" ]; then sudo -n bash -c "$1"; else bash -c "$1"; fi 2>/dev/null; }
J() { if [ -n "$S" ]; then sudo -n journalctl "$@"; else journalctl "$@"; fi 2>/dev/null; }

echo "META hostname $(hostname)"
echo "META os $(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
echo "META uptime $(uptime -p 2>/dev/null)"
[ -n "$S" ] && echo "META root yes" || echo "META root no"
if [ -n "$S" ] || id -nG | grep -qwE 'adm|systemd-journal|wheel'; then echo "META journal ok"; else echo "META journal limited"; fi

# --- SSH authentication events since SINCE ---
SSHLOG=$(J --since "@$SINCE" -o cat _COMM=sshd _COMM=sshd-session)
FAIL=$(printf '%s\n' "$SSHLOG" | grep -E "Failed |Invalid user|Connection closed by (invalid|authenticating) user|Disconnected from (invalid|authenticating) user|Unable to negotiate|banner exchange|maximum authentication|Received disconnect from .*\[preauth\]")
IPS=$(printf '%s\n' "$FAIL" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
PUB=$(printf '%s\n' "$IPS" | grep . | grep -vE "$PRIV")
echo "SSHFAIL $(printf '%s\n' "$FAIL" | grep -c .) $(printf '%s\n' "$PUB" | grep -c .) $(printf '%s\n' "$PUB" | grep . | sort -u | wc -l)"
printf '%s\n' "$IPS" | grep . | sort | uniq -c | sort -rn | head -5 | while read -r c ip; do echo "SSHFAILTOP $c $ip"; done
printf '%s\n' "$FAIL" | grep -oE "(Invalid user|Failed password for( invalid user)?) [^ ]+" | awk '{print $NF}' | sort | uniq -c | sort -rn | head -5 | while read -r c u; do echo "SSHFAILUSER $c $u"; done
printf '%s\n' "$SSHLOG" | grep -oE "Accepted [a-z-]+ for [^ ]+ from [^ ]+" | awk '{print $4, $2, $6}' | sort | uniq -c | sort -rn | head -20 | while read -r c u m ip; do echo "ACCEPT $c $u $m $ip"; done
echo "SUDOFAIL $(J --since "@$SINCE" -o cat _COMM=sudo | grep -cE 'authentication failure|incorrect password attempt')"

# --- packets from the internet blocked by the host firewall ---
BLK=$(J -k --since "@$SINCE" -o cat | grep 'UFW BLOCK' | grep -oE 'SRC=[^ ]+' | cut -d= -f2)
BPUB=$(printf '%s\n' "$BLK" | grep . | grep -vE "$PRIV" | grep -vE '^(fe80|ff0)')
echo "FWBLOCK $(printf '%s\n' "$BLK" | grep -c .) $(printf '%s\n' "$BPUB" | grep -c .) $(printf '%s\n' "$BPUB" | grep . | sort -u | wc -l)"
if [ -n "$S" ]; then echo "FIREWALL ufw $(sudo -n ufw status 2>/dev/null | head -1 | awk '{print $2}')"
elif [ -r /etc/ufw/ufw.conf ]; then grep -q '^ENABLED=yes' /etc/ufw/ufw.conf && echo "FIREWALL ufw active" || echo "FIREWALL ufw inactive"; fi

# --- listening sockets (non-loopback) ---
R "ss -H -tulpn" | awk '{p=$7; sub(/^users:\(\("/,"",p); sub(/".*/,"",p); a=$5; n=split(a,x,":"); port=x[n]; addr=substr(a,1,length(a)-length(port)-1); if (addr ~ /^(127\.|\[::1\]|\[::ffff:127\.)/) next; if (p=="") p="?"; print "LISTEN", $1, addr, port, p}' | sort -u

# --- accounts, keys, sensitive files ---
awk -F: '$3==0{print "UID0 "$1}' /etc/passwd
awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print "SHELLUSER "$1}' /etc/passwd
for h in /root $(awk -F: '$3>=1000 && $3<65000 {print $6}' /etc/passwd); do
  for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
    R "test -f '$f' && ssh-keygen -lf '$f'" | awk -v f="$f" '{c=""; for(i=3;i<NF;i++) c=c" "$i; print "AUTHKEY " f " " $2 c}'
  done
done
for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config /etc/pam.d/common-auth /etc/pam.d/sshd; do
  [ -e "$f" ] && echo "MTIME $f $(stat -c %Y "$f")"
done
R "find /etc/sudoers.d /etc/ssh/sshd_config.d -maxdepth 1 -type f -printf 'MTIME %p %T@\n'" | awk '{sub(/\..*/,"",$3); print}'
if [ -s /etc/ld.so.preload ]; then echo "PRELOAD $(tr '\n' ' ' < /etc/ld.so.preload | cut -c1-200)"; fi

# --- suspicious executables ---
R 'for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null) || continue; case "$e" in /tmp/*|/var/tmp/*|/dev/shm/*) echo "TMPEXE ${p#/proc/} $e";; esac; done' | head -10
# new files that are really executable (ELF binary or #! script), not just +x data files
R 'find /tmp /var/tmp /dev/shm -xdev -type f -perm -u+x -newermt @'"$SINCE"' -print0 2>/dev/null | while IFS= read -r -d "" f; do case "$(head -c 2 "$f" | od -An -tx1 | tr -d " \n")" in 7f45|2321) echo "TMPFILE $f";; esac; done' | head -10

# --- persistence: services, timers, cron ---
for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer; do [ -f "$f" ] && echo "UNIT system ${f##*/}"; done
for h in $(awk -F: '$3>=1000 && $3<65000 {print $1":"$6}' /etc/passwd); do
  u=${h%%:*}; d=${h#*:}/.config/systemd/user
  for f in "$d"/*.service "$d"/*.timer; do [ -f "$f" ] && echo "UNIT user:$u ${f##*/}"; done
done
crontab -l 2>/dev/null | grep -vE '^\s*(#|$)' | while IFS= read -r l; do echo "CRON $(id -un) $(printf '%s' "$l" | sha256sum | cut -c1-10) $(printf '%s' "$l" | cut -c1-60)"; done
R 'for f in /var/spool/cron/crontabs/*; do [ -f "$f" ] || continue; u=$(basename "$f"); grep -vE "^\s*(#|$)" "$f" | while IFS= read -r l; do echo "CRON $u $(printf "%s" "$l" | sha256sum | cut -c1-10) $(printf "%s" "$l" | cut -c1-60)"; done; done' | grep -v "^CRON $(id -un) "
for f in /etc/cron.d/*; do [ -f "$f" ] && echo "CRONFILE ${f##*/}"; done

[ -f /var/run/reboot-required ] && echo "REBOOT required"
echo "END"
