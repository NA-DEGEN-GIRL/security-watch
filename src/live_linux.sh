#!/usr/bin/env bash
# security-watch live feed for a Linux host. Read-only.
# Streams SSH/sudo/firewall journal events as they happen ("EV ...") and, every
# INTERVAL seconds: the established inbound TCP connections ("CONNS" block), the
# programs holding outbound connections ("O" lines) and newly started processes
# ("P" lines). What counts as suspicious is decided by security-watch, not here.
# Usage: bash -s -- <interval_seconds>
#
# One sudo for the whole stream (when passwordless sudo exists) instead of one per
# tick, which would write a sudo log entry every few seconds. Bash reads this script
# from stdin line by line, so the re-executed shell simply continues below.
if [ "$(id -u)" != 0 ] && sudo -n true 2>/dev/null; then exec sudo -n bash -s -- "$@"; fi
export LC_ALL=C
INTERVAL="${1:-5}"
PRIV='^(10[.]|127[.]|0[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[01])[.]|100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.]|169[.]254[.]|::1$|fe[89ab]|f[cd])'
trap 'trap - EXIT; kill 0 2>/dev/null' EXIT HUP TERM INT PIPE

(
  journalctl -f -n 0 -o short-unix _COMM=sshd _COMM=sshd-session _COMM=sudo + _TRANSPORT=kernel 2>/dev/null \
    | grep --line-buffered -E 'sshd|sudo|UFW BLOCK' \
    | sed -u 's/^/EV /'
) &

PREV=""
while :; do
  NOW=$(date +%s)
  echo "CONNS $NOW" || break
  # Listeners reachable from outside, as "addr:port" (loopback-only ones excluded). An
  # established socket is inbound only if its local addr:port matches one of them, either
  # exactly or through a wildcard listener; matching on the port alone misreads outbound
  # connections whose ephemeral port equals some loopback listener's port.
  LISTEN=" $(ss -Htln 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|\[::1\]|\[::ffff:127\.)' | sort -u | tr '\n' ' ') "
  ss -Htnp state established 2>/dev/null | awk -v L="$LISTEN" -v T="$NOW" -v PRIV="$PRIV" '
    { n = split($3, a, ":"); port = a[n]
      if ($4 ~ /^(127\.|\[::1\]|\[::ffff:127\.)/) next
      p = $5; sub(/^users:\(\("/, "", p); sub(/".*/, "", p); if (p == "") p = "?"
      ph = $4; sub(/:[0-9]+$/, "", ph)
      if (index(L, " " $3 " ") == 0 && index(L, " *:" port " ") == 0 && index(L, " 0.0.0.0:" port " ") == 0 && index(L, " [::]:" port " ") == 0) {
        # outbound: one line per program and remote port, public peers only
        rp = $4; sub(/.*:/, "", rp); gsub(/[\[\]]/, "", ph); sub(/^::ffff:/, "", ph)
        if (ph ~ PRIV || ((p " " rp) in seen)) next
        seen[p " " rp] = 1; out[++m] = "O\t" T "\t" p "\t" ph "\t" rp
        next
      }
      lh = $3; sub(/:[0-9]+$/, "", lh)
      if (lh == ph) next   # the host talking to itself through its LAN address
      print "CONN tcp", $3, $4, p }
    END { for (i = 1; i <= m; i++) print out[i] }'
  echo "CONNS_END" || break

  # Processes started since the last tick (everything on the first one), with the exe
  # path where it is readable. Kernel threads and this script's own helpers are skipped.
  while IFS= read -r l; do
    case "$l" in PIDS*) PREV=${l#PIDS} ;; *) echo "$l" ;; esac
  done < <({ find /proc -maxdepth 2 -name exe -printf 'E %h %l\n' 2>/dev/null; ps -eo pid=,ppid=,args=; } | awk -v prev="$PREV" -v T="$NOW" -v self="$$" '
    function base(s) { sub(/ \(deleted\)$/, "", s); sub(/.*\//, "", s); sub(/:$/, "", s); return s }
    function ours(p, d) { for (d = 0; d < 8 && p > 1; d++) { if (p == self) return 1; p = pp[p] } return 0 }
    BEGIN { n = split(prev, a, " "); for (i = 1; i <= n; i++) old[a[i]] = 1 }
    $1 == "E" { p = $2; sub(/^\/proc\//, "", p); l = $0; sub(/^E [^ ]+ ?/, "", l); exe[p] = l; next }
    { p = $1; pp[p] = $2; s = $0; sub(/^ *[0-9]+ +[0-9]+ +/, "", s); gsub(/\t/, " ", s); ar[p] = s
      nm[p] = (exe[p] != "") ? base(exe[p]) : base($3); order[++m] = p }
    END {
      for (i = 1; i <= m; i++) {
        p = order[i]; all = all " " p
        if ((p in old) || p == 2 || pp[p] == 2 || ours(p)) continue
        print "P\t" T "\t" p "\t" pp[p] "\t" nm[p] "\t" nm[pp[p]] "\t-\t" exe[p] "\t" substr(ar[p], 1, 600)
      }
      print "PIDS" all
    }') || break
  sleep "$INTERVAL" || break
done
