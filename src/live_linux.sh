#!/usr/bin/env bash
# security-watch live feed for a Linux host. Read-only.
# Streams SSH/sudo/firewall journal events as they happen ("EV ...") and, every
# INTERVAL seconds, the established inbound TCP connections ("CONNS" block).
# Usage: bash -s -- <interval_seconds>
export LC_ALL=C
INTERVAL="${1:-5}"
S=""; sudo -n true 2>/dev/null && S="sudo -n"
trap 'trap - EXIT; kill 0 2>/dev/null' EXIT HUP TERM INT PIPE

(
  $S journalctl -f -n 0 -o short-unix _COMM=sshd _COMM=sshd-session _COMM=sudo + _TRANSPORT=kernel 2>/dev/null \
    | grep --line-buffered -E 'sshd|sudo|UFW BLOCK' \
    | sed -u 's/^/EV /'
) &

while :; do
  echo "CONNS $(date +%s)" || break
  # Listeners reachable from outside, as "addr:port" (loopback-only ones excluded). An
  # established socket is inbound only if its local addr:port matches one of them, either
  # exactly or through a wildcard listener; matching on the port alone misreads outbound
  # connections whose ephemeral port equals some loopback listener's port.
  LISTEN=" $(ss -Htln 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|\[::1\]|\[::ffff:127\.)' | sort -u | tr '\n' ' ') "
  $S ss -Htnp state established 2>/dev/null | awk -v L="$LISTEN" '
    { n = split($3, a, ":"); port = a[n]
      if (index(L, " " $3 " ") == 0 && index(L, " *:" port " ") == 0 && index(L, " 0.0.0.0:" port " ") == 0 && index(L, " [::]:" port " ") == 0) next
      if ($4 ~ /^(127\.|\[::1\]|\[::ffff:127\.)/) next
      lh = $3; sub(/:[0-9]+$/, "", lh); ph = $4; sub(/:[0-9]+$/, "", ph)
      if (lh == ph) next   # the host talking to itself through its LAN address
      p = $5; sub(/^users:\(\("/, "", p); sub(/".*/, "", p); if (p == "") p = "?"
      print "CONN tcp", $3, $4, p }'
  echo "CONNS_END" || break
  sleep "$INTERVAL" || break
done
