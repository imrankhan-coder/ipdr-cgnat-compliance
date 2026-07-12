#!/bin/bash
# ============================================================================
# nat_tail.sh — Follows the current day's NAT log, handles midnight rollover
#
# The daily log filename is date-based (YYYY-MM-DD-nat.log). A plain
# `tail -F *.log` expands the glob once at startup and never picks up the
# new day's file. This wrapper watches for the date to change and re-tails
# the current file, so ingestion continues seamlessly across midnight.
# ============================================================================

PARSER=("/opt/ipdr/venv/bin/python3" "/opt/ipdr/scripts/nat_parser.py" "--mode" "stdin")
LOGDIR="/var/log/nat"

# Everything inside the braces is piped into a single long-lived parser process.
{
  CURRENT=""
  TAIL_PID=""
  while true; do
    TODAY="${LOGDIR}/$(date +%Y-%m-%d)-nat.log"
    if [ "$TODAY" != "$CURRENT" ]; then
      # Date changed (or first run) — switch to the new file
      [ -n "$TAIL_PID" ] && kill "$TAIL_PID" 2>/dev/null || true
      # Wait for the new file to be created by rsyslog
      while [ ! -f "$TODAY" ]; do sleep 2; done
      # -n0 = start at end (don't re-read whole file); -F = follow by name with retry
      tail -n0 -F "$TODAY" &
      TAIL_PID=$!
      CURRENT="$TODAY"
    fi
    sleep 30
  done
} | "${PARSER[@]}"
