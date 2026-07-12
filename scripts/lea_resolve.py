#!/usr/bin/env python3
"""
lea_resolve.py — resolve an LEA request given a tcpdump-style line.

An authority emails lines like:
  1783851029.560458 IP 203.0.113.2.37358 > 91.190.98.12.443: Flags [S], ...

This parses the public IP:port, destination, and epoch, converts the epoch to
the wall-clock that matches the stored log_time (naive PKT), queries the
translations within a +/- window, and prints the matching subscriber(s) with
identity (customer name / phone / MAC where available).

Usage:
  # paste one or more lines on stdin:
  echo '1783851029.560458 IP 203.0.113.10.51596 > 99.80.34.227.443: Flags [S] ...' \\
    | sudo /opt/ipdr/venv/bin/python /opt/ipdr/scripts/lea_resolve.py

  # or pass a file:
  sudo /opt/ipdr/venv/bin/python /opt/ipdr/scripts/lea_resolve.py request.txt

Options via env:
  LEA_WINDOW_SECONDS   +/- match window (default 300 = 5 min)
  LEA_EPOCH_TZ         how to interpret the emailed epoch: 'utc' (default, matches
                       how extract(epoch) stored it) or 'pkt'
"""

import os
import re
import sys
from datetime import datetime, timezone, timedelta

import psycopg2
from psycopg2.extras import RealDictCursor

WINDOW = int(os.environ.get("LEA_WINDOW_SECONDS", "300"))
EPOCH_TZ = os.environ.get("LEA_EPOCH_TZ", "utc").lower()

# tcpdump line: <epoch>[.frac] IP <sip>.<sport> > <dip>.<dport>: ...
LINE_RE = re.compile(
    r'^\s*(?P<epoch>\d+)(?:\.\d+)?\s+IP\s+'
    r'(?P<sip>\d+\.\d+\.\d+\.\d+)\.(?P<sport>\d+)\s+>\s+'
    r'(?P<dip>\d+\.\d+\.\d+\.\d+)\.(?P<dport>\d+):'
)


def _dsn():
    env = os.environ.get("IPDR_ENV", "/opt/ipdr/.env")
    with open(env) as f:
        for line in f:
            if line.startswith("DATABASE_URL="):
                return line.split("=", 1)[1].strip()
    raise RuntimeError("DATABASE_URL not found")


def epoch_to_wall(epoch):
    """Convert emailed epoch to the naive wall-clock matching stored log_time."""
    if EPOCH_TZ == "pkt":
        dt = datetime.fromtimestamp(int(epoch), timezone(timedelta(hours=5)))
    else:  # 'utc' — matches extract(epoch) on the naive column
        dt = datetime.fromtimestamp(int(epoch), timezone.utc)
    return dt.replace(tzinfo=None)


def resolve(conn, sip, sport, dip, dport, epoch):
    wall = epoch_to_wall(epoch)
    lo = wall - timedelta(seconds=WINDOW)
    hi = wall + timedelta(seconds=WINDOW)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT t.username, host(t.private_ip) AS private_ip,
                   host(t.public_ip) AS public_ip, t.public_port,
                   host(t.dest_ip) AS dest_ip, t.dest_port, t.protocol,
                   t.log_time, t.src_mac, n.name AS nas_name,
                   s.comment AS customer, s.phone
            FROM mikrotik_translations t
            LEFT JOIN nas_devices n ON n.id = t.nas_id
            LEFT JOIN mikrotik_secrets s
                   ON s.nas_id = t.nas_id AND s.username = t.username
            WHERE t.public_ip = %s AND t.public_port = %s
              AND t.log_time BETWEEN %s AND %s
            ORDER BY abs(extract(epoch FROM (t.log_time - %s)))
            LIMIT 25
            """,
            (sip, int(sport), lo, hi, wall),
        )
        rows = cur.fetchall()
    return wall, rows, (dip, dport)


def main():
    data = ""
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        data = open(sys.argv[1]).read()
    else:
        data = sys.stdin.read()

    conn = psycopg2.connect(_dsn())
    any_line = False
    for raw in data.splitlines():
        m = LINE_RE.match(raw)
        if not m:
            continue
        any_line = True
        g = m.groupdict()
        wall, rows, (dip, dport) = resolve(
            conn, g["sip"], g["sport"], g["dip"], g["dport"], g["epoch"])
        print("=" * 70)
        print(f"REQUEST : {g['sip']}:{g['sport']} -> {g['dip']}:{g['dport']}  "
              f"epoch={g['epoch']}")
        print(f"TIME    : log_time ~ {wall}  (+/- {WINDOW}s, epoch as {EPOCH_TZ.upper()})")
        if not rows:
            print("RESULT  : NO MATCH in window. Check timezone (LEA_EPOCH_TZ=pkt?), "
                  "port type, or that this public IP is on this box.")
            continue
        # flag whether the destination confirms (vs port reuse)
        for r in rows:
            confirm = "  <-- DEST MATCHES (confirmed)" if (
                r["dest_ip"] == dip and str(r["dest_port"]) == dport) else ""
            who = r["customer"] or "(no customer comment)"
            print(f"  {r['log_time']}  user={r['username']}  "
                  f"priv={r['private_ip']}  dst={r['dest_ip']}:{r['dest_port']} "
                  f"{r['protocol']}  nas={r['nas_name']}{confirm}")
            print(f"       identity: {who}"
                  + (f"  phone={r['phone']}" if r.get('phone') else "")
                  + (f"  mac={r['src_mac']}" if r.get('src_mac') else ""))
        distinct_users = {r["username"] for r in rows}
        if len(distinct_users) > 1:
            print(f"  ** PORT REUSE: {len(distinct_users)} distinct subscribers in "
                  f"window — use the DEST MATCH line as the answer. **")
    if not any_line:
        print("No tcpdump-style lines found in input.", file=sys.stderr)
        sys.exit(1)
    conn.close()


if __name__ == "__main__":
    main()
