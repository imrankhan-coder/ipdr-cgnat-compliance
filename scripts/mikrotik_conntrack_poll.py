#!/usr/bin/env python3
"""
mikrotik_conntrack_poll.py — poll connection-tracking on each API-enabled
MikroTik NAS and record real CGNAT port-usage metrics (replacing the invalid
Juniper PBA model).

Two things are captured each run:
  1. Box-wide health from /ip/firewall/connection/tracking (cheap, one row):
       total-entries / max-entries  -> mikrotik_conntrack_stats
  2. Per-public-IP snapshot from /ip/firewall/connection (proplist + srcnat
     filter, ~10s for ~100k conns): for each public IP (reply-dst-address),
     count concurrent srcnat conns, DISTINCT public source ports
     (reply-dst-port), unique subscribers (src-address), and protocol split
     -> mikrotik_conntrack_pool

Field mapping for a srcnat (CGNAT) connection:
    src-address        = private subscriber IP (100.64/10)
    reply-dst-address  = PUBLIC NAT IP  (the pool IP)
    reply-dst-port     = PUBLIC source port consumed on that IP
    protocol           = tcp/udp/icmp/...

Usage:
    IPDR_ENV=/opt/ipdr/.env python3 mikrotik_conntrack_poll.py [--pool]

  Without --pool: only the cheap box-wide tracking summary is polled (run
    frequently, e.g. every 60s).
  With --pool: also does the full per-IP connection scan (run every ~10 min).

Env: DATABASE_URL, MT_FERNET_KEY (from .env).
"""
import os
import sys
import time
import logging
from collections import defaultdict
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from librouteros import connect
from librouteros.query import Key

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mt_crypto

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s mt-conntrack %(levelname)s %(message)s")
log = logging.getLogger("mt-conntrack")

USABLE_PORTS = 64512  # ports 1024-65535, standard CGNAT assumption


def _dsn():
    dsn = os.environ.get("DATABASE_URL")
    if dsn:
        return dsn
    # check IPDR_ENV / ELB_ENV, then common paths
    for env_path in (os.environ.get("IPDR_ENV"), os.environ.get("ELB_ENV"),
                     "/opt/ipdr/.env", "/opt/elb-ipdr/.env"):
        if env_path and os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.startswith("DATABASE_URL="):
                        return line.split("=", 1)[1].strip()
    raise RuntimeError("DATABASE_URL not found")


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def poll_tracking(api, conn, nas_id, nas_name):
    """Cheap box-wide conntrack summary -> mikrotik_conntrack_stats."""
    rows = list(api.path("ip", "firewall", "connection", "tracking"))
    if not rows:
        log.warning("nas %s: empty tracking summary", nas_name)
        return
    t = dict(rows[0])
    total = _int(t.get("total-entries"))
    mx = _int(t.get("max-entries"))
    ip4 = _int(t.get("total-ip4-entries"))
    ip6 = _int(t.get("total-ip6-entries"))
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO mikrotik_conntrack_stats "
            "(nas_id, total_entries, max_entries, ip4_entries, ip6_entries) "
            "VALUES (%s,%s,%s,%s,%s)",
            (nas_id, total, mx, ip4, ip6),
        )
    conn.commit()
    pct = (total / mx * 100) if mx else 0
    log.info("nas %s: conntrack %d/%d (%.1f%%) ip4=%d ip6=%d",
             nas_name, total, mx, pct, ip4, ip6)


def poll_pool(api, conn, nas_id, nas_name):
    """Per-public-IP CGNAT port usage from srcnat connections."""
    t0 = time.time()
    ports = defaultdict(set)     # public_ip -> set of reply-dst-port
    subs = defaultdict(set)      # public_ip -> set of src-address
    conns = defaultdict(int)     # public_ip -> conn count
    proto = defaultdict(lambda: defaultdict(int))  # public_ip -> proto -> count

    q = (api.path("ip", "firewall", "connection")
         .select(Key("reply-dst-address"), Key("reply-dst-port"),
                 Key("src-address"), Key("protocol"), Key("srcnat"))
         .where(Key("srcnat") == True))  # noqa: E712 (librouteros needs ==)
    def _split_ip_port(addr):
        if addr is None:
            return None, None
        a = str(addr)
        if a.startswith("["):
            host, _, port = a[1:].partition("]")
            port = port.lstrip(":") or None
            return host, port
        if a.count(":") == 1:
            host, _, port = a.partition(":")
            return host, (port or None)
        return a, None

    n = 0
    for row in q:
        d = dict(row)
        raw_ip = d.get("reply-dst-address")
        if not raw_ip:
            continue
        ip, bundled_port = _split_ip_port(raw_ip)
        if not ip:
            continue
        port = d.get("reply-dst-port")
        if port in (None, "", 0):
            port = bundled_port
        conns[ip] += 1
        ports[ip].add(port)
        subs[ip].add(d.get("src-address"))
        p = (d.get("protocol") or "other").lower()
        proto[ip][p] += 1
        n += 1

    ts = datetime.now()
    batch = []
    for ip in conns:
        pr = proto[ip]
        tcp = pr.get("tcp", 0)
        udp = pr.get("udp", 0)
        icmp = pr.get("icmp", 0)
        other = conns[ip] - tcp - udp - icmp
        batch.append((
            nas_id, ts, ip, conns[ip], len(ports[ip]), len(subs[ip]),
            tcp, udp, icmp, max(0, other),
        ))

    if batch:
        with conn.cursor() as cur:
            execute_values(
                cur,
                "INSERT INTO mikrotik_conntrack_pool "
                "(nas_id, ts, public_ip, concurrent_conns, distinct_ports, "
                " unique_subs, tcp_conns, udp_conns, icmp_conns, other_conns) "
                "VALUES %s",
                batch,
            )
        conn.commit()
    dt = time.time() - t0
    log.info("nas %s: pool snapshot %d srcnat conns across %d public IPs in %.1fs",
             nas_name, n, len(conns), dt)


def _detect_routeros_version(api, conn, nas_id, nas_name):
    try:
        res = list(api.path("system", "resource"))
        if not res:
            return
        ver = str(dict(res[0]).get("version") or "").strip()
        if not ver:
            return
        major = None
        head = ver.split()[0] if ver else ""
        if head and head[0].isdigit():
            try:
                major = int(head.split(".")[0])
            except ValueError:
                major = None
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE nas_devices SET routeros_version=%s, routeros_major=%s, "
                "routeros_seen_at=now() WHERE id=%s AND "
                "(routeros_version IS DISTINCT FROM %s OR routeros_major IS DISTINCT FROM %s "
                " OR routeros_seen_at IS NULL)",
                (ver, major, nas_id, ver, major),
            )
        conn.commit()
    except Exception as e:
        log.warning("nas %s: version detect failed: %s", nas_name, e)


def poll_nas(conn, nas, do_pool):
    nas_id = nas["id"]
    host = nas["api_host"] or nas["ip_address"]
    port = int(nas["api_port"] or 8728)
    user = nas["api_user"]
    try:
        password = mt_crypto.decrypt(nas["api_password_enc"])
    except Exception as e:
        log.error("nas %s: decrypt failed: %s", nas["name"], e)
        return
    try:
        api = connect(username=user, password=password, host=host, port=port)
    except Exception as e:
        log.error("nas %s: connect failed: %s", nas["name"], e)
        return
    try:
        _detect_routeros_version(api, conn, nas_id, nas["name"])
        poll_tracking(api, conn, nas_id, nas["name"])
        if do_pool:
            poll_pool(api, conn, nas_id, nas["name"])
    except Exception as e:
        log.error("nas %s: poll error: %s", nas["name"], e)
    finally:
        try:
            api.close()
        except Exception:
            pass


def main():
    do_pool = "--pool" in sys.argv
    conn = psycopg2.connect(_dsn(), cursor_factory=RealDictCursor)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM nas_devices "
            "WHERE nas_type='mikrotik' AND api_enabled=TRUE "
            "AND api_password_enc IS NOT NULL"
        )
        nases = cur.fetchall()
    conn.commit()
    if not nases:
        log.info("no API-enabled MikroTik NAS; nothing to poll")
        conn.close()
        return
    for nas in nases:
        poll_nas(conn, nas, do_pool)
    conn.close()


if __name__ == "__main__":
    main()
