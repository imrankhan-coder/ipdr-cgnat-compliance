#!/usr/bin/env python3
"""
mikrotik_dhcp_poll.py — poll /ip/dhcp-server/lease on each API-enabled MikroTik
NAS and maintain mikrotik_dhcp_leases (keyed on MAC) + mikrotik_dhcp_ip_history.

DHCP identity semantics (defensible for LEA):
  MAC is the durable identity (IP changes across leases). The lease comment /
  hostname is the human label. When a MAC's IP changes, the current history
  interval is closed and a new one opened, so a past DHCP IP resolves to the
  MAC that held it at that time.

Static vs dynamic: RouterOS lease has 'dynamic' = 'true'/'false'. A "Make Static"
lease has dynamic=false. We store is_static accordingly.

Env: DATABASE_URL, MT_FERNET_KEY (from .env).
Usage: mikrotik_dhcp_poll.py [--nas-id N]   (default: all api-enabled)
"""
import os
import sys
import logging
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor
from librouteros import connect

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mt_crypto

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s mt-dhcp-poll %(levelname)s %(message)s")
log = logging.getLogger("mt-dhcp-poll")


def _dsn():
    dsn = os.environ.get("DATABASE_URL")
    if dsn:
        return dsn
    env_path = os.environ.get("IPDR_ENV", "/opt/ipdr/.env")
    with open(env_path) as f:
        for line in f:
            if line.startswith("DATABASE_URL="):
                return line.split("=", 1)[1].strip()
    raise RuntimeError("DATABASE_URL not found")


def _norm_mac(m):
    return m.strip().upper() if m else None


def apply_leases(conn, nas_id, leases, now):
    """Diff the current lease list against stored leases. Upsert keyed on MAC;
    track IP changes into history. Separated from the API call for testability.

    leases: list of dicts from /ip/dhcp-server/lease (RouterOS field names).
    Returns stats dict.
    """
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        "INSERT INTO mikrotik_dhcp_poll_state (nas_id, last_poll) VALUES (%s,%s) "
        "ON CONFLICT (nas_id) DO UPDATE SET last_poll = EXCLUDED.last_poll",
        (nas_id, now),
    )

    # current stored leases for this NAS
    cur.execute(
        "SELECT mac, host(ip) AS ip, is_static FROM mikrotik_dhcp_leases WHERE nas_id=%s",
        (nas_id,),
    )
    stored = {r["mac"]: r for r in cur.fetchall()}

    seen_macs = set()
    added = updated = ip_changed = 0

    for L in leases:
        mac = _norm_mac(L.get("mac-address"))
        if not mac:
            continue
        seen_macs.add(mac)
        # RouterOS: active-address is the live one; fall back to 'address'
        ip = L.get("active-address") or L.get("address")
        def _s(v):  # str-coerce (RouterOS may return ints e.g. numeric hostnames)
            return str(v) if v is not None and v != "" else None
        ip = _s(ip)
        host = _s(L.get("host-name") or L.get("active-host-name"))
        comment = _s(L.get("comment"))
        server = _s(L.get("server"))
        status = _s(L.get("status"))
        dynamic = str(L.get("dynamic", "false")).lower() == "true"
        is_static = not dynamic
        class_id = _s(L.get("class-id"))  # device model/vendor

        prev = stored.get(mac)
        if prev is None:
            cur.execute(
                """INSERT INTO mikrotik_dhcp_leases
                   (nas_id, mac, ip, hostname, comment, server, is_static,
                    status, class_id, first_seen, last_seen, active)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,true)
                   ON CONFLICT (nas_id, mac) DO NOTHING""",
                (nas_id, mac, ip, host, comment, server, is_static, status, class_id, now, now),
            )
            if ip:
                cur.execute(
                    """INSERT INTO mikrotik_dhcp_ip_history
                       (nas_id, mac, ip, seen_from) VALUES (%s,%s,%s,%s)""",
                    (nas_id, mac, ip, now),
                )
            added += 1
        else:
            # IP change? close old open interval, open new
            if ip and prev["ip"] != ip:
                cur.execute(
                    """UPDATE mikrotik_dhcp_ip_history SET seen_to=%s
                       WHERE nas_id=%s AND mac=%s AND seen_to IS NULL""",
                    (now, nas_id, mac),
                )
                cur.execute(
                    """INSERT INTO mikrotik_dhcp_ip_history
                       (nas_id, mac, ip, seen_from) VALUES (%s,%s,%s,%s)""",
                    (nas_id, mac, ip, now),
                )
                ip_changed += 1
            cur.execute(
                """UPDATE mikrotik_dhcp_leases
                   SET ip=COALESCE(%s,ip), hostname=COALESCE(%s,hostname),
                       comment=COALESCE(%s,comment), server=COALESCE(%s,server),
                       is_static=%s, status=%s, class_id=COALESCE(%s,class_id),
                       last_seen=%s, active=true
                   WHERE nas_id=%s AND mac=%s""",
                (ip, host, comment, server, is_static, status, class_id, now, nas_id, mac),
            )
            updated += 1

    # mark leases not seen this poll as inactive (but keep the row + history)
    if seen_macs:
        cur.execute(
            "UPDATE mikrotik_dhcp_leases SET active=false "
            "WHERE nas_id=%s AND active=true AND NOT (mac = ANY(%s))",
            (nas_id, list(seen_macs)),
        )
    else:
        cur.execute("UPDATE mikrotik_dhcp_leases SET active=false WHERE nas_id=%s", (nas_id,))

    conn.commit()
    return {"added": added, "updated": updated, "ip_changed": ip_changed,
            "seen": len(seen_macs)}


def poll_nas(conn, nas):
    """Connect to one NAS's API and poll its DHCP leases."""
    nas_id = nas["id"]; name = nas["name"]
    host = nas.get("api_host") or nas.get("source_ip") or nas["ip_address"]
    port = int(nas.get("api_port") or (8729 if nas.get("api_ssl") else 8728))
    user = nas.get("api_user") or "elbipdr"
    pw = mt_crypto.decrypt(nas["api_password_enc"])
    log.info("nas %s (%s:%s): connecting", name, host, port)
    kw = dict(username=user, password=pw, host=host, port=port)
    if nas.get("api_ssl"):
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
        kw["ssl_wrapper"] = ctx.wrap_socket
    api = connect(**kw)
    try:
        leases = list(api.path("ip", "dhcp-server", "lease"))
    finally:
        try: api.close()
        except Exception: pass
    now = datetime.now()  # local-time (matches PG now(); column is tz-naive local)
    stats = apply_leases(conn, nas_id, leases, now)
    log.info("nas %s: leases=%d added=%d updated=%d ip_changed=%d",
             name, stats["seen"], stats["added"], stats["updated"], stats["ip_changed"])
    return stats


def main():
    only = None
    if "--nas-id" in sys.argv:
        only = int(sys.argv[sys.argv.index("--nas-id") + 1])
    conn = psycopg2.connect(_dsn())
    cur = conn.cursor(cursor_factory=RealDictCursor)
    q = ("SELECT * FROM nas_devices WHERE nas_type='mikrotik' AND api_enabled=true "
         "AND api_password_enc IS NOT NULL")
    params = []
    if only:
        q += " AND id=%s"; params.append(only)
    cur.execute(q, params)
    nas_list = cur.fetchall()
    total = 0
    for nas in nas_list:
        try:
            s = poll_nas(conn, nas)
            total += s["seen"]
        except Exception as e:
            conn.rollback()
            log.error("nas %s: DHCP poll failed: %s", nas["name"], e)
    log.info("dhcp poll complete: %d lease(s) across %d NAS", total, len(nas_list))
    conn.close()


if __name__ == "__main__":
    main()
