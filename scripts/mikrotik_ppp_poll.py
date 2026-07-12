#!/usr/bin/env python3
"""
mikrotik_ppp_poll.py — poll /ppp/active on each API-enabled MikroTik NAS and
maintain mikrotik_ppp_sessions (open a row on first appearance, close it when it
vanishes). Run every ~1 minute via a systemd timer.

Session boundary semantics (defensible for LEA):
  session_start = first poll the login was seen (approximate login time)
  session_stop  = last_seen at the poll it disappeared (last CONFIRMED online)
  reconnect     = if router uptime drops below last recorded, the old session is
                  closed and a new one opened (login/out between polls).

Env: DATABASE_URL, MT_FERNET_KEY (from .env).
"""

import os
import re
import sys
import logging
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor
from librouteros import connect

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mt_crypto

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s mt-ppp-poll %(levelname)s %(message)s")
log = logging.getLogger("mt-ppp-poll")

_UPTIME_RE = re.compile(r'(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?')


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


def parse_uptime(s):
    """RouterOS uptime like '3d4h5m6s' -> seconds. None if unparseable."""
    if not s:
        return None
    m = _UPTIME_RE.fullmatch(s.strip())
    if not m:
        return None
    w, d, h, mi, se = (int(x) if x else 0 for x in m.groups())
    return ((((w * 7 + d) * 24 + h) * 60 + mi) * 60) + se


def apply_active(conn, nas_id, nas_name, active, now):
    """Diff the current /ppp/active list against open DB sessions and record
    logins/logouts/reconnects. Separated from the API call so it's testable."""
    cur_active = {}
    for a in active:
        name = a.get("name")
        if name:
            cur_active[name] = a

    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        "INSERT INTO mikrotik_ppp_poll_state (nas_id, last_poll) VALUES (%s, %s) "
        "ON CONFLICT (nas_id) DO UPDATE SET last_poll = EXCLUDED.last_poll",
        (nas_id, now),
    )
    cur.execute(
        "SELECT id, username, uptime_seconds, session_start FROM mikrotik_ppp_sessions "
        "WHERE nas_id=%s AND session_stop IS NULL", (nas_id,),
    )
    open_rows = {r["username"]: r for r in cur.fetchall()}

    opened = closed = updated = reconnected = 0
    for name, a in cur_active.items():
        up = parse_uptime(a.get("uptime"))
        framed = a.get("address")
        caller = a.get("caller-id")
        svc = a.get("service")
        rid = a.get(".id")
        row = open_rows.get(name)
        if row is None:
            cur.execute(
                """INSERT INTO mikrotik_ppp_sessions
                   (nas_id, username, framed_ip, caller_id, ppp_service,
                    router_session_id, session_start, last_seen, uptime_seconds)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (nas_id, username, session_start) DO NOTHING""",
                (nas_id, name, framed, caller, svc, rid, now, now, up),
            )
            opened += 1
        else:
            prev_up = row["uptime_seconds"]
            if prev_up is not None and up is not None and up + 5 < prev_up:
                cur.execute(
                    "UPDATE mikrotik_ppp_sessions SET session_stop=last_seen, "
                    "uptime_seconds=%s WHERE id=%s", (prev_up, row["id"]),
                )
                cur.execute(
                    """INSERT INTO mikrotik_ppp_sessions
                       (nas_id, username, framed_ip, caller_id, ppp_service,
                        router_session_id, session_start, last_seen, uptime_seconds)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (nas_id, username, session_start) DO NOTHING""",
                    (nas_id, name, framed, caller, svc, rid, now, now, up),
                )
                reconnected += 1
            else:
                cur.execute(
                    "UPDATE mikrotik_ppp_sessions SET last_seen=%s, uptime_seconds=%s, "
                    "framed_ip=COALESCE(%s,framed_ip), caller_id=COALESCE(%s,caller_id) "
                    "WHERE id=%s", (now, up, framed, caller, row["id"]),
                )
                updated += 1

    vanished = [r["id"] for name, r in open_rows.items() if name not in cur_active]
    if vanished:
        cur.execute(
            "UPDATE mikrotik_ppp_sessions SET session_stop=last_seen WHERE id = ANY(%s)",
            (vanished,),
        )
        closed = len(vanished)

    conn.commit()
    log.info("nas %s: active=%d opened=%d closed=%d reconnect=%d updated=%d",
             nas_name, len(cur_active), opened, closed, reconnected, updated)


def poll_nas(conn, nas):
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
        active = list(api.path("ppp", "active"))
        api.close()
    except Exception as e:
        log.error("nas %s: /ppp/active poll failed: %s", nas["name"], e)
        return
    apply_active(conn, nas_id, nas["name"], active, datetime.now())


def main():
    conn = psycopg2.connect(_dsn(), cursor_factory=RealDictCursor)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM nas_devices "
            "WHERE nas_type='mikrotik' AND api_enabled=TRUE AND api_password_enc IS NOT NULL"
        )
        nases = cur.fetchall()
    conn.commit()
    if not nases:
        log.info("no API-enabled MikroTik NAS; nothing to poll")
        return
    for nas in nases:
        poll_nas(conn, nas)
    conn.close()


if __name__ == "__main__":
    main()
