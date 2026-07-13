#!/usr/bin/env python3
"""
mikrotik_arp_poll.py — poll /ip arp on each API-enabled MikroTik NAS and track
STATIC ARP entries (infrastructure devices: OLTs, switches, CCTV, statically-
addressed hosts) in mikrotik_arp.

Classification (per the router ARP analysis):
  * dhcp == true            -> a DHCP-learned entry; belongs to the DHCP views,
                               NOT tracked here.
  * interface contains WAN  -> upstream/transit gateway; excluded.
  * everything else         -> STATIC ARP (Management-900, CCTV, other VLANs).

Open/update model: first sighting inserts a row; subsequent polls update
last_seen + status. Rows are preserved (not deleted) for attribution history.

Usage: IPDR_ENV=/opt/ipdr/.env python3 mikrotik_arp_poll.py
Env: DATABASE_URL, MT_FERNET_KEY (from .env).
"""
import os
import sys
import logging
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from librouteros import connect

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mt_crypto

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s mt-arp-poll %(levelname)s %(message)s")
log = logging.getLogger("mt-arp-poll")


def _dsn():
    dsn = os.environ.get("DATABASE_URL")
    if dsn:
        return dsn
    for env_path in (os.environ.get("IPDR_ENV"), os.environ.get("ELB_ENV"),
                     "/opt/ipdr/.env", "/opt/elb-ipdr/.env"):
        if env_path and os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.startswith("DATABASE_URL="):
                        return line.split("=", 1)[1].strip()
    raise RuntimeError("DATABASE_URL not found")


def _is_static(d):
    """True if this ARP entry is a static infrastructure entry we track."""
    # DHCP-learned entries are handled by the DHCP views, not here.
    if str(d.get("dhcp")).lower() == "true":
        return False
    iface = str(d.get("interface") or "")
    if "WAN" in iface.upper():
        return False
    # must have an address to be useful
    if not d.get("address"):
        return False
    return True


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
    bogon = {"drop": False, "accept": False, "script": False, "local": 0}
    try:
        api = connect(username=user, password=password, host=host, port=port)
        arp = list(api.path("ip", "arp"))
        # bogon-mitigation detection on the same connection
        try:
            for r in api.path("ip", "firewall", "raw"):
                d = dict(r); cm = (d.get("comment") or "").lower()
                if "bogon" in cm and d.get("action") == "drop":
                    bogon["drop"] = True
                if "local device" in cm and d.get("action") == "accept":
                    bogon["accept"] = True
            for a in api.path("ip", "firewall", "address-list"):
                if dict(a).get("list") == "LOCAL_DEVICES":
                    bogon["local"] += 1
            for s in api.path("system", "script"):
                if dict(s).get("name") == "sync-local-devices":
                    bogon["script"] = True; break
        except Exception as _be:
            log.warning("nas %s: bogon detect failed: %s", nas["name"], _be)
        api.close()
    except Exception as e:
        log.error("nas %s: /ip arp poll failed: %s", nas["name"], e)
        return
    # store cached bogon status
    try:
        _cfg = bogon["drop"] and bogon["accept"] and bogon["script"]
        with conn.cursor() as _c:
            _c.execute(
                "UPDATE nas_devices SET bogon_configured=%s, bogon_local_devices=%s, "
                "bogon_has_drop=%s, bogon_has_accept=%s, bogon_has_script=%s, "
                "bogon_checked_at=now() WHERE id=%s",
                (_cfg, bogon["local"], bogon["drop"], bogon["accept"],
                 bogon["script"], nas_id),
            )
        conn.commit()
    except Exception as _ue:
        log.warning("nas %s: bogon status store failed: %s", nas["name"], _ue)

    now = datetime.now()
    rows = []
    for entry in arp:
        d = dict(entry)
        if not _is_static(d):
            continue
        rows.append((
            nas_id,
            d.get("address"),
            (d.get("mac-address") or None),
            str(d.get("interface") or ""),
            (d.get("status") or None),
            now, now,
        ))

    if not rows:
        log.info("nas %s: no static ARP entries", nas["name"])
        return

    with conn.cursor() as cur:
        execute_values(
            cur,
            "INSERT INTO mikrotik_arp "
            "(nas_id, ip_address, mac_address, interface, status, first_seen, last_seen) "
            "VALUES %s "
            "ON CONFLICT (nas_id, ip_address, mac_address) DO UPDATE SET "
            "  interface = EXCLUDED.interface, "
            "  status    = EXCLUDED.status, "
            "  last_seen = EXCLUDED.last_seen",
            rows,
        )
    conn.commit()
    log.info("nas %s: upserted %d static ARP entries", nas["name"], len(rows))


def main():
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
        poll_nas(conn, nas)
    conn.close()


if __name__ == "__main__":
    main()
