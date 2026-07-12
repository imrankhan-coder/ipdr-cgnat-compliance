#!/usr/bin/env python3
"""
mikrotik_secrets_sync.py — pull /ppp/secret from each API-enabled MikroTik NAS
into the mikrotik_secrets cache table (for LEA enrichment).

Reads nas_devices for rows where nas_type='mikrotik' AND api_enabled,
decrypts the stored API password, connects via librouteros, upserts every
secret, and extracts a phone number from the comment when present.

Run manually or via cron/systemd-timer (hourly is plenty):
    /opt/ipdr/venv/bin/python /opt/ipdr/scripts/mikrotik_secrets_sync.py

Env: DATABASE_URL (libpq DSN) from .env; MT_FERNET_KEY from .env.
"""

import os
import re
import sys
import logging

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from librouteros import connect

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mt_crypto

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s mt-secrets-sync %(levelname)s %(message)s")
log = logging.getLogger("mt-secrets-sync")

# Pakistani mobile: 03xx-xxxxxxx or 03xxxxxxxxx or +923xxxxxxxxx (loose).
PHONE_RE = re.compile(r'(?:\+?92|0)?3\d{2}[-\s]?\d{7}')


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


def extract_phone(comment):
    if not comment:
        return None
    m = PHONE_RE.search(comment)
    if not m:
        return None
    digits = re.sub(r'[^\d]', '', m.group(0))
    # normalise to 03xxxxxxxxx
    if digits.startswith("92"):
        digits = "0" + digits[2:]
    if len(digits) == 10 and digits.startswith("3"):
        digits = "0" + digits
    return digits if len(digits) == 11 else m.group(0)


def sync_nas(conn, nas):
    nas_id = nas["id"]
    host = nas["api_host"] or nas["ip_address"]
    port = int(nas["api_port"] or 8728)
    user = nas["api_user"]
    try:
        password = mt_crypto.decrypt(nas["api_password_enc"])
    except Exception as e:
        log.error("nas %s: cannot decrypt API password: %s", nas["name"], e)
        return 0

    log.info("nas %s (%s:%s): connecting", nas["name"], host, port)
    try:
        api = connect(username=user, password=password, host=host, port=port)
    except Exception as e:
        log.error("nas %s: API connect failed: %s", nas["name"], e)
        return 0

    try:
        secrets = list(api.path("ppp", "secret"))
    except Exception as e:
        log.error("nas %s: /ppp/secret read failed: %s", nas["name"], e)
        try: api.close()
        except Exception: pass
        return 0
    try:
        api.close()
    except Exception:
        pass

    rows = []
    for s in secrets:
        name = s.get("name")
        if not name:
            continue
        comment = s.get("comment")
        rows.append((
            nas_id, name, comment, extract_phone(comment),
            s.get("caller-id"), s.get("last-caller-id"),
            s.get("profile"), s.get("service"),
            str(s.get("disabled", "false")).lower() in ("true", "yes"),
            s.get("last-logged-out"),
        ))

    if not rows:
        log.warning("nas %s: no secrets returned", nas["name"])
        return 0

    with conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO mikrotik_secrets
              (nas_id, username, comment, phone, caller_id, last_caller_id,
               profile, service, disabled, last_logged_out)
            VALUES %s
            ON CONFLICT (nas_id, username) DO UPDATE SET
              comment=EXCLUDED.comment, phone=EXCLUDED.phone,
              caller_id=EXCLUDED.caller_id, last_caller_id=EXCLUDED.last_caller_id,
              profile=EXCLUDED.profile, service=EXCLUDED.service,
              disabled=EXCLUDED.disabled, last_logged_out=EXCLUDED.last_logged_out,
              synced_at=now()
        """, rows, page_size=500)
    conn.commit()
    log.info("nas %s: upserted %d secret(s)", nas["name"], len(rows))
    return len(rows)


def main():
    conn = psycopg2.connect(_dsn(), cursor_factory=RealDictCursor)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM nas_devices "
            "WHERE nas_type='mikrotik' AND api_enabled = TRUE AND api_password_enc IS NOT NULL"
        )
        nases = cur.fetchall()
    conn.commit()
    if not nases:
        log.info("no API-enabled MikroTik NAS configured; nothing to sync")
        return
    total = 0
    for nas in nases:
        total += sync_nas(conn, nas)
    log.info("sync complete: %d secret(s) across %d NAS", total, len(nases))
    conn.close()


if __name__ == "__main__":
    main()
