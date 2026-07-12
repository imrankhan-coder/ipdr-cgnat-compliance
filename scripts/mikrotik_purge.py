#!/usr/bin/env python3
"""
mikrotik_purge.py — safe batched purge for mikrotik_translations.

Two modes:
  --udp          Delete all protocol='UDP' rows (one-time cleanup after
                 disabling UDP logging). Reclaims reusable space.
  --days N       Delete rows older than N days (ongoing retention). Run daily
                 via the systemd timer.

Batched (default 50k rows/batch) with a short pause so it never storms the
disk or holds long locks. Runs VACUUM (plain, non-blocking) at the end so freed
space is reused by new inserts (prevents further growth). Note: plain VACUUM
does NOT return space to the OS — that comes with partitioning (drop old
partitions). Full reclaim now would need VACUUM FULL/pg_repack (locks table),
which we avoid on a live compliance box.

Env: DATABASE_URL from .env (or PG* vars).
Examples:
  mikrotik_purge.py --udp
  mikrotik_purge.py --days 90
"""

import os
import sys
import time
import argparse
import logging

import psycopg2

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s mt-purge %(levelname)s %(message)s")
log = logging.getLogger("mt-purge")

BATCH = int(os.environ.get("MT_PURGE_BATCH", "50000"))
PAUSE = float(os.environ.get("MT_PURGE_PAUSE", "0.3"))


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


def batched_delete(conn, where_sql, params):
    """Delete matching rows in batches by id. Returns total deleted."""
    total = 0
    while True:
        with conn.cursor() as cur:
            cur.execute(
                f"""DELETE FROM mikrotik_translations
                    WHERE id IN (
                        SELECT id FROM mikrotik_translations
                        WHERE {where_sql}
                        ORDER BY id
                        LIMIT %s
                    )""",
                params + [BATCH],
            )
            n = cur.rowcount
        conn.commit()
        total += n
        if n:
            log.info("deleted %d (running total %d)", n, total)
        if n < BATCH:
            break
        time.sleep(PAUSE)
    return total


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--udp", action="store_true", help="delete all UDP rows")
    g.add_argument("--days", type=int, help="delete rows older than N days")
    ap.add_argument("--no-vacuum", action="store_true")
    args = ap.parse_args()

    conn = psycopg2.connect(_dsn())
    conn.autocommit = False

    if args.udp:
        log.info("purging protocol='UDP' rows (batch=%d)", BATCH)
        total = batched_delete(conn, "protocol = %s", ["UDP"])
    else:
        if args.days < 1:
            log.error("--days must be >= 1"); sys.exit(1)
        log.info("purging rows older than %d day(s) (batch=%d)", args.days, BATCH)
        total = batched_delete(
            conn, "log_time < now() - (%s || ' days')::interval", [str(args.days)]
        )

    log.info("purge complete: %d row(s) deleted", total)

    if total and not args.no_vacuum:
        log.info("running VACUUM ANALYZE (non-blocking)...")
        old_iso = conn.isolation_level
        conn.set_isolation_level(0)  # autocommit for VACUUM
        with conn.cursor() as cur:
            cur.execute("VACUUM ANALYZE mikrotik_translations")
        conn.set_isolation_level(old_iso)
        log.info("VACUUM done")

    conn.close()


if __name__ == "__main__":
    main()
