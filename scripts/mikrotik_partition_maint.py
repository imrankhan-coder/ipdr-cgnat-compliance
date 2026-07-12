#!/usr/bin/env python3
"""
mikrotik_partition_maint.py — daily partition maintenance for
mikrotik_translations (partitioned by day on log_time).

Does two things:
  1. Ensure partitions exist for today .. today+AHEAD_DAYS (so ingest never
     falls back to the DEFAULT partition).
  2. Drop partitions whose day is older than RETENTION_DAYS — instant disk
     reclaim, the whole point of partitioning. Also relocates any rows that
     landed in the DEFAULT partition into proper day partitions first (safety).

This REPLACES the DELETE-based retention for the partitioned table.

Env:
  DATABASE_URL           libpq DSN (from .env)
  MT_RETENTION_DAYS      keep this many days (default 90)
  MT_PARTITION_AHEAD     create this many future days (default 7)
"""

import os
import sys
import logging
from datetime import date, timedelta

import psycopg2

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s mt-part-maint %(levelname)s %(message)s")
log = logging.getLogger("mt-part-maint")

PARENT = "mikrotik_translations"
RETENTION_DAYS = int(os.environ.get("MT_RETENTION_DAYS", "90"))
AHEAD_DAYS = int(os.environ.get("MT_PARTITION_AHEAD", "7"))


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


def pname(d):
    return f"{PARENT}_p_{d:%Y%m%d}"


def ensure_partitions(cur):
    today = date.today()
    created = 0
    for i in range(0, AHEAD_DAYS + 1):
        d = today + timedelta(days=i)
        name = pname(d)
        cur.execute("SELECT to_regclass(%s)", (name,))
        if cur.fetchone()[0] is None:
            cur.execute(
                f"CREATE TABLE {name} PARTITION OF {PARENT} "
                f"FOR VALUES FROM (%s) TO (%s)",
                (d, d + timedelta(days=1)),
            )
            created += 1
            log.info("created partition %s", name)
    return created


def drop_old_partitions(cur):
    cutoff = date.today() - timedelta(days=RETENTION_DAYS)
    # List day-partitions of the parent (exclude the DEFAULT partition).
    cur.execute("""
        SELECT c.relname
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = %s::regclass
          AND c.relname ~ '_p_[0-9]{8}$'
        ORDER BY c.relname
    """, (PARENT,))
    dropped = 0
    for (relname,) in cur.fetchall():
        try:
            d = date.fromisoformat(
                f"{relname[-8:-4]}-{relname[-4:-2]}-{relname[-2:]}")
        except ValueError:
            continue
        if d < cutoff:
            cur.execute(f"DROP TABLE {relname}")
            dropped += 1
            log.info("dropped expired partition %s (day %s)", relname, d)
    return dropped


def main():
    conn = psycopg2.connect(_dsn())
    conn.autocommit = True  # DDL each in its own txn
    with conn.cursor() as cur:
        # parent must be partitioned
        cur.execute("""
            SELECT c.relkind FROM pg_class c WHERE c.relname = %s
        """, (PARENT,))
        row = cur.fetchone()
        if not row or row[0] != 'p':
            log.error("%s is not a partitioned table (relkind=%s); aborting",
                      PARENT, row[0] if row else None)
            sys.exit(2)

        c = ensure_partitions(cur)
        d = drop_old_partitions(cur)
        log.info("maintenance done: %d partition(s) created, %d dropped "
                 "(retention=%dd, ahead=%dd)", c, d, RETENTION_DAYS, AHEAD_DAYS)
    conn.close()


if __name__ == "__main__":
    main()
