#!/usr/bin/env python3
"""
mikrotik_ingest.py  —  IPDR MikroTik ingest daemon.

Tails the rsyslog capture file, attributes each line to a NAS by source IP,
parses the NAT translation, and batch-inserts into mikrotik_translations.

Design
------
* Source-IP attribution is authoritative and comes from a FIXED front-of-line
  position (rsyslog's fromhost-ip), parsed independently of the body — so even
  a malformed body still gets attributed or safely dropped.
* Lines whose source IP is not a registered MikroTik NAS are DROPPED and
  counted (anti-spoof / anti-garbage). The NAS map refreshes periodically.
* Batch inserts via execute_values for throughput under burst.
* Follows log rotation done with copytruncate (detects truncation by size).
* Skip stats (no-nat-body, private-to-private, unknown-source) are logged
  periodically so silent breakage is visible.

Env (read from /opt/ipdr/.env or process env):
  PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD
Config constants below (path, batch size, flush interval) can move to .env later.
"""

import os
import re
import sys
import time
import signal
import logging

import psycopg2
from psycopg2.extras import execute_values

# --- allow importing the sibling parser ------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mikrotik_parser import parse_line

CAPTURE_FILE   = os.environ.get("MT_CAPTURE_FILE", "/var/log/mikrotik/ingest.log")
BATCH_SIZE     = int(os.environ.get("MT_BATCH_SIZE", "500"))
FLUSH_SECONDS  = float(os.environ.get("MT_FLUSH_SECONDS", "2.0"))
NASMAP_REFRESH = float(os.environ.get("MT_NASMAP_REFRESH", "60"))
STATS_EVERY    = float(os.environ.get("MT_STATS_EVERY", "300"))

# Front-of-line extractor: collector-ts (rfc3339 or space) + source IP.
# Independent of body parsing so attribution never depends on a clean NAT clause.
FRONT_RE = re.compile(
    r'^(?P<collector_ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}'
    r'(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+'
    r'(?:[A-Za-z]+\.[A-Za-z]+\s+)?'
    r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s'
)

INSERT_SQL = """
    INSERT INTO mikrotik_translations
        (nas_id, log_time, collector_ts, router_ip, hostname, iface, username,
         private_ip, private_port, public_ip, public_port,
         dest_ip, dest_port, protocol, tcp_flags, conn_state, raw_log, src_mac)
    VALUES %s
"""

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s mikrotik-ingest %(levelname)s %(message)s",
)
log = logging.getLogger("mikrotik-ingest")


class Ingestor:
    def __init__(self):
        self.conn = None
        self.nas_by_ip = {}          # src_ip -> nas_id
        self.nasmap_loaded = 0.0
        self.buf = []                # pending rows
        self.last_flush = time.time()
        self.stats = {"inserted": 0, "no_nat_body": 0,
                      "private_to_private": 0, "unknown_source": 0}
        self.last_stats = time.time()
        self.running = True

    # --- db -----------------------------------------------------------------
    def db(self):
        if self.conn is None or self.conn.closed:
            dsn = os.environ.get("DATABASE_URL")
            if dsn:
                # .env stores a libpq keyword DSN, e.g.
                #   host=127.0.0.1 dbname=ipdr user=ipdr_user password=...
                self.conn = psycopg2.connect(dsn)
            else:
                self.conn = psycopg2.connect(
                    host=os.environ.get("PGHOST", "127.0.0.1"),
                    port=os.environ.get("PGPORT", "5432"),
                    dbname=os.environ.get("PGDATABASE", "ipdr"),
                    user=os.environ.get("PGUSER", "ipdr"),
                    password=os.environ.get("PGPASSWORD", ""),
                )
            self.conn.autocommit = False
        return self.conn

    def refresh_nasmap(self, force=False):
        now = time.time()
        if not force and (now - self.nasmap_loaded) < NASMAP_REFRESH:
            return
        try:
            with self.db().cursor() as cur:
                # MikroTik NASes: attribution key is source_ip. Only enabled rows.
                cur.execute(
                    "SELECT source_ip, id FROM nas_devices "
                    "WHERE source_ip IS NOT NULL AND source_ip <> '' "
                    "AND nas_type = 'mikrotik' AND enabled = true"
                )
                rows = cur.fetchall()
            self.db().commit()
            self.nas_by_ip = {ip: nid for ip, nid in rows}
            self.nasmap_loaded = now
            log.info("nas map refreshed: %d source IP(s) known", len(self.nas_by_ip))
        except Exception as e:
            log.error("nas map refresh failed: %s", e)
            try:
                self.db().rollback()
            except Exception:
                pass

    # --- ingest -------------------------------------------------------------
    def handle_line(self, line):
        front = FRONT_RE.match(line)
        if not front:
            return  # not a capture line we understand; skip quietly
        src_ip = front.group("src_ip")
        nas_id = self.nas_by_ip.get(src_ip)
        if nas_id is None:
            self.stats["unknown_source"] += 1
            return

        res = parse_line(line, nas_id=nas_id)
        if not res.ok:
            key = res.reason.replace("-", "_")
            if key in self.stats:
                self.stats[key] += 1
            return

        r = res.record
        self.buf.append((
            r["nas_id"], r["log_time"], r["collector_ts"], r["router_ip"],
            r["hostname"], r["iface"], r["username"], r["private_ip"],
            r["private_port"], r["public_ip"], r["public_port"], r["dest_ip"],
            r["dest_port"], r["protocol"], r["tcp_flags"], r["conn_state"],
            r["raw_log"], r.get("src_mac"),
        ))
        if len(self.buf) >= BATCH_SIZE:
            self.flush()

    def flush(self):
        if not self.buf:
            self.last_flush = time.time()
            return
        rows, self.buf = self.buf, []
        try:
            with self.db().cursor() as cur:
                execute_values(cur, INSERT_SQL, rows, page_size=500)
            self.db().commit()
            self.stats["inserted"] += len(rows)
        except Exception as e:
            log.error("insert failed (%d rows dropped from buffer): %s", len(rows), e)
            try:
                self.db().rollback()
            except Exception:
                self.conn = None  # force reconnect next time
        self.last_flush = time.time()

    def maybe_stats(self):
        now = time.time()
        if (now - self.last_stats) >= STATS_EVERY:
            log.info("stats: %s", self.stats)
            self.last_stats = now

    def _open_capture(self):
        """Open the capture file, waiting/retrying until it exists. Never raises."""
        while self.running:
            try:
                f = open(CAPTURE_FILE, "r")
                f.seek(0, os.SEEK_END)   # tail; don't re-ingest history
                return f
            except FileNotFoundError:
                log.info("waiting for capture file %s", CAPTURE_FILE)
                time.sleep(2)
        return None

    # --- tail loop ----------------------------------------------------------
    def run(self):
        self.refresh_nasmap(force=True)
        f = self._open_capture()
        if f is None:
            return
        inode = os.fstat(f.fileno()).st_ino

        while self.running:
            line = f.readline()
            if line:
                self.handle_line(line.rstrip("\n"))
                continue

            # no data: periodic housekeeping
            self.refresh_nasmap()
            now = time.time()
            if self.buf and (now - self.last_flush) >= FLUSH_SECONDS:
                self.flush()
            self.maybe_stats()

            # detect rotation: copytruncate (size shrank) or new inode
            try:
                st = os.stat(CAPTURE_FILE)
                if st.st_ino != inode or f.tell() > st.st_size:
                    log.info("capture file rotated; reopening")
                    f.close()
                    f = self._open_capture()
                    if f is None:
                        break
                    inode = os.fstat(f.fileno()).st_ino
                    continue
            except FileNotFoundError:
                time.sleep(1)
                continue

            time.sleep(0.2)

        self.flush()
        log.info("shutdown flush complete; final stats: %s", self.stats)

    def stop(self, *_):
        self.running = False


def main():
    ing = Ingestor()
    signal.signal(signal.SIGTERM, ing.stop)
    signal.signal(signal.SIGINT, ing.stop)
    ing.run()


if __name__ == "__main__":
    main()
