#!/usr/bin/env python3
"""
nat_parser.py — Parses Juniper MX NAT syslog messages and inserts into PostgreSQL.

Reads syslog lines from:
  1. A named pipe (rsyslog omprog) — primary/real-time
  2. Or stdin for batch replay of log files

Handles these Juniper MX syslog message types:
  - RT_SRC_NAT_PBA_ALLOC      — Port block allocated to subscriber
  - RT_SRC_NAT_PBA_RELEASE     — Port block released
  - RT_SRC_NAT_PBA_INTERIM     — Periodic interim report (every 86400s)
  - RT_NAT_RULE_MATCH          — Per-flow NAT rule match (optional, high volume)

Usage:
  # Real-time via rsyslog omprog:
  python3 nat_parser.py --mode pipe

  # Batch replay of old logs:
  cat /var/log/nat/*.log | python3 nat_parser.py --mode stdin

  # Watch a log file:
  tail -F /var/log/nat/nat.log | python3 nat_parser.py --mode stdin
"""

import sys
import os
import re
import signal
import logging
import argparse
from datetime import datetime
from collections import deque

import psycopg2
import psycopg2.extras

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DB_DSN = os.environ.get(
    "DATABASE_URL",
    "host=127.0.0.1 dbname=ipdr user=ipdr_user password=changeme"
)

PIPE_PATH = "/var/run/ipdr/nat-syslog.pipe"
BATCH_SIZE = 100  # Flush to DB every N records
FLUSH_INTERVAL = 5  # Or every N seconds

LOG_FMT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
log = logging.getLogger("nat-parser")

# ---------------------------------------------------------------------------
# Regex patterns for Juniper MX NAT syslog
# ---------------------------------------------------------------------------

# PBA_ALLOC example:
# <14>Jun 30 22:44:25 SITE-B-BNG-01 RT_NAT: RT_SRC_NAT_PBA_ALLOC:
# Subscriber 100.64.60.74 used/maximum [10/15] blocks, allocates port block
# [24064-24191] from 203.0.113.100 in source pool EXAMPLE_POOL lsys_id: 0 epoch 0x6a44007a

RE_PBA_ALLOC = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"RT_NAT:\s*RT_SRC_NAT_PBA_ALLOC:\s*"
    r"Subscriber\s+(?P<subscriber_ip>[\d.]+)\s+"
    r"used/maximum\s+\[(?P<used>\d+)/(?P<max>\d+)\]\s+blocks,\s+"
    r"allocates\s+port\s+block\s+\[(?P<port_start>\d+)-(?P<port_end>\d+)\]\s+"
    r"from\s+(?P<public_ip>[\d.]+)\s+"
    r"in\s+source\s+pool\s+(?P<pool>\S+)"
    r"(?:\s+lsys_id:\s*\d+)?"
    r"(?:\s+epoch\s+(?P<epoch>\S+))?"
)

# PBA_RELEASE example:
# RT_SRC_NAT_PBA_RELEASE: Subscriber 100.64.x.x used/maximum [5/15] blocks,
# releases port block [1024-1151] from 203.0.113.x in source pool EXAMPLE_POOL
RE_PBA_RELEASE = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"RT_NAT:\s*RT_SRC_NAT_PBA_RELEASE:\s*"
    r"Subscriber\s+(?P<subscriber_ip>[\d.]+)\s+"
    r"used/maximum\s+\[(?P<used>\d+)/(?P<max>\d+)\]\s+blocks,\s+"
    r"releases\s+port\s+block\s+\[(?P<port_start>\d+)-(?P<port_end>\d+)\]\s+"
    r"from\s+(?P<public_ip>[\d.]+)\s+"
    r"in\s+source\s+pool\s+(?P<pool>\S+)"
    r"(?:\s+lsys_id:\s*\d+)?"
    r"(?:\s+epoch\s+(?P<epoch>\S+))?"
)

# PBA_INTERIM — same format as ALLOC but with INTERIM keyword
RE_PBA_INTERIM = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"RT_NAT:\s*RT_SRC_NAT_PBA_INTERIM:\s*"
    r"Subscriber\s+(?P<subscriber_ip>[\d.]+)\s+"
    r"used/maximum\s+\[(?P<used>\d+)/(?P<max>\d+)\]\s+blocks,\s+"
    r"(?:port\s+block\s+\[(?P<port_start>\d+)-(?P<port_end>\d+)\]\s+)?"
    r"from\s+(?P<public_ip>[\d.]+)\s+"
    r"in\s+source\s+pool\s+(?P<pool>\S+)"
)

# RT_NAT_RULE_MATCH example:
# RT_NAT: RT_NAT_RULE_MATCH: protocol-id 6 protocol-name tcp application junos-https
# interface-name ae0.32767 source-address 100.64.4.199 source-port 42730
# destination-address 138.199.14.51 destination-port 443
# rule-set-name CGN_PLUS_0 rule-name 3
RE_RULE_MATCH = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"RT_NAT:\s*RT_NAT_RULE_MATCH:\s*"
    r"protocol-id\s+(?P<proto_id>\d+)\s+"
    r"protocol-name\s+(?P<proto_name>\S+)\s+"
    r"application\s+(?P<application>\S+)\s+"
    r"interface-name\s+(?P<interface>\S+)\s+"
    r"source-address\s+(?P<src_ip>[\d.]+)\s+"
    r"source-port\s+(?P<src_port>\d+)\s+"
    r"destination-address\s+(?P<dst_ip>[\d.]+)\s+"
    r"destination-port\s+(?P<dst_port>\d+)\s+"
    r"rule-set-name\s+(?P<rule_set>\S+)\s+"
    r"rule-name\s+(?P<rule_name>\S+)"
)

# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------
CURRENT_YEAR = datetime.now().year

def parse_syslog_timestamp(ts_str):
    """Parse syslog timestamp like 'Jun 30 22:44:25' — assumes current year."""
    try:
        dt = datetime.strptime(f"{CURRENT_YEAR} {ts_str}", "%Y %b %d %H:%M:%S")
        # Handle year rollover (Dec logs replayed in Jan)
        if dt.month == 12 and datetime.now().month == 1:
            dt = dt.replace(year=CURRENT_YEAR - 1)
        return dt
    except ValueError:
        return datetime.now()

# ---------------------------------------------------------------------------
# Database insert
# ---------------------------------------------------------------------------
class DBWriter:
    def __init__(self, dsn):
        self.dsn = dsn
        self.conn = None
        self.nat_buffer = deque()
        self.flow_buffer = deque()
        self.connect()

    def connect(self):
        try:
            self.conn = psycopg2.connect(self.dsn)
            self.conn.autocommit = False
            log.info("Connected to PostgreSQL")
        except Exception as e:
            log.error(f"DB connection failed: {e}")
            self.conn = None

    def reconnect(self):
        try:
            if self.conn:
                self.conn.close()
        except:
            pass
        self.connect()

    def flush_nat(self):
        if not self.nat_buffer:
            return
        if not self.conn:
            self.reconnect()
            if not self.conn:
                return

        try:
            cur = self.conn.cursor()
            psycopg2.extras.execute_values(
                cur,
                """INSERT INTO nat_logs
                   (log_time, log_type, subscriber_ip, public_ip,
                    port_block_start, port_block_end, blocks_used, blocks_max,
                    nat_pool, epoch, nas_hostname, raw_log)
                   VALUES %s""",
                list(self.nat_buffer),
                template="(%(log_time)s, %(log_type)s, %(subscriber_ip)s, %(public_ip)s, "
                         "%(port_block_start)s, %(port_block_end)s, %(blocks_used)s, %(blocks_max)s, "
                         "%(nat_pool)s, %(epoch)s, %(nas_hostname)s, %(raw_log)s)",
            )
            self.conn.commit()
            count = len(self.nat_buffer)
            self.nat_buffer.clear()
            log.info(f"Flushed {count} NAT PBA records")
        except Exception as e:
            log.error(f"NAT flush error: {e}")
            self.conn.rollback()
            self.reconnect()

    def flush_flow(self):
        if not self.flow_buffer:
            return
        if not self.conn:
            self.reconnect()
            if not self.conn:
                return

        try:
            cur = self.conn.cursor()
            psycopg2.extras.execute_values(
                cur,
                """INSERT INTO nat_flow_logs
                   (log_time, protocol, protocol_name, application,
                    source_ip, source_port, destination_ip, destination_port,
                    rule_set, rule_name, interface_name, raw_log)
                   VALUES %s""",
                list(self.flow_buffer),
                template="(%(log_time)s, %(protocol)s, %(protocol_name)s, %(application)s, "
                         "%(source_ip)s, %(source_port)s, %(destination_ip)s, %(destination_port)s, "
                         "%(rule_set)s, %(rule_name)s, %(interface_name)s, %(raw_log)s)",
            )
            self.conn.commit()
            count = len(self.flow_buffer)
            self.flow_buffer.clear()
            log.info(f"Flushed {count} NAT flow records")
        except Exception as e:
            log.error(f"Flow flush error: {e}")
            self.conn.rollback()
            self.reconnect()

    def flush_all(self):
        self.flush_nat()
        self.flush_flow()

    def add_pba(self, record):
        self.nat_buffer.append(record)
        if len(self.nat_buffer) >= BATCH_SIZE:
            self.flush_nat()

    def add_flow(self, record):
        self.flow_buffer.append(record)
        if len(self.flow_buffer) >= BATCH_SIZE:
            self.flush_flow()

    def update_release(self, subscriber_ip, public_ip, port_start, port_end, release_time):
        """When a PBA_RELEASE comes, mark the corresponding ALLOC with release_time."""
        if not self.conn:
            return
        try:
            cur = self.conn.cursor()
            cur.execute(
                """UPDATE nat_logs SET release_time = %s
                   WHERE ctid = (
                     SELECT ctid FROM nat_logs
                     WHERE subscriber_ip = %s AND public_ip = %s
                       AND port_block_start = %s AND port_block_end = %s
                       AND log_type = 'PBA_ALLOC' AND release_time IS NULL
                     ORDER BY log_time DESC LIMIT 1
                   )""",
                (release_time, subscriber_ip, public_ip, port_start, port_end),
            )
            self.conn.commit()
        except Exception as e:
            log.error(f"Release update error: {e}")
            self.conn.rollback()

# ---------------------------------------------------------------------------
# Line parser
# ---------------------------------------------------------------------------
def parse_line(line, db_writer):
    """Parse a single syslog line and route to appropriate handler."""
    line = line.strip()
    if not line:
        return

    # Strip syslog priority tag if present: <14>...
    line = re.sub(r"^<\d+>", "", line)

    # Try PBA_ALLOC
    m = RE_PBA_ALLOC.search(line)
    if m:
        d = m.groupdict()
        record = {
            "log_time": parse_syslog_timestamp(d["timestamp"]),
            "log_type": "PBA_ALLOC",
            "subscriber_ip": d["subscriber_ip"],
            "public_ip": d["public_ip"],
            "port_block_start": int(d["port_start"]),
            "port_block_end": int(d["port_end"]),
            "blocks_used": int(d["used"]),
            "blocks_max": int(d["max"]),
            "nat_pool": d["pool"],
            "epoch": d.get("epoch"),
            "nas_hostname": d["hostname"],
            "raw_log": line[:2000],
        }
        db_writer.add_pba(record)
        return

    # Try PBA_RELEASE
    m = RE_PBA_RELEASE.search(line)
    if m:
        d = m.groupdict()
        release_time = parse_syslog_timestamp(d["timestamp"])
        record = {
            "log_time": release_time,
            "log_type": "PBA_RELEASE",
            "subscriber_ip": d["subscriber_ip"],
            "public_ip": d["public_ip"],
            "port_block_start": int(d["port_start"]),
            "port_block_end": int(d["port_end"]),
            "blocks_used": int(d["used"]),
            "blocks_max": int(d["max"]),
            "nat_pool": d["pool"],
            "epoch": d.get("epoch"),
            "nas_hostname": d["hostname"],
            "raw_log": line[:2000],
        }
        db_writer.add_pba(record)
        # Mark the ALLOC record with release time
        db_writer.update_release(
            d["subscriber_ip"], d["public_ip"],
            int(d["port_start"]), int(d["port_end"]),
            release_time,
        )
        return

    # Try PBA_INTERIM
    m = RE_PBA_INTERIM.search(line)
    if m:
        d = m.groupdict()
        record = {
            "log_time": parse_syslog_timestamp(d["timestamp"]),
            "log_type": "PBA_INTERIM",
            "subscriber_ip": d["subscriber_ip"],
            "public_ip": d["public_ip"],
            "port_block_start": int(d["port_start"]) if d.get("port_start") else None,
            "port_block_end": int(d["port_end"]) if d.get("port_end") else None,
            "blocks_used": int(d["used"]),
            "blocks_max": int(d["max"]),
            "nat_pool": d["pool"],
            "epoch": None,
            "nas_hostname": d["hostname"],
            "raw_log": line[:2000],
        }
        db_writer.add_pba(record)
        return

    # Try RULE_MATCH (per-flow)
    m = RE_RULE_MATCH.search(line)
    if m:
        d = m.groupdict()
        record = {
            "log_time": parse_syslog_timestamp(d["timestamp"]),
            "protocol": d["proto_id"],
            "protocol_name": d["proto_name"],
            "application": d["application"],
            "source_ip": d["src_ip"],
            "source_port": int(d["src_port"]),
            "destination_ip": d["dst_ip"],
            "destination_port": int(d["dst_port"]),
            "rule_set": d["rule_set"],
            "rule_name": d["rule_name"],
            "interface_name": d["interface"],
            "raw_log": line[:2000],
        }
        db_writer.add_flow(record)
        return

    # Unknown line — skip silently (could be other syslog noise)

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="IPDR NAT Syslog Parser")
    parser.add_argument("--mode", choices=["pipe", "stdin"], default="stdin",
                        help="Input mode: 'pipe' for named pipe, 'stdin' for stdin")
    parser.add_argument("--pipe-path", default=PIPE_PATH,
                        help="Path to named pipe (pipe mode only)")
    parser.add_argument("--dsn", default=DB_DSN, help="PostgreSQL DSN")
    args = parser.parse_args()

    db_writer = DBWriter(args.dsn)

    # Graceful shutdown
    def shutdown(sig, frame):
        log.info("Shutting down, flushing buffers...")
        db_writer.flush_all()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    lines_processed = 0

    if args.mode == "stdin":
        log.info("Reading NAT syslog from stdin...")
        for line in sys.stdin:
            parse_line(line, db_writer)
            lines_processed += 1
            if lines_processed % 10000 == 0:
                log.info(f"Processed {lines_processed} lines")
                db_writer.flush_all()
        db_writer.flush_all()
        log.info(f"Done. Total lines processed: {lines_processed}")

    elif args.mode == "pipe":
        pipe_path = args.pipe_path
        os.makedirs(os.path.dirname(pipe_path), exist_ok=True)
        if not os.path.exists(pipe_path):
            os.mkfifo(pipe_path)
            log.info(f"Created named pipe: {pipe_path}")

        log.info(f"Reading NAT syslog from pipe: {pipe_path}")
        while True:
            try:
                with open(pipe_path, "r") as pipe:
                    for line in pipe:
                        parse_line(line, db_writer)
                        lines_processed += 1
                        if lines_processed % 1000 == 0:
                            db_writer.flush_all()
            except Exception as e:
                log.error(f"Pipe read error: {e}")
                db_writer.flush_all()
                import time
                time.sleep(1)

if __name__ == "__main__":
    main()
