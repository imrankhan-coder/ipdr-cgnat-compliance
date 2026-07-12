#!/usr/bin/env python3
"""
radius_parser.py — Parses FreeRADIUS accounting detail files into PostgreSQL.

FreeRADIUS writes detail files to /var/log/radius/radacct/<nas>/detail-YYYYMMDD.
This daemon watches those files and inserts accounting records into the
radius_accounting table.

It can also be pointed at a single detail file for batch replay.

Usage:
  # Watch mode (production):
  python3 radius_parser.py --mode watch --dir /var/log/radius/radacct

  # Batch mode (replay old files):
  python3 radius_parser.py --mode batch --file /var/log/radius/radacct/163.61.128.2/detail-20260630
"""

import sys
import os
import re
import time
import signal
import logging
import argparse
import glob
from datetime import datetime
from pathlib import Path

import psycopg2
import psycopg2.extras

DB_DSN = os.environ.get(
    "DATABASE_URL",
    "host=127.0.0.1 dbname=ipdr user=ipdr_user password=changeme"
)

LOG_FMT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
log = logging.getLogger("radius-parser")

# Track file positions for tail-like behavior
POSITION_FILE = "/var/lib/ipdr/radius-positions.txt"

# ---------------------------------------------------------------------------
# Detail file parser
# ---------------------------------------------------------------------------
def parse_detail_records(filepath):
    """Yield accounting records from a FreeRADIUS detail file."""
    record = {}
    timestamp = None

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")

            # Record separator — timestamp line
            if line.startswith("\t") and "=" in line:
                key, _, value = line.strip().partition(" = ")
                key = key.strip()
                value = value.strip().strip('"')
                record[key] = value

            elif line == "":
                # Blank line = end of record
                if record:
                    yield record
                    record = {}

            elif not line.startswith("\t"):
                # Timestamp line like: Mon Jun 30 22:44:25 2026
                if record:
                    yield record
                    record = {}
                # Try to parse timestamp
                try:
                    # Format: Day Mon DD HH:MM:SS YYYY
                    timestamp = datetime.strptime(line.strip(), "%a %b %d %H:%M:%S %Y")
                    record["_timestamp"] = timestamp
                except ValueError:
                    pass

        # Last record in file
        if record:
            yield record


def record_to_db_row(record):
    """Convert a FreeRADIUS detail record dict to a DB insert dict."""
    raw_status = record.get("Acct-Status-Type", "").strip()
    # Normalize: match FreeRADIUS's canonical casing without breaking hyphenated names
    status_map = {
        "start": "Start", "stop": "Stop",
        "interim-update": "Interim-Update",
        "accounting-on": "Accounting-On", "accounting-off": "Accounting-Off",
    }
    acct_status = status_map.get(raw_status.lower())
    if acct_status is None:
        return None

    username = record.get("User-Name", "")
    if not username:
        return None

    framed_ip = record.get("Framed-IP-Address")
    session_id = record.get("Acct-Session-Id", "")
    calling = record.get("Calling-Station-Id", "")  # MAC
    called = record.get("Called-Station-Id", "")
    nas_ip = record.get("NAS-IP-Address")
    nas_port = record.get("NAS-Port")
    nas_port_id = record.get("NAS-Port-Id", "")
    nas_port_type = record.get("NAS-Port-Type", "")
    service_type = record.get("Service-Type", "")
    session_time = record.get("Acct-Session-Time")
    input_octets = record.get("Acct-Input-Octets", "0")
    output_octets = record.get("Acct-Output-Octets", "0")
    terminate_cause = record.get("Acct-Terminate-Cause", "")
    delegated_ipv6 = record.get("Delegated-IPv6-Prefix", "")
    framed_ipv6 = record.get("Framed-IPv6-Prefix", "")

    # Calculate 64-bit octet counters if Gigawords present
    input_giga = int(record.get("Acct-Input-Gigawords", "0"))
    output_giga = int(record.get("Acct-Output-Gigawords", "0"))
    total_input = int(input_octets) + (input_giga * 4294967296)
    total_output = int(output_octets) + (output_giga * 4294967296)

    timestamp = record.get("_timestamp", datetime.now())

    return {
        "acct_session_id": session_id,
        "acct_status": acct_status,
        "username": username,
        "framed_ip": framed_ip if framed_ip and framed_ip != "0.0.0.0" else None,
        "framed_ipv6_prefix": framed_ipv6 or delegated_ipv6 or None,
        "calling_station_id": calling,
        "called_station_id": called,
        "nas_ip_address": nas_ip,
        "nas_port": int(nas_port) if nas_port else None,
        "nas_port_id": nas_port_id,
        "nas_port_type": nas_port_type,
        "service_type": service_type,
        "session_start": timestamp if acct_status == "Start" else None,
        "session_stop": timestamp if acct_status == "Stop" else None,
        "session_duration": int(session_time) if session_time else None,
        "input_octets": total_input,
        "output_octets": total_output,
        "terminate_cause": terminate_cause if acct_status == "Stop" else None,
        "delegated_ipv6": delegated_ipv6 or None,
        "raw_record": str(record)[:4000],
    }


def insert_radius_record(cur, row):
    """Insert or update a RADIUS accounting record."""
    if row["acct_status"] == "Start":
        cur.execute(
            """INSERT INTO radius_accounting
               (acct_session_id, acct_status, username, framed_ip, framed_ipv6_prefix,
                calling_station_id, called_station_id, nas_ip_address, nas_port,
                nas_port_id, nas_port_type, service_type, session_start,
                input_octets, output_octets, delegated_ipv6, raw_record)
               VALUES (%(acct_session_id)s, %(acct_status)s, %(username)s, %(framed_ip)s,
                %(framed_ipv6_prefix)s, %(calling_station_id)s, %(called_station_id)s,
                %(nas_ip_address)s, %(nas_port)s, %(nas_port_id)s, %(nas_port_type)s,
                %(service_type)s, %(session_start)s, %(input_octets)s, %(output_octets)s,
                %(delegated_ipv6)s, %(raw_record)s)
               ON CONFLICT DO NOTHING""",
            row,
        )
    elif row["acct_status"] == "Stop":
        # Try to update existing Start record
        cur.execute(
            """UPDATE radius_accounting
               SET session_stop = %(session_stop)s,
                   session_duration = %(session_duration)s,
                   input_octets = %(input_octets)s,
                   output_octets = %(output_octets)s,
                   terminate_cause = %(terminate_cause)s,
                   acct_status = 'Stop'
               WHERE acct_session_id = %(acct_session_id)s
                 AND username = %(username)s
                 AND session_stop IS NULL""",
            row,
        )
        if cur.rowcount == 0:
            # No matching Start found — insert standalone Stop
            row["session_start"] = row["session_stop"]
            cur.execute(
                """INSERT INTO radius_accounting
                   (acct_session_id, acct_status, username, framed_ip, framed_ipv6_prefix,
                    calling_station_id, called_station_id, nas_ip_address, nas_port,
                    nas_port_id, nas_port_type, service_type, session_start, session_stop,
                    session_duration, input_octets, output_octets, terminate_cause,
                    delegated_ipv6, raw_record)
                   VALUES (%(acct_session_id)s, 'Stop', %(username)s, %(framed_ip)s,
                    %(framed_ipv6_prefix)s, %(calling_station_id)s, %(called_station_id)s,
                    %(nas_ip_address)s, %(nas_port)s, %(nas_port_id)s, %(nas_port_type)s,
                    %(service_type)s, %(session_start)s, %(session_stop)s, %(session_duration)s,
                    %(input_octets)s, %(output_octets)s, %(terminate_cause)s,
                    %(delegated_ipv6)s, %(raw_record)s)""",
                row,
            )
    elif row["acct_status"] == "Interim-Update":
        # Primary: match on session_id + username for active session
        cur.execute(
            """UPDATE radius_accounting
               SET framed_ip = COALESCE(%(framed_ip)s, framed_ip),
                   input_octets = %(input_octets)s,
                   output_octets = %(output_octets)s,
                   session_duration = %(session_duration)s
               WHERE acct_session_id = %(acct_session_id)s
                 AND username = %(username)s
                 AND session_stop IS NULL""",
            row,
        )
        if cur.rowcount == 0:
            # Fallback: match active session by framed_ip (session_id may not align)
            cur.execute(
                """UPDATE radius_accounting
                   SET input_octets = %(input_octets)s,
                       output_octets = %(output_octets)s,
                       session_duration = %(session_duration)s
                   WHERE framed_ip = %(framed_ip)s
                     AND username = %(username)s
                     AND session_stop IS NULL""",
                row,
            )
        if cur.rowcount == 0:
            # No active Start found — insert the interim as a standalone active session
            row["session_start"] = row.get("session_start") or datetime.now()
            cur.execute(
                """INSERT INTO radius_accounting
                   (acct_session_id, acct_status, username, framed_ip, framed_ipv6_prefix,
                    calling_station_id, called_station_id, nas_ip_address, nas_port,
                    nas_port_id, nas_port_type, service_type, session_start,
                    session_duration, input_octets, output_octets, delegated_ipv6, raw_record)
                   VALUES (%(acct_session_id)s, 'Start', %(username)s, %(framed_ip)s,
                    %(framed_ipv6_prefix)s, %(calling_station_id)s, %(called_station_id)s,
                    %(nas_ip_address)s, %(nas_port)s, %(nas_port_id)s, %(nas_port_type)s,
                    %(service_type)s, %(session_start)s, %(session_duration)s,
                    %(input_octets)s, %(output_octets)s, %(delegated_ipv6)s, %(raw_record)s)
                   ON CONFLICT DO NOTHING""",
                row,
            )


# ---------------------------------------------------------------------------
# Watch mode
# ---------------------------------------------------------------------------
def watch_directory(acct_dir, dsn):
    """Continuously watch for new detail files and tail them."""
    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    cur = conn.cursor()

    # Load saved positions
    positions = {}
    if os.path.exists(POSITION_FILE):
        with open(POSITION_FILE) as f:
            for line in f:
                parts = line.strip().split("\t")
                if len(parts) == 2:
                    positions[parts[0]] = int(parts[1])

    log.info(f"Watching {acct_dir} for RADIUS detail files...")

    while True:
        try:
            # Find all detail files
            for detail_file in sorted(glob.glob(f"{acct_dir}/*/detail-*")):
                file_size = os.path.getsize(detail_file)
                last_pos = positions.get(detail_file, 0)

                if file_size <= last_pos:
                    continue

                log.info(f"Processing {detail_file} from position {last_pos}")
                count = 0

                with open(detail_file, "r", errors="replace") as f:
                    f.seek(last_pos)
                    # Read remaining content and parse
                    content = f.read()
                    new_pos = f.tell()

                # Parse records from the new content
                # Write to temp file for parsing
                import tempfile
                with tempfile.NamedTemporaryFile(mode="w", suffix=".detail", delete=False) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name

                try:
                    for record in parse_detail_records(tmp_path):
                        row = record_to_db_row(record)
                        if row:
                            insert_radius_record(cur, row)
                            count += 1
                            if count % 100 == 0:
                                conn.commit()
                finally:
                    os.unlink(tmp_path)

                conn.commit()
                positions[detail_file] = new_pos

                if count > 0:
                    log.info(f"Inserted {count} records from {detail_file}")

            # Save positions
            os.makedirs(os.path.dirname(POSITION_FILE), exist_ok=True)
            with open(POSITION_FILE, "w") as f:
                for path, pos in positions.items():
                    f.write(f"{path}\t{pos}\n")

            time.sleep(10)  # Check every 10 seconds

        except psycopg2.Error as e:
            log.error(f"DB error: {e}")
            try:
                conn.rollback()
                conn = psycopg2.connect(dsn)
                conn.autocommit = False
                cur = conn.cursor()
            except:
                time.sleep(5)
        except Exception as e:
            log.error(f"Watch error: {e}")
            time.sleep(5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="IPDR RADIUS Detail Parser")
    parser.add_argument("--mode", choices=["watch", "batch"], default="watch")
    parser.add_argument("--dir", default="/var/log/radius/radacct",
                        help="RADIUS accounting detail directory (watch mode)")
    parser.add_argument("--file", help="Single detail file to process (batch mode)")
    parser.add_argument("--dsn", default=DB_DSN)
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    if args.mode == "batch":
        if not args.file:
            print("--file is required for batch mode")
            sys.exit(1)

        conn = psycopg2.connect(args.dsn)
        conn.autocommit = False
        cur = conn.cursor()
        count = 0

        for record in parse_detail_records(args.file):
            row = record_to_db_row(record)
            if row:
                insert_radius_record(cur, row)
                count += 1
                if count % 500 == 0:
                    conn.commit()
                    log.info(f"Processed {count} records")

        conn.commit()
        log.info(f"Done. Total records: {count}")

    elif args.mode == "watch":
        watch_directory(args.dir, args.dsn)


if __name__ == "__main__":
    main()
