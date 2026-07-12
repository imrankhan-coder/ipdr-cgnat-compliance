"""
mikrotik_lea.py  —  LEA lookup engine for the IPDR MikroTik appliance.

Answers the officer's forensic question:
    "Who held <public_ip>:<port> at time T?"

Behaviour (decided design):
  * Search a tight window around T (default +/- 5 min, configurable).
  * The authoritative answer is the CLOSEST-in-time match.
  * If more than one DISTINCT subscriber (username) held that public IP:port in
    the window, return ALL of them flagged as a port-reuse collision, with their
    timestamps, so the officer decides on full evidence rather than the box
    silently picking one. This is the defensible LEA posture.
  * Identity key is the normalized PPPoE username (b169), stable across the
    whole fleet whether or not a given NAS uses RADIUS. Enrichment (name/CNIC)
    is layered on top and is optional/per-NAS.

This module is pure lookup + shaping; it does NOT write the audit entry (the
LEA page shell owns audit/CSV, identical to the Juniper box).
"""

from datetime import timedelta

DEFAULT_WINDOW_SECONDS = 300   # +/- 5 minutes around T


# The window query. Primary answer = row with smallest |log_time - T|.
# We pull all distinct-subscriber rows in the window to detect port reuse.
_WINDOW_SQL = """
    SELECT
        t.id, t.nas_id, n.name AS nas_name,
        t.log_time, t.username, t.iface,
        t.private_ip, t.private_port,
        t.public_ip, t.public_port,
        t.dest_ip, t.dest_port, t.protocol, t.tcp_flags,
        abs(extract(epoch FROM (t.log_time - %(t)s))) AS delta_seconds
    FROM mikrotik_translations t
    LEFT JOIN nas_devices n ON n.id = t.nas_id
    WHERE t.public_ip = %(public_ip)s
      AND t.public_port = %(public_port)s
      AND t.log_time BETWEEN %(t_lo)s AND %(t_hi)s
    ORDER BY delta_seconds ASC, t.log_time ASC
"""


class LeaResult:
    """
    Shaped result for the LEA page.
      found          : bool
      primary        : dict | None   — closest-in-time match (the answer)
      port_reuse     : bool          — >1 distinct subscriber in window
      candidates     : list[dict]    — all distinct-subscriber rows (time-sorted)
      window_seconds : int
      query          : dict          — echo of the query params
    """
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def to_dict(self):
        return dict(self.__dict__)


def _row_to_dict(cols, row):
    d = dict(zip(cols, row))
    # tidy types for JSON / display
    if d.get("log_time") is not None:
        d["log_time"] = d["log_time"].strftime("%Y-%m-%d %H:%M:%S")
    for k in ("private_ip", "public_ip", "dest_ip"):
        if d.get(k) is not None:
            d[k] = str(d[k])
    if d.get("delta_seconds") is not None:
        d["delta_seconds"] = round(float(d["delta_seconds"]), 1)
    return d


def lookup(conn, public_ip, public_port, when, window_seconds=DEFAULT_WINDOW_SECONDS,
           enrich_fn=None):
    """
    Run the LEA lookup.

    conn           : an open psycopg2 connection
    public_ip      : str  (the CGNAT public address)
    public_port    : int
    when           : datetime  (T, the moment of interest)
    window_seconds : int  (+/- around T)
    enrich_fn      : optional callable(username, nas_id) -> dict | None
                     e.g. {'customer_name':..., 'address':..., 'cnic':..., 'source':'radius'}

    Returns LeaResult.
    """
    public_port = int(public_port)
    t_lo = when - timedelta(seconds=window_seconds)
    t_hi = when + timedelta(seconds=window_seconds)

    params = {
        "public_ip": public_ip, "public_port": public_port,
        "t": when, "t_lo": t_lo, "t_hi": t_hi,
    }

    with conn.cursor() as cur:
        cur.execute(_WINDOW_SQL, params)
        cols = [c.name for c in cur.description]
        rows = [_row_to_dict(cols, r) for r in cur.fetchall()]
    conn.commit()

    query_echo = {
        "public_ip": public_ip, "public_port": public_port,
        "time": when.strftime("%Y-%m-%d %H:%M:%S"),
        "window_seconds": window_seconds,
    }

    if not rows:
        return LeaResult(found=False, primary=None, port_reuse=False,
                         candidates=[], window_seconds=window_seconds,
                         query=query_echo)

    # Distinct subscribers in the window (collapse repeated connections).
    seen, distinct = set(), []
    for r in rows:
        key = (r["username"], r["nas_id"])
        if key not in seen:
            seen.add(key)
            distinct.append(r)

    port_reuse = len(distinct) > 1
    primary = rows[0]   # smallest delta (already sorted)

    # Optional enrichment on each distinct candidate.
    if enrich_fn:
        for r in distinct:
            info = None
            try:
                info = enrich_fn(r["username"], r["nas_id"])
            except Exception:
                info = None
            r["identity"] = info or {
                "customer_name": None, "source": "unenriched",
                "note": f"look up account '{r['username']}' on {r['nas_name']}",
            }
        # keep primary's identity in sync if it's among distinct
        for r in distinct:
            if r["id"] == primary["id"]:
                primary["identity"] = r["identity"]

    return LeaResult(found=True, primary=primary, port_reuse=port_reuse,
                     candidates=distinct, window_seconds=window_seconds,
                     query=query_echo)
