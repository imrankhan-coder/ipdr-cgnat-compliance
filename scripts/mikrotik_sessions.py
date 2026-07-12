"""
mikrotik_sessions.py — synthesize session-like activity windows from
per-connection MikroTik translations for a username.

MikroTik firewall syslog has no PPP session boundaries (that's what the API's
/ppp/active + accounting will provide later). Until then, we group a subscriber's
connections into "activity windows": consecutive connections with no gap longer
than GAP_SECONDS form one window. Each window fills the session-shaped template
slots truthfully:
    session_start = first connection in window
    session_stop  = last connection in window (None if window is still open,
                    i.e. its last connection is within GAP_SECONDS of now)
    framed_ip     = None   (MikroTik doesn't log the PPP framed IP; API fills it)
    mac / vlan    = None   (not in firewall logs)
    session_duration = stop - start (seconds) when closed
Plus the public IP(s) the subscriber was NAT'd to during the window, and the
underlying connections for the timeline drill-down.
"""

from datetime import timedelta

GAP_SECONDS = 900          # 15-min idle gap splits a window
MAX_WINDOWS = 100
MAX_CONNS_PER_WINDOW = 500  # cap drill-down rows per window


def build_windows(rows, now=None):
    """
    rows: list of dicts (or RealDict) ordered by log_time ASC, each with at least
          log_time, username, public_ip, public_port, private_ip, private_port,
          dest_ip, dest_port, protocol.
    Returns a list of window dicts newest-first, each:
      { 'session': {...session-shaped...}, 'nat_maps': [conn rows...] }
    """
    if not rows:
        return []

    windows = []
    cur = None

    for r in rows:
        lt = r["log_time"]
        if cur is None:
            cur = _new_window(r)
        else:
            gap = (lt - cur["_last_ts"]).total_seconds()
            if gap > GAP_SECONDS:
                windows.append(cur)
                cur = _new_window(r)
            else:
                _extend_window(cur, r)
    if cur is not None:
        windows.append(cur)

    # finalize: shape each window, newest first
    out = []
    for w in reversed(windows[-MAX_WINDOWS:]):
        start = w["_first_ts"]
        last = w["_last_ts"]
        # Consider the window "open" if its last activity is recent.
        open_window = False
        if now is not None:
            open_window = (now - last).total_seconds() <= GAP_SECONDS
        stop = None if open_window else last
        duration = None if stop is None else int((stop - start).total_seconds())
        pub_ips = sorted(w["_pub_ips"])
        # most-common src_mac in the window (DHCP/routed identity)
        _mac = None
        if w.get("_macs"):
            _mac = max(w["_macs"].items(), key=lambda kv: kv[1])[0]
        session = {
            "username": w["username"],
            "framed_ip": None,          # API will fill
            "mac": _mac,
            "vlan": None,
            "session_start": start,
            "session_stop": stop,
            "session_duration": duration,
            "public_ips": pub_ips,
            "public_ip": pub_ips[0] if pub_ips else None,
            "cgn_ip": pub_ips[0] if pub_ips else None,
            "conn_count": w["_count"],
        }
        out.append({"session": session, "nat_maps": w["_conns"]})
    return out


def _new_window(r):
    w = {
        "username": r.get("username"),
        "_first_ts": r["log_time"],
        "_last_ts": r["log_time"],
        "_pub_ips": set(),
        "_macs": {},  # _macs  # session-mac
        "_conns": [],
        "_count": 0,
    }
    _extend_window(w, r)
    return w


def _extend_window(w, r):
    w["_last_ts"] = r["log_time"]
    if r.get("public_ip"):
        w["_pub_ips"].add(str(r["public_ip"]))
    _m = r.get("src_mac")
    if _m:
        w["_macs"][_m] = w["_macs"].get(_m, 0) + 1
    w["_count"] += 1
    if len(w["_conns"]) < MAX_CONNS_PER_WINDOW:
        # shape a connection row for the timeline drill-down. Reuse the
        # template's expected keys (log_time, public_ip) plus extras.
        w["_conns"].append({
            "log_time": r["log_time"],
            "public_ip": str(r["public_ip"]) if r.get("public_ip") else None,
            "public_port": r.get("public_port"),
            "private_ip": str(r["private_ip"]) if r.get("private_ip") else None,
            "private_port": r.get("private_port"),
            "dest_ip": str(r["dest_ip"]) if r.get("dest_ip") else None,
            "dest_port": r.get("dest_port"),
            "protocol": r.get("protocol"),
            "src_mac": r.get("src_mac"),
            # template also references port block / blocks-used for Juniper;
            # give harmless placeholders so it renders.
            "log_type": "MT_XLATE",
            "port_block_start": r.get("public_port"),
            "port_block_end": r.get("public_port"),
            "blocks_used": None,
        })
