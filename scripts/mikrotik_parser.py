"""
mikrotik_parser.py  —  Model B (per-connection syslog) parser for the
IPDR MikroTik appliance.

Parses RouterOS firewall 'forward:' NAT log lines as emitted by NAS-EXAMPLE
(198.51.100.2) and landing on this box via rsyslog. Extracts the full
translation (private -> public:port -> dest) plus the in:<pppoe-XXX>
interface, which IS the subscriber identity.

Design notes
------------
* Anchor on the message BODY (everything from 'in:<...>' onward), not on
  the collector header. The collector header (date, Facility.Severity,
  source IP, RFC-3164 stamp, hostname, tag) varies by rsyslog template and
  RouterOS version; the body is stable. We still opportunistically pull the
  router IP / hostname / router timestamp from the header when present.
* Filter private->private lines (UPnP etc.): if the NAT *public* address is
  RFC1918, the line is not CGNAT-to-internet and must never reach LEA.
* Store raw fidelity. No ingest-time dedup. raw_log is preserved verbatim.
* Tolerant of RouterOS v6 (classic RFC-3164) and v7 (ms timestamps); the
  body regex is version-independent. CEF (v7.18+) is handled by a fallback
  hook (parse_cef) that can be filled in once we see a real CEF sample.
"""

import re
import ipaddress
from datetime import datetime

# --- Body regex: the validated NAT translation clause -----------------------
# Matches e.g.:
#   in:<pppoe-b162> out:1sfp-WAN, connection-state:new,snat proto TCP (SYN),
#   100.64.0.10:54124->69.29.87.37:21001,
#   NAT (100.64.0.10:54124->203.0.113.10:54124)->69.29.87.37:21001, len 60
BODY_RE = re.compile(
    r'in:<?(?P<iface>[^>,\s]+)>?\s+out:(?P<out>\S+?),\s+'
    r'connection-state:(?P<state>[^,\s]+)(?:,(?P<snat>snat))?\s+'
    r'(?:src-mac\s+(?P<src_mac>[0-9a-fA-F:]{17}),\s+)?'
    r'proto\s+(?P<proto>\w+)(?:\s+\((?P<flags>[^)]+)\))?,\s+'
    r'(?P<priv_ip>\d+\.\d+\.\d+\.\d+):(?P<priv_port>\d+)->'
    r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+),\s+'
    r'NAT\s+\((?P<n_priv_ip>\d+\.\d+\.\d+\.\d+):(?P<n_priv_port>\d+)->'
    r'(?P<pub_ip>\d+\.\d+\.\d+\.\d+):(?P<pub_port>\d+)\)->'
    r'(?P<n_dst_ip>\d+\.\d+\.\d+\.\d+):(?P<n_dst_port>\d+)'
)

# --- Header regex: opportunistic, tolerant ---------------------------------
# 2026-07-08 14:19:00  Daemon.Info  198.51.100.2  Jul  8 14:19:18 NAS-EXAMPLE forward:
HEADER_RE = re.compile(
    r'^(?P<collector_ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}'
    r'(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+'
    r'(?:(?P<priority>[A-Za-z]+\.[A-Za-z]+)\s+)?'
    r'(?P<router_ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?P<router_ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>.+?)\s+'          # multi-word hostnames (e.g. 'Example ISP')
    r'(?P<tag>\S+?):'
)


def _is_rfc1918(ip_str):
    """True if ip_str is a private / non-global address (RFC1918, CGN, etc.)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable -> treat as non-routable, exclude
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast


def _parse_router_ts(router_ts, collector_ts):
    """
    RouterOS RFC-3164 stamp has no year ('Jul  8 14:19:18'). Borrow the year
    from the collector timestamp (which is full ISO). Returns ISO string or None.
    """
    if not router_ts:
        return None
    year = None
    if collector_ts and len(collector_ts) >= 4 and collector_ts[:4].isdigit():
        year = int(collector_ts[:4])
    if year is None:
        year = datetime.now().year
    try:
        # normalise the double space RouterOS uses for single-digit days
        cleaned = re.sub(r'\s+', ' ', router_ts.strip())
        dt = datetime.strptime(f"{year} {cleaned}", "%Y %b %d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _normalize_username(iface):
    """
    Derive the stable subscriber key from the interface name.
    'pppoe-b169' -> 'b169', '<pppoe-G0620>' -> 'G0620'. Non-pppoe ifaces are
    returned unchanged (still a usable key for that NAS).
    """
    if not iface:
        return None
    m = re.match(r'^<?pppoe-(?P<u>[^>]+)>?$', iface)
    return m.group("u") if m else iface


class ParseResult:
    """Lightweight parse outcome."""
    __slots__ = ("ok", "reason", "record")

    def __init__(self, ok, reason=None, record=None):
        self.ok = ok
        self.reason = reason      # why skipped, when ok is False
        self.record = record      # dict ready for mikrotik_translations

    def __repr__(self):
        if self.ok:
            r = self.record
            return (f"<ParseResult ok iface={r['iface']} "
                    f"{r['private_ip']}:{r['private_port']}"
                    f"->{r['public_ip']}:{r['public_port']}"
                    f"->{r['dest_ip']}:{r['dest_port']}>")
        return f"<ParseResult skip reason={self.reason}>"


def parse_line(line, nas_id=None):
    """
    Parse one raw log line into a translation record.

    Returns ParseResult:
      ok=True  -> .record is a dict matching the mikrotik_translations schema
      ok=False -> .reason explains the skip ('no-nat-body',
                  'private-to-private', etc.)
    """
    line = line.rstrip("\n")

    body = BODY_RE.search(line)
    if not body:
        return ParseResult(False, reason="no-nat-body")

    b = body.groupdict()

    # Guard: the NAT *public* address must be globally routable. Private
    # 'public' side = UPnP / hairpin / internal, not CGNAT-to-internet.
    if _is_rfc1918(b["pub_ip"]):
        return ParseResult(False, reason="private-to-private")

    hdr = HEADER_RE.match(line)
    h = hdr.groupdict() if hdr else {}

    collector_ts = h.get("collector_ts")
    router_ts_raw = h.get("router_ts")
    log_time = _parse_router_ts(router_ts_raw, collector_ts) or collector_ts

    record = {
        "nas_id":        nas_id,
        "log_time":      log_time,
        "collector_ts":  collector_ts,
        "router_ip":     h.get("router_ip"),
        "hostname":      h.get("hostname"),
        "iface":         b["iface"],            # pppoe session OR interface name
        "username":      _normalize_username(b["iface"]),  # normalized key (b169 / iface)
        "src_mac":       b.get("src_mac"),      # DHCP/routed identity anchor (None for pppoe)
        "private_ip":    b["priv_ip"],
        "private_port":  int(b["priv_port"]),
        "public_ip":     b["pub_ip"],
        "public_port":   int(b["pub_port"]),
        "dest_ip":       b["dst_ip"],
        "dest_port":     int(b["dst_port"]),
        "protocol":      b["proto"],
        "tcp_flags":     b.get("flags"),
        "conn_state":    b["state"],
        "raw_log":       line,
    }
    return ParseResult(True, record=record)


def parse_cef(line, nas_id=None):
    """
    Placeholder for RouterOS v7.18+ CEF format. Fill in once a real CEF
    sample is captured. For now, classic format only (validated).
    """
    raise NotImplementedError("CEF parsing pending a real v7.18+ sample")


def parse_stream(lines, nas_id=None):
    """
    Generator: yield only the ok records from an iterable of lines.
    Skips (no-nat-body, private-to-private) are silently dropped; callers
    that want skip stats should use parse_line directly.
    """
    for line in lines:
        res = parse_line(line, nas_id=nas_id)
        if res.ok:
            yield res.record
