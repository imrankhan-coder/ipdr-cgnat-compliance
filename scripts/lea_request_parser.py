"""
lea_request_parser.py — parse LEA / abuse / copyright requests in the formats
used internationally, into a common list of lookup items.

Auto-detects and extracts (source public IP, source port, timestamp, and where
available destination + case/title):

  1. tcpdump / libpcap lines:
       1783851029.560458 IP 1.2.3.4.37358 > 5.6.7.8.443: Flags [S] ...
  2. ACNS XML (copyright/BitTorrent — Paramount, BREIN, Vobile, etc.):
       <IP_Address>..</IP_Address><Port>..</Port><TimeStamp>..Z</TimeStamp>
  3. X-ARF / key:value abuse reports (common in EU/CERTs):
       Source-IP: 1.2.3.4   Source-Port: 5060   Date: 2026-..Z
  4. NetFlow / firewall-log style:
       2026-07-12T19:38:25 proto=TCP src=1.2.3.4:40652 dst=5.6.7.8:443
  5. Minimal "IP:port <isotime>" or "IP port <isotime>"
  6. RFC5424-ish syslog with IP/port + timestamp
  7. Generic: any line containing an IP, a port-ish number, and a parseable time

Timezone: stored log_time is naive and equals the UTC wall-clock (extract(epoch)
stored it as-if-UTC). So every input is normalised to naive-UTC.
"""
import re
from datetime import datetime, timezone

# ---- timestamp normalisation ------------------------------------------------
def _to_stored(dt):
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt

def _from_epoch(epoch):
    return datetime.fromtimestamp(int(float(epoch)), timezone.utc).replace(tzinfo=None)

def _from_iso(s):
    s = s.strip().replace("Z", "+00:00")
    # allow space separator
    s = re.sub(r'^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})', r'\1T\2', s)
    return _to_stored(datetime.fromisoformat(s))

# common non-ISO time formats seen in reports
_TIME_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",   # apache/CLF: 12/Jul/2026:19:38:25 +0000
    "%d-%b-%Y %H:%M:%S",      # 12-Jul-2026 19:38:25
    "%b %d %H:%M:%S %Y",      # Jul 12 19:38:25 2026
    "%Y/%m/%d %H:%M:%S",      # 2026/07/12 19:38:25
    "%m/%d/%Y %H:%M:%S",      # US 07/12/2026 19:38:25
]

def _parse_any_time(s):
    s = s.strip()
    # ISO first
    try:
        return _from_iso(s)
    except Exception:
        pass
    # epoch (10+ digits, optional frac)
    if re.fullmatch(r'\d{9,}(?:\.\d+)?', s):
        return _from_epoch(s)
    for fmt in _TIME_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return _to_stored(dt)
        except ValueError:
            continue
    return None

# ---- format matchers --------------------------------------------------------
TCPDUMP_RE = re.compile(
    r'(?P<epoch>\d{9,}(?:\.\d+)?)\s+IP\s+'
    r'(?P<sip>\d+\.\d+\.\d+\.\d+)\.(?P<sport>\d+)\s+>\s+'
    r'(?P<dip>\d+\.\d+\.\d+\.\d+)\.(?P<dport>\d+):')

ACNS_IP   = re.compile(r'<IP_Address>\s*(\d+\.\d+\.\d+\.\d+)\s*</IP_Address>', re.I)
ACNS_PORT = re.compile(r'<Port>\s*(\d+)\s*</Port>', re.I)
ACNS_TS   = re.compile(r'<TimeStamp>\s*([0-9T:\-\.Z\+ ]+?)\s*</TimeStamp>', re.I)
ACNS_TITLE= re.compile(r'<Title>\s*([^<]+?)\s*</Title>', re.I)
ACNS_CASE = re.compile(r'<ID>\s*([^<]+?)\s*</ID>', re.I)

# netflow/firewall: src=IP:port dst=IP:port  (+ a time somewhere on the line)
NETFLOW_RE = re.compile(
    r'src[=:\s]+(?P<sip>\d+\.\d+\.\d+\.\d+)[:\.](?P<sport>\d+).*?'
    r'dst[=:\s]+(?P<dip>\d+\.\d+\.\d+\.\d+)[:\.](?P<dport>\d+)', re.I)

# key:value blocks (X-ARF style)
KV_IP   = re.compile(r'(?:source[-_ ]?ip|src[-_ ]?ip|ip[-_ ]?address)\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)', re.I)
KV_PORT = re.compile(r'(?:source[-_ ]?port|src[-_ ]?port|port)\s*[:=]\s*(\d+)', re.I)
KV_DIP  = re.compile(r'(?:dest(?:ination)?[-_ ]?ip|dst[-_ ]?ip)\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)', re.I)
KV_DPORT= re.compile(r'(?:dest(?:ination)?[-_ ]?port|dst[-_ ]?port)\s*[:=]\s*(\d+)', re.I)
KV_DATE = re.compile(r'(?:date|time|timestamp|event[-_ ]?time)\s*[:=]\s*([0-9A-Za-z:\-\.Z\+/ ]+)', re.I)

# minimal "IP:port <time>" or "IP port <time>"
MIN_RE = re.compile(
    r'(?P<sip>\d+\.\d+\.\d+\.\d+)[:\s](?P<sport>\d{1,5})\s+(?P<ts>\S+.*)$')

ANY_IP = re.compile(r'(\d+\.\d+\.\d+\.\d+)')

# BitNinja / web-abuse incident:  "Remote connection: IP:port" + "Time of catch: <time>"
BN_CONN = re.compile(r'Remote\s+connection\s*:\s*(\d+\.\d+\.\d+\.\d+):(\d+)', re.I)  # bitninja
BN_TIME = re.compile(r'Time\s+of\s+catch\s*:\s*([0-9\-:/ TZ\.\+]+)', re.I)


def _add(items, fmts, fmt, sip, sport, when, dip=None, dport=None, title=None, case=None):
    if not (sip and sport and when):
        return
    items.append({"format": fmt, "src_ip": sip, "src_port": int(sport),
                  "dest_ip": dip, "dest_port": (int(dport) if dport else None),
                  "when": when, "when_raw": str(when), "title": title, "case": case})
    fmts.add(fmt)


def parse(text):
    items = []; fmts = set()

    # 1. tcpdump
    for m in TCPDUMP_RE.finditer(text):
        g = m.groupdict()
        _add(items, fmts, "tcpdump", g["sip"], g["sport"],
             _from_epoch(g["epoch"]), g["dip"], g["dport"])

    # 2. ACNS XML
    if "<IP_Address>" in text or "acns" in text.lower():
        ips = ACNS_IP.findall(text); ports = ACNS_PORT.findall(text)
        tss = ACNS_TS.findall(text)
        title = ACNS_TITLE.search(text); case = ACNS_CASE.search(text)
        title = title.group(1).strip() if title else None
        case = case.group(1).strip() if case else None
        for i in range(max(len(ips), len(ports))):
            ip = ips[i] if i < len(ips) else (ips[0] if ips else None)
            port = ports[i] if i < len(ports) else (ports[0] if ports else None)
            ts = tss[i] if i < len(tss) else (tss[0] if tss else None)
            when = _parse_any_time(ts) if ts else None
            _add(items, fmts, "acns", ip, port, when, None, None, title, case)

    # 3. netflow / firewall line (per line, with a time on/near the line)
    for line in text.splitlines():
        m = NETFLOW_RE.search(line)
        if m:
            g = m.groupdict()
            # find a time on the line
            when = None
            tmatch = re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*', line)
            if tmatch: when = _parse_any_time(tmatch.group(0))
            _add(items, fmts, "netflow", g["sip"], g["sport"], when,
                 g["dip"], g["dport"])

    # 4. key:value / X-ARF block (treat whole text as one report)
    kip = KV_IP.search(text); kport = KV_PORT.search(text); kdate = KV_DATE.search(text)
    if kip and kport and kdate:
        when = _parse_any_time(kdate.group(1))
        kdip = KV_DIP.search(text); kdport = KV_DPORT.search(text)
        _add(items, fmts, "keyvalue", kip.group(1), kport.group(1), when,
             (kdip.group(1) if kdip else None), (kdport.group(1) if kdport else None))

    # 4b. BitNinja / web-abuse incident report
    bn_conn = BN_CONN.search(text)
    bn_time = BN_TIME.search(text)
    if bn_conn and bn_time:
        when = _parse_any_time(bn_time.group(1).strip())
        _add(items, fmts, "bitninja", bn_conn.group(1), bn_conn.group(2), when)

    # 5. minimal "IP:port <time>" lines (only if nothing else matched that line)
    if not items:
        for line in text.splitlines():
            m = MIN_RE.match(line.strip())
            if m:
                g = m.groupdict()
                when = _parse_any_time(g["ts"])
                _add(items, fmts, "minimal", g["sip"], g["sport"], when)

    # de-dupe on (ip, port, when)
    seen = set(); uniq = []
    for it in items:
        k = (it["src_ip"], it["src_port"], it["when"])
        if k in seen: continue
        seen.add(k); uniq.append(it)

    if not uniq:
        return "none", []
    fmt = "mixed" if len(fmts) > 1 else next(iter(fmts))
    return fmt, uniq
