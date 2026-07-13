#!/usr/bin/env python3
"""
enrich.py — GeoIP + Application decoding for IPDR.

Provides offline enrichment:
  - GeoIP: destination IP → country (using MaxMind GeoLite2 or IP2Location Lite)
  - App decoding: protocol + port + junos-app → human-readable application/service

Used by both the web app (query-time) and can pre-populate columns.
"""

import os
import ipaddress

# ---------------------------------------------------------------------------
# GeoIP — uses geoip2 with MaxMind GeoLite2-Country.mmdb
# Falls back gracefully if DB not present
# ---------------------------------------------------------------------------
GEOIP_DB = os.environ.get("GEOIP_DB", "/opt/ipdr/data/GeoLite2-Country.mmdb")
_geoip_reader = None

def get_geoip_reader():
    global _geoip_reader
    if _geoip_reader is None:
        try:
            import geoip2.database
            if os.path.exists(GEOIP_DB):
                _geoip_reader = geoip2.database.Reader(GEOIP_DB)
            else:
                _geoip_reader = False
        except ImportError:
            _geoip_reader = False
    return _geoip_reader

# Known local/CDN ranges to label without GeoIP lookup
LOCAL_RANGES = [
    (ipaddress.ip_network("100.64.0.0/10"), "CGN"),
    (ipaddress.ip_network("10.0.0.0/8"), "Private"),
    (ipaddress.ip_network("172.16.0.0/12"), "Private"),
    (ipaddress.ip_network("192.168.0.0/16"), "Private"),
    (ipaddress.ip_network("203.0.113.100/24"), "PK-Example ISP"),
    (ipaddress.ip_network("192.0.2.10/23"), "PK-Example ISP"),
    (ipaddress.ip_network("192.0.2.0/24"), "PK-Example ISP"),
]

def geo_country(ip_str):
    """Return ISO country code for an IP, or a special label."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "??"

    # Check local ranges first
    for net, label in LOCAL_RANGES:
        if ip in net:
            return label

    reader = get_geoip_reader()
    if not reader:
        return "??"

    try:
        resp = reader.country(ip_str)
        return resp.country.iso_code or "??"
    except Exception:
        return "??"

def geo_country_name(ip_str):
    """Return full country name."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "Unknown"
    for net, label in LOCAL_RANGES:
        if ip in net:
            return label
    reader = get_geoip_reader()
    if not reader:
        return "Unknown"
    try:
        resp = reader.country(ip_str)
        return resp.country.name or "Unknown"
    except Exception:
        return "Unknown"

# ---------------------------------------------------------------------------
# Application decoding — protocol + port → service name
# The Junos "application" field is primary; this fills gaps for "Unknown"
# ---------------------------------------------------------------------------
PORT_MAP = {
    # Web
    (80, "tcp"): "HTTP",
    (443, "tcp"): "HTTPS",
    (443, "udp"): "HTTPS/QUIC",
    (8080, "tcp"): "HTTP-Proxy",
    (8443, "tcp"): "HTTPS-Alt",
    # Messaging / VoIP
    (5222, "tcp"): "XMPP/WhatsApp",
    (5223, "tcp"): "WhatsApp/APNS",
    (3478, "udp"): "STUN/WhatsApp-Call",
    (3479, "udp"): "STUN/Voice",
    (3480, "udp"): "STUN/Video",
    (5060, "udp"): "SIP",
    (5061, "tcp"): "SIP-TLS",
    # DNS
    (53, "udp"): "DNS",
    (53, "tcp"): "DNS",
    (853, "tcp"): "DNS-over-TLS",
    # Mail
    (25, "tcp"): "SMTP",
    (465, "tcp"): "SMTPS",
    (587, "tcp"): "SMTP-Submission",
    (110, "tcp"): "POP3",
    (143, "tcp"): "IMAP",
    (993, "tcp"): "IMAPS",
    (995, "tcp"): "POP3S",
    # File / Remote
    (21, "tcp"): "FTP",
    (22, "tcp"): "SSH",
    (23, "tcp"): "Telnet",
    (3389, "tcp"): "RDP",
    (445, "tcp"): "SMB",
    (139, "tcp"): "NetBIOS",
    # Gaming
    (3074, "tcp"): "Xbox-Live",
    (3074, "udp"): "Xbox-Live",
    (3075, "tcp"): "CoD",
    (27015, "udp"): "Steam",
    (1119, "tcp"): "Battle.net",
    (3659, "tcp"): "EA-Games",
    # Streaming / Misc
    (1935, "tcp"): "RTMP-Stream",
    (554, "tcp"): "RTSP",
    (1194, "udp"): "OpenVPN",
    (1701, "udp"): "L2TP",
    (51820, "udp"): "WireGuard",
    (123, "udp"): "NTP",
    (6881, "tcp"): "BitTorrent",
    (6882, "tcp"): "BitTorrent",
}

# Known destination IP prefixes → service (major providers)
IP_SERVICE_MAP = [
    (ipaddress.ip_network("157.240.0.0/16"), "Facebook/Meta"),
    (ipaddress.ip_network("31.13.24.0/21"), "Facebook/Meta"),
    (ipaddress.ip_network("129.134.0.0/16"), "Facebook/Meta"),
    (ipaddress.ip_network("57.144.0.0/14"), "WhatsApp/Meta"),
    (ipaddress.ip_network("142.250.0.0/15"), "Google"),
    (ipaddress.ip_network("172.217.0.0/16"), "Google"),
    (ipaddress.ip_network("216.239.32.0/19"), "Google"),
    (ipaddress.ip_network("74.125.0.0/16"), "Google"),
    (ipaddress.ip_network("8.8.8.0/24"), "Google-DNS"),
    (ipaddress.ip_network("17.0.0.0/8"), "Apple"),
    (ipaddress.ip_network("13.107.0.0/16"), "Microsoft"),
    (ipaddress.ip_network("204.79.195.0/24"), "Microsoft"),
    (ipaddress.ip_network("104.16.0.0/12"), "Cloudflare"),
    (ipaddress.ip_network("1.1.1.0/24"), "Cloudflare-DNS"),
    (ipaddress.ip_network("151.101.0.0/16"), "Fastly-CDN"),
    (ipaddress.ip_network("52.84.0.0/15"), "Amazon-CF"),
    (ipaddress.ip_network("13.32.0.0/15"), "Amazon-CF"),
    (ipaddress.ip_network("23.40.0.0/13"), "Akamai"),
    (ipaddress.ip_network("104.244.40.0/21"), "Twitter/X"),
    (ipaddress.ip_network("140.82.112.0/20"), "GitHub"),
]

def decode_application(junos_app, protocol_name, dst_port, dst_ip=None):
    """
    Best-effort application name.
    Priority: destination IP service > known port > junos app.
    """
    # If Junos gave a meaningful app, prefer it (but clean it up)
    if junos_app and junos_app not in ("Unknown", "None", "N/A", ""):
        clean = junos_app.replace("junos-", "").upper()
        return clean

    # Try destination IP service mapping
    if dst_ip:
        try:
            ip = ipaddress.ip_address(dst_ip)
            for net, svc in IP_SERVICE_MAP:
                if ip in net:
                    return svc
        except ValueError:
            pass

    # Try port map
    if dst_port:
        try:
            port = int(dst_port)
            proto = (protocol_name or "tcp").lower()
            key = (port, proto)
            if key in PORT_MAP:
                return PORT_MAP[key]
            # Try other protocol
            other = "udp" if proto == "tcp" else "tcp"
            if (port, other) in PORT_MAP:
                return PORT_MAP[(port, other)]
        except (ValueError, TypeError):
            pass

    return "Unknown"


if __name__ == "__main__":
    # Test
    tests = [
        ("junos-https", "tcp", 443, "142.250.4.94"),
        ("Unknown", "tcp", 443, "157.240.148.141"),
        ("Unknown", "udp", 3478, "8.8.8.8"),
        ("None", "tcp", 5223, None),
    ]
    for app, proto, port, ip in tests:
        print(f"{app}/{proto}/{port}/{ip} → {decode_application(app, proto, port, ip)}")
        if ip:
            print(f"    Country: {geo_country_name(ip)}")
