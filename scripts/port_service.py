"""
port_service.py — map a destination port (+protocol) to a human service name.

Used by the analytics Top Applications panel on the MikroTik box, where the
firewall log carries the 5-tuple but no DPI/app field. Port classification is
honest and useful (separates web / mail / DNS / SSH / etc.); it deliberately
does NOT try to name the app behind 443 — that needs IP-based CDN ranges
(a later API-client phase). Everything on 443 is labelled "HTTPS / TLS".
"""

# port -> service label. Kept intentionally small and unambiguous.
_PORT_MAP = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 465: "SMTPS", 587: "SMTP (submission)",
    53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP",
    80: "HTTP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    110: "POP3", 995: "POP3S", 143: "IMAP", 993: "IMAPS",
    123: "NTP",
    161: "SNMP", 162: "SNMP-trap",
    179: "BGP",
    389: "LDAP", 636: "LDAPS",
    443: "HTTPS / TLS",
    500: "IPsec/IKE", 4500: "IPsec NAT-T", 1701: "L2TP", 1723: "PPTP",
    1194: "OpenVPN", 51820: "WireGuard",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    3389: "RDP", 5900: "VNC",
    5060: "SIP", 5061: "SIP-TLS",
    1935: "RTMP (streaming)",
    3478: "STUN/TURN (voice/video)", 3479: "STUN/TURN",
    19302: "STUN (Google voice/video)",
    27015: "Game (Source)", 25565: "Game (Minecraft)",
    6881: "BitTorrent", 6882: "BitTorrent", 51413: "BitTorrent",
}

# Common QUIC/HTTP3 note: 443/udp is also HTTPS(QUIC).
def classify(port, protocol=None):
    """Return a service label for a destination port. Never returns None."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        return "Unknown"
    if p in _PORT_MAP:
        # 443/udp is QUIC (HTTP/3) — nice to distinguish
        if p == 443 and protocol and str(protocol).upper() == "UDP":
            return "HTTPS / QUIC"
        return _PORT_MAP[p]
    if 49152 <= p <= 65535:
        return "Ephemeral / P2P"
    if 1024 <= p < 49152:
        return "Other (registered)"
    return f"Port {p}"
