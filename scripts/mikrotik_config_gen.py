"""
mikrotik_config_gen.py  —  NAS onboarding config generator for IPDR MikroTik.

Given the parameters of a NAS being onboarded, produce:
  (a) the RouterOS config the CLIENT pastes on their MikroTik  -> generate_router_config()
  (b) the config the BOX applies to itself to receive the logs -> generate_box_config()

This is the MikroTik analogue of the Juniper NAS-panel snippet. Model-aware:
'syslog' (Model B), 'deterministic' (Model A), or 'both'.

IMPORTANT: the firewall log RULE is intentionally left as a reference to the
proven NAS-EXAMPLE config rather than invented here. We template from a router that
already emits the validated line. Fill GOLDEN_LOG_RULE once NAS-EXAMPLE's
`/ip firewall export where log=yes` is captured.
"""

import ipaddress
import secrets
import string


# Golden log rule — lifted verbatim from NAS-EXAMPLE (RouterOS 7.21.4), the router
# that already emits the validated line. Keys off address-lists, not a
# hardcoded subnet, so it covers both CGN (100.64/10) and RFC1918 (Local-NAT)
# customers. NEW connections only; empty log-prefix -> the 'forward:' lines we
# parse. UDP is present but disabled by default (enable only if the client
# wants UDP forensics and can absorb the extra volume).
GOLDEN_LOG_RULE = (
    "# ---- CGNAT connection-logging rules (from NAS-EXAMPLE, proven) ----\n"
    "# Prereq: address-lists 'CGNAT' and 'Local-NAT' must exist and contain\n"
    "# the private customer ranges (this is your existing CGNAT setup).\n"
    "/ip firewall filter\n"
    "add action=log chain=forward connection-state=new protocol=tcp \\\n"
    "    src-address-list=CGNAT\n"
    "add action=log chain=forward connection-state=new protocol=tcp \\\n"
    "    src-address-list=Local-NAT\n"
    "# UDP (disabled by default — enable only if you need UDP in LEA):\n"
    "# add action=log chain=forward connection-state=new protocol=udp \\\n"
    "#     src-address-list=CGNAT\n"
)


def gen_api_password(length=28):
    """Strong random API password. URL/CLI-safe (no shell-hostile chars)."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _validate(params):
    for f in ("nas_name", "box_log_ip", "syslog_port", "model"):
        if not params.get(f):
            raise ValueError(f"missing required param: {f}")
    ipaddress.ip_address(params["box_log_ip"])
    if params["model"] not in ("syslog", "deterministic", "both"):
        raise ValueError("model must be syslog | deterministic | both")
    if params.get("api_enabled"):
        for f in ("api_host", "api_port", "api_user", "api_password", "box_api_src_ip"):
            if not params.get(f):
                raise ValueError(f"api_enabled but missing: {f}")
        ipaddress.ip_address(params["box_api_src_ip"])


def generate_router_config(params):
    """
    Config the CLIENT pastes on their MikroTik router.

    params:
      nas_name, model, box_log_ip, syslog_port
      api_enabled(bool), api_user, api_password, api_port, api_ssl(bool),
      box_api_src_ip   (the box's outbound IP the router must trust for API)
    """
    _validate(params)
    p = params
    L = []
    L.append(f"# ============================================================")
    L.append(f"# IPDR onboarding config for NAS: {p['nas_name']}")
    L.append(f"# Model: {p['model']}   Box: {p['box_log_ip']}")
    L.append(f"# Paste on the MikroTik router in a terminal.")
    L.append(f"# ============================================================")
    L.append("")

    # --- Remote logging (send logs to the box) -- needed for syslog / both ---
    if p["model"] in ("syslog", "both"):
        L.append("# ---- 1. Send firewall logs to the IPDR box ----")
        L.append(f"# Named action (does NOT touch the built-in 'remote' action,")
        L.append(f"# so this dual-sends alongside any existing collector).")
        # RouterOS logging action names must be letters/numbers only (no hyphens).
        L.append(f"/system logging action add name=elbipdr target=remote \\")
        L.append(f"    remote={p['box_log_ip']} remote-port={p['syslog_port']} \\")
        L.append(f"    remote-log-format=syslog")
        L.append(f"/system logging add topics=firewall action=elbipdr")
        L.append("")
        L.append(GOLDEN_LOG_RULE)
        L.append("")

    # --- Deterministic note ---
    if p["model"] in ("deterministic", "both"):
        L.append("# ---- Deterministic NAT (Model A) ----")
        L.append("# No per-connection logging needed. The box imports your")
        L.append("# src-nat rules (via API or pasted export) and computes LEA")
        L.append("# answers from the port ranges. Ensure your src-nat rules use")
        L.append("# fixed to-ports ranges per private IP.")
        L.append("")

    # --- API access (box -> router, IP-restricted, read-only user) ---
    if p.get("api_enabled"):
        svc = "api-ssl" if p.get("api_ssl") else "api"
        L.append("# ---- 2. Read-only API user for the box (identity + Model-A pull) ----")
        L.append("# Group grants ONLY read+api. No 'write','policy','sensitive':")
        L.append("# the box cannot change config and cannot read PPPoE passwords.")
        L.append(f"/user group add name=elbipdrro policy=read,api \\")
        L.append(f"    comment=\"IPDR read-only\"")
        L.append(f"/user add name={p['api_user']} group=elbipdrro \\")
        L.append(f"    password={p['api_password']} \\")
        L.append(f"    address={p['box_api_src_ip']}/32 \\")
        L.append(f"    comment=\"IPDR API (box-locked)\"")
        L.append("")
        L.append(f"# ---- 3. Expose the API only to the box, on a custom port ----")
        L.append(f"/ip service set {svc} \\")
        L.append(f"    address={p['box_api_src_ip']}/32 \\")
        L.append(f"    port={p['api_port']} disabled=no")
        L.append("")

    return "\n".join(L)


def generate_box_config(params):
    """
    Config the BOX applies to itself so it will accept this NAS's logs.
    Emits: nftables allow (append log_source_ip to the mikrotik-nas set) and
    the rsyslog reception note. Idempotent-friendly.
    """
    p = params
    src = p["log_source_ip"]
    ipaddress.ip_address(src)
    port = p["syslog_port"]
    L = []
    L.append(f"# ---- Box-side: accept logs from {p['nas_name']} ({src}) ----")
    L.append(f"# The firewall is handled automatically: clicking 'Apply & Reload'")
    L.append(f"# in Settings -> NAS Devices opens udp/{port} from {src} (UFW).")
    L.append(f"# Manual equivalent, if ever needed:")
    L.append(f"#   sudo ufw allow from {src} to any port {port} proto udp")
    L.append(f"#")
    L.append(f"# rsyslog listens on udp/{port} (90-mikrotik-ingest.conf). Attribution")
    L.append(f"# is by source IP -> nas_id; lines from IPs not registered as a NAS")
    L.append(f"# are dropped by the ingest daemon.")
    return "\n".join(L)
