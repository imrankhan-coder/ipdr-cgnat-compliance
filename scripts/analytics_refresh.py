#!/usr/bin/env python3
"""
analytics_refresh.py — precompute analytics for LONG ranges per NAS scope into
analytics_cache. Runs every 5 min. Uses TABLESAMPLE on the underlying partitioned
table for heavy aggregations so the job stays cheap, scaling counts by 1/sample.

Key perf fix: the COUNT(DISTINCT ...) over millions of rows is the bottleneck.
We sample the base table (mikrotik_translations) at a small % and scale up.
"""
import os, sys, logging
from datetime import datetime, timezone
import psycopg2
from psycopg2.extras import RealDictCursor, Json

sys.path.insert(0, "/opt/ipdr")
sys.path.insert(0, "/opt/ipdr/scripts")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s analytics-refresh %(levelname)s %(message)s")
log = logging.getLogger("analytics-refresh")

RANGES = {"30m": "30 minutes", "1h": "1 hour", "12h": "12 hours",
          "24h": "24 hours", "1w": "7 days", "1M": "30 days"}
SAMPLE_PCT = {"30m": 50, "1h": 30, "12h": 10, "24h": 5, "1w": 2, "1M": 1}
TIERS = {"fast": ["30m"], "slow": ["1h", "12h", "24h", "1w", "1M"]}

def _dsn():
    dsn = os.environ.get("DATABASE_URL")
    if dsn: return dsn
    for line in open(os.environ.get("IPDR_ENV", "/opt/ipdr/.env")):
        if line.startswith("DATABASE_URL="):
            return line.split("=",1)[1].strip()
    raise RuntimeError("no DATABASE_URL")

try:
    import port_service
except Exception:
    port_service = None
def _classify(port, proto):
    if port_service:
        try: return port_service.classify(port, proto)
        except Exception: pass
    return "other"
try:
    from app import geo_country_name
except Exception:
    def geo_country_name(ip): return "Unknown"

def compute(cur, nas_id, rng):
    interval = RANGES[rng]
    pct = SAMPLE_PCT[rng]
    factor = 100.0 / pct
    nas_and = f" AND nas_id = {int(nas_id)}" if nas_id else ""
    # Sample the BASE table (view can't be sampled). TABLESAMPLE SYSTEM reads a
    # fraction of blocks — fast. Then filter by time + nas, scale counts up.
    base = (f"(SELECT * FROM mikrotik_translations TABLESAMPLE SYSTEM ({pct}) "
            f"WHERE log_time > NOW() - INTERVAL '{interval}'{nas_and}) s")
    # column names in base table: username, private_ip, public_ip, public_port,
    # dest_ip, dest_port, protocol. Map to the view's names used by the template.
    def scale(n): return int((n or 0) * factor)

    # stats
    cur.execute(f"SELECT COUNT(*) AS tf, COUNT(DISTINCT username) AS us, "
                f"COUNT(DISTINCT dest_ip) AS ud, COUNT(DISTINCT public_ip) AS ni FROM {base}")
    r = cur.fetchone()
    stats = {"total_flows": scale(r["tf"]), "unique_subs": scale(r["us"]),
             "unique_dests": scale(r["ud"]), "active_nat_ips": (r["ni"] or 0)}

    # protocols
    cur.execute(f"SELECT COALESCE(protocol,'unknown') AS proto, COUNT(*) AS cnt "
                f"FROM {base} GROUP BY 1 ORDER BY 2 DESC LIMIT 10")
    protocols = [{"proto": x["proto"], "cnt": scale(x["cnt"])} for x in cur.fetchall()]

    # top apps by port
    cur.execute(f"SELECT dest_port AS destination_port, protocol AS protocol_name, "
                f"COUNT(*) AS cnt FROM {base} GROUP BY 1,2 ORDER BY cnt DESC LIMIT 400")
    svc = {}
    for x in cur.fetchall():
        label = _classify(x["destination_port"], x.get("protocol_name"))
        svc[label] = svc.get(label, 0) + x["cnt"]
    top_apps = [{"app": k, "cnt": scale(v)} for k, v in sorted(svc.items(), key=lambda i:-i[1])[:12]]

    # top subs
    cur.execute(f"SELECT host(public_ip) AS source_ip, MAX(username) AS username, "
                f"COUNT(*) AS sessions, COUNT(DISTINCT dest_ip) AS destinations, "
                f"COUNT(DISTINCT dest_port) AS services FROM {base} "
                f"GROUP BY public_ip ORDER BY sessions DESC LIMIT 10")
    top_subs = []
    for x in cur.fetchall():
        top_subs.append({"source_ip": x["source_ip"], "username": x["username"],
                         "sessions": scale(x["sessions"]),
                         "destinations": x["destinations"], "services": x["services"]})

    # top dests + geo
    cur.execute(f"SELECT host(dest_ip) AS destination_ip, COUNT(*) AS sessions "
                f"FROM {base} GROUP BY dest_ip ORDER BY 2 DESC LIMIT 10")
    top_dests = []
    for x in cur.fetchall():
        top_dests.append({"destination_ip": x["destination_ip"],
                          "sessions": scale(x["sessions"]),
                          "country": geo_country_name(x["destination_ip"])})

    # country dist from top 200
    cur.execute(f"SELECT host(dest_ip) AS destination_ip, COUNT(*) AS cnt "
                f"FROM {base} GROUP BY dest_ip ORDER BY 2 DESC LIMIT 200")
    cc = {}
    for x in cur.fetchall():
        c = geo_country_name(x["destination_ip"]); cc[c] = cc.get(c, 0) + x["cnt"]
    top_countries = sorted(cc.items(), key=lambda i:-i[1])[:10]

    # timeline hourly
    cur.execute(f"SELECT to_char(date_trunc('hour', log_time),'MM-DD HH24:MI') AS t, "
                f"COUNT(*) AS sessions, 0 AS subs FROM {base} "
                f"GROUP BY date_trunc('hour', log_time) ORDER BY date_trunc('hour', log_time)")
    timeline = [{"t": x["t"], "sessions": scale(x["sessions"]), "subs": 0} for x in cur.fetchall()]

    return {"stats": stats, "protocols": protocols, "top_apps": top_apps,
            "top_subs": top_subs, "top_dests": top_dests,
            "top_countries": top_countries, "timeline": timeline, "sample_pct": pct}

def main():
    tier = "all"
    if "--tier" in sys.argv:
        tier = sys.argv[sys.argv.index("--tier") + 1]
    ranges = RANGES if tier == "all" else {r: RANGES[r] for r in TIERS.get(tier, [])}
    conn = psycopg2.connect(_dsn())
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id FROM nas_devices WHERE nas_type='mikrotik'")
    nas_ids = [r["id"] for r in cur.fetchall()]
    scopes = [("all", None)] + [(f"nas:{i}", i) for i in nas_ids]
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for skey, nid in scopes:
        for rng in ranges:
            try:
                import time; t0=time.time()
                payload = compute(cur, nid, rng)
                cur.execute(
                    """INSERT INTO analytics_cache (scope_key, range_key, payload, computed_at)
                       VALUES (%s,%s,%s,%s) ON CONFLICT (scope_key, range_key) DO UPDATE
                       SET payload=EXCLUDED.payload, computed_at=EXCLUDED.computed_at""",
                    (skey, rng, Json(payload), now))
                conn.commit()
                log.info("scope %s range %s: %.2fs (%d flows)", skey, rng, time.time()-t0,
                         payload["stats"]["total_flows"])
            except Exception as e:
                conn.rollback(); log.error("scope %s range %s failed: %s", skey, rng, e)
    conn.close()

if __name__ == "__main__":
    main()
