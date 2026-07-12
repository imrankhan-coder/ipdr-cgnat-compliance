#!/usr/bin/env python3
"""
dashboard_stats_refresh.py — compute expensive dashboard aggregates for each NAS
scope (and 'all') and upsert into dashboard_stats_cache. Run every 60s via timer.
The dashboard route reads this cache instead of scanning 24h of translations.

Env: DATABASE_URL (from .env).
"""
import os, sys, json, logging
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor, Json

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s dash-stats %(levelname)s %(message)s")
log = logging.getLogger("dash-stats")

def _dsn():
    dsn = os.environ.get("DATABASE_URL")
    if dsn: return dsn
    for line in open(os.environ.get("IPDR_ENV", "/opt/ipdr/.env")):
        if line.startswith("DATABASE_URL="):
            return line.split("=",1)[1].strip()
    raise RuntimeError("no DATABASE_URL")

def compute_scope(cur, nas_id):
    """Compute stats for one scope (nas_id=None means 'all')."""
    nf = " AND nas_id = %s" if nas_id else ""
    nf_where = " WHERE nas_id = %s" if nas_id else ""
    p = [nas_id] if nas_id else []

    # 24h + 1h counts (bounded, partition-pruned)
    cur.execute(
        "SELECT COUNT(*) FILTER (WHERE log_time > NOW()-INTERVAL '24 hours') AS h24, "
        "COUNT(*) FILTER (WHERE log_time > NOW()-INTERVAL '1 hour') AS h1 "
        "FROM mikrotik_translations WHERE log_time > NOW()-INTERVAL '24 hours'" + nf, p)
    r = cur.fetchone(); h24 = r["h24"] or 0; h1 = r["h1"] or 0

    # grand total estimate from partition stats (no scan)
    cur.execute(
        "SELECT COALESCE(SUM(c.reltuples),0)::bigint AS est FROM pg_inherits i "
        "JOIN pg_class c ON c.oid=i.inhrelid JOIN pg_class pp ON pp.oid=i.inhparent "
        "WHERE pp.relname='mikrotik_translations'")
    est = cur.fetchone()["est"] or h24

    # online subscribers from ppp_sessions
    cur.execute("SELECT COUNT(*) AS s FROM mikrotik_ppp_sessions WHERE session_stop IS NULL" + nf, p)
    subs = cur.fetchone()["s"] or 0

    # unique public IPs (1h window, few IPs)
    cur.execute(
        "SELECT COUNT(DISTINCT public_ip) AS u FROM mikrotik_translations "
        "WHERE log_time > NOW()-INTERVAL '1 hour'" + nf, p)
    uips = cur.fetchone()["u"] or 0

    # hourly chart (24h)
    cur.execute(
        "SELECT date_trunc('hour', log_time) AS hour, COUNT(*) AS cnt "
        "FROM mikrotik_translations WHERE log_time > NOW()-INTERVAL '24 hours'" + nf +
        " GROUP BY 1 ORDER BY 1", p)
    chart = [{"hour": row["hour"].isoformat(), "cnt": row["cnt"]} for row in cur.fetchall()]

    return {"nat_total": est, "nat_24h": h24, "nat_1h": h1,
            "subs_online": subs, "unique_ips": uips, "chart": chart}

def main():
    conn = psycopg2.connect(_dsn())
    cur = conn.cursor(cursor_factory=RealDictCursor)
    # scopes: 'all' + each mikrotik nas
    cur.execute("SELECT id FROM nas_devices WHERE nas_type='mikrotik'")
    nas_ids = [r["id"] for r in cur.fetchall()]
    scopes = [("all", None)] + [(f"nas:{i}", i) for i in nas_ids]
    now = datetime.utcnow()
    for key, nid in scopes:
        try:
            s = compute_scope(cur, nid)
            cur.execute(
                """INSERT INTO dashboard_stats_cache
                   (scope_key, nat_total, nat_24h, nat_1h, subs_online, unique_ips, chart_json, computed_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (scope_key) DO UPDATE SET
                     nat_total=EXCLUDED.nat_total, nat_24h=EXCLUDED.nat_24h, nat_1h=EXCLUDED.nat_1h,
                     subs_online=EXCLUDED.subs_online, unique_ips=EXCLUDED.unique_ips,
                     chart_json=EXCLUDED.chart_json, computed_at=EXCLUDED.computed_at""",
                (key, s["nat_total"], s["nat_24h"], s["nat_1h"], s["subs_online"],
                 s["unique_ips"], Json(s["chart"]), now))
            conn.commit()
            log.info("scope %s: 24h=%d subs=%d ips=%d", key, s["nat_24h"], s["subs_online"], s["unique_ips"])
        except Exception as e:
            conn.rollback(); log.error("scope %s failed: %s", key, e)
    conn.close()

if __name__ == "__main__":
    main()
