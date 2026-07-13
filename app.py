#!/usr/bin/env python3
"""
IPDR — CGNAT IPDR & LEA Compliance Portal
Example ISP — AS64500

Ingests:
  1. NAT PBA syslog from Juniper MX480 (UDP 514)
  2. RADIUS accounting from MX480 (via FreeRADIUS → PostgreSQL)

Provides:
  - LEA query portal (public IP + port + timestamp → subscriber identity)
  - Username lookup (subscriber → all NAT mappings in a date range)
  - Audit trail of every query
  - PDF/XLSX report generation
  - Admin panel (user management, system config, log retention)
  - Dashboard with live stats
"""

VERSION = "3.0"

import os
import re
import csv
import io
import hashlib
import secrets
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

# Local enrichment (GeoIP + app decoding)
try:
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))
    from enrich import geo_country, geo_country_name, decode_application
    ENRICH_AVAILABLE = True
except ImportError:
    ENRICH_AVAILABLE = False
    def geo_country(ip): return "??"
    def geo_country_name(ip): return "Unknown"
    def decode_application(a, p, port, ip=None): return a or "Unknown"

try:
    import branding as branding_mod
    BRANDING_AVAILABLE = True
except ImportError:
    BRANDING_AVAILABLE = False

try:
    import sysmetrics
    SYSMETRICS_AVAILABLE = True
except ImportError:
    SYSMETRICS_AVAILABLE = False

try:
    import mikrotik_lea
    MIKROTIK_LEA_AVAILABLE = True
except ImportError:
    MIKROTIK_LEA_AVAILABLE = False

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, send_file, abort, g
)
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
# Trust nginx's X-Forwarded-Proto/For (SSL terminated at nginx) so secure cookies work
try:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_for=1, x_host=1)
except ImportError:
    pass
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
# Cookie hardening — portal is HTTPS-only behind nginx+Let's Encrypt
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

@app.template_filter("format_mac")
def format_mac(mac):
    if not mac:
        return ""
    return mac.upper().replace("-", ":")

@app.template_filter("geo")
def geo_filter(ip):
    return geo_country_name(ip)

@app.template_filter("geo_code")
def geo_code_filter(ip):
    return geo_country(ip)

LOG_FMT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
log = logging.getLogger("elb-ipdr")

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
DB_DSN = os.environ.get(
    "DATABASE_URL",
    "host=127.0.0.1 dbname=elb_ipdr user=elb_ipdr password=changeme"
)

pool = None

def get_pool():
    global pool
    if pool is None:
        pool = ThreadedConnectionPool(2, 20, DB_DSN)
    return pool

def get_db():
    if "db" not in g:
        g.db = get_pool().getconn()
        g.db.autocommit = True
    return g.db

@app.teardown_appcontext
def return_db(exc):
    db = g.pop("db", None)
    if db is not None:
        get_pool().putconn(db)

_BOX_ENGINE_CACHE = None

def _selected_nas_id():
    """Active NAS filter from session: int nas_id, or None for fleet/all."""
    v = session.get("sel_nas")
    if v in (None, "", "all"):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@app.context_processor
def inject_nas_scope():
    """Expose the NAS list + current selection to every template."""
    try:
        nas_list = query(
            "SELECT id, name FROM nas_devices "
            "WHERE nas_type='mikrotik' AND enabled ORDER BY name"
        ) or []
    except Exception:
        nas_list = []
    sel = _selected_nas_id()
    sel_name = None
    if sel is not None:
        for n in nas_list:
            if n["id"] == sel:
                sel_name = n["name"]; break
    return {"nas_list": nas_list, "sel_nas": sel, "sel_nas_name": sel_name}


@app.context_processor
def inject_box_engine():
    """Expose box_engine ('mikrotik'|'juniper') to templates, cached after first use."""
    global _BOX_ENGINE_CACHE
    if _BOX_ENGINE_CACHE is None:
        try:
            r = query("SELECT 1 FROM mikrotik_translations LIMIT 1", one=True)
            _BOX_ENGINE_CACHE = "mikrotik" if r is not None else "juniper"
        except Exception:
            _BOX_ENGINE_CACHE = "juniper"
    return {"box_engine": _BOX_ENGINE_CACHE}


def query(sql, params=None, one=False):
    cur = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, params)
    if cur.description is None:
        return None
    rows = cur.fetchall()
    return rows[0] if one and rows else rows if not one else None

def execute(sql, params=None):
    cur = get_db().cursor()
    cur.execute(sql, params)
    return cur

# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated

def lea_required(f):
    """Requires LEA or admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") not in ("admin", "lea", "operator"):
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------
def audit_log(action, detail="", target_user=None):
    execute(
        """INSERT INTO audit_log (user_id, username, action, detail, target_user, ip_address)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (
            session.get("user_id"),
            session.get("username", "system"),
            action,
            detail,
            target_user,
            request.remote_addr,
        ),
    )

# ---------------------------------------------------------------------------
# Context processor — inject user info into all templates
# ---------------------------------------------------------------------------
def load_branding():
    """Load branding config from DB, falling back to defaults."""
    try:
        b = query("SELECT * FROM branding WHERE id = 1", one=True)
        if b:
            return dict(b)
    except Exception:
        pass
    # Fallback defaults if table missing or error
    from branding import DEFAULTS
    return dict(DEFAULTS)

@app.context_processor
def inject_user():
    return {
        "current_user": session.get("username"),
        "current_role": session.get("role"),
        "now": datetime.now(),
        "branding": load_branding(),
        "app_version": VERSION,
    }

# ---------------------------------------------------------------------------
# Routes — Auth
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = query(
            "SELECT * FROM users WHERE username = %s AND is_active = true",
            (username,), one=True,
        )
        if user and check_password_hash(user["password_hash"], password):
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            execute(
                "UPDATE users SET last_login = NOW() WHERE id = %s",
                (user["id"],),
            )
            audit_log("LOGIN", f"Successful login")
            return redirect(url_for("dashboard"))
        audit_log("LOGIN_FAILED", f"Failed login for '{username}'")
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    audit_log("LOGOUT", "User logged out")
    session.clear()
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    stats = {}
    mt_row = query("SELECT EXISTS(SELECT 1 FROM mikrotik_translations LIMIT 1) AS e", one=True)  # dash-perf
    is_mikrotik = bool(mt_row["e"]) if mt_row else False

    if is_mikrotik:
        _sel = _selected_nas_id()  # _nas_scope  # dashboard
        _nf = (" AND nas_id = %s" if _sel else "")
        _nf_where = (" WHERE nas_id = %s" if _sel else "")
        _p = ([_sel] if _sel else [])
        stats["scope_nas_id"] = _sel
        # dash-cache-clean: read precomputed stats (instant); live fallback if missing
        _scope = f"nas:{_sel}" if _sel else "all"
        _cache = query("SELECT * FROM dashboard_stats_cache WHERE scope_key=%s", (_scope,), one=True)
        _cache_chart = None
        if _cache:
            stats["nat_24h"] = _cache["nat_24h"]
            stats["nat_1h"] = _cache["nat_1h"]
            stats["nat_total"] = _cache["nat_total"]
            stats["radius_total"] = _cache["subs_online"]
            stats["radius_active"] = _cache["subs_online"]
            stats["unique_public_ips"] = _cache["unique_ips"]
            _cache_chart = _cache["chart_json"]
        else:
            # fallback: compute live (first run before the timer populates cache)
            row = query(
                "SELECT COUNT(*) FILTER (WHERE log_time > NOW()-INTERVAL '24 hours') AS last_24h, "
                "COUNT(*) FILTER (WHERE log_time > NOW()-INTERVAL '1 hour') AS last_1h "
                "FROM mikrotik_translations WHERE log_time > NOW()-INTERVAL '24 hours'" + _nf, _p, one=True)
            stats["nat_24h"] = row["last_24h"] if row else 0
            stats["nat_1h"] = row["last_1h"] if row else 0
            est = query(
                "SELECT COALESCE(SUM(c.reltuples),0)::bigint AS est FROM pg_inherits i "
                "JOIN pg_class c ON c.oid=i.inhrelid JOIN pg_class p ON p.oid=i.inhparent "
                "WHERE p.relname='mikrotik_translations'", one=True)
            stats["nat_total"] = (est["est"] if est and est["est"] else stats["nat_24h"])
            row = query("SELECT COUNT(*) AS subs FROM mikrotik_ppp_sessions WHERE session_stop IS NULL" + _nf, _p, one=True)
            stats["radius_total"] = row["subs"] if row else 0
            stats["radius_active"] = row["subs"] if row else 0
            row = query("SELECT COUNT(DISTINCT public_ip) AS u FROM mikrotik_translations WHERE log_time > NOW()-INTERVAL '1 hour'" + _nf, _p, one=True)
            stats["unique_public_ips"] = row["u"] if row else 0
        row = query(
            "SELECT COUNT(*) AS total, "
            "COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS last_24h "
            "FROM audit_log WHERE action IN ('LEA_QUERY', 'USERNAME_QUERY')", one=True,
        )
        stats["queries_total"] = row["total"] if row else 0
        stats["queries_24h"] = row["last_24h"] if row else 0
        # dash-cache-clean: unique_public_ips now set from cache/fallback above
        recent_raw = query(
            "SELECT log_time, username, private_ip, public_ip, public_port, "
            "dest_ip, dest_port, protocol "
            "FROM mikrotik_translations" + _nf_where + " ORDER BY id DESC LIMIT 15",
            _p,
        ) or []
        recent_nat = []
        for r in recent_raw:
            recent_nat.append({
                "log_time": r["log_time"],
                "log_type": "MT_XLATE",
                "subscriber_ip": r["username"],
                "public_ip": str(r["public_ip"]),
                "port_block_start": r["public_port"],
                "port_block_end": r["public_port"],
            })
        if _cache_chart is not None:
            # cached chart (list of {hour, cnt}); normalize to row-like dicts
            from datetime import datetime as _dt
            chart_data = [{"hour": _dt.fromisoformat(x["hour"]), "cnt": x["cnt"]} for x in _cache_chart]
        else:
            chart_data = query(
                "SELECT date_trunc('hour', log_time) AS hour, COUNT(*) AS cnt "
                "FROM mikrotik_translations WHERE log_time > NOW()-INTERVAL '24 hours'" + _nf + " "
                "GROUP BY 1 ORDER BY 1", _p,
            ) or []
        stats["engine"] = "mikrotik"
    else:
        row = query(
            "SELECT COUNT(*) as total, "
            "COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as last_24h, "
            "COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 hour') as last_1h "
            "FROM nat_logs", one=True,
        )
        stats["nat_total"] = row["total"] if row else 0
        stats["nat_24h"] = row["last_24h"] if row else 0
        stats["nat_1h"] = row["last_1h"] if row else 0
        row = query(
            "SELECT COUNT(*) as total, "
            "COUNT(*) FILTER (WHERE acct_status = 'Start' AND session_stop IS NULL) as active "
            "FROM radius_accounting", one=True,
        )
        stats["radius_total"] = row["total"] if row else 0
        stats["radius_active"] = row["active"] if row else 0
        row = query(
            "SELECT COUNT(*) as total, "
            "COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as last_24h "
            "FROM audit_log WHERE action IN ('LEA_QUERY', 'USERNAME_QUERY')", one=True,
        )
        stats["queries_total"] = row["total"] if row else 0
        stats["queries_24h"] = row["last_24h"] if row else 0
        row = query(
            "SELECT COUNT(DISTINCT public_ip) as unique_ips FROM nat_logs "
            "WHERE log_type = 'PBA_ALLOC'", one=True,
        )
        stats["unique_public_ips"] = row["unique_ips"] if row else 0
        recent_nat = query("SELECT * FROM nat_logs ORDER BY log_time DESC LIMIT 15") or []
        chart_data = query(
            "SELECT date_trunc('hour', log_time) as hour, COUNT(*) as cnt "
            "FROM nat_logs WHERE log_time > NOW() - INTERVAL '24 hours' "
            "GROUP BY 1 ORDER BY 1"
        ) or []
        stats["engine"] = "juniper"

    recent_audit = query(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 15"
    ) or []
    return render_template(
        "dashboard.html",
        stats=stats,
        recent_nat=recent_nat,
        recent_audit=recent_audit,
        chart_data=chart_data,
    )


# ---------------------------------------------------------------------------
# Routes — LEA Query (the core compliance feature)
# ---------------------------------------------------------------------------
@app.route("/lea-query", methods=["GET", "POST"])
@lea_required
def lea_query():
    results = None
    form_data = {}
    if request.method == "POST":
        public_ip = request.form.get("public_ip", "").strip()
        port = request.form.get("port", "").strip()
        timestamp_str = request.form.get("timestamp", "").strip()
        case_ref = request.form.get("case_ref", "").strip()
        reason = request.form.get("reason", "").strip()
        try:
            window_seconds = int(request.form.get("window_seconds", "300"))
        except (ValueError, TypeError):
            window_seconds = 300
        # clamp to sane bounds: 60s .. 6h
        window_seconds = max(60, min(window_seconds, 21600))

        form_data = {
            "public_ip": public_ip,
            "port": port,
            "timestamp": timestamp_str,
            "case_ref": case_ref,
            "reason": reason,
            "window_seconds": window_seconds,
        }

        if not all([public_ip, port, timestamp_str]):
            flash("Public IP, Port, and Timestamp are required.", "warning")
            return render_template("lea_query.html", results=None, form_data=form_data)

        try:
            port_num = int(port)
            query_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, TypeError) as e:
            flash(f"Invalid port or timestamp format: {e}", "danger")
            return render_template("lea_query.html", results=None, form_data=form_data)

        # --- MikroTik branch: syslog-based CGNAT lookup --------------------
        if MIKROTIK_LEA_AVAILABLE:
            def _mt_enrich(_username, _nas_id):
                _r = query(
                    "SELECT comment, phone, caller_id, last_caller_id "
                    "FROM mikrotik_secrets WHERE nas_id=%s AND username=%s",
                    (_nas_id, _username), one=True,
                )
                if not _r:
                    _r = query(
                        "SELECT comment, phone, caller_id, last_caller_id "
                        "FROM mikrotik_secrets WHERE username=%s LIMIT 1",
                        (_username,), one=True,
                    )
                if not _r:
                    return None
                return {
                    "customer_name": _r["comment"],
                    "phone": _r.get("phone"),
                    "mac": _r.get("caller_id") or _r.get("last_caller_id"),
                    "source": "mikrotik-api",
                }
            mt = mikrotik_lea.lookup(get_db(), public_ip, port_num, query_time,
                                     window_seconds=window_seconds,
                                     enrich_fn=_mt_enrich)
            # mt-lea-always-return: on a MikroTik box the MikroTik lookup is
            # authoritative. Always render its result (found OR not-found) and
            # return; never fall through to the Juniper nat_logs/nat_flow_logs
            # queries, which don't apply here and crash on schema mismatch.
            if mt.found:
                audit_log(
                    "LEA_QUERY",
                    f"IP={public_ip} Port={port} Time={timestamp_str} "
                    f"CaseRef={case_ref} Reason={reason} "
                    f"Engine=mikrotik Window={window_seconds}s Subscriber={mt.primary['username']} "
                    f"PortReuse={mt.port_reuse} Candidates={len(mt.candidates)}",
                )
            else:
                audit_log(
                    "LEA_QUERY",
                    f"IP={public_ip} Port={port} Time={timestamp_str} "
                    f"CaseRef={case_ref} Reason={reason} "
                    f"Engine=mikrotik Window={window_seconds}s Result=NOT_FOUND",
                )
            return render_template(
                "lea_query.html",
                results=None, flow_matches=None,
                mt_result=mt, form_data=form_data, query_time=query_time,
            )

        # Step 1: Find NAT PBA log where the port falls in the block range
        nat_matches = query(
            """SELECT * FROM nat_logs
               WHERE public_ip = %s
                 AND port_block_start <= %s
                 AND port_block_end >= %s
                 AND log_time <= %s
                 AND (release_time IS NULL OR release_time >= %s)
               ORDER BY log_time DESC
               LIMIT 10""",
            (public_ip, port_num, port_num, query_time, query_time),
        ) or []

        # Step 2: For each NAT match, find RADIUS session
        results = []
        for nat in nat_matches:
            subscriber_ip = nat["subscriber_ip"]
            radius = query(
                """SELECT * FROM radius_accounting
                   WHERE framed_ip = %s
                     AND session_start <= %s
                     AND (session_stop IS NULL OR session_stop >= %s)
                   ORDER BY session_start DESC
                   LIMIT 1""",
                (subscriber_ip, query_time, query_time),
                one=True,
            )
            results.append({
                "nat": dict(nat),
                "radius": dict(radius) if radius else None,
            })

        # Step 3: Also check per-flow RT_NAT_RULE_MATCH logs if available
        flow_matches = query(
            """SELECT * FROM nat_flow_logs
               WHERE public_ip = %s
                 AND log_time BETWEEN %s - INTERVAL '5 minutes' AND %s + INTERVAL '5 minutes'
                 AND (translated_port = %s OR source_port = %s)
               ORDER BY log_time DESC
               LIMIT 20""",
            (public_ip, query_time, query_time, port_num, port_num),
        ) or []

        # Audit the query
        audit_log(
            "LEA_QUERY",
            f"IP={public_ip} Port={port} Time={timestamp_str} CaseRef={case_ref} "
            f"Reason={reason} Results={len(results)} FlowMatches={len(flow_matches)}",
        )

        return render_template(
            "lea_query.html",
            results=results,
            flow_matches=flow_matches,
            form_data=form_data,
            query_time=query_time,
        )

    return render_template("lea_query.html", results=None, form_data=form_data)

# ---------------------------------------------------------------------------
# Routes — Username Lookup
# ---------------------------------------------------------------------------
@app.route("/username-query", methods=["GET", "POST"])
@lea_required
def username_query():
    results = None
    form_data = {}
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        date_from = request.form.get("date_from", "").strip()
        date_to = request.form.get("date_to", "").strip()
        case_ref = request.form.get("case_ref", "").strip()
        reason = request.form.get("reason", "").strip()

        form_data = {
            "username": username,
            "date_from": date_from,
            "date_to": date_to,
            "case_ref": case_ref,
            "reason": reason,
        }

        if not username:
            flash("Username is required.", "warning")
            return render_template("username_query.html", results=None, form_data=form_data)

        # Default date range: last 30 days
        try:
            dt_from = datetime.fromisoformat(date_from) if date_from else datetime.now() - timedelta(days=30)
            dt_to = datetime.fromisoformat(date_to) if date_to else datetime.now()
            # date_to end-of-day: a date-only value is midnight; extend to the
            # end of that day so same-day / single-day searches include the day.
            if date_to and len(date_to) <= 10:
                dt_to = dt_to + timedelta(days=1) - timedelta(microseconds=1)
        except ValueError:
            flash("Invalid date format.", "danger")
            return render_template("username_query.html", results=None, form_data=form_data)

        mt_probe = query("SELECT 1 FROM mikrotik_translations LIMIT 1", one=True)
        if mt_probe is not None:
            # MikroTik: sessionize translations in the date range into windows,
            # then flatten each window into a session-shaped result row.
            import mikrotik_sessions
            rows = query(
                """SELECT log_time, username, private_ip, private_port,
                          public_ip, public_port, dest_ip, dest_port, protocol, src_mac
                   FROM mikrotik_translations
                   WHERE username ILIKE %s
                     AND log_time BETWEEN %s AND %s
                   ORDER BY log_time ASC
                   LIMIT 20000""",
                (username, dt_from, dt_to),
            ) or []
            _now = datetime.now(rows[0]["log_time"].tzinfo) if rows else None
            windows = mikrotik_sessions.build_windows([dict(r) for r in rows], now=_now)
            results = []
            for w in windows:
                s = dict(w["session"])
                s["nat_mappings"] = s.get("public_ips") or []
                results.append(s)
            audit_log(
                "USERNAME_QUERY",
                f"Username={username} From={date_from} To={date_to} "
                f"CaseRef={case_ref} Reason={reason} "
                f"Results={len(results)} Engine=mikrotik Windows={len(results)}",
            )
            return render_template("username_query.html", results=results, form_data=form_data)

        # --- Juniper path (RADIUS) ---
        sessions = query(
            """SELECT ra.*, 
                      array_agg(DISTINCT nl.public_ip || ':' || nl.port_block_start || '-' || nl.port_block_end) 
                        FILTER (WHERE nl.id IS NOT NULL) as nat_mappings
               FROM radius_accounting ra
               LEFT JOIN nat_logs nl ON nl.subscriber_ip = ra.framed_ip
                 AND nl.log_time BETWEEN ra.session_start AND COALESCE(ra.session_stop, NOW())
               WHERE ra.username ILIKE %s
                 AND ra.session_start BETWEEN %s AND %s
               GROUP BY ra.id
               ORDER BY ra.session_start DESC
               LIMIT 200""",
            (f"%{username}%", dt_from, dt_to),
        ) or []
        results = sessions
        audit_log(
            "USERNAME_QUERY",
            f"Username={username} From={date_from} To={date_to} "
            f"CaseRef={case_ref} Reason={reason} Results={len(results)}",
        )
        return render_template("username_query.html", results=results, form_data=form_data)

    return render_template("username_query.html", results=None, form_data=form_data)

# ---------------------------------------------------------------------------
# Routes — v2.3 Subscriber search + NAT footprint (shared by Username Lookup
# and Subscriber Timeline).
# ---------------------------------------------------------------------------
import re as _re

_MAC_RE = _re.compile(r'^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$')
_IP_RE = _re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def _classify_q(q):
    """Detect what kind of identifier the search string is."""
    q = q.strip()
    if _MAC_RE.match(q):
        return "mac"
    if _IP_RE.match(q):
        # CGN 100.64/10 vs public
        try:
            first, second = int(q.split(".")[0]), int(q.split(".")[1])
        except (ValueError, IndexError):
            return "ip"
        if first == 100 and 64 <= second <= 127:
            return "cgn"
        if first in (10, 127) or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168):
            return "private"
        return "public"
    return "username"


def _detect_bogon_mitigation(nas):
    """Check a MikroTik NAS via API for bogon-mitigation deployment.
    Returns dict: {configured, has_drop, has_accept, local_devices, has_script}.
    Read-only — never modifies the router. Safe timeouts; returns unknown on
    connection failure."""
    out = {"configured": False, "has_drop": False, "has_accept": False,
           "local_devices": 0, "has_script": False, "reachable": False}
    if nas.get("nas_type") != "mikrotik" or not nas.get("api_enabled"):
        return out
    try:
        from librouteros import connect as _mt_connect
        import mt_crypto as _mtc
        pw = _mtc.decrypt(nas["api_password_enc"])
        api = _mt_connect(username=nas["api_user"], password=pw,
                          host=nas["api_host"] or nas["ip_address"],
                          port=int(nas["api_port"] or 8728))
        out["reachable"] = True
        for r in api.path("ip", "firewall", "raw"):
            d = dict(r); cm = (d.get("comment") or "").lower()
            if "bogon" in cm and d.get("action") == "drop":
                out["has_drop"] = True
            if "local device" in cm and d.get("action") == "accept":
                out["has_accept"] = True
        n = 0
        for a in api.path("ip", "firewall", "address-list"):
            if dict(a).get("list") == "LOCAL_DEVICES":
                n += 1
        out["local_devices"] = n
        for s in api.path("system", "script"):
            if dict(s).get("name") == "sync-local-devices":
                out["has_script"] = True; break
        api.close()
    except Exception:
        return out
    out["configured"] = out["has_drop"] and out["has_accept"] and out["has_script"]
    return out


@app.route("/settings/nas/<int:nas_id>/bogon-config")
@admin_required
def nas_bogon_config(nas_id):
    """Render paste-ready RouterOS bogon-mitigation config for this NAS.
    Entire config pastes in New Terminal; the sync script uses RouterOS's own
    exported form (paste-safe, no GUI step)."""
    nas = query("SELECT * FROM nas_devices WHERE id=%s", (nas_id,), one=True)
    if not nas:
        flash("NAS not found.", "warning")
        return redirect(url_for("nas_devices"))
    _script = '/system script\nadd dont-require-permissions=no name=sync-local-devices policy=read,write,test source="/ip firewall address-list remove [find list=LOCAL_DEVICES comment=\\"arp-sync\\"]\\r\\\n    \\n:foreach a in=[/ip arp find] do={\\r\\\n    \\n  :local ip [/ip arp get \\$a address]\\r\\\n    \\n  :local iface [/ip arp get \\$a interface]\\r\\\n    \\n  :local mac [/ip arp get \\$a mac-address]\\r\\\n    \\n  :if ([:find \\$iface \\"WAN\\"]<0 && [:len \\$mac]>0) do={\\r\\\n    \\n    :if ([:pick \\$ip 0 4]=\\"172.\\" || [:pick \\$ip 0 3]=\\"10.\\" || [:pick \\$ip 0 8]=\\"192.168.\\") do={\\r\\\n    \\n      :do { /ip firewall address-list add list=LOCAL_DEVICES address=\\$ip comment=\\"arp-sync\\" } on-error={}\\r\\\n    \\n    }\\r\\\n    \\n  }\\r\\\n    \\n}"'
    cfg = """# ==============================================================
# Bogon mitigation for {name} ({ip})
# Paste this ENTIRE block in WinBox > New Terminal. Review first.
# The platform detects status read-only; it does NOT push this.
# ==============================================================

# 1) BOGON_DEST -- private/bogon destination ranges
/ip firewall address-list
add list=BOGON_DEST address=10.0.0.0/8 comment=bogon
add list=BOGON_DEST address=172.16.0.0/12 comment=bogon
add list=BOGON_DEST address=192.168.0.0/16 comment=bogon
add list=BOGON_DEST address=169.254.0.0/16 comment=bogon
add list=BOGON_DEST address=127.0.0.0/8 comment=bogon
add list=BOGON_DEST address=100.64.0.0/10 comment=bogon

# 2) LOCAL_MANUAL -- always-allow (EDIT to your mgmt subnet / service IPs)
/ip firewall address-list
add list=LOCAL_MANUAL address=172.16.0.0/24 comment="manual: edit to your mgmt subnet"

# 3) sync-local-devices script (RouterOS export form -- pastes as-is)
{script}

# 4) schedule the sync every 5 minutes
/system scheduler
add name=sync-local-devices-sched interval=5m on-event=sync-local-devices comment="refresh LOCAL_DEVICES from ARP"

# 5) run the sync once + verify (expect > 0)
/system script run sync-local-devices
/ip firewall address-list print count-only where list=LOCAL_DEVICES

# 6) raw rules -- ACCEPT local + manual BEFORE the bogon rule (starts as observe)
/ip firewall raw
add chain=prerouting action=accept src-address=100.64.0.0/10 dst-address-list=LOCAL_DEVICES comment="Allow subscribers to real local devices (ARP)"
add chain=prerouting action=accept src-address=100.64.0.0/10 dst-address-list=LOCAL_MANUAL comment="Allow subscribers to manual always-allow"
add chain=prerouting action=passthrough src-address=100.64.0.0/10 dst-address-list=BOGON_DEST comment="COUNT-bogon-dest observe before drop"

# 7) OBSERVE, verify bogon dests are not your own infra, then flip to drop:
#    /ip firewall raw print stats where comment~"COUNT-bogon"
#    /ip firewall raw set [find comment~"COUNT-bogon"] action=drop comment="DROP-bogon-dest pre-conntrack saves NAT table"
""".format(name=nas["name"], ip=nas["ip_address"], script=_script)
    return render_template("nas_bogon_config.html", nas=nas, cfg=cfg)


@app.route("/api/bogon-status/<int:nas_id>")
@lea_required
def api_bogon_status(nas_id):
    """Cached bogon-mitigation status for one NAS. Read from nas_devices
    (refreshed by the ARP poller every 5 min) so this is instant and never
    blocks on a live router call."""
    nas = query("SELECT * FROM nas_devices WHERE id=%s", (nas_id,), one=True)
    if not nas:
        return jsonify({"error": "NAS not found"}), 404
    st = {
        "reachable": nas.get("bogon_checked_at") is not None,
        "configured": bool(nas.get("bogon_configured")),
        "has_drop": bool(nas.get("bogon_has_drop")),
        "has_accept": bool(nas.get("bogon_has_accept")),
        "has_script": bool(nas.get("bogon_has_script")),
        "local_devices": nas.get("bogon_local_devices") or 0,
        "enabled": bool(nas.get("bogon_mitigation_enabled")),
        "checked_at": nas.get("bogon_checked_at").isoformat() if nas.get("bogon_checked_at") else None,
    }
    return jsonify(st)


@app.route("/api/static-arp")
@lea_required
def api_static_arp():
    """Static ARP entries (infrastructure: OLTs, switches, radios, CCTV) for the
    selected NAS. Returns an interface summary (for filter chips) and the
    filtered device rows. Query params: iface (filter), q (search IP/MAC/iface)."""
    _sel = _selected_nas_id()
    if not _sel:
        return jsonify({"interfaces": [], "rows": [], "total": 0})
    iface = (request.args.get("iface") or "").strip()
    q = (request.args.get("q") or "").strip()

    # interface summary for the chips (always full, unfiltered by iface)
    ifaces = query(
        "SELECT interface, COUNT(*) AS n FROM mikrotik_arp "
        "WHERE nas_id = %s GROUP BY interface ORDER BY n DESC",
        (_sel,),
    ) or []
    total = sum(r["n"] for r in ifaces)

    # rows, filtered
    sql = ("SELECT host(ip_address) AS ip, mac_address, interface, status, "
           "       first_seen, last_seen "
           "FROM mikrotik_arp WHERE nas_id = %s")
    params = [_sel]
    if iface:
        sql += " AND interface = %s"; params.append(iface)
    if q:
        sql += (" AND (host(ip_address) ILIKE %s OR mac_address ILIKE %s "
                "OR interface ILIKE %s)")
        like = f"%{q}%"; params += [like, like, like]
    sql += " ORDER BY interface, ip_address LIMIT 2000"
    rows = query(sql, params) or []

    return jsonify({
        "interfaces": [{"interface": r["interface"], "count": r["n"]} for r in ifaces],
        "rows": [dict(r) for r in rows],
        "total": total,
        "shown": len(rows),
    })


@app.route("/api/subscriber-search")
@lea_required
def api_subscriber_search():
    """Typeahead + universal search. Returns candidate usernames for a query
    that may be a username fragment, a CGN IP, a public IP, or a MAC."""
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"results": []})
    kind = _classify_q(q)
    out = []
    _sel = _selected_nas_id()
    _nf = (" AND nas_id = %s" if _sel else "")
    _np = ([_sel] if _sel else [])
    try:
        if kind == "username":
            # typeahead from the known secrets (small, indexed) + any usernames
            # actually seen in recent translations
            rows = query(
                "SELECT DISTINCT username FROM mikrotik_secrets "
                "WHERE username ILIKE %s" + _nf +
                " ORDER BY username LIMIT 12",
                ([f"%{q}%"] + _np),
            ) or []
            out = [{"username": r["username"], "via": "secret"} for r in rows]
        elif kind == "cgn":
            rows = query(
                "SELECT username, COUNT(*) AS flows, MAX(log_time) AS last_seen "
                "FROM mikrotik_translations "
                "WHERE private_ip = %s AND log_time > NOW() - INTERVAL '7 days'" + _nf +
                " GROUP BY username ORDER BY last_seen DESC LIMIT 12",
                ([q] + _np),
            ) or []
            out = [{"username": r["username"], "via": f"CGN {q} ({r['flows']} flows)"} for r in rows if r["username"]]
        elif kind == "public":
            rows = query(
                "SELECT username, COUNT(*) AS flows, MAX(log_time) AS last_seen "
                "FROM mikrotik_translations "
                "WHERE public_ip = %s AND log_time > NOW() - INTERVAL '24 hours'" + _nf +
                " GROUP BY username ORDER BY last_seen DESC LIMIT 12",
                ([q] + _np),
            ) or []
            out = [{"username": r["username"], "via": f"public {q} ({r['flows']} flows)"} for r in rows if r["username"]]
        elif kind == "mac":
            rows = query(
                "SELECT DISTINCT username FROM mikrotik_translations "
                "WHERE src_mac = %s AND log_time > NOW() - INTERVAL '7 days'" + _nf +
                " LIMIT 12",
                ([q.upper()] + _np),
            ) or []
            out = [{"username": r["username"], "via": f"MAC {q}"} for r in rows if r["username"]]
    except Exception as e:
        log.error("subscriber-search failed: %s", e)
    return jsonify({"kind": kind, "results": out})


@app.route("/api/subscriber-footprint")
@lea_required
def api_subscriber_footprint():
    """Honest NAT footprint for a subscriber: group by public IP, count DISTINCT
    ports (never a range), time window, flows, unique destinations. Complete
    (aggregate, no row LIMIT). Bounded by the requested time window."""
    username = (request.args.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username required"}), 400
    hours = request.args.get("hours", "6")
    try:
        hours = max(1, min(int(hours), 720))  # cap 30 days
    except ValueError:
        hours = 6
    _sel = _selected_nas_id()
    _nf = (" AND nas_id = %s" if _sel else "")
    _np = ([_sel] if _sel else [])
    rows = query(
        "SELECT host(public_ip) AS public_ip, "
        "       COUNT(DISTINCT public_port) AS distinct_ports, "
        "       MIN(log_time) AS first_seen, MAX(log_time) AS last_seen, "
        "       COUNT(*) AS flows, COUNT(DISTINCT dest_ip) AS unique_dests "
        "FROM mikrotik_translations "
        "WHERE username = %s AND log_time > NOW() - (%s || ' hours')::interval" + _nf +
        " GROUP BY public_ip ORDER BY MAX(log_time) DESC",
        ([username, str(hours)] + _np),
    ) or []
    total_flows = sum(r["flows"] for r in rows)
    return jsonify({
        "username": username, "hours": hours,
        "public_ips": [dict(r) for r in rows],
        "total_flows": total_flows,
        "total_public_ips": len(rows),
    })


@app.route("/api/subscriber-flows")
@lea_required
def api_subscriber_flows():
    """Drill-down: exact discrete translation rows for one subscriber on one
    public IP within a window. Paginated. Uses the (public_ip,port,log_time)
    LEA index. This is the court-defensible per-flow evidence."""
    username = (request.args.get("username") or "").strip()
    public_ip = (request.args.get("public_ip") or "").strip()
    hours = request.args.get("hours", "6")
    page = request.args.get("page", "1")
    try:
        hours = max(1, min(int(hours), 720)); page = max(1, int(page))
    except ValueError:
        hours, page = 6, 1
    if not username or not public_ip:
        return jsonify({"error": "username and public_ip required"}), 400
    per = 100
    off = (page - 1) * per
    _sel = _selected_nas_id()
    _nf = (" AND nas_id = %s" if _sel else "")
    _np = ([_sel] if _sel else [])
    rows = query(
        "SELECT log_time, host(private_ip) AS private_ip, private_port, "
        "       public_port, host(dest_ip) AS dest_ip, dest_port, protocol "
        "FROM mikrotik_translations "
        "WHERE username = %s AND public_ip = %s "
        "  AND log_time > NOW() - (%s || ' hours')::interval" + _nf +
        " ORDER BY log_time DESC LIMIT %s OFFSET %s",
        ([username, public_ip, str(hours)] + _np + [per, off]),
    ) or []
    return jsonify({"rows": [dict(r) for r in rows], "page": page, "per_page": per})


# ---------------------------------------------------------------------------
# Routes — CGN IP Lookup (reverse: given a 100.64.x.x, find username)
# ---------------------------------------------------------------------------
@app.route("/cgn-lookup", methods=["GET", "POST"])
@lea_required
def cgn_lookup():
    results = None
    form_data = {}
    if request.method == "GET" and request.args.get("cgn_ip"):
        form_data = {"cgn_ip": request.args.get("cgn_ip", "").strip()}
    if request.method == "POST":
        cgn_ip = request.form.get("cgn_ip", "").strip()
        timestamp_str = request.form.get("timestamp", "").strip()
        form_data = {"cgn_ip": cgn_ip, "timestamp": timestamp_str}

        if not cgn_ip:
            flash("CGN IP is required.", "warning")
            return render_template("cgn_lookup.html", results=None, form_data=form_data)

        try:
            ts = datetime.fromisoformat(timestamp_str) if timestamp_str else datetime.now()
        except ValueError:
            ts = datetime.now()

        results = query(
            """SELECT * FROM radius_accounting
               WHERE framed_ip = %s
                 AND session_start <= %s
                 AND (session_stop IS NULL OR session_stop >= %s)
               ORDER BY session_start DESC LIMIT 10""",
            (cgn_ip, ts, ts),
        ) or []

        audit_log("CGN_LOOKUP", f"CGN_IP={cgn_ip} Time={ts} Results={len(results)}")

    return render_template("cgn_lookup.html", results=results, form_data=form_data)

# ---------------------------------------------------------------------------
# Routes — Destination Lookup (who connected to a target IP/port?)
# ---------------------------------------------------------------------------
@app.route("/dest-lookup", methods=["GET", "POST"])
@lea_required
def dest_lookup():
    results = None
    form_data = {}
    # GET with ?dest_ip=X pre-fills the form (from Analytics deep-link)
    if request.method == "GET" and request.args.get("dest_ip"):
        form_data = {"dest_ip": request.args.get("dest_ip", "").strip()}
    if request.method == "POST":
        dest_ip = request.form.get("dest_ip", "").strip()
        dest_port = request.form.get("dest_port", "").strip()
        date_from = request.form.get("date_from", "").strip()
        date_to = request.form.get("date_to", "").strip()
        case_ref = request.form.get("case_ref", "").strip()
        reason = request.form.get("reason", "").strip()

        form_data = {
            "dest_ip": dest_ip, "dest_port": dest_port,
            "date_from": date_from, "date_to": date_to,
            "case_ref": case_ref, "reason": reason,
        }

        if not dest_ip:
            flash("Destination IP is required.", "warning")
            return render_template("dest_lookup.html", results=None, form_data=form_data)

        try:
            dt_from = datetime.fromisoformat(date_from) if date_from else datetime.now() - timedelta(hours=24)
            dt_to = datetime.fromisoformat(date_to) if date_to else datetime.now()
            if date_to and len(date_to) <= 10:  # dest date_to end-of-day
                dt_to = dt_to + timedelta(days=1) - timedelta(microseconds=1)
        except ValueError:
            flash("Invalid date format.", "danger")
            return render_template("dest_lookup.html", results=None, form_data=form_data)

        # Build query
        where = ["destination_ip = %s", "log_time BETWEEN %s AND %s"]
        params = [dest_ip, dt_from, dt_to]
        if dest_port:
            where.append("destination_port = %s")
            params.append(int(dest_port))

        where_str = " AND ".join(where)

        # Get matching flows with subscriber correlation
        flows = query(
            f"""SELECT f.log_time, f.protocol_name, f.source_ip, f.source_port,
                       f.destination_ip, f.destination_port, f.application,
                       f.rule_set, f.rule_name,
                       ra.username, ra.calling_station_id as mac, ra.nas_port_id as vlan
                FROM nat_flow_logs f
                LEFT JOIN radius_accounting ra
                    ON ra.framed_ip = f.source_ip
                    AND ra.session_start <= f.log_time
                    AND (ra.session_stop IS NULL OR ra.session_stop >= f.log_time)
                WHERE {where_str}
                ORDER BY f.log_time DESC
                LIMIT 200""",
            params,
        ) or []

        # Summary: unique subscribers who connected
        subscribers = query(
            f"""SELECT f.source_ip as cgn_ip,
                       COUNT(*) as connection_count,
                       MIN(f.log_time) as first_seen,
                       MAX(f.log_time) as last_seen,
                       ra.username, ra.calling_station_id as mac
                FROM nat_flow_logs f
                LEFT JOIN radius_accounting ra
                    ON ra.framed_ip = f.source_ip
                    AND ra.session_start <= f.log_time
                    AND (ra.session_stop IS NULL OR ra.session_stop >= f.log_time)
                WHERE {where_str}
                GROUP BY f.source_ip, ra.username, ra.calling_station_id
                ORDER BY connection_count DESC
                LIMIT 50""",
            params,
        ) or []

        results = {"flows": flows, "subscribers": subscribers}

        audit_log(
            "DEST_LOOKUP",
            f"DestIP={dest_ip} DestPort={dest_port} From={date_from} To={date_to} "
            f"CaseRef={case_ref} Reason={reason} Subscribers={len(subscribers)} Flows={len(flows)}",
        )

    return render_template("dest_lookup.html", results=results, form_data=form_data)

# ---------------------------------------------------------------------------
# Routes — Export (PDF / XLSX / CSV)
# ---------------------------------------------------------------------------
@app.route("/export/lea-report", methods=["POST"])
@lea_required
def export_lea_report():
    """Generate a CSV report for LEA response."""
    public_ip = request.form.get("public_ip", "")
    port = request.form.get("port", "")
    timestamp = request.form.get("timestamp", "")
    case_ref = request.form.get("case_ref", "")
    results_json = request.form.get("results_data", "[]")

    import json
    try:
        results = json.loads(results_json)
    except json.JSONDecodeError:
        results = []

    output = io.StringIO()
    output.write(f"EXAMPLE ISP — CGNAT IPDR REPORT\n")
    output.write(f"AS64500 — Example ISP\n")
    output.write(f"{'='*60}\n")
    output.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S PKT')}\n")
    output.write(f"Generated By: {session.get('full_name', session.get('username'))}\n")
    output.write(f"Case Reference: {case_ref}\n")
    output.write(f"Query: Public IP={public_ip}, Port={port}, Timestamp={timestamp}\n")
    output.write(f"{'='*60}\n\n")

    if results:
        writer = csv.writer(output)
        writer.writerow([
            "Subscriber IP (CGN)", "Public IP", "Port Block",
            "NAT Alloc Time", "NAT Release Time",
            "Username", "MAC Address", "NAS Port", "VLAN",
            "Session Start", "Session Stop",
        ])
        for r in results:
            nat = r.get("nat", {})
            rad = r.get("radius", {})
            writer.writerow([
                nat.get("subscriber_ip", ""),
                nat.get("public_ip", ""),
                f"{nat.get('port_block_start', '')}-{nat.get('port_block_end', '')}",
                nat.get("log_time", ""),
                nat.get("release_time", "N/A"),
                rad.get("username", "UNKNOWN"),
                rad.get("calling_station_id", ""),
                rad.get("nas_port", ""),
                rad.get("nas_port_id", ""),
                rad.get("session_start", ""),
                rad.get("session_stop", "N/A"),
            ])
    else:
        output.write("No matching records found.\n")

    output.write(f"\n{'='*60}\n")
    output.write(f"PECA Section 29 — Retention: Minimum 1 Year\n")
    output.write(f"This report is generated from automated CGNAT logging systems.\n")
    output.write(f"Data integrity verified by system audit trail.\n")

    audit_log("EXPORT_REPORT", f"LEA Report exported for IP={public_ip} Port={port}")

    buf = io.BytesIO(output.getvalue().encode("utf-8"))
    filename = f"LEA_IPDR_Report_{public_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="text/csv")

# ---------------------------------------------------------------------------
# Routes — Admin: User Management
# ---------------------------------------------------------------------------
@app.route("/admin/users")
@admin_required
def admin_users():
    users = query("SELECT * FROM users ORDER BY created_at DESC") or []
    return render_template("admin_users.html", users=users)

@app.route("/admin/users/add", methods=["POST"])
@admin_required
def admin_add_user():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    full_name = request.form.get("full_name", "").strip()
    role = request.form.get("role", "operator")

    if not all([username, password, full_name]):
        flash("All fields are required.", "warning")
        return redirect(url_for("admin_users"))

    existing = query("SELECT id FROM users WHERE username = %s", (username,), one=True)
    if existing:
        flash(f"Username '{username}' already exists.", "danger")
        return redirect(url_for("admin_users"))

    execute(
        """INSERT INTO users (username, password_hash, full_name, role)
           VALUES (%s, %s, %s, %s)""",
        (username, generate_password_hash(password), full_name, role),
    )
    audit_log("USER_CREATED", f"Created user '{username}' with role '{role}'", username)
    flash(f"User '{username}' created.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_user(user_id):
    user = query("SELECT * FROM users WHERE id = %s", (user_id,), one=True)
    if not user:
        abort(404)
    new_status = not user["is_active"]
    execute("UPDATE users SET is_active = %s WHERE id = %s", (new_status, user_id))
    action = "ENABLED" if new_status else "DISABLED"
    audit_log(f"USER_{action}", f"User '{user['username']}' {action.lower()}", user["username"])
    flash(f"User '{user['username']}' {action.lower()}.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    user = query("SELECT * FROM users WHERE id = %s", (user_id,), one=True)
    if not user:
        abort(404)
    new_password = request.form.get("new_password", "")
    if len(new_password) < 8:
        flash("Password must be at least 8 characters.", "warning")
        return redirect(url_for("admin_users"))
    execute(
        "UPDATE users SET password_hash = %s WHERE id = %s",
        (generate_password_hash(new_password), user_id),
    )
    audit_log("PASSWORD_RESET", f"Password reset for '{user['username']}'", user["username"])
    flash(f"Password reset for '{user['username']}'.", "success")
    return redirect(url_for("admin_users"))

# ---------------------------------------------------------------------------
# Routes — Admin: Audit Log
# ---------------------------------------------------------------------------
@app.route("/admin/audit")
@admin_required
def admin_audit():
    page = int(request.args.get("page", 1))
    per_page = 50
    offset = (page - 1) * per_page

    action_filter = request.args.get("action", "")
    user_filter = request.args.get("user", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")

    where = ["1=1"]
    params = []
    if action_filter:
        where.append("action = %s")
        params.append(action_filter)
    if user_filter:
        where.append("username ILIKE %s")
        params.append(f"%{user_filter}%")
    if date_from:
        where.append("created_at >= %s")
        params.append(date_from)
    if date_to:
        where.append("created_at <= %s")
        params.append(date_to)

    where_str = " AND ".join(where)

    total = query(
        f"SELECT COUNT(*) as cnt FROM audit_log WHERE {where_str}", params, one=True
    )
    total_count = total["cnt"] if total else 0

    params_with_limit = params + [per_page, offset]
    logs = query(
        f"SELECT * FROM audit_log WHERE {where_str} ORDER BY created_at DESC LIMIT %s OFFSET %s",
        params_with_limit,
    ) or []

    return render_template(
        "admin_audit.html",
        logs=logs,
        page=page,
        total_pages=(total_count + per_page - 1) // per_page,
        total_count=total_count,
        filters={"action": action_filter, "user": user_filter,
                 "date_from": date_from, "date_to": date_to},
    )

# ---------------------------------------------------------------------------
# Routes — Admin: System Status
# ---------------------------------------------------------------------------
@app.route("/admin/system")
@admin_required
def admin_system():
    # DB size
    db_info = query(
        "SELECT pg_size_pretty(pg_database_size(current_database())) as db_size", one=True
    )
    # Table sizes
    table_sizes = query(
        """SELECT C.relname as table_name,
                  pg_size_pretty(pg_total_relation_size(C.oid)) as total_size,
                  n_live_tup as row_count
           FROM pg_class C
           LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace)
           LEFT JOIN pg_stat_user_tables S ON S.relid = C.oid
           WHERE nspname = 'public' AND C.relkind = 'r'
           ORDER BY pg_total_relation_size(C.oid) DESC"""
    ) or []

    nat_range = query(
        "SELECT MIN(log_time) as oldest, MAX(log_time) as newest FROM nat_logs", one=True
    )
    radius_range = query(
        "SELECT MIN(session_start) as oldest, MAX(session_start) as newest FROM radius_accounting", one=True
    )

    # Storage config
    cfg = {r["key"]: r["value"] for r in (query("SELECT key, value FROM system_config") or [])}

    return render_template(
        "admin_system.html",
        db_info=db_info,
        table_sizes=table_sizes,
        nat_range=nat_range,
        radius_range=radius_range,
        cfg=cfg,
    )

@app.route("/api/system-metrics")
@admin_required
def api_system_metrics():
    """Live system metrics for the System Status dashboard (polled)."""
    if not SYSMETRICS_AVAILABLE:
        return jsonify({"error": "sysmetrics unavailable"}), 503

    cfg = {r["key"]: r["value"] for r in (query("SELECT key, value FROM system_config") or [])}
    log_path = cfg.get("log_storage_path", "/var/log/nat")
    db_path = cfg.get("db_storage_path", "/var/lib/postgresql")
    alloc_gb = float(cfg.get("log_storage_alloc_gb", "0") or 0)

    cr = sysmetrics.cpu_ram()

    # Disks — root always; log + db if distinct
    root_disk = sysmetrics.disk_for("/")
    log_disk = sysmetrics.disk_for(log_path)
    db_disk = sysmetrics.disk_for(db_path)
    log_dir_used = sysmetrics.dir_size_gb(log_path)

    # DB size in GB (numeric)
    db_bytes = query("SELECT pg_database_size(current_database()) as b", one=True)
    db_gb = round((db_bytes["b"] or 0) / 1e9, 2) if db_bytes else 0

    # sysmetrics-mt: engine + NAS-scoped feed freshness
    _mt = query("SELECT EXISTS(SELECT 1 FROM mikrotik_translations LIMIT 1) AS e", one=True)
    engine = "mikrotik" if (_mt and _mt["e"]) else "juniper"
    _ssel = _selected_nas_id()
    _snf = (" WHERE nas_id = %s" if _ssel else "")
    _sp = ([_ssel] if _ssel else [])
    # Feed freshness
    nat_last = query("SELECT MAX(log_time) as t FROM nat_flow_logs" + _snf, _sp, one=True)
    rad_last = query("SELECT MAX(created_at) as t FROM radius_accounting", one=True)
    dhcp_last = query("SELECT MAX(last_poll) as t FROM mikrotik_dhcp_poll_state" + _snf, _sp, one=True)
    sec_last = query("SELECT MAX(synced_at) as t FROM mikrotik_secrets" + _snf, _sp, one=True)
    def age_secs(row):
        if not row or not row["t"]:
            return None
        t = row["t"]
        ref = datetime.now(t.tzinfo) if t.tzinfo else datetime.now()
        return int((ref - t).total_seconds())

    if engine == "mikrotik":
        services = sysmetrics.service_status(
            ["elb-ipdr-web", "mikrotik-ingest", "mikrotik-secrets-sync.timer",
             "mikrotik-dhcp-poll.timer", "postgresql"]
        )
    else:
        services = sysmetrics.service_status(
            ["elb-ipdr-web", "elb-ipdr-nat-parser", "elb-ipdr-radius-parser", "postgresql", "freeradius"]
        )

    # Log storage: if alloc set, compute against allocation; else against filesystem
    if alloc_gb > 0:
        log_alloc_pct = round(log_dir_used / alloc_gb * 100, 1) if alloc_gb else 0
        log_storage = {"used_gb": log_dir_used, "alloc_gb": alloc_gb, "pct": log_alloc_pct, "mode": "allocated"}
    elif log_disk:
        log_storage = {"used_gb": log_disk["used_gb"], "alloc_gb": log_disk["total_gb"],
                       "pct": log_disk["pct"], "mode": "filesystem", "path": log_path}
    else:
        log_storage = {"used_gb": log_dir_used, "alloc_gb": 0, "pct": 0, "mode": "dir-only", "path": log_path}

    return jsonify({
        "cpu": cr,
        "uptime": sysmetrics.uptime(),
        "net": sysmetrics.net_io(),
        "root_disk": root_disk,
        "log_disk": log_disk,
        "db_disk": db_disk,
        "log_storage": log_storage,
        "db_gb": db_gb,
        "log_path": log_path,
        "db_path": db_path,
        "engine": engine,
        "feeds": {
            "nat_age": age_secs(nat_last),
            "radius_age": age_secs(rad_last),
            "dhcp_age": age_secs(dhcp_last),
            "secrets_age": age_secs(sec_last),
        },
        "services": services,
        "warn_pct": float(cfg.get("storage_warn_pct", "75")),
        "critical_pct": float(cfg.get("storage_critical_pct", "90")),
    })

@app.route("/settings/storage", methods=["POST"])
@admin_required
def save_storage_config():
    """Save storage paths + thresholds."""
    updates = {
        "log_storage_path": request.form.get("log_storage_path", "/var/log/nat").strip()[:256],
        "db_storage_path": request.form.get("db_storage_path", "/var/lib/postgresql").strip()[:256],
        "log_storage_alloc_gb": request.form.get("log_storage_alloc_gb", "0").strip()[:12],
        "storage_warn_pct": request.form.get("storage_warn_pct", "75").strip()[:5],
        "storage_critical_pct": request.form.get("storage_critical_pct", "90").strip()[:5],
        "autopurge_enabled": "true" if request.form.get("autopurge_enabled") else "false",
    }
    for k, v in updates.items():
        execute(
            """INSERT INTO system_config (key, value) VALUES (%s, %s)
               ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value""",
            (k, v),
        )
    audit_log("STORAGE_CONFIG", f"Updated storage config: log={updates['log_storage_path']}, crit={updates['storage_critical_pct']}%")
    flash("Storage configuration saved.", "success")
    return redirect(url_for("admin_system"))

# ---------------------------------------------------------------------------
# Routes — Admin: Data Retention / Purge
# ---------------------------------------------------------------------------
@app.route("/admin/retention", methods=["GET", "POST"])
@admin_required
def admin_retention():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "purge_old":
            months = int(request.form.get("months", 13))
            cutoff = datetime.now() - timedelta(days=months * 30)

            nat_del = execute(
                "DELETE FROM nat_logs WHERE log_time < %s", (cutoff,)
            )
            flow_del = execute(
                "DELETE FROM nat_flow_logs WHERE log_time < %s", (cutoff,)
            )
            radius_del = execute(
                "DELETE FROM radius_accounting WHERE session_start < %s", (cutoff,)
            )

            audit_log(
                "DATA_PURGE",
                f"Purged records older than {months} months (before {cutoff.isoformat()})",
            )
            flash(f"Purged records older than {months} months.", "success")

    # Current retention stats
    retention_stats = query(
        """SELECT
             (SELECT COUNT(*) FROM nat_logs) as nat_count,
             (SELECT COUNT(*) FROM nat_flow_logs) as flow_count,
             (SELECT COUNT(*) FROM radius_accounting) as radius_count,
             (SELECT MIN(log_time) FROM nat_logs) as nat_oldest,
             (SELECT MIN(log_time) FROM nat_flow_logs) as flow_oldest,
             (SELECT MIN(session_start) FROM radius_accounting) as radius_oldest
        """, one=True,
    )

    return render_template("admin_retention.html", stats=retention_stats)

# ---------------------------------------------------------------------------
# Routes — Admin: NAT Pool Status
# ---------------------------------------------------------------------------
@app.route("/nat-pool")
@lea_required
def nat_pool_status():
    """Public-IP pool utilization (MikroTik: derived from translations)."""
    mt_probe_pool = query("SELECT 1 FROM mikrotik_translations LIMIT 1", one=True)
    if mt_probe_pool is not None:
        # conntrack-pool-metrics: MikroTik uses dynamic NAPT, not port blocks.
        # Real metrics come from live conntrack snapshots (polled every ~10min),
        # not cumulative translation counts.
        _sel = _selected_nas_id()
        _pnf = (" AND nas_id = %s" if _sel else "")
        _pp = ([_sel] if _sel else [])
        # box-wide conntrack table health (the true capacity ceiling)
        ct_stats = query(
            "SELECT nas_id, ts, total_entries, max_entries, ip4_entries, ip6_entries "
            "FROM v_conntrack_latest_stats WHERE 1=1" + _pnf +
            " ORDER BY total_entries DESC", _pp
        ) or []
        # per-public-IP concurrent port usage (public IPs only, via the view)
        pool_usage = query(
            "SELECT public_ip, ts, concurrent_conns, distinct_ports, unique_subs, "
            "       tcp_conns, udp_conns, icmp_conns, "
            "       ROUND(distinct_ports::numeric / 64512 * 100, 1) AS port_util_pct "
            "FROM v_conntrack_latest_pool WHERE 1=1" + _pnf +
            " ORDER BY concurrent_conns DESC", _pp
        ) or []
        snapshot_ts = pool_usage[0]["ts"] if pool_usage else (ct_stats[0]["ts"] if ct_stats else None)
        return render_template("nat_pool.html", engine="mikrotik",
                               ct_stats=ct_stats, pool_usage=pool_usage,
                               snapshot_ts=snapshot_ts, usable_ports=64512)

    pool_usage = query(
        """SELECT public_ip,
                  COUNT(*) as active_blocks,
                  SUM(port_block_end - port_block_start + 1) as ports_allocated,
                  COUNT(DISTINCT subscriber_ip) as unique_subscribers
           FROM nat_logs
           WHERE log_type = 'PBA_ALLOC' AND release_time IS NULL
           GROUP BY public_ip
           ORDER BY public_ip"""
    ) or []
    return render_template("nat_pool.html", pool_usage=pool_usage)


# ---------------------------------------------------------------------------
# Routes — Live NAT Logs viewer
# ---------------------------------------------------------------------------
@app.route("/nat-logs")
@lea_required
def nat_logs_view():
    page = int(request.args.get("page", 1))
    per_page = 50
    offset = (page - 1) * per_page
    log_type = request.args.get("type", "")
    subscriber = request.args.get("subscriber", "")
    public_ip = request.args.get("public_ip", "")

    where = ["1=1"]
    params = []
    if log_type:
        where.append("log_type = %s")
        params.append(log_type)
    if subscriber:
        where.append("subscriber_ip = %s")
        params.append(subscriber)
    if public_ip:
        where.append("public_ip = %s")
        params.append(public_ip)

    where_str = " AND ".join(where)
    total = query(f"SELECT COUNT(*) as cnt FROM nat_logs WHERE {where_str}", params, one=True)
    total_count = total["cnt"] if total else 0

    params_q = params + [per_page, offset]
    logs = query(
        f"SELECT * FROM nat_logs WHERE {where_str} ORDER BY log_time DESC LIMIT %s OFFSET %s",
        params_q,
    ) or []

    return render_template(
        "nat_logs.html", logs=logs, page=page,
        total_pages=(total_count + per_page - 1) // per_page,
        total_count=total_count,
        filters={"type": log_type, "subscriber": subscriber, "public_ip": public_ip},
    )

# ---------------------------------------------------------------------------
# Routes — Flow Logs viewer (per-flow src→dst records)
# ---------------------------------------------------------------------------
@app.route("/flow-logs")
@lea_required
def flow_logs_view():
    page = int(request.args.get("page", 1))
    per_page = 50
    offset = (page - 1) * per_page
    src_ip = request.args.get("src_ip", "")
    dst_ip = request.args.get("dst_ip", "")
    dst_port = request.args.get("dst_port", "")
    protocol = request.args.get("protocol", "")

    mt_probe = query("SELECT 1 FROM mikrotik_translations LIMIT 1", one=True)
    is_mikrotik = mt_probe is not None

    if is_mikrotik:
        where = ["1=1"]
        params = []
        _sel = _selected_nas_id()  # _tx_nas_scope
        if _sel:
            where.append("t.nas_id = %s"); params.append(_sel)
        if src_ip:
            where.append("t.private_ip = %s"); params.append(src_ip)
        if dst_ip:
            where.append("t.dest_ip = %s"); params.append(dst_ip)
        if dst_port:
            where.append("t.dest_port = %s"); params.append(int(dst_port))
        if protocol:
            where.append("t.protocol = %s"); params.append(protocol)
        where_str = " AND ".join(where)
        total = query(f"SELECT COUNT(*) as cnt FROM mikrotik_translations t WHERE {where_str}", params, one=True)
        total_count = total["cnt"] if total else 0
        params_q = params + [per_page, offset]
        rows = query(
            f"""SELECT t.log_time, t.username,
                       t.private_ip AS source_ip, t.private_port AS source_port,
                       t.dest_ip AS destination_ip, t.dest_port AS destination_port,
                       t.protocol AS protocol_name, t.public_ip, t.public_port,
                       t.tcp_flags
                FROM mikrotik_translations t
                WHERE {where_str}
                ORDER BY t.log_time DESC LIMIT %s OFFSET %s""",
            params_q,
        ) or []
        logs = []
        for r in rows:
            d = dict(r)
            d["mac"] = None
            d["rule"] = None
            d["application"] = None
            d["country"] = geo_country(str(d["destination_ip"])) if d.get("destination_ip") else "??"
            d["decoded"] = decode_application(
                None, d.get("protocol_name"), d.get("destination_port"),
                str(d["destination_ip"]) if d.get("destination_ip") else None
            )
            logs.append(d)
        return render_template(
            "flow_logs.html", logs=logs, page=page,
            total_pages=min((total_count + per_page - 1) // per_page, 1000),
            total_count=total_count,
            filters={"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "protocol": protocol},
        )

    # --- original Juniper path (unchanged) ---------------------------------
    where = ["1=1"]
    params = []
    if src_ip:
        where.append("f.source_ip = %s"); params.append(src_ip)
    if dst_ip:
        where.append("f.destination_ip = %s"); params.append(dst_ip)
    if dst_port:
        where.append("f.destination_port = %s"); params.append(int(dst_port))
    if protocol:
        where.append("f.protocol_name = %s"); params.append(protocol)
    where_str = " AND ".join(where)
    total = query(f"SELECT COUNT(*) as cnt FROM nat_flow_logs f WHERE {where_str}", params, one=True)
    total_count = total["cnt"] if total else 0
    params_q = params + [per_page, offset]
    logs = query(
        f"""SELECT f.*, ra.username, ra.calling_station_id as mac
            FROM nat_flow_logs f
            LEFT JOIN radius_accounting ra
                ON ra.framed_ip = f.source_ip
                AND ra.session_start <= f.log_time
                AND (ra.session_stop IS NULL OR ra.session_stop >= f.log_time)
            WHERE {where_str}
            ORDER BY f.log_time DESC LIMIT %s OFFSET %s""",
        params_q,
    ) or []
    for l in logs:
        l["country"] = geo_country(str(l["destination_ip"]))
        l["decoded"] = decode_application(
            l.get("application"), l.get("protocol_name"),
            l.get("destination_port"), str(l["destination_ip"])
        )
    return render_template(
        "flow_logs.html", logs=logs, page=page,
        total_pages=min((total_count + per_page - 1) // per_page, 1000),
        total_count=total_count,
        filters={"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "protocol": protocol},
    )


# ---------------------------------------------------------------------------
# Routes — RADIUS Sessions viewer
# ---------------------------------------------------------------------------
@app.route("/radius-sessions")
@lea_required
def radius_sessions():
    page = int(request.args.get("page", 1))
    per_page = 50
    offset = (page - 1) * per_page
    username = request.args.get("username", "")
    active_only = request.args.get("active", "")

    where = ["1=1"]
    params = []
    if username:
        where.append("username ILIKE %s")
        params.append(f"%{username}%")
    if active_only:
        where.append("session_stop IS NULL")

    where_str = " AND ".join(where)
    total = query(f"SELECT COUNT(*) as cnt FROM radius_accounting WHERE {where_str}", params, one=True)
    total_count = total["cnt"] if total else 0

    params_q = params + [per_page, offset]
    sessions = query(
        f"SELECT * FROM radius_accounting WHERE {where_str} ORDER BY session_start DESC LIMIT %s OFFSET %s",
        params_q,
    ) or []

    return render_template(
        "radius_sessions.html", sessions=sessions, page=page,
        total_pages=(total_count + per_page - 1) // per_page,
        total_count=total_count,
        filters={"username": username, "active": active_only},
    )

# ---------------------------------------------------------------------------
# API — for dashboard charts (AJAX)
# ---------------------------------------------------------------------------
@app.route("/api/stats/hourly")
@login_required
def api_hourly_stats():
    rows = query(
        """SELECT to_char(date_trunc('hour', log_time), 'HH24:MI') as hour,
                  COUNT(*) FILTER (WHERE log_type = 'PBA_ALLOC') as allocs,
                  COUNT(*) FILTER (WHERE log_type = 'PBA_RELEASE') as releases,
                  COUNT(*) FILTER (WHERE log_type = 'RULE_MATCH') as flows
           FROM nat_logs
           WHERE log_time > NOW() - INTERVAL '24 hours'
           GROUP BY 1 ORDER BY 1"""
    ) or []
    return jsonify(rows)

# ---------------------------------------------------------------------------
# Change own password
# ---------------------------------------------------------------------------
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        user = query("SELECT * FROM users WHERE id = %s", (session["user_id"],), one=True)
        if not check_password_hash(user["password_hash"], current):
            flash("Current password is incorrect.", "danger")
        elif new_pw != confirm:
            flash("New passwords do not match.", "danger")
        elif len(new_pw) < 8:
            flash("Password must be at least 8 characters.", "warning")
        else:
            execute(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (generate_password_hash(new_pw), session["user_id"]),
            )
            audit_log("PASSWORD_CHANGE", "User changed own password")
            flash("Password changed successfully.", "success")
            return redirect(url_for("dashboard"))

    return render_template("change_password.html")

# ---------------------------------------------------------------------------
# Routes — Bulk LEA Query (upload Excel/CSV with multiple IPs)
# ---------------------------------------------------------------------------
@app.route("/bulk-query", methods=["GET", "POST"])
@lea_required
def bulk_query():
    results = None
    if request.method == "POST":
        case_ref = request.form.get("case_ref", "").strip()
        reason = request.form.get("reason", "").strip()
        file = request.files.get("file")
        raw_text = request.form.get("raw_input", "").strip()

        queries = []

        # Parse uploaded CSV/text
        if file and file.filename:
            content = file.read().decode("utf-8", errors="replace")
            reader = csv.reader(io.StringIO(content))
            for row in reader:
                if len(row) >= 3:
                    queries.append({
                        "public_ip": row[0].strip(),
                        "port": row[1].strip(),
                        "timestamp": row[2].strip(),
                    })
        elif raw_text:
            for line in raw_text.strip().split("\n"):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 3:
                    queries.append({
                        "public_ip": parts[0],
                        "port": parts[1],
                        "timestamp": parts[2],
                    })

        if not queries:
            flash("No valid queries found. Use format: IP, Port, Timestamp (one per line)", "warning")
            return render_template("bulk_query.html", results=None)

        results = []
        for q in queries[:100]:  # Limit to 100 queries per batch
            try:
                port_num = int(q["port"])
                query_time = datetime.fromisoformat(q["timestamp"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                results.append({"query": q, "nat": None, "radius": None, "error": "Invalid port/timestamp"})
                continue

            nat = query(
                """SELECT * FROM nat_logs
                   WHERE public_ip = %s AND port_block_start <= %s AND port_block_end >= %s
                     AND log_time <= %s AND (release_time IS NULL OR release_time >= %s)
                   ORDER BY log_time DESC LIMIT 1""",
                (q["public_ip"], port_num, port_num, query_time, query_time),
                one=True,
            )
            radius = None
            if nat:
                radius = query(
                    """SELECT * FROM radius_accounting
                       WHERE framed_ip = %s AND session_start <= %s
                         AND (session_stop IS NULL OR session_stop >= %s)
                       ORDER BY session_start DESC LIMIT 1""",
                    (nat["subscriber_ip"], query_time, query_time),
                    one=True,
                )
            results.append({
                "query": q,
                "nat": dict(nat) if nat else None,
                "radius": dict(radius) if radius else None,
                "error": None,
            })

        audit_log(
            "BULK_QUERY",
            f"Batch of {len(queries)} queries. CaseRef={case_ref} Reason={reason} Matched={sum(1 for r in results if r['nat'])}",
        )

        return render_template("bulk_query.html", results=results, case_ref=case_ref)

    return render_template("bulk_query.html", results=None)

@app.route("/export/bulk-report", methods=["POST"])
@lea_required
def export_bulk_report():
    """Export bulk query results as CSV."""
    import json
    results = json.loads(request.form.get("results_data", "[]"))
    case_ref = request.form.get("case_ref", "")

    output = io.StringIO()
    output.write(f"EXAMPLE ISP — BULK IPDR REPORT\n")
    output.write(f"AS64500 — Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S PKT')}\n")
    output.write(f"Case Reference: {case_ref}\n")
    output.write(f"Generated By: {session.get('full_name', session.get('username'))}\n\n")

    writer = csv.writer(output)
    writer.writerow([
        "Query IP", "Query Port", "Query Time",
        "Subscriber IP", "Public IP", "Port Block",
        "Username", "MAC", "VLAN", "Session Start", "Session Stop", "Status",
    ])
    for r in results:
        q = r.get("query", {})
        nat = r.get("nat", {}) or {}
        rad = r.get("radius", {}) or {}
        writer.writerow([
            q.get("public_ip", ""), q.get("port", ""), q.get("timestamp", ""),
            nat.get("subscriber_ip", "NO MATCH"), nat.get("public_ip", ""),
            f"{nat.get('port_block_start', '')}-{nat.get('port_block_end', '')}" if nat.get("port_block_start") else "",
            rad.get("username", "UNKNOWN"), rad.get("calling_station_id", ""),
            rad.get("nas_port_id", ""), rad.get("session_start", ""),
            rad.get("session_stop", "ACTIVE"), "MATCHED" if nat else "NO MATCH",
        ])

    audit_log("EXPORT_BULK", f"Bulk report exported. CaseRef={case_ref}")
    buf = io.BytesIO(output.getvalue().encode("utf-8"))
    filename = f"BULK_IPDR_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="text/csv")

# ---------------------------------------------------------------------------
# Routes — Subscriber Timeline
# ---------------------------------------------------------------------------
@app.route("/live-sessions")
@lea_required
def live_sessions():
    q = request.args.get("q", "").strip()
    where = ["s.session_stop IS NULL"]
    params = []
    _sel = _selected_nas_id()  # live-sessions scope
    if _sel:
        where.append("s.nas_id = %s"); params.append(_sel)
    if q:
        where.append("(s.username ILIKE %s OR host(s.framed_ip) ILIKE %s OR s.caller_id ILIKE %s)")
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    where_str = " AND ".join(where)
    total = query("SELECT count(*) AS c FROM mikrotik_ppp_sessions WHERE session_stop IS NULL"
                  + (" AND nas_id = %s" if _sel else ""), ([_sel] if _sel else []), one=True)
    _total_ppp = total["c"] if total else 0
    pg_ppp = _page_meta(_paginate(default=25), _total_ppp)
    sessions = query(
        f"""SELECT s.username, host(s.framed_ip) AS framed_ip, s.caller_id,
                   s.ppp_service, s.session_start, s.uptime_seconds,
                   n.name AS nas_name, sec.comment AS customer, sec.phone
            FROM mikrotik_ppp_sessions s
            LEFT JOIN nas_devices n ON n.id = s.nas_id
            LEFT JOIN mikrotik_secrets sec ON sec.nas_id = s.nas_id AND sec.username = s.username
            WHERE {where_str}
            ORDER BY s.session_start DESC
            LIMIT %s OFFSET %s""",
        params + [pg_ppp["limit"], pg_ppp["offset"]],
    ) or []
    state = query("SELECT max(last_poll) AS last_poll, min(polling_since) AS since FROM mikrotik_ppp_poll_state", one=True)
    # dhcp-tabs: load DHCP leases (dynamic + static) for the same scope
    _dwhere = ["active = true"]
    _dp = []
    if _sel:
        _dwhere.append("l.nas_id = %s"); _dp.append(_sel)
    if q:
        _dwhere.append("(l.mac ILIKE %s OR host(l.ip) ILIKE %s OR l.hostname ILIKE %s OR l.comment ILIKE %s)")
        _dp += [f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"]
    def _load_dhcp(static_flag):
        w = list(_dwhere) + ["l.is_static = %s"]
        p = list(_dp) + [static_flag]
        return query(
            f"""SELECT l.mac, host(l.ip) AS ip, l.hostname, l.comment, l.server,
                       l.status, l.class_id, l.first_seen, l.last_seen, n.name AS nas_name
                FROM mikrotik_dhcp_leases l
                LEFT JOIN nas_devices n ON n.id = l.nas_id
                WHERE {' AND '.join(w)}
                ORDER BY l.last_seen DESC LIMIT 500""",
            p,
        ) or []
    dhcp_dyn = _load_dhcp(False)
    dhcp_static = _load_dhcp(True)
    def _dhcp_count(static_flag):
        w = ["active = true", "is_static = %s"]
        p = [static_flag]
        if _sel:
            w.append("nas_id = %s"); p.append(_sel)
        r = query(f"SELECT count(*) AS c FROM mikrotik_dhcp_leases WHERE {' AND '.join(w)}", p, one=True)
        return r["c"] if r else 0
    dhcp_dyn_total = _dhcp_count(False)
    dhcp_static_total = _dhcp_count(True)
    dstate = query("SELECT max(last_poll) AS last_poll FROM mikrotik_dhcp_poll_state", one=True)
    return render_template("live_sessions.html",
                           sessions=sessions, total=(total["c"] if total else 0),
                           shown=len(sessions), q=q, pg_ppp=pg_ppp,
                           last_poll=(state["last_poll"] if state else None),
                           since=(state["since"] if state else None),
                           dhcp_dyn=dhcp_dyn, dhcp_static=dhcp_static,
                           dhcp_dyn_total=dhcp_dyn_total, dhcp_static_total=dhcp_static_total,
                           dhcp_last_poll=(dstate["last_poll"] if dstate else None))


@app.route("/live-sessions/refresh-dhcp", methods=["POST"])
@lea_required
def refresh_dhcp():
    """On-demand DHCP poll for the selected NAS (or all)."""
    import subprocess
    _sel = _selected_nas_id()
    cmd = ["/opt/elb-ipdr/venv/bin/python",
           "/opt/elb-ipdr/scripts/mikrotik_dhcp_poll.py"]
    if _sel:
        cmd += ["--nas-id", str(_sel)]
    try:
        env = dict(os.environ)
        # load .env for the subprocess
        with open("/opt/elb-ipdr/.env") as f:
            for line in f:
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.strip().split("=", 1); env[k] = v
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45, env=env)
        ok = r.returncode == 0
        msg = "DHCP refreshed" if ok else f"DHCP refresh failed: {r.stderr[-200:]}"
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"ok": ok, "message": msg})
        flash(msg, "success" if ok else "danger")
    except Exception as e:
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"ok": False, "message": f"DHCP refresh error: {e}"})
        flash(f"DHCP refresh error: {e}", "danger")
    return redirect(url_for("live_sessions"))


@app.route("/subscriber-timeline", methods=["GET", "POST"])
@lea_required
def subscriber_timeline():
    timeline = None
    form_data = {}
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
    else:
        username = request.args.get("username", "").strip()

    if username:
        form_data = {"username": username}
        mt_probe = query("SELECT 1 FROM mikrotik_translations LIMIT 1", one=True)

        if mt_probe is not None:
            # MikroTik: real PPP sessions first (mikrotik_ppp_sessions  -- timeline),
            # synthesized translation-windows for time before polling began.
            import mikrotik_sessions
            ppp = query(
                """SELECT username, host(framed_ip) AS framed_ip, caller_id,
                          ppp_service, session_start, session_stop, last_seen,
                          uptime_seconds
                   FROM mikrotik_ppp_sessions
                   WHERE username ILIKE %s
                   ORDER BY session_start DESC LIMIT 200""",
                (username,),
            ) or []
            since_row = query(
                "SELECT min(polling_since) AS since FROM mikrotik_ppp_poll_state",
                one=True,
            )
            polling_since = since_row["since"] if since_row else None

            timeline = []
            for s in ppp:
                # real connections that fall within this session window
                nat_maps = query(
                    """SELECT log_time, host(public_ip) AS public_ip, public_port,
                              host(dest_ip) AS dest_ip, dest_port, protocol
                       FROM mikrotik_translations
                       WHERE username ILIKE %s
                         AND log_time BETWEEN %s AND COALESCE(%s, now())
                       ORDER BY log_time LIMIT 500""",
                    (username, s["session_start"], s["session_stop"]),
                ) or []
                dur = s["uptime_seconds"]
                if dur is None and s["session_stop"] and s["session_start"]:
                    dur = int((s["session_stop"] - s["session_start"]).total_seconds())
                sess = {
                    "username": s["username"],
                    "framed_ip": s["framed_ip"],
                    "mac": s["caller_id"],
                    "session_start": s["session_start"],
                    "session_stop": s["session_stop"],
                    "session_duration": dur,
                    "public_ip": (nat_maps[0]["public_ip"] if nat_maps else None),
                    "conn_count": len(nat_maps),
                    "source": "ppp-session",
                }
                timeline.append({"session": sess,
                                 "nat_maps": [dict(n) for n in nat_maps]})

            # Reconstructed history for the period before polling started.
            if polling_since is not None:
                rows = query(
                    """SELECT log_time, username, private_ip, private_port,
                              public_ip, public_port, dest_ip, dest_port, protocol
                       FROM mikrotik_translations
                       WHERE username ILIKE %s AND log_time < %s
                       ORDER BY log_time ASC LIMIT 20000""",
                    (username, polling_since),
                ) or []
                if rows:
                    windows = mikrotik_sessions.build_windows(
                        [dict(r) for r in rows], now=polling_since)
                    for w in windows:
                        w["session"]["source"] = "reconstructed"
                    timeline.extend(windows)

            audit_log("TIMELINE_QUERY",
                      f"Username={username} PPP={len(ppp)} Total={len(timeline)} Engine=mikrotik")
            return render_template("subscriber_timeline.html",
                                   timeline=timeline, form_data=form_data,
                                   polling_since=polling_since)

        # --- Juniper path (RADIUS) ---
        sessions = query(
            """SELECT * FROM radius_accounting
               WHERE username ILIKE %s ORDER BY session_start DESC LIMIT 100""",
            (f"%{username}%",),
        ) or []
        timeline = []
        for s in sessions:
            nat_maps = []
            if s["framed_ip"]:
                nat_maps = query(
                    """SELECT * FROM nat_logs
                       WHERE subscriber_ip = %s
                         AND log_time BETWEEN %s AND COALESCE(%s, NOW())
                       ORDER BY log_time""",
                    (s["framed_ip"], s["session_start"], s["session_stop"]),
                ) or []
            timeline.append({"session": dict(s), "nat_maps": [dict(n) for n in nat_maps]})
        audit_log("TIMELINE_QUERY", f"Username={username} Sessions={len(sessions)}")

    return render_template("subscriber_timeline.html", timeline=timeline, form_data=form_data)


# ---------------------------------------------------------------------------
# API — Feed Health Status
# ---------------------------------------------------------------------------
import hmac as _hmac
import socket as _socket

def _lea_api_token():
    return os.environ.get("LEA_API_TOKEN", "")

@app.route("/api/lea-lookup", methods=["POST"])
def api_lea_lookup():
    """Token-authed LEA lookup for central fan-out. Returns this box's own
    (local) subscriber matches for the given public ip:port:time."""
    token = _lea_api_token()
    if not token:
        return jsonify({"ok": False, "error": "api disabled (no LEA_API_TOKEN)"}), 503
    auth = request.headers.get("Authorization", "")
    presented = auth[7:] if auth.startswith("Bearer ") else ""
    if not presented or not _hmac.compare_digest(presented, token):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    public_ip = (data.get("public_ip") or "").strip()
    port = data.get("port")
    ts = (data.get("timestamp") or "").strip()
    if not public_ip or port is None or not ts:
        return jsonify({"ok": False, "error": "need public_ip, port, timestamp"}), 400
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "port must be an integer"}), 400
    try:
        query_time = datetime.fromisoformat(ts)
    except ValueError:
        return jsonify({"ok": False, "error": "timestamp must be ISO8601"}), 400

    hostname = _socket.gethostname()
    try:
        import mikrotik_lea
        # local enricher (same as the LEA page)
        def _enrich(_username, _nas_id):
            _r = query(
                "SELECT comment, phone, caller_id, last_caller_id "
                "FROM mikrotik_secrets WHERE nas_id=%s AND username=%s",
                (_nas_id, _username), one=True,
            ) or query(
                "SELECT comment, phone, caller_id, last_caller_id "
                "FROM mikrotik_secrets WHERE username=%s LIMIT 1",
                (_username,), one=True,
            )
            if not _r:
                return None
            return {"customer_name": _r["comment"], "phone": _r.get("phone"),
                    "mac": _r.get("caller_id") or _r.get("last_caller_id")}
        mt = mikrotik_lea.lookup(get_db(), public_ip, port_num, query_time,
                                 enrich_fn=_enrich)
    except Exception as e:
        return jsonify({"ok": False, "source": hostname, "error": str(e)}), 500

    # Normalise the engine result into plain JSON dicts.
    # candidates is a list[dict] (from _row_to_dict); log_time is already a
    # formatted string, identity is a dict with customer_name/phone/mac.
    out = []
    cands = getattr(mt, "candidates", None) or []
    if not cands and getattr(mt, "primary", None):
        cands = [mt.primary]
    for d in cands:
        ident = d.get("identity") or {}
        out.append({
            "username": d.get("username"),
            "nas_name": d.get("nas_name"),
            "public_ip": d.get("public_ip") or public_ip,
            "public_port": d.get("public_port", port_num),
            "private_ip": d.get("private_ip"),
            "dest_ip": d.get("dest_ip"),
            "dest_port": d.get("dest_port"),
            "protocol": d.get("protocol"),
            "log_time": d.get("log_time"),
            "delta_seconds": d.get("delta_seconds"),
            "customer_name": ident.get("customer_name"),
            "phone": ident.get("phone"),
            "mac": ident.get("mac"),
        })
    audit_log("LEA_API", f"src={request.remote_addr} ip={public_ip}:{port_num} results={len(out)}")
    return jsonify({"ok": True, "source": hostname,
                    "port_reuse": bool(getattr(mt, "port_reuse", False)) if mt else False,
                    "results": out})


@app.route("/set-nas/<nas>")
@login_required
def set_nas(nas):
    """Set the global per-device scope, then return to the referring page."""
    if nas == "all":
        session.pop("sel_nas", None)
    else:
        try:
            session["sel_nas"] = int(nas)
        except (TypeError, ValueError):
            session.pop("sel_nas", None)
    ref = request.referrer
    return redirect(ref if ref else url_for("dashboard"))


@app.route("/paste-request", methods=["GET", "POST"])
@lea_required
def paste_request():
    parsed = None
    grouped = None
    raw_text = ""
    fmt = None
    if request.method == "POST":
        raw_text = request.form.get("payload", "")
        case_ref = request.form.get("case_ref", "").strip()
        reason = request.form.get("reason", "").strip()
        import lea_request_parser as lrp
        fmt, items = lrp.parse(raw_text)
        parsed = items
        from collections import OrderedDict
        by_nas = OrderedDict()
        WINDOW = 300
        for it in items:
            rows = query(
                """SELECT t.username, host(t.private_ip) AS private_ip,
                          host(t.public_ip) AS public_ip, t.public_port,
                          host(t.dest_ip) AS dest_ip, t.dest_port, t.protocol,
                          t.log_time, t.src_mac, t.nas_id, n.name AS nas_name,
                          s.comment AS customer, s.phone
                   FROM mikrotik_translations t
                   LEFT JOIN nas_devices n ON n.id = t.nas_id
                   LEFT JOIN mikrotik_secrets s
                          ON s.nas_id=t.nas_id AND s.username=t.username
                   WHERE t.public_ip=%s AND t.public_port=%s
                     AND t.log_time BETWEEN %s AND %s
                   ORDER BY abs(extract(epoch FROM (t.log_time - %s)))
                   LIMIT 25""",
                (it["src_ip"], it["src_port"],
                 it["when"] - timedelta(seconds=WINDOW),
                 it["when"] + timedelta(seconds=WINDOW),
                 it["when"]),
            ) or []
            # attach dest-match confirmation for each row
            matches = []
            for r in rows:
                rd = dict(r)
                rd["dest_confirms"] = bool(
                    it.get("dest_ip") and r["dest_ip"] == it["dest_ip"]
                    and str(r["dest_port"]) == str(it.get("dest_port")))
                matches.append(rd)
            distinct = {r["username"] for r in rows}
            entry = {
                "request": it,
                "matches": matches,
                "port_reuse": len(distinct) > 1,
                "found": len(rows) > 0,
            }
            # group by the NAS of the primary match (or 'Unresolved')
            key = (matches[0]["nas_name"] if matches else "Unresolved / not on this network")
            by_nas.setdefault(key, []).append(entry)
        grouped = by_nas
        audit_log("PASTE_REQUEST",
                  f"fmt={fmt} items={len(items)} "
                  f"resolved={sum(1 for g in by_nas.values() for e in g if e['found'])} "
                  f"CaseRef={case_ref} Reason={reason}")
    return render_template("paste_request.html", parsed=parsed, grouped=grouped,
                           raw_text=raw_text, fmt=fmt)


@app.route("/tuple-lookup", methods=["GET", "POST"])
@lea_required
def tuple_lookup():
    results = None
    form_data = {}
    port_reuse = False
    if request.method == "POST":
        src_ip = request.form.get("src_ip", "").strip()
        src_port = request.form.get("src_port", "").strip()
        dst_ip = request.form.get("dst_ip", "").strip()
        dst_port = request.form.get("dst_port", "").strip()
        ts_str = request.form.get("timestamp", "").strip()
        window = request.form.get("window", "5").strip()
        case_ref = request.form.get("case_ref", "").strip()
        reason = request.form.get("reason", "").strip()
        form_data = {"src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip,
                     "dst_port": dst_port, "timestamp": ts_str, "window": window,
                     "case_ref": case_ref, "reason": reason}
        if not (src_ip and src_port and ts_str):
            flash("Source public IP, source port, and timestamp are required.", "warning")
            return render_template("tuple_lookup.html", results=None, form_data=form_data)
        try:
            src_port_n = int(src_port)
            win_s = max(0, int(window)) * 60
            when = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if when.tzinfo is not None:
                from datetime import timezone as _tz
                when = when.astimezone(_tz.utc).replace(tzinfo=None)
        except (ValueError, TypeError) as e:
            flash(f"Invalid port / timestamp / window: {e}", "danger")
            return render_template("tuple_lookup.html", results=None, form_data=form_data)

        where = ["t.public_ip = %s", "t.public_port = %s",
                 "t.log_time BETWEEN %s AND %s"]
        params = [src_ip, src_port_n,
                  when - timedelta(minutes=int(window or 5)),
                  when + timedelta(minutes=int(window or 5))]
        if dst_ip:
            where.append("t.dest_ip = %s"); params.append(dst_ip)
        if dst_port:
            where.append("t.dest_port = %s"); params.append(int(dst_port))
        params.append(when)  # for ordering
        rows = query(
            f"""SELECT t.username, host(t.private_ip) AS private_ip,
                       host(t.public_ip) AS public_ip, t.public_port,
                       host(t.dest_ip) AS dest_ip, t.dest_port, t.protocol,
                       t.log_time, t.src_mac, n.name AS nas_name,
                       s.comment AS customer, s.phone
                FROM mikrotik_translations t
                LEFT JOIN nas_devices n ON n.id = t.nas_id
                LEFT JOIN mikrotik_secrets s
                       ON s.nas_id=t.nas_id AND s.username=t.username
                WHERE {' AND '.join(where)}
                ORDER BY abs(extract(epoch FROM (t.log_time - %s)))
                LIMIT 50""",
            params,
        ) or []
        results = []
        for r in rows:
            rd = dict(r)
            rd["dest_confirms"] = bool(
                dst_ip and r["dest_ip"] == dst_ip
                and (not dst_port or str(r["dest_port"]) == str(dst_port)))
            results.append(rd)
        port_reuse = len({r["username"] for r in rows}) > 1
        audit_log("TUPLE_LOOKUP",
                  f"src={src_ip}:{src_port} dst={dst_ip}:{dst_port} time={ts_str} "
                  f"CaseRef={case_ref} Reason={reason} results={len(results)} "
                  f"port_reuse={port_reuse}")
    return render_template("tuple_lookup.html", results=results,
                           form_data=form_data, port_reuse=port_reuse)


@app.route("/api/health")
@login_required
def api_health():
    nat_last = query(
        "SELECT MAX(log_time) as last_log, COUNT(*) FILTER (WHERE log_time > NOW() - INTERVAL '5 minutes') as last_5m FROM nat_logs",
        one=True,
    )
    _fsel = _selected_nas_id()  # health-nas-scope flow
    _fnf = (" WHERE nas_id = %s" if _fsel else "")
    flow_last = query(
        "SELECT MAX(log_time) as last_log, "
        "COUNT(*) FILTER (WHERE log_time > NOW() - INTERVAL '5 minutes') as last_5m "
        "FROM nat_flow_logs" + _fnf, ([_fsel] if _fsel else []), one=True,
    )
    radius_last = query(
        "SELECT MAX(created_at) as last_log, COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '5 minutes') as last_5m FROM radius_accounting",
        one=True,
    )
    db_size = query("SELECT pg_size_pretty(pg_database_size(current_database())) as size", one=True)

    def feed_status(row):
        if not row or not row["last_log"]:
            return {"status": "dead", "last": None, "rate": 0}
        age = (datetime.now(row["last_log"].tzinfo if row["last_log"].tzinfo else None) - row["last_log"]).total_seconds() if row["last_log"] else 9999
        return {
            "status": "healthy" if age < 120 else "stale" if age < 600 else "dead",
            "last": row["last_log"].isoformat() if row["last_log"] else None,
            "rate": row["last_5m"] or 0,
        }

    # dhcpsec-scope: NAS-scoped DHCP + secrets feeds
    _hsel = _selected_nas_id()
    _hnf = (" AND nas_id = %s" if _hsel else "")
    _hnf_where = (" WHERE nas_id = %s" if _hsel else "")
    _hp = ([_hsel] if _hsel else [])
    dhcp_last = query(
        "SELECT MAX(last_poll) AS last_log, 0 AS last_5m FROM mikrotik_dhcp_poll_state"
        + _hnf_where, _hp, one=True,
    )
    dhcp_cnt = query(
        "SELECT COUNT(*) AS c FROM mikrotik_dhcp_leases WHERE active=true" + _hnf,
        _hp, one=True,
    )
    secrets_last = query(
        "SELECT MAX(synced_at) AS last_log, COUNT(*) AS last_5m FROM mikrotik_secrets"
        + _hnf_where, _hp, one=True,
    )
    def feed_status_ts(row, count_as_rate=None):
        if not row or not row["last_log"]:
            return {"status": "dead", "last": None, "rate": 0}
        lt = row["last_log"]
        age = (datetime.now(lt.tzinfo if lt.tzinfo else None) - lt).total_seconds()
        # DHCP polls every 2min, secrets hourly -> looser thresholds
        return {
            "status": "healthy" if age < 900 else "stale" if age < 3600 else "dead",
            "last": lt.isoformat(),
            "rate": count_as_rate if count_as_rate is not None else (row["last_5m"] or 0),
        }
    return jsonify({
        "nat_pba": feed_status(nat_last),
        "nat_flow": feed_status(flow_last),
        "radius": feed_status(radius_last),
        "dhcp": feed_status_ts(dhcp_last, count_as_rate=(dhcp_cnt["c"] if dhcp_cnt else 0)),
        "secrets": feed_status_ts(secrets_last, count_as_rate=(secrets_last["last_5m"] if secrets_last else 0)),
        "db_size": db_size["size"] if db_size else "N/A",
    })

# ---------------------------------------------------------------------------
# Routes — Analytics Dashboard (charts, top lists, geo)
# ---------------------------------------------------------------------------
@app.route("/analytics")
@login_required
def analytics():
    # Time range from query param
    rng = request.args.get("range", "1h")
    range_map = {
        "5m": "5 minutes", "15m": "15 minutes", "30m": "30 minutes",
        "1h": "1 hour", "12h": "12 hours", "24h": "24 hours",
        "1w": "7 days", "1M": "30 days",
    }
    interval = range_map.get(rng, "1 hour")
    # analytics-cache-read: long ranges served from the 5-min cache (NMS-style)
    if rng in ("30m", "1h", "12h", "24h", "1w", "1M"):
        _asel = _selected_nas_id()
        _ascope = f"nas:{_asel}" if _asel else "all"
        _ac = query("SELECT payload FROM analytics_cache WHERE scope_key=%s AND range_key=%s",
                    (_ascope, rng), one=True)
        if _ac and _ac["payload"]:
            _pl = _ac["payload"]
            return render_template(
                "analytics.html",
                stats=_pl.get("stats", {}), protocols=_pl.get("protocols", []),
                top_apps=_pl.get("top_apps", []), top_ports=[],
                top_subs=_pl.get("top_subs", []), top_dests=_pl.get("top_dests", []),
                top_countries=_pl.get("top_countries", []),
                timeline=_pl.get("timeline", []), current_range=rng, range_map=range_map,
                is_sampled=True, sample_pct=_pl.get("sample_pct", 5),
            )

    # For long ranges, sample the flow table to keep the page fast.
    # Short ranges scan everything (small row count); long ranges use TABLESAMPLE.
    long_range = rng in ("12h", "24h", "1w", "1M")
    sample_pct = {"12h": 10, "24h": 5, "1w": 2, "1M": 1}.get(rng, 100)

    # nat_flow_logs is a VIEW over mikrotik_translations on this box; TABLESAMPLE
    # cannot apply to a view, so scan directly (no sampling).
    factor = 1.0
    flow_src = "nat_flow_logs"

    time_filter = f"log_time > NOW() - INTERVAL '{interval}'"
    _sel = _selected_nas_id()  # _analytics_nas_scope
    if _sel:
        time_filter += f" AND nas_id = {int(_sel)}"
    # CDN query joins cdn_prefixes (also has nas_id) -> qualify to f.nas_id.
    _cdn_time_filter = time_filter.replace("nas_id", "f.nas_id")

    # --- Single combined stats query (was 1 heavy 3x-DISTINCT) ---
    stats = query(
        f"""SELECT
              COUNT(*) as total_flows,
              COUNT(DISTINCT source_ip) as unique_subs,
              COUNT(DISTINCT destination_ip) as unique_dests
           FROM {flow_src} WHERE {time_filter}""",
        one=True,
    ) or {"total_flows": 0, "unique_subs": 0, "unique_dests": 0}
    if long_range and stats:
        stats["total_flows"] = int((stats["total_flows"] or 0) * factor)
        stats["unique_subs"] = int((stats["unique_subs"] or 0) * factor)
        stats["unique_dests"] = int((stats["unique_dests"] or 0) * factor)

    # Public pool IPs seen in-window (flow view's translated_ip; nat_logs is
    # empty on a MikroTik box).
    active_nat_ips = query(
        f"SELECT COUNT(DISTINCT translated_ip) as cnt FROM {flow_src} WHERE {time_filter}",
        one=True,
    )
    stats["active_nat_ips"] = active_nat_ips["cnt"] if active_nat_ips else 0

    # --- Protocol distribution ---
    protocols = query(
        f"""SELECT COALESCE(protocol_name, 'unknown') as proto, COUNT(*) as cnt
            FROM {flow_src} WHERE {time_filter}
            GROUP BY 1 ORDER BY 2 DESC LIMIT 10""",
    ) or []

    # --- Top applications ---
    # MikroTik logs no DPI/app field, so classify by destination port. When a
    # real `application` value exists (Juniper DPI), prefer it. Port rows are
    # re-aggregated by service label in Python.
    import port_service
    _port_rows = query(
        f"""SELECT destination_port, protocol_name,
                   COALESCE(NULLIF(application, ''), '') AS application,
                   COUNT(*) as cnt
            FROM {flow_src} WHERE {time_filter}
            GROUP BY destination_port, protocol_name, application
            ORDER BY cnt DESC LIMIT 400""",
    ) or []
    _svc = {}
    for _r in _port_rows:
        _label = _r["application"] or port_service.classify(
            _r["destination_port"], _r.get("protocol_name"))
        _svc[_label] = _svc.get(_label, 0) + _r["cnt"]
    top_apps = [{"app": k, "cnt": (int(v * factor) if long_range else v)}
                for k, v in sorted(_svc.items(), key=lambda x: -x[1])[:12]]

    # --- CDN overlay: reclassify HTTPS/QUIC/HTTP traffic to known CDNs by dest IP ---
    # cdn_rows  # app-classification via GiST-indexed prefix containment.
    try:
        _cdn = query(
            f"""SELECT p.app AS app, COUNT(*) AS cnt
                FROM {flow_src} f
                JOIN mikrotik_cdn_prefixes p
                  ON p.nas_id = f.nas_id AND p.prefix >>= f.destination_ip
                WHERE {_cdn_time_filter}
                GROUP BY p.app ORDER BY cnt DESC""",
        ) or []
    except Exception:
        _cdn = []
    if _cdn:
        # CDN traffic is a subset of the generic web buckets; surface it as its
        # own named bars and trim the generic buckets so totals stay sensible.
        web_labels = {"HTTPS / TLS", "HTTPS / QUIC", "HTTP", "HTTPS-alt", "HTTP-alt"}
        cdn_total = 0
        cdn_named = []
        for r in _cdn:
            c = int(r["cnt"] * factor) if long_range else r["cnt"]
            cdn_named.append({"app": r["app"], "cnt": c})
            cdn_total += c
        # subtract CDN volume proportionally from the largest web bucket
        merged = {a["app"]: a["cnt"] for a in top_apps}
        for wl in sorted(web_labels, key=lambda w: -merged.get(w, 0)):
            if cdn_total <= 0:
                break
            take = min(merged.get(wl, 0), cdn_total)
            if take > 0:
                merged[wl] -= take
                cdn_total -= take
        for c in cdn_named:
            merged[c["app"]] = merged.get(c["app"], 0) + c["cnt"]
        top_apps = [{"app": k, "cnt": v} for k, v in
                    sorted(merged.items(), key=lambda x: -x[1]) if v > 0][:12]

    # --- Top subscribers — username comes straight from the flow source ---
    # (mikrotik_translations exposes `username`; on Juniper the column is null
    # and we fall back to a RADIUS lookup per IP.)
    top_subs = query(
        f"""SELECT source_ip,
                   MAX(username) AS username,
                   COUNT(*) as sessions,
                   COUNT(DISTINCT destination_ip) as destinations,
                   COUNT(DISTINCT destination_port) as services
            FROM {flow_src} WHERE {time_filter}
            GROUP BY source_ip ORDER BY sessions DESC LIMIT 10""",
    ) or []
    for s in top_subs:
        if not s.get("username"):
            u = query(
                """SELECT username FROM radius_accounting
                   WHERE framed_ip = %s ORDER BY session_start DESC LIMIT 1""",
                (s["source_ip"],), one=True,
            )
            s["username"] = u["username"] if u else None
        if long_range:
            s["sessions"] = int(s["sessions"] * factor)

    # --- Top destinations ---
    top_dests = query(
        f"""SELECT destination_ip, COUNT(*) as sessions
            FROM {flow_src} WHERE {time_filter}
            GROUP BY 1 ORDER BY 2 DESC LIMIT 10""",
    ) or []
    for d in top_dests:
        d["country"] = geo_country_name(str(d["destination_ip"]))
        if long_range:
            d["sessions"] = int(d["sessions"] * factor)

    # --- Country distribution (from top 200 dests only — geo lookup is Python-side) ---
    dest_sample = query(
        f"""SELECT destination_ip, COUNT(*) as cnt
            FROM {flow_src} WHERE {time_filter}
            GROUP BY 1 ORDER BY 2 DESC LIMIT 200""",
    ) or []
    country_counts = {}
    for row in dest_sample:
        c = geo_country_name(str(row["destination_ip"]))
        country_counts[c] = country_counts.get(c, 0) + row["cnt"]
    top_countries = sorted(country_counts.items(), key=lambda x: -x[1])[:10]

    # --- Session timeline (bucketed; no DISTINCT for long ranges) ---
    bucket = "minute" if rng in ("5m", "15m", "30m", "1h") else "hour"
    if long_range:
        # Skip the expensive COUNT(DISTINCT source_ip) per bucket on long ranges
        timeline = query(
            f"""SELECT to_char(date_trunc('{bucket}', log_time), 'MM-DD HH24:MI') as t,
                       COUNT(*) as sessions, 0 as subs
                FROM {flow_src} WHERE {time_filter}
                GROUP BY date_trunc('{bucket}', log_time)
                ORDER BY date_trunc('{bucket}', log_time)""",
        ) or []
        for t in timeline:
            t["sessions"] = int(t["sessions"] * factor)
    else:
        timeline = query(
            f"""SELECT to_char(date_trunc('{bucket}', log_time), 'MM-DD HH24:MI') as t,
                       COUNT(*) as sessions,
                       COUNT(DISTINCT source_ip) as subs
                FROM {flow_src} WHERE {time_filter}
                GROUP BY date_trunc('{bucket}', log_time)
                ORDER BY date_trunc('{bucket}', log_time)""",
        ) or []

    return render_template(
        "analytics.html",
        stats=stats, protocols=protocols, top_apps=top_apps, top_ports=[],
        top_subs=top_subs, top_dests=top_dests, top_countries=top_countries,
        timeline=timeline, current_range=rng, range_map=range_map,
        is_sampled=long_range, sample_pct=sample_pct,
    )

# ---------------------------------------------------------------------------
# Routes — NAS Device Management (admin only, Settings)
# ---------------------------------------------------------------------------
import subprocess
import ipaddress as _ipaddr

def _valid_ip(s):
    try:
        _ipaddr.ip_address(s)
        return True
    except ValueError:
        return False

@app.route("/settings/nas")
@admin_required
def nas_devices():
    devices = query("SELECT * FROM nas_devices ORDER BY id") or []
    pending = query(
        "SELECT COUNT(*) as c FROM nas_devices WHERE status='staged' OR (enabled=FALSE AND status='active')",
        one=True,
    )
    pending_count = pending["c"] if pending else 0
    return render_template("admin_nas.html", devices=devices, pending_count=pending_count)

@app.route("/settings/nas/add", methods=["POST"])
@admin_required
def nas_add():
    name = request.form.get("name", "").strip()
    ip = request.form.get("ip_address", "").strip()
    desc = request.form.get("description", "").strip()
    nas_type = request.form.get("nas_type", "juniper").strip()
    source_ip = request.form.get("source_ip", "").strip()
    secret_mode = request.form.get("secret_mode", "auto")
    secret = request.form.get("secret", "").strip()
    # MikroTik-specific (ignored for other vendors)
    model = request.form.get("model", "syslog").strip()
    syslog_port_raw = request.form.get("syslog_port", "514").strip()
    # API access (MikroTik enrichment): optional, strong password generated.
    api_enabled = request.form.get("api_enabled") in ("on", "true", "1", "yes")
    api_host = request.form.get("api_host", "").strip()
    api_user = request.form.get("api_user", "").strip() or "elbipdr"
    api_ssl = request.form.get("api_ssl") in ("on", "true", "1", "yes")
    api_port_raw = request.form.get("api_port", "").strip()
    api_password = request.form.get("api_password", "").strip()
    bogon_mit = request.form.get("bogon_mitigation") in ("on", "true", "1", "yes")

    if not name or not ip:
        flash("Name and IP address are required.", "warning")
        return redirect(url_for("nas_devices"))
    if not _valid_ip(ip):
        flash(f"Invalid IP address: {ip}", "danger")
        return redirect(url_for("nas_devices"))
    if source_ip and not _valid_ip(source_ip):
        flash(f"Invalid source IP: {source_ip}", "danger")
        return redirect(url_for("nas_devices"))

    if secret_mode == "auto" or not secret:
        secret = secrets.token_urlsafe(24)

    existing = query("SELECT id FROM nas_devices WHERE ip_address = %s", (ip,), one=True)
    if existing:
        flash(f"A NAS with IP {ip} already exists.", "warning")
        return redirect(url_for("nas_devices"))

    if nas_type == "mikrotik":
        # Logs arrive from source_ip; default it to the NAS IP if not given.
        if not source_ip:
            source_ip = ip
        try:
            syslog_port = int(syslog_port_raw)
            if not (1 <= syslog_port <= 65535):
                syslog_port = 514
        except (ValueError, TypeError):
            syslog_port = 514
        if model not in ("syslog", "deterministic", "both"):
            model = "syslog"
        api_pw_enc = None  # api_pw_enc  # onboard
        api_port = None
        if api_enabled:
            try:
                api_port = int(api_port_raw) if api_port_raw else (8729 if api_ssl else 8728)
                if not (1 <= api_port <= 65535):
                    api_port = 8729 if api_ssl else 8728
            except (ValueError, TypeError):
                api_port = 8729 if api_ssl else 8728
            if not api_password:
                api_password = secrets.token_urlsafe(18)
            try:
                import mt_crypto
                api_pw_enc = mt_crypto.encrypt(api_password)
            except Exception as e:
                flash(f"API password encrypt failed: {e}", "danger")
                return redirect(url_for("nas_devices"))
        execute(
            """INSERT INTO nas_devices
                 (name, ip_address, secret, description, nas_type, source_ip,
                  model, syslog_port, status, enabled, created_by,
                  api_enabled, api_host, api_port, api_ssl, api_user, api_password_enc,
                  bogon_mitigation_enabled)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'staged', TRUE, %s,
                       %s, %s, %s, %s, %s, %s, %s)""",
            (name, ip, secret, desc, nas_type, source_ip, model, syslog_port,
             session.get("username"),
             api_enabled, (api_host or source_ip or None), api_port, api_ssl,
             (api_user if api_enabled else None), api_pw_enc, bogon_mit),
        )
    else:
        execute(
            """INSERT INTO nas_devices
                 (name, ip_address, secret, description, nas_type, source_ip,
                  status, enabled, created_by)
               VALUES (%s, %s, %s, %s, %s, %s, 'staged', TRUE, %s)""",
            (name, ip, secret, desc, nas_type, source_ip or None,
             session.get("username")),
        )
    audit_log("NAS_ADD", f"Staged {nas_type} NAS {name} ({ip})")
    flash(f"NAS '{name}' staged. Click 'Apply & Reload' to activate.", "success")
    return redirect(url_for("nas_devices"))


PAGE_SIZES = [25, 100, 250, 500, 1000]  # 'all' handled separately, capped

def _paginate(default=25, max_all=5000):
    """Read page/per_page from the request and compute limit/offset.
    Returns a dict: {page, per_page, per_raw, limit, offset, sizes, is_all}.
    'all' is capped at max_all to protect the browser + DB on huge tables."""
    per_raw = request.args.get("per_page", str(default)).strip().lower()
    if per_raw == "all":
        limit = max_all; per_page = max_all; is_all = True
    else:
        try:
            per_page = int(per_raw)
        except (ValueError, TypeError):
            per_page = default
        if per_page not in PAGE_SIZES:
            per_page = default
        limit = per_page; is_all = False
    try:
        page = max(1, int(request.args.get("page", "1")))
    except (ValueError, TypeError):
        page = 1
    offset = (page - 1) * limit
    return {"page": page, "per_page": per_page, "per_raw": per_raw,
            "limit": limit, "offset": offset, "sizes": PAGE_SIZES,
            "is_all": is_all}


def _page_meta(pg, total):
    """Given a _paginate() dict and a total count, add page navigation math."""
    limit = pg["limit"]
    pages = max(1, (total + limit - 1) // limit) if total else 1
    pg = dict(pg)
    pg["total"] = total
    pg["pages"] = pages
    pg["has_prev"] = pg["page"] > 1
    pg["has_next"] = pg["page"] < pages
    pg["start"] = 0 if total == 0 else (pg["page"] - 1) * limit + 1
    pg["end"] = min(pg["page"] * limit, total)
    return pg


def _box_ip():
    """Best-effort primary IP of this box (the address a NAS logs to)."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "<BOX_IP>"


@app.route("/settings/nas/<int:nas_id>/cdn")
@admin_required
def nas_cdn(nas_id):
    dev = query("SELECT * FROM nas_devices WHERE id=%s", (nas_id,), one=True)
    if not dev:
        abort(404)
    prefixes = query(
        """SELECT id, app, host(prefix) AS ip, masklen(prefix) AS mask,
                  text(prefix) AS cidr, comment
           FROM mikrotik_cdn_prefixes WHERE nas_id=%s
           ORDER BY app, prefix""",
        (nas_id,),
    ) or []
    by_app = {}
    for p in prefixes:
        by_app.setdefault(p["app"], []).append(p)
    return render_template("admin_cdn.html", dev=dev, by_app=by_app,
                           total=len(prefixes))


@app.route("/settings/nas/<int:nas_id>/cdn/add", methods=["POST"])
@admin_required
def nas_cdn_add(nas_id):
    dev = query("SELECT id FROM nas_devices WHERE id=%s", (nas_id,), one=True)
    if not dev:
        abort(404)
    app_label = request.form.get("app", "").strip()[:64]
    cidr = request.form.get("prefix", "").strip()
    comment = request.form.get("comment", "").strip()[:200]
    if not app_label or not cidr:
        flash("App label and prefix are required.", "warning")
        return redirect(url_for("nas_cdn", nas_id=nas_id))
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr if "/" in cidr else cidr + "/32", strict=False)
    except ValueError:
        flash(f"Invalid prefix: {cidr}", "danger")
        return redirect(url_for("nas_cdn", nas_id=nas_id))
    try:
        execute(
            """INSERT INTO mikrotik_cdn_prefixes (nas_id, app, prefix, comment)
               VALUES (%s,%s,%s,%s)
               ON CONFLICT (nas_id, app, prefix) DO UPDATE SET comment=EXCLUDED.comment""",
            (nas_id, app_label, str(net), comment or None),
        )
        audit_log("CDN_ADD", f"nas={nas_id} app={app_label} prefix={net}")
        flash(f"Added {net} → {app_label}.", "success")
    except Exception as e:
        flash(f"Add failed: {e}", "danger")
    return redirect(url_for("nas_cdn", nas_id=nas_id))


@app.route("/settings/nas/<int:nas_id>/cdn/delete", methods=["POST"])
@admin_required
def nas_cdn_delete(nas_id):
    pid = request.form.get("id")
    if pid:
        execute("DELETE FROM mikrotik_cdn_prefixes WHERE id=%s AND nas_id=%s",
                (pid, nas_id))
        audit_log("CDN_DELETE", f"nas={nas_id} prefix_id={pid}")
        flash("Prefix deleted.", "success")
    return redirect(url_for("nas_cdn", nas_id=nas_id))


@app.route("/settings/nas/<int:nas_id>/cdn/bulk", methods=["POST"])
@admin_required
def nas_cdn_bulk(nas_id):
    dev = query("SELECT id FROM nas_devices WHERE id=%s", (nas_id,), one=True)
    if not dev:
        abort(404)
    import ipaddress
    text = request.form.get("bulk", "")
    added = skipped = 0
    errors = []
    rows = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [x.strip() for x in line.split(",")]
        if len(parts) < 2 or not parts[0] or not parts[1]:
            skipped += 1
            errors.append(f"line {lineno}: need 'app,prefix'")
            continue
        app_label = parts[0][:64]
        cidr_in = parts[1]
        comment = (parts[2][:200] if len(parts) > 2 else None)
        try:
            net = ipaddress.ip_network(cidr_in if "/" in cidr_in else cidr_in + "/32",
                                       strict=False)
        except ValueError:
            skipped += 1
            errors.append(f"line {lineno}: invalid prefix '{cidr_in}'")
            continue
        rows.append((nas_id, app_label, str(net), comment))
    for r in rows:
        try:
            execute(
                """INSERT INTO mikrotik_cdn_prefixes (nas_id, app, prefix, comment)
                   VALUES (%s,%s,%s,%s)
                   ON CONFLICT (nas_id, app, prefix) DO UPDATE SET comment=EXCLUDED.comment""",
                r,
            )
            added += 1
        except Exception as e:
            skipped += 1
            errors.append(f"{r[2]}: {e}")
    audit_log("CDN_BULK", f"nas={nas_id} added={added} skipped={skipped}")
    msg = f"Bulk import: {added} added"
    if skipped:
        msg += f", {skipped} skipped"
    flash(msg + (" - " + "; ".join(errors[:5]) if errors else ""),
          "success" if added else "warning")
    return redirect(url_for("nas_cdn", nas_id=nas_id))


@app.route("/settings/nas/config/<int:nas_id>")
@admin_required
def nas_config(nas_id):
    """Return the paste-ready RouterOS config for a MikroTik NAS."""
    dev = query("SELECT * FROM nas_devices WHERE id = %s", (nas_id,), one=True)
    if not dev:
        abort(404)
    if dev.get("nas_type") != "mikrotik":
        return ("Router config generation is available for MikroTik NAS only.",
                200, {"Content-Type": "text/plain; charset=utf-8"})
    try:
        import mikrotik_config_gen as cg
        _api_pw = None
        if dev.get("api_enabled") and dev.get("api_password_enc"):
            try:
                import mt_crypto
                _api_pw = mt_crypto.decrypt(dev["api_password_enc"])
            except Exception:
                _api_pw = None
        params = {
            "nas_name": dev["name"],
            "model": dev.get("model") or "syslog",
            "box_log_ip": _box_ip(),
            "syslog_port": dev.get("syslog_port") or 514,
            "log_source_ip": dev.get("source_ip") or dev["ip_address"],
            "api_enabled": bool(dev.get("api_enabled")),
            "api_ssl": bool(dev.get("api_ssl")),
            "api_host": dev.get("api_host") or dev.get("source_ip") or dev["ip_address"],
            "api_user": dev.get("api_user") or "elbipdr",
            "api_port": dev.get("api_port") or (8729 if dev.get("api_ssl") else 8728),
            "api_password": _api_pw or "<SET-API-PASSWORD>",
            "box_api_src_ip": _box_ip(),
        }
        text = cg.generate_router_config(params)
        text += "\n\n" + cg.generate_box_config(params)
        audit_log("NAS_CONFIG_VIEW", f"Viewed router config for {dev['name']}")
        return (text, 200, {"Content-Type": "text/plain; charset=utf-8"})
    except Exception as e:
        return (f"Config generation failed: {e}", 200,
                {"Content-Type": "text/plain; charset=utf-8"})


@app.route("/settings/nas/toggle/<int:nas_id>", methods=["POST"])
@admin_required
def nas_toggle(nas_id):
    dev = query("SELECT * FROM nas_devices WHERE id = %s", (nas_id,), one=True)
    if not dev:
        flash("NAS not found.", "warning")
        return redirect(url_for("nas_devices"))
    new_state = not dev["enabled"]
    execute("UPDATE nas_devices SET enabled = %s WHERE id = %s", (new_state, nas_id))
    audit_log("NAS_TOGGLE", f"{'Enabled' if new_state else 'Disabled'} NAS {dev['name']} ({dev['ip_address']})")
    flash(f"NAS '{dev['name']}' {'enabled' if new_state else 'disabled'}. Apply & Reload to take effect.", "info")
    return redirect(url_for("nas_devices"))

@app.route("/settings/nas/delete/<int:nas_id>", methods=["POST"])
@admin_required
def nas_delete(nas_id):
    dev = query("SELECT * FROM nas_devices WHERE id = %s", (nas_id,), one=True)
    if not dev:
        flash("NAS not found.", "warning")
        return redirect(url_for("nas_devices"))
    # Soft-delete: mark disabled + pending-removal. Apply removes its firewall
    # rules AND purges the row. (Hard-deleting here would orphan the UFW rules.)
    execute("UPDATE nas_devices SET enabled = FALSE, status = 'removing' WHERE id = %s", (nas_id,))
    audit_log("NAS_DELETE", f"Deleted NAS {dev['name']} ({dev['ip_address']})")
    flash(f"NAS '{dev['name']}' marked for removal. Click Apply & Reload to remove its client + firewall rules.", "info")
    return redirect(url_for("nas_devices"))

@app.route("/settings/nas/bulk", methods=["POST"])
@admin_required
def nas_bulk_add():
    import ipaddress, secrets as _secrets
    text = request.form.get("bulk", "")
    added = skipped = 0
    errors = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [x.strip() for x in line.split(",")]
        name = parts[0] if parts else ""
        src = parts[1] if len(parts) > 1 else ""
        role = (parts[2].lower() if len(parts) > 2 and parts[2] else "local")
        region = (parts[3] if len(parts) > 3 and parts[3] else None)
        model = (parts[4].lower() if len(parts) > 4 and parts[4] else "syslog")
        if not name:
            skipped += 1; errors.append(f"line {lineno}: missing name"); continue
        if role not in ("local", "remote"):
            skipped += 1; errors.append(f"line {lineno}: role must be local/remote"); continue
        if model not in ("syslog", "deterministic", "both"):
            model = "syslog"
        if role == "local":
            if not src or not _valid_ip(src):
                skipped += 1; errors.append(f"line {lineno}: local NAS needs valid source_ip"); continue
        # duplicate check by name
        if query("SELECT 1 FROM nas_devices WHERE name=%s", (name,), one=True):
            skipped += 1; errors.append(f"line {lineno}: '{name}' already exists"); continue
        secret = _secrets.token_urlsafe(24)
        try:
            execute(
                """INSERT INTO nas_devices
                     (name, ip_address, secret, nas_type, source_ip, model,
                      collection_role, region, syslog_port, status, enabled, created_by)
                   VALUES (%s,%s,%s,'mikrotik',%s,%s,%s,%s,514,'staged',TRUE,%s)""",
                (name, (src or "0.0.0.0"), secret, (src or None), model,
                 role, region, session.get("username")),
            )
            added += 1
        except Exception as e:
            skipped += 1; errors.append(f"line {lineno}: {e}")
    audit_log("NAS_BULK", f"added={added} skipped={skipped}")
    msg = f"Bulk NAS: {added} staged"
    if skipped:
        msg += f", {skipped} skipped"
    flash(msg + (" - " + "; ".join(errors[:6]) if errors else "") +
          (". Click Apply & Reload to activate." if added else ""),
          "success" if added else "warning")
    return redirect(url_for("nas_devices"))


@app.route("/settings/nas/<int:nas_id>/edit", methods=["GET", "POST"])
@admin_required
def nas_edit(nas_id):
    dev = query("SELECT * FROM nas_devices WHERE id=%s", (nas_id,), one=True)
    if not dev:
        abort(404)
    if request.method == "GET":
        # decrypt api password only to indicate presence (never render it)
        has_api_pw = bool(dev.get("api_password_enc"))
        return render_template("admin_nas_edit.html", dev=dev, has_api_pw=has_api_pw)

    # POST — save
    name = request.form.get("name", "").strip()
    desc = request.form.get("description", "").strip()
    source_ip = request.form.get("source_ip", "").strip()
    model = request.form.get("model", dev.get("model") or "syslog").strip()
    region = request.form.get("region", "").strip() or None
    role = request.form.get("collection_role", dev.get("collection_role") or "local").strip()
    syslog_port_raw = request.form.get("syslog_port", str(dev.get("syslog_port") or 514)).strip()
    if not name:
        flash("Name is required.", "warning")
        return redirect(url_for("nas_edit", nas_id=nas_id))
    if source_ip and not _valid_ip(source_ip):
        flash(f"Invalid source IP: {source_ip}", "danger")
        return redirect(url_for("nas_edit", nas_id=nas_id))
    if role not in ("local", "remote"):
        role = "local"
    if model not in ("syslog", "deterministic", "both"):
        model = "syslog"
    try:
        syslog_port = int(syslog_port_raw)
        if not (1 <= syslog_port <= 65535):
            syslog_port = 514
    except (ValueError, TypeError):
        syslog_port = 514

    # --- API section (password preservation) ---
    api_enabled = request.form.get("api_enabled") in ("on", "true", "1", "yes")
    api_host = request.form.get("api_host", "").strip() or source_ip or None
    api_user = request.form.get("api_user", "").strip() or "elbipdr"
    api_ssl = request.form.get("api_ssl") in ("on", "true", "1", "yes")
    api_port_raw = request.form.get("api_port", "").strip()
    api_password = request.form.get("api_password", "").strip()
    try:
        api_port = int(api_port_raw) if api_port_raw else (8729 if api_ssl else 8728)
        if not (1 <= api_port <= 65535):
            api_port = 8729 if api_ssl else 8728
    except (ValueError, TypeError):
        api_port = 8729 if api_ssl else 8728

    api_pw_enc = dev.get("api_password_enc")  # default: keep existing
    if api_enabled:
        if api_password:
            # explicit new password provided
            try:
                import mt_crypto
                api_pw_enc = mt_crypto.encrypt(api_password)
            except Exception as e:
                flash(f"API password encrypt failed: {e}", "danger")
                return redirect(url_for("nas_edit", nas_id=nas_id))
        elif not api_pw_enc:
            # enabled, no existing password, none provided -> generate
            try:
                import mt_crypto
                api_pw_enc = mt_crypto.encrypt(secrets.token_urlsafe(18))
            except Exception as e:
                flash(f"API password generate failed: {e}", "danger")
                return redirect(url_for("nas_edit", nas_id=nas_id))
        # else: keep existing api_pw_enc (preservation)

    execute(
        """UPDATE nas_devices
           SET name=%s, description=%s, source_ip=%s, model=%s, region=%s,
               collection_role=%s, syslog_port=%s,
               api_enabled=%s, api_host=%s, api_port=%s, api_ssl=%s,
               api_user=%s, api_password_enc=%s
           WHERE id=%s""",
        (name, desc or None, source_ip or None, model, region, role, syslog_port,
         api_enabled, (api_host if api_enabled else dev.get("api_host")),
         (api_port if api_enabled else dev.get("api_port")), api_ssl,
         (api_user if api_enabled else dev.get("api_user")), api_pw_enc, nas_id),
    )
    audit_log("NAS_EDIT", f"Edited NAS {name} (id={nas_id}) api={api_enabled}")
    flash(f"NAS '{name}' updated." +
          (" Use the Config button to get the API user config." if api_enabled else ""),
          "success")
    return redirect(url_for("nas_devices"))


@app.route("/settings/nas/<int:nas_id>/api-test", methods=["POST"])
@admin_required
def nas_api_test(nas_id):
    dev = query("SELECT * FROM nas_devices WHERE id=%s", (nas_id,), one=True)
    if not dev:
        abort(404)
    if not dev.get("api_enabled") or not dev.get("api_password_enc"):
        flash("API is not configured for this NAS.", "warning")
        return redirect(url_for("nas_devices"))
    host = dev.get("api_host") or dev.get("source_ip") or dev["ip_address"]
    port = int(dev.get("api_port") or (8729 if dev.get("api_ssl") else 8728))
    user = dev.get("api_user") or "elbipdr"
    try:
        import mt_crypto
        pw = mt_crypto.decrypt(dev["api_password_enc"])
    except Exception as e:
        flash(f"API test: token decrypt failed — {e}", "danger")
        return redirect(url_for("nas_devices"))
    try:
        from librouteros import connect
        kw = dict(username=user, password=pw, host=host, port=port)
        if dev.get("api_ssl"):
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            kw["ssl_wrapper"] = ctx.wrap_socket
        api = connect(**kw)
        n_secrets = len(list(api.path("ppp", "secret")))
        try:
            n_active = len(list(api.path("ppp", "active")))
        except Exception:
            n_active = None
        api.close()
        msg = f"API OK — {host}:{port} as {user}: {n_secrets} PPP secret(s)"
        if n_active is not None:
            msg += f", {n_active} online"
        audit_log("API_TEST", f"nas={nas_id} OK secrets={n_secrets}")  # api-test-ajax
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"ok": True, "message": msg})
        flash(msg, "success")
    except Exception as e:
        _fm = f"API test FAILED — {host}:{port} as {user}: {type(e).__name__}: {str(e)[:140]}"
        audit_log("API_TEST", f"nas={nas_id} FAIL {type(e).__name__}")
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify({"ok": False, "message": _fm})
        flash(_fm, "danger")
    return redirect(url_for("nas_devices"))


@app.route("/settings/nas/apply", methods=["POST"])
@admin_required
def nas_apply():
    """Invoke the scoped root helper to regenerate config + reload FreeRADIUS."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "/opt/elb-ipdr/scripts/elb-nas-apply.sh"],
            capture_output=True, text=True, timeout=60,
        )
        out = (result.stdout or "").strip()
        err = (result.stderr or "").strip()
        if result.returncode == 0 and out.startswith("OK:"):
            count = out.split(":")[1] if ":" in out else "?"
            audit_log("NAS_APPLY", f"Applied NAS config, {count} active device(s)")
            flash(f"Applied successfully — {count} active NAS device(s), FreeRADIUS reloaded.", "success")
        elif "CONFIG_INVALID" in out or "CONFIG_INVALID" in err:
            audit_log("NAS_APPLY_FAIL", "FreeRADIUS config validation failed")
            flash("FreeRADIUS config validation failed — changes NOT applied. Check the NAS entries.", "danger")
        else:
            audit_log("NAS_APPLY_FAIL", f"rc={result.returncode} err={err[:200]}")
            flash(f"Apply failed (rc={result.returncode}). {err[:200]}", "danger")
    except subprocess.TimeoutExpired:
        flash("Apply timed out after 60s. Check the server.", "danger")
    except FileNotFoundError:
        flash("Helper script not found or sudo not configured. Run the v1.2 installer.", "danger")
    except Exception as e:
        flash(f"Apply error: {e}", "danger")
    return redirect(url_for("nas_devices"))

# ---------------------------------------------------------------------------
# Routes — Branding (admin white-label)
# ---------------------------------------------------------------------------
from flask import send_from_directory

BRANDING_DIR = os.environ.get("BRANDING_DIR", "/opt/elb-ipdr/branding")

@app.route("/branding/asset/<path:filename>")
def branding_asset(filename):
    """Serve branding assets (logo, favicons). Public — needed for login page + favicons."""
    safe = os.path.basename(filename)  # prevent traversal
    if os.path.exists(os.path.join(BRANDING_DIR, safe)):
        return send_from_directory(BRANDING_DIR, safe)
    abort(404)

# Serve favicon.ico from branding if present, else default
@app.route("/favicon.ico")
def favicon_ico():
    p = os.path.join(BRANDING_DIR, "favicon.ico")
    if os.path.exists(p):
        return send_from_directory(BRANDING_DIR, "favicon.ico")
    abort(404)

@app.route("/settings/branding", methods=["GET"])
@admin_required
def branding_settings():
    b = load_branding()
    limits = {
        "logo_max_kb": branding_mod.LOGO_MAX_BYTES // 1024 if BRANDING_AVAILABLE else 500,
        "logo_formats": ", ".join(sorted(branding_mod.LOGO_ALLOWED)) if BRANDING_AVAILABLE else "png, svg, jpg",
        "logo_max_dim": branding_mod.LOGO_MAX_DIM if BRANDING_AVAILABLE else 1200,
        "icon_min": branding_mod.ICON_MIN_DIM if BRANDING_AVAILABLE else 128,
        "icon_rec": branding_mod.ICON_RECOMMENDED if BRANDING_AVAILABLE else 512,
    }
    return render_template("admin_branding.html", b=b, limits=limits)

@app.route("/settings/branding/save", methods=["POST"])
@admin_required
def branding_save():
    """Save text/color branding fields."""
    fields = {
        "product_name": request.form.get("product_name", "").strip()[:64] or "IPDR",
        "tagline": request.form.get("tagline", "").strip()[:128],
        "company_name": request.form.get("company_name", "").strip()[:128],
        "domain": request.form.get("domain", "").strip()[:128],
        "color_primary": request.form.get("color_primary", "#20A0E0")[:9],
        "color_primary_dark": request.form.get("color_primary_dark", "#1880B8")[:9],
        "color_bg_dark": request.form.get("color_bg_dark", "#0f1923")[:9],
        "color_bg_sidebar": request.form.get("color_bg_sidebar", "#141e2a")[:9],
        "color_bg_card": request.form.get("color_bg_card", "#1a2736")[:9],
        "color_bg_body": request.form.get("color_bg_body", "#111a24")[:9],
        "color_success": request.form.get("color_success", "#2ecc71")[:9],
        "color_warning": request.form.get("color_warning", "#f1c40f")[:9],
        "color_danger": request.form.get("color_danger", "#e74c3c")[:9],
    }
    # Validate hex colors
    import re as _re
    for k, v in fields.items():
        if k.startswith("color_") and not _re.match(r"^#[0-9A-Fa-f]{6}$", v):
            flash(f"Invalid color for {k}: {v}", "warning")
            return redirect(url_for("branding_settings"))

    set_clause = ", ".join(f"{k} = %s" for k in fields)
    params = list(fields.values()) + [session.get("username")]
    execute(f"UPDATE branding SET {set_clause}, updated_by = %s, updated_at = NOW() WHERE id = 1", params)
    audit_log("BRANDING_SAVE", f"Updated branding: {fields['product_name']} / {fields['domain']}")
    flash("Branding saved. Refresh to see changes.", "success")
    return redirect(url_for("branding_settings"))

@app.route("/settings/branding/logo", methods=["POST"])
@admin_required
def branding_logo():
    """Upload sidebar logo."""
    if not BRANDING_AVAILABLE:
        flash("Branding module unavailable.", "danger")
        return redirect(url_for("branding_settings"))
    f = request.files.get("logo")
    ok, msg, ext = branding_mod.validate_image(f, kind="logo")
    if not ok:
        flash(f"Logo rejected: {msg}", "warning")
        return redirect(url_for("branding_settings"))
    branding_mod.save_logo(f, ext)
    execute("UPDATE branding SET has_logo = TRUE, logo_version = logo_version + 1, updated_at = NOW() WHERE id = 1")
    audit_log("BRANDING_LOGO", f"Uploaded logo ({ext}, {msg})")
    flash(f"Logo uploaded ({msg}). Refresh to see it.", "success")
    return redirect(url_for("branding_settings"))

@app.route("/settings/branding/favicon", methods=["POST"])
@admin_required
def branding_favicon():
    """Upload square icon → generate full favicon set."""
    if not BRANDING_AVAILABLE:
        flash("Branding module unavailable.", "danger")
        return redirect(url_for("branding_settings"))
    f = request.files.get("icon")
    ok, msg, ext = branding_mod.validate_image(f, kind="icon")
    if not ok:
        flash(f"Icon rejected: {msg}", "warning")
        return redirect(url_for("branding_settings"))
    gen_ok, gen_msg = branding_mod.generate_favicons(f)
    if not gen_ok:
        flash(f"Favicon generation failed: {gen_msg}", "danger")
        return redirect(url_for("branding_settings"))
    execute("UPDATE branding SET has_favicon = TRUE, favicon_version = favicon_version + 1, updated_at = NOW() WHERE id = 1")
    audit_log("BRANDING_FAVICON", f"Generated favicons ({msg})")
    flash(f"Favicon set generated. {gen_msg}", "success")
    return redirect(url_for("branding_settings"))

@app.route("/settings/branding/reset", methods=["POST"])
@admin_required
def branding_reset():
    """Reset colors/text to Example ISP defaults (keeps uploaded assets)."""
    if BRANDING_AVAILABLE:
        d = branding_mod.DEFAULTS
        execute("""UPDATE branding SET product_name=%s, tagline=%s, company_name=%s, domain=%s,
                   color_primary=%s, color_primary_dark=%s, color_bg_dark=%s, color_bg_sidebar=%s,
                   color_bg_card=%s, color_bg_body=%s, color_success=%s, color_warning=%s,
                   color_danger=%s, updated_at=NOW() WHERE id=1""",
                (d["product_name"], d["tagline"], d["company_name"], d["domain"],
                 d["color_primary"], d["color_primary_dark"], d["color_bg_dark"], d["color_bg_sidebar"],
                 d["color_bg_card"], d["color_bg_body"], d["color_success"], d["color_warning"], d["color_danger"]))
        audit_log("BRANDING_RESET", "Reset branding to defaults")
        flash("Branding reset to defaults.", "info")
    return redirect(url_for("branding_settings"))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
