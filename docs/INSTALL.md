# Installation Guide

This guide walks through deploying IPDR on a fresh Debian/Ubuntu server. Adapt
paths, users, and network details to your environment.

> **Before you begin:** This software processes subscriber PII and lawful-
> intercept data. Deploy it only if you have the legal authority to do so, and
> review [SECURITY.md](../SECURITY.md) and [DISCLAIMER.md](../DISCLAIMER.md).

---

## 1. Requirements

- **OS:** Debian 12/13 or Ubuntu 22.04+ (a dedicated VM or host)
- **CPU/RAM:** 4+ cores, 8+ GB RAM (more for high translation volume)
- **Disk:** sized for your retention window. CGNAT logging can produce millions
  of rows/day; budget accordingly (e.g. 100–200 GB for ~90 days at mid volume).
- **Software:** PostgreSQL 15/16, Python 3.11+, nginx, rsyslog
- **Network:** reachable by your NAS/BNG for syslog (UDP/514) and, optionally,
  the RouterOS API (TCP/8728 or 8729) for session/lease polling.

---

## 2. System packages

```bash
sudo apt update && sudo apt install -y \
  postgresql postgresql-contrib \
  python3 python3-venv python3-pip \
  nginx rsyslog git curl
```

Create a service user for the app:

```bash
sudo useradd -r -m -s /bin/bash ipdr
```

---

## 3. PostgreSQL setup

```bash
sudo -u postgres psql <<'SQL'
CREATE USER ipdr_user WITH PASSWORD 'CHANGE_ME_STRONG_PASSWORD';
CREATE DATABASE ipdr OWNER ipdr_user;
GRANT ALL PRIVILEGES ON DATABASE ipdr TO ipdr_user;
SQL
```

Tune PostgreSQL for a write-heavy, time-partitioned workload (edit
`/etc/postgresql/16/main/postgresql.conf`) — as a starting point:

```
shared_buffers = 2GB
work_mem = 64MB
maintenance_work_mem = 512MB
effective_cache_size = 6GB
```

Restart: `sudo systemctl restart postgresql`.

---

## 4. Application code

```bash
sudo -u ipdr -i
git clone https://github.com/imrankhan-coder/<REPO>.git /opt/ipdr
cd /opt/ipdr
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt
exit
```

If there is no `requirements.txt`, install the core dependencies:

```bash
sudo -u ipdr /opt/ipdr/venv/bin/pip install \
  flask gunicorn psycopg2-binary cryptography librouteros
```

---

## 5. Environment configuration

Copy the example env and fill in real values:

```bash
sudo -u ipdr cp /opt/ipdr/.env.example /opt/ipdr/.env
sudo -u ipdr nano /opt/ipdr/.env
```

Generate the secrets:

```bash
# Flask session secret
python3 -c "import secrets; print('FLASK_SECRET='+secrets.token_hex(32))"
# Fernet key (encrypts stored NAS API passwords)
python3 -c "from cryptography.fernet import Fernet; print('MT_FERNET_KEY='+Fernet.generate_key().decode())"
# LEA API bearer token
python3 -c "import secrets; print('LEA_API_TOKEN='+secrets.token_urlsafe(32))"
```

Set `DATABASE_URL=postgresql://ipdr_user:YOUR_PASSWORD@127.0.0.1:5432/ipdr`
and `MT_RETENTION_DAYS` to your legal obligation.

**Never commit `.env`. Keep it `chmod 600`, owned by the `ipdr` user.**

---

## 6. Database schema

Apply the schema files in order. They are idempotent:

```bash
cd /opt/ipdr/schema
for f in mikrotik_schema.sql mikrotik_partition.sql mikrotik_ppp_sessions.sql \
         mikrotik_secrets.sql mikrotik_srcmac.sql mikrotik_dhcp.sql \
         mikrotik_lea_username.sql \
         mikrotik_flowview.sql mikrotik_cdn.sql mikrotik_scale.sql \
         mikrotik_autovacuum.sql dashboard_cache.sql analytics_cache.sql; do
  echo "== $f =="
  PGPASSWORD=YOUR_PASSWORD psql -h 127.0.0.1 -U ipdr_user -d ipdr -f "$f"
done
```

(Adjust the list to the files present in `schema/`.)

---

## 7. Syslog ingest (NAT logs)

IPDR ingests carrier NAT translation logs via rsyslog on UDP/514.

1. Point your NAS/BNG to log NAT/connection events to this server's IP, UDP/514.
2. Install the rsyslog template that writes the raw messages where the ingest
   daemon tails them:

```bash
sudo cp /opt/ipdr/deploy/90-mikrotik-ingest.conf /etc/rsyslog.d/
sudo systemctl restart rsyslog
```

3. Confirm logs are arriving:

```bash
sudo tcpdump -ni any udp port 514 -c 5
```

**RouterOS side (example):** enable connection logging on your CGNAT rules and
point `/system logging` action to a remote syslog target (this server). The
exact rule set is vendor/version-specific — see `scripts/mikrotik_config_gen.py`
for the reference logging rule this parser expects.

---

## 8. systemd services

Copy the unit files and enable them:

```bash
sudo cp /opt/ipdr/deploy/*.service /opt/ipdr/deploy/*.timer /etc/systemd/system/
sudo systemctl daemon-reload

# core ingest + web
sudo systemctl enable --now mikrotik-ingest.service
sudo systemctl enable --now ipdr-web.service        # rename to match your unit

# pollers + maintenance (timers)
sudo systemctl enable --now mikrotik-ppp-poll.timer
sudo systemctl enable --now mikrotik-dhcp-poll.timer
sudo systemctl enable --now mikrotik-secrets-sync.timer
sudo systemctl enable --now mikrotik-partition-maint.timer

# performance caches
sudo systemctl enable --now dashboard-stats.timer
sudo systemctl enable --now analytics-stats-fast.timer
sudo systemctl enable --now analytics-stats-slow.timer
```

Check status: `systemctl list-timers 'mikrotik-*' 'ipdr-*' 'dashboard-*' 'analytics-*'`.

> The unit files ship with `User=ipdr` and paths under `/opt/ipdr`. Edit them if
> your user or install path differs.

---

## 9. Web server (gunicorn + nginx)

The `ipdr-web` service runs gunicorn on a local port. Put nginx in front to
terminate TLS.

Example nginx site (`/etc/nginx/sites-available/ipdr`):

```nginx
server {
    listen 443 ssl;
    server_name ipdr.example.com;

    ssl_certificate     /etc/letsencrypt/live/ipdr.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ipdr.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
server {
    listen 80;
    server_name ipdr.example.com;
    return 301 https://$host$request_uri;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/ipdr /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Obtain a certificate with certbot, or install your own.

---

## 10. First login & NAS onboarding

1. Browse to `https://ipdr.example.com`.
2. Log in with the initial admin credentials (see the app's first-run setup;
   change the password immediately).
3. Go to **Settings → NAS Devices → Add** and register your first NAS:
   - Name, source IP (the IP your NAS logs from), collection role
   - For RouterOS API polling: enable API access, set host/port/user. The app
     generates and Fernet-encrypts a strong API password, and produces the
     router-side config to create a read-only API user.
4. Use **API Test** to confirm connectivity. Once green, PPPoE sessions, DHCP
   leases, and `/ppp/secret` enrichment begin flowing.

---

## 11. Verify the pipeline

- **Dashboard** should show the Flow Log Feed incrementing and DHCP/Secrets
  feeds green.
- **Live Sessions** should list online PPPoE subscribers and DHCP leases.
- Run a **5-Tuple Lookup** with a known public IP:port:time and confirm it
  resolves to the expected subscriber.

---

## 12. Hardening (do before production)

- Restrict admin/LEA routes to a management network or VPN.
- Give the RouterOS API user **read-only** access scoped to this server's IP.
- Set `MT_RETENTION_DAYS` and enable auto-purge to hold only what you're
  legally required to retain — no more.
- Schedule encrypted database backups (the DB contains subscriber PII).
- Keep `.env` at `chmod 600`; rotate secrets if ever exposed.

---

## Troubleshooting

- **No translations appearing:** confirm UDP/514 reaches the box
  (`tcpdump`), rsyslog is writing the file, and `mikrotik-ingest.service` is
  active (`journalctl -u mikrotik-ingest -n 50`).
- **API test fails:** verify the RouterOS API service is enabled, the user is
  read-only, and the source IP is allowed on the router.
- **Slow dashboard/analytics:** ensure the `*-stats` cache timers are enabled;
  the pages read precomputed caches, not the raw partitions.
- **Lookup returns no match for a real event:** check that the event's
  timestamp falls within your retention window, and that timezone handling
  matches how your NAS emits log times.
