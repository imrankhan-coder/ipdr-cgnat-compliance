# Security

## Reporting
If you find a vulnerability, please open a private security advisory rather than
a public issue.

## Handling secrets
- All credentials live in `.env` (gitignored) — DB URL, Flask secret, Fernet
  key, LEA API token.
- Run `./scan_secrets.sh` before every commit; CI should block on it.
- Rotate any secret that is ever committed, even briefly.

## Deployment hardening
- Terminate TLS at nginx; do not expose gunicorn directly.
- Restrict the LEA API and admin routes to trusted networks / VPN.
- Give the RouterOS API user **read-only** access, scoped to the collector IP.
- Set `MT_RETENTION_DAYS` to your legal obligation and enable auto-purge.
- Back up the database encrypted; it contains subscriber PII.
