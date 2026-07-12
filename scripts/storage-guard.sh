#!/bin/bash
# ============================================================================
# storage-guard.sh — Self-healing storage management
# Runs periodically (cron). If log/DB storage crosses the critical threshold,
# purges the oldest nat_flow_logs in batches until back under threshold.
# Reads config from system_config table.
# ============================================================================

APP_DIR="/opt/ipdr"
LOG="/var/log/ipdr/storage-guard.log"
DB_PASS=$(grep '^DATABASE_URL' ${APP_DIR}/.env | sed 's/.*password=//')
PSQL="psql -h 127.0.0.1 -U ipdr_user -d ipdr -tAc"

q() { PGPASSWORD="$DB_PASS" $PSQL "$1" 2>/dev/null; }

# Read config
ENABLED=$(q "SELECT value FROM system_config WHERE key='autopurge_enabled';")
CRIT=$(q "SELECT value FROM system_config WHERE key='storage_critical_pct';")
LOG_PATH=$(q "SELECT value FROM system_config WHERE key='log_storage_path';")
DB_PATH=$(q "SELECT value FROM system_config WHERE key='db_storage_path';")

[ "$ENABLED" != "true" ] && exit 0
[ -z "$CRIT" ] && CRIT=90
[ -z "$LOG_PATH" ] && LOG_PATH="/var/log/nat"
[ -z "$DB_PATH" ] && DB_PATH="/var/lib/postgresql"

# Get highest usage% across the monitored filesystems
usage_pct() {
    df --output=pcent "$1" 2>/dev/null | tail -1 | tr -d ' %'
}
LOG_PCT=$(usage_pct "$LOG_PATH"); [ -z "$LOG_PCT" ] && LOG_PCT=0
DB_PCT=$(usage_pct "$DB_PATH"); [ -z "$DB_PCT" ] && DB_PCT=0
MAX_PCT=$LOG_PCT; [ "$DB_PCT" -gt "$MAX_PCT" ] && MAX_PCT=$DB_PCT

if [ "$MAX_PCT" -lt "$CRIT" ]; then
    exit 0   # under threshold, nothing to do
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') CRITICAL: storage at ${MAX_PCT}% (>= ${CRIT}%). Starting purge." >> "$LOG"

# Purge oldest flow logs in daily batches until under threshold (max 30 iterations)
for i in $(seq 1 30); do
    # Delete the oldest day of flow logs
    DELETED=$(q "WITH d AS (DELETE FROM nat_flow_logs WHERE log_time < (SELECT MIN(log_time)+INTERVAL '1 day' FROM nat_flow_logs) RETURNING 1) SELECT COUNT(*) FROM d;")
    echo "$(date '+%Y-%m-%d %H:%M:%S') Purged batch $i: ${DELETED} rows" >> "$LOG"

    # Re-check
    LOG_PCT=$(usage_pct "$LOG_PATH"); [ -z "$LOG_PCT" ] && LOG_PCT=0
    DB_PCT=$(usage_pct "$DB_PATH"); [ -z "$DB_PCT" ] && DB_PCT=0
    MAX_PCT=$LOG_PCT; [ "$DB_PCT" -gt "$MAX_PCT" ] && MAX_PCT=$DB_PCT

    if [ "$MAX_PCT" -lt "$CRIT" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') Storage back to ${MAX_PCT}%. Purge complete." >> "$LOG"
        break
    fi
    [ "$DELETED" = "0" ] && { echo "$(date '+%Y-%m-%d %H:%M:%S') No more rows to purge." >> "$LOG"; break; }
done
