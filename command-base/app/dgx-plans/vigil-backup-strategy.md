# DGX Spark — Backup & Disaster Recovery Plan
**Specialist:** Vigil (SRE)  
**Priority:** HIGH — Configure on Day 1  
**Target:** NVIDIA DGX Spark, Ubuntu 24.04

---

## What to Back Up (Priority Order)

| Priority | Item | Location on DGX | Size estimate |
|----------|------|-----------------|---------------|
| 1 | `the_team.db` | `/opt/command-base/data/db/the_team.db` | ~50MB–500MB |
| 2 | `uploads/` directory | `/opt/command-base/data/uploads/` | Varies |
| 3 | `.env` / environment config | `/opt/command-base/app/.env` | <1KB |
| 4 | `docker-compose.yml` | `/opt/command-base/app/docker-compose.yml` | <1KB |
| 5 | Claude config | `/opt/command-base/data/claude-config/` | <1MB |

---

## File 1: `backup-dgx.sh` (full script)

```bash
#!/bin/bash
set -euo pipefail

# ── Configuration ──────────────────────────────────────────────
DB_PATH="/opt/command-base/data/db/the_team.db"
UPLOADS_PATH="/opt/command-base/data/uploads"
LOCAL_BACKUP_DIR="/opt/command-base/backups"
MAC_USER="maxstewart"
MAC_HOST="maxs-mac.local"          # Update with actual hostname or Tailscale IP
MAC_BACKUP_DIR="/Users/maxstewart/backups/dgx"
LOG_FILE="/var/log/command-base-backup.log"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ── Logging ────────────────────────────────────────────────────
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

# ── Create backup directory ────────────────────────────────────
mkdir -p "$LOCAL_BACKUP_DIR/daily"
mkdir -p "$LOCAL_BACKUP_DIR/weekly"

# ── 1. SQLite online backup (safe for live DB) ─────────────────
log "Starting SQLite backup..."
BACKUP_FILE="$LOCAL_BACKUP_DIR/daily/the_team_${TIMESTAMP}.db"

sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"

if [ ! -f "$BACKUP_FILE" ]; then
  log "ERROR: Backup file not created"
  exit 1
fi

# ── 2. Integrity check on the backup ──────────────────────────
INTEGRITY=$(sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" 2>&1)
if [ "$INTEGRITY" != "ok" ]; then
  log "ERROR: Backup integrity check failed: $INTEGRITY"
  # Write notification to DB
  sqlite3 "$DB_PATH" "INSERT INTO notifications (type, title, message, read, created_at) VALUES ('system', 'Backup integrity FAILED', 'SQLite backup ${TIMESTAMP} failed integrity check: ${INTEGRITY}', 0, datetime('now'));" || true
  exit 1
fi
log "Integrity check passed"

# ── 3. Compress ────────────────────────────────────────────────
gzip -9 "$BACKUP_FILE"
COMPRESSED="${BACKUP_FILE}.gz"
log "Compressed: $(du -sh "$COMPRESSED" | cut -f1)"

# ── 4. Checksum ────────────────────────────────────────────────
sha256sum "$COMPRESSED" > "${COMPRESSED}.sha256"
log "SHA256: $(cat "${COMPRESSED}.sha256" | cut -d' ' -f1)"

# ── 5. Rsync to Mac ────────────────────────────────────────────
if ssh -o ConnectTimeout=5 -o BatchMode=yes "${MAC_USER}@${MAC_HOST}" true 2>/dev/null; then
  rsync -avz --progress \
    "$COMPRESSED" \
    "${COMPRESSED}.sha256" \
    "${MAC_USER}@${MAC_HOST}:${MAC_BACKUP_DIR}/daily/" \
    >> "$LOG_FILE" 2>&1
  log "Synced to Mac successfully"
else
  log "WARNING: Mac unreachable — backup stored locally only at $COMPRESSED"
fi

# ── 6. Rotation: keep 7 daily backups locally ─────────────────
find "$LOCAL_BACKUP_DIR/daily" -name "*.db.gz" -mtime +7 -delete
find "$LOCAL_BACKUP_DIR/daily" -name "*.sha256" -mtime +7 -delete
log "Daily rotation complete (keeping 7 days)"

log "Backup complete: $COMPRESSED"
```

---

## File 2: `backup-weekly.sh` (full backup including uploads)

```bash
#!/bin/bash
set -euo pipefail

DB_PATH="/opt/command-base/data/db/the_team.db"
UPLOADS_PATH="/opt/command-base/data/uploads"
LOCAL_BACKUP_DIR="/opt/command-base/backups/weekly"
MAC_USER="maxstewart"
MAC_HOST="maxs-mac.local"
MAC_BACKUP_DIR="/Users/maxstewart/backups/dgx"
LOG_FILE="/var/log/command-base-backup.log"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$LOCAL_BACKUP_DIR"

# DB backup
DB_BACKUP="/tmp/the_team_weekly_${TIMESTAMP}.db"
sqlite3 "$DB_PATH" ".backup '$DB_BACKUP'"
gzip -9 "$DB_BACKUP"

# Uploads tarball
UPLOADS_BACKUP="$LOCAL_BACKUP_DIR/uploads_${TIMESTAMP}.tar.gz"
tar -czf "$UPLOADS_BACKUP" -C "$(dirname "$UPLOADS_PATH")" "$(basename "$UPLOADS_PATH")"

# Move DB backup
mv "${DB_BACKUP}.gz" "$LOCAL_BACKUP_DIR/"
sha256sum "$LOCAL_BACKUP_DIR/the_team_weekly_${TIMESTAMP}.db.gz" > "$LOCAL_BACKUP_DIR/the_team_weekly_${TIMESTAMP}.db.gz.sha256"

# Rsync full weekly to Mac
if ssh -o ConnectTimeout=5 -o BatchMode=yes "${MAC_USER}@${MAC_HOST}" true 2>/dev/null; then
  rsync -avz "$LOCAL_BACKUP_DIR/" "${MAC_USER}@${MAC_HOST}:${MAC_BACKUP_DIR}/weekly/"
  echo "[$(date)] Weekly backup synced to Mac" >> /var/log/command-base-backup.log
fi

# Keep 4 weekly backups locally
find "$LOCAL_BACKUP_DIR" -name "*.gz" -mtime +28 -delete
```

---

## File 3: `verify-integrity.sh` (daily integrity check)

```bash
#!/bin/bash

DB_PATH="/opt/command-base/data/db/the_team.db"
LOG_FILE="/var/log/command-base-backup.log"

RESULT=$(sqlite3 "$DB_PATH" "PRAGMA integrity_check;" 2>&1)

if [ "$RESULT" != "ok" ]; then
  echo "[$(date)] ERROR: DB integrity check FAILED: $RESULT" >> "$LOG_FILE"
  # Write alert to notifications table
  sqlite3 "$DB_PATH" "INSERT INTO notifications (type, title, message, read, created_at) \
    VALUES ('system', 'DB Integrity Alert', 'PRAGMA integrity_check failed: ${RESULT}', 0, datetime('now'));" 2>/dev/null || true
  exit 1
fi

echo "[$(date)] DB integrity check: OK" >> "$LOG_FILE"
```

---

## Cron Schedule

Add to root crontab on DGX (`sudo crontab -e`):

```cron
# Command Base — Automated Backups
# DB backup every 6 hours
0 */6 * * * /opt/command-base/scripts/backup-dgx.sh >> /var/log/command-base-backup.log 2>&1

# Weekly full backup (Sunday at 2am)
0 2 * * 0 /opt/command-base/scripts/backup-weekly.sh >> /var/log/command-base-backup.log 2>&1

# Daily integrity check (3am)
0 3 * * * /opt/command-base/scripts/verify-integrity.sh

# Daily rsync of latest backup to Mac (4am)
0 4 * * * rsync -avz /opt/command-base/backups/daily/ maxstewart@maxs-mac.local:/Users/maxstewart/backups/dgx/daily/ >> /var/log/command-base-backup.log 2>&1
```

---

## Backup Rotation Policy

| Backup Type | Retention (Local DGX) | Retention (Mac) |
|-------------|----------------------|-----------------|
| Daily DB | 7 days | 14 days |
| Weekly full | 4 weeks | 8 weeks |

---

## Disaster Recovery Plan

### Scenario: DGX Spark hardware failure

**RTO (Recovery Time Objective): < 30 minutes**  
**RPO (Recovery Point Objective): < 6 hours**

#### Step 1 — Assess (2 min)
```bash
# On Mac:
ping dgx-spark.local  # Or Tailscale IP
ssh user@dgx-spark    # Confirm unreachable
```

#### Step 2 — Restore database on Mac (5 min)
```bash
# Find latest backup
ls -lt ~/backups/dgx/daily/*.db.gz | head -3

# Verify checksum
sha256sum -c latest_backup.db.gz.sha256

# Decompress
gunzip -k the_team_YYYYMMDD_HHMMSS.db.gz

# Copy to Mac app location
cp the_team_YYYYMMDD_HHMMSS.db "/Users/maxstewart/Desktop/The Team/the_team.db"
```

#### Step 3 — Start app on Mac (5 min)
```bash
cd "/Users/maxstewart/Desktop/The Team/app"
node server.js
# App starts on port 3000 with restored DB
```

#### Step 4 — Update DNS/access (if applicable) (5 min)
- Update Tailscale or local DNS to point to Mac's IP
- Notify team of temporary fallback

#### Step 5 — Verify (3 min)
```bash
curl http://localhost:3000/health
# Check task counts match expected state
```

---

## External Backup (Future Phase)

Use `rclone` to Backblaze B2:

```bash
# Install rclone
curl https://rclone.org/install.sh | sudo bash

# Configure B2
rclone config  # Follow prompts for Backblaze B2

# Add to weekly cron
rclone sync /opt/command-base/backups b2:command-base-backup --transfers 4
```

**Cost:** ~$0.006/GB/month for B2 storage. At 500MB compressed weekly backups, ~$0.003/month.

---

## Day 1 Setup Checklist

- [ ] Create scripts directory: `sudo mkdir -p /opt/command-base/scripts`
- [ ] Copy `backup-dgx.sh`, `backup-weekly.sh`, `verify-integrity.sh` to `/opt/command-base/scripts/`
- [ ] Make executable: `sudo chmod +x /opt/command-base/scripts/*.sh`
- [ ] Create log file: `sudo touch /var/log/command-base-backup.log && sudo chmod 666 /var/log/command-base-backup.log`
- [ ] Create Mac backup destination: `mkdir -p ~/backups/dgx/{daily,weekly}`
- [ ] Set up SSH key auth from DGX to Mac (no password prompt for rsync):
  ```bash
  # On DGX:
  ssh-keygen -t ed25519 -C "dgx-spark-backup"
  ssh-copy-id maxstewart@maxs-mac.local
  ```
- [ ] Test SSH: `ssh -o BatchMode=yes maxstewart@maxs-mac.local echo "OK"`
- [ ] Install cron jobs: `sudo crontab -e` (paste entries from above)
- [ ] Run first backup manually: `sudo /opt/command-base/scripts/backup-dgx.sh`
- [ ] Verify backup file: `ls -lh /opt/command-base/backups/daily/`
- [ ] Verify rsync to Mac: `ls -lh ~/backups/dgx/daily/`
- [ ] Test integrity check: `sudo /opt/command-base/scripts/verify-integrity.sh && echo "PASS"`
