# Database Migration Plan: the_team.db — macOS → NVIDIA DGX Spark
**Authored by:** Query (Backend Specialist, Data)  
**Tasked by:** Bower (SVP Product)  
**Date:** 2026-04-04  
**Status:** Ready for execution

---

## Database Snapshot (as of plan date)

| Property | Value |
|---|---|
| File | `/Users/maxstewart/Desktop/The Team/the_team.db` |
| Main file size | 42 MB |
| WAL file size | 4.1 MB (`the_team.db-wal`) |
| SHM file size | 32 KB (`the_team.db-shm`) |
| Total on-disk | ~46 MB |
| Page size | 4096 bytes |
| Page count | 10,717 |
| Encoding | UTF-8 |
| Journal mode | **WAL (active)** |
| Foreign keys | OFF (application-enforced) |
| Auto vacuum | OFF |
| Synchronous | NORMAL (1) |
| Tables | 149 |
| Indexes | ~220 |
| Triggers | 0 |
| Views | 0 |
| SQLite version (Mac) | 3.51.0 |
| Node.js version (Mac) | v25.8.1 |
| better-sqlite3 version | ^11.7.0 |

**Key row counts:**

| Table | Rows |
|---|---|
| team_members | 173 |
| tasks | 1,502 |
| activity_log | 9,970 |
| notifications | 3,001 |
| task_assignments | 1,523 |
| governance_receipts | 1,981 |
| decisions | 3 |
| notes | 4 |
| projects | 5 |
| contacts | 0 |

---

## Architecture Notes

**Both platforms are ARM64.** macOS (Apple Silicon M-series, arm64) and DGX Spark (GB10 Grace Blackwell, aarch64 Linux / Ubuntu 24.04) share the same instruction set. This eliminates any byte-order or struct alignment differences. The SQLite binary file format is endian-independent and fully portable between them. No data transformation is required — this is a straight file copy.

**WAL mode is active.** The database has a live WAL file (`the_team.db-wal`, 4.1 MB) and SHM file (`the_team.db-shm`, 32 KB). These files are NOT portable between processes (the SHM file in particular is process-local memory-mapped state). The migration procedure must flush the WAL into the main DB file before transfer, producing a single clean `.db` file with no companion files. The WAL can then be re-enabled on DGX after arrival.

**better-sqlite3 v11.x native addon.** better-sqlite3 uses a compiled C++ Node.js native addon (`.node` binary). The Mac-compiled `.node` file targets macOS/arm64 and will not run on Linux/aarch64. The addon MUST be recompiled on DGX after the app code is transferred. `npm rebuild better-sqlite3` performs this in-place.

---

## Section 1 — Pre-Migration Checklist (on Mac)

### 1.1 Stop the Application

All database connections must be closed before backup. Open connections holding WAL frames will cause an incomplete checkpoint.

**For the Node.js app (split-server.js / the-team-dashboard):**

```bash
# Option A: If running via npm start
pkill -f "node.*split-server"

# Option B: If running as a process manager (pm2)
pm2 stop the-team-dashboard
pm2 status   # confirm status: stopped

# Option C: Find and kill by port (default 3001)
lsof -ti :3001 | xargs kill -9 2>/dev/null || true
lsof -ti :3002 | xargs kill -9 2>/dev/null || true

# Verify no process holds the DB open
lsof "/Users/maxstewart/Desktop/The Team/the_team.db" 2>/dev/null
# Should return empty output
```

**Stop the heartbeat service if running:**

```bash
# Check for heartbeat
ps aux | grep -i heartbeat | grep -v grep
# Kill if found
pkill -f heartbeat
```

### 1.2 WAL Checkpoint Flush

After stopping the app, force a full WAL checkpoint to merge all WAL frames back into the main database file:

```bash
sqlite3 "/Users/maxstewart/Desktop/The Team/the_team.db" "
PRAGMA wal_checkpoint(TRUNCATE);
"
```

Expected output:
```
0|0|0
```

Columns: `(busy, log, checkpointed)`. All three should be `0` after a clean truncate. If `busy` is non-zero, a connection is still open — revisit step 1.1.

**Verify WAL and SHM files are gone or empty:**

```bash
ls -lh "/Users/maxstewart/Desktop/The Team/the_team.db"*
# The -wal file should be 0 bytes or absent
# The -shm file should be 0 bytes or absent
```

### 1.3 Integrity Check

```bash
sqlite3 "/Users/maxstewart/Desktop/The Team/the_team.db" "PRAGMA integrity_check;"
```

Expected output: `ok`

Any other output is a corruption warning. Do NOT proceed with migration if integrity check fails — investigate and repair first.

Also run foreign key check (even though FKs are off, this surfaces orphaned rows):

```bash
sqlite3 "/Users/maxstewart/Desktop/The Team/the_team.db" "PRAGMA foreign_key_check;" 2>&1 | head -20
```

### 1.4 Record Baseline Row Counts

Run this query and save the output — you will compare against it on DGX:

```bash
sqlite3 "/Users/maxstewart/Desktop/The Team/the_team.db" "
SELECT 'team_members' as tbl, COUNT(*) as cnt FROM team_members
UNION ALL SELECT 'tasks', COUNT(*) FROM tasks
UNION ALL SELECT 'activity_log', COUNT(*) FROM activity_log
UNION ALL SELECT 'notifications', COUNT(*) FROM notifications
UNION ALL SELECT 'task_assignments', COUNT(*) FROM task_assignments
UNION ALL SELECT 'governance_receipts', COUNT(*) FROM governance_receipts
UNION ALL SELECT 'decisions', COUNT(*) FROM decisions
UNION ALL SELECT 'notes', COUNT(*) FROM notes
UNION ALL SELECT 'projects', COUNT(*) FROM projects
UNION ALL SELECT 'llm_usage', COUNT(*) FROM llm_usage
ORDER BY tbl;
" > ~/Desktop/db-baseline-counts.txt
cat ~/Desktop/db-baseline-counts.txt
```

### 1.5 Backup Procedure

```bash
# Set timestamp
TS=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$HOME/Desktop/the_team_db_backup_${TS}"
DB_SRC="/Users/maxstewart/Desktop/The Team/the_team.db"

mkdir -p "$BACKUP_DIR"

# Copy main DB file (WAL should now be empty/absent after checkpoint)
cp "$DB_SRC" "${BACKUP_DIR}/the_team.db"

# Generate SHA-256 checksum
shasum -a 256 "${BACKUP_DIR}/the_team.db" > "${BACKUP_DIR}/the_team.db.sha256"
cat "${BACKUP_DIR}/the_team.db.sha256"

# Verify the backup immediately
shasum -a 256 -c "${BACKUP_DIR}/the_team.db.sha256"
# Expected: the_team.db: OK

echo "Backup complete: ${BACKUP_DIR}"
ls -lh "${BACKUP_DIR}"
```

Keep this backup. Do NOT delete it until the DGX migration is confirmed successful and the app has been running stably for at least 48 hours.

---

## Section 2 — better-sqlite3 ARM64 Linux Compatibility

### 2.1 Compatibility Confirmation

**better-sqlite3 v11.x fully supports aarch64 Linux.** The library uses `node-gyp` to compile a native C++ addon at install time. It has no platform-specific code paths — it wraps the SQLite amalgamation source directly. The aarch64 Linux build is a first-class target tested in CI.

Key facts:
- better-sqlite3 v11.0.0+ requires Node.js v18.0.0 or later
- Node.js v18+ (LTS) ships pre-built binaries for `linux-arm64`
- Ubuntu 24.04 on DGX Spark ships with GCC 13+ which supports aarch64 natively
- SQLite's WAL mode works identically on Linux — same POSIX file locking semantics

**Required build tools on DGX (Ubuntu 24.04):**

```bash
sudo apt-get update
sudo apt-get install -y build-essential python3 git
# Verify
gcc --version
python3 --version
```

### 2.2 Node.js on DGX

Recommended: install Node.js v22 LTS (or match your Mac version) via nvm:

```bash
# Install nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source ~/.bashrc

# Install Node.js LTS
nvm install --lts
nvm use --lts
node --version   # should be v22.x.x or similar
npm --version
```

### 2.3 Rebuild Native Addon After Transfer

After transferring the app directory to DGX, the Mac-compiled `.node` binary in `node_modules/better-sqlite3/build/` must be replaced:

```bash
# In the app directory on DGX
cd /path/to/the-team-app

# Remove the Mac binary and recompile for Linux/aarch64
npm rebuild better-sqlite3

# Confirm the new binary exists and is ELF (Linux format, not Mach-O)
file node_modules/better-sqlite3/build/Release/better_sqlite3.node
# Expected: ELF 64-bit LSB shared object, ARM aarch64, ...
# NOT: Mach-O 64-bit dynamically linked shared library arm64
```

If `npm rebuild` fails due to missing `sqlite3.h`, install the SQLite dev package:

```bash
sudo apt-get install -y libsqlite3-dev
# Then retry:
npm rebuild better-sqlite3
```

### 2.4 Post-Install Test Query

Run this after rebuild to confirm better-sqlite3 opens the database correctly:

```bash
node -e "
const Database = require('better-sqlite3');
const db = new Database('/path/to/the_team.db', { readonly: true });

// Check journal mode
const mode = db.prepare('PRAGMA journal_mode').get();
console.log('Journal mode:', mode.journal_mode);

// Quick row count
const count = db.prepare('SELECT COUNT(*) as cnt FROM team_members').get();
console.log('team_members count:', count.cnt);

// Check integrity
const check = db.prepare('PRAGMA integrity_check').get();
console.log('Integrity:', check.integrity_check);

db.close();
console.log('SUCCESS: better-sqlite3 is working correctly on this platform.');
"
```

Expected output:
```
Journal mode: wal
team_members count: 173
Integrity: ok
SUCCESS: better-sqlite3 is working correctly on this platform.
```

---

## Section 3 — Migration Script (migrate-db.sh)

Save this file as `migrate-db.sh` on the Mac, make it executable, and run from the Mac terminal.

```bash
#!/usr/bin/env bash
# migrate-db.sh
# Usage: ./migrate-db.sh <dgx-user> <dgx-host> <dgx-dest-path>
# Example: ./migrate-db.sh max 192.168.1.100 /home/max/the-team

set -euo pipefail

DGX_USER="${1:-}"
DGX_HOST="${2:-}"
DGX_DEST="${3:-}"

if [[ -z "$DGX_USER" || -z "$DGX_HOST" || -z "$DGX_DEST" ]]; then
  echo "Usage: $0 <dgx-user> <dgx-host> <dgx-dest-path>"
  echo "Example: $0 max 192.168.1.100 /home/max/the-team"
  exit 1
fi

DB_PATH="/Users/maxstewart/Desktop/The Team/the_team.db"
TS=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$HOME/Desktop/the_team_db_backup_${TS}"

echo "============================================"
echo "  the_team.db Migration: Mac to DGX Spark"
echo "  Timestamp: ${TS}"
echo "============================================"
echo ""

# PHASE 1: Pre-flight on Mac

echo "[1/7] Checking for open database connections..."
OPEN_CONNS=$(lsof "$DB_PATH" 2>/dev/null | grep -v "^COMMAND" || true)
if [[ -n "$OPEN_CONNS" ]]; then
  echo "ERROR: Database is open by the following processes:"
  echo "$OPEN_CONNS"
  echo "Stop the application before running this script."
  exit 1
fi
echo "      No open connections -- safe to proceed."

# PHASE 2: WAL Checkpoint

echo ""
echo "[2/7] Flushing WAL (Write-Ahead Log) to main database file..."
CHECKPOINT_RESULT=$(sqlite3 "$DB_PATH" "PRAGMA wal_checkpoint(TRUNCATE);")
BUSY=$(echo "$CHECKPOINT_RESULT" | cut -d'|' -f1)
if [[ "$BUSY" != "0" ]]; then
  echo "ERROR: WAL checkpoint returned busy=${BUSY}. A connection may still be open."
  exit 1
fi
echo "      WAL checkpoint complete: ${CHECKPOINT_RESULT}"

WAL_FILE="${DB_PATH}-wal"
if [[ -f "$WAL_FILE" ]]; then
  WAL_SIZE=$(stat -f%z "$WAL_FILE" 2>/dev/null || stat -c%s "$WAL_FILE" 2>/dev/null)
  if [[ "$WAL_SIZE" -gt 0 ]]; then
    echo "WARNING: WAL file still has ${WAL_SIZE} bytes. Proceeding, but verify on DGX."
  else
    echo "      WAL file is empty -- clean checkpoint confirmed."
  fi
fi

# PHASE 3: Integrity Check

echo ""
echo "[3/7] Running integrity check..."
INTEGRITY=$(sqlite3 "$DB_PATH" "PRAGMA integrity_check;")
if [[ "$INTEGRITY" != "ok" ]]; then
  echo "ERROR: Integrity check failed:"
  echo "$INTEGRITY"
  echo "Do NOT migrate a corrupt database. Investigate first."
  exit 1
fi
echo "      Integrity: OK"

# PHASE 4: Backup with Checksum

echo ""
echo "[4/7] Creating timestamped backup..."
mkdir -p "$BACKUP_DIR"
cp "$DB_PATH" "${BACKUP_DIR}/the_team.db"
shasum -a 256 "${BACKUP_DIR}/the_team.db" > "${BACKUP_DIR}/the_team.db.sha256"
SOURCE_HASH=$(cat "${BACKUP_DIR}/the_team.db.sha256" | awk '{print $1}')
echo "      Backup saved to: ${BACKUP_DIR}"
echo "      SHA-256: ${SOURCE_HASH}"

# PHASE 5: Transfer via rsync

echo ""
echo "[5/7] Transferring database to DGX Spark (${DGX_USER}@${DGX_HOST}:${DGX_DEST})..."
rsync -avz --progress \
  --checksum \
  "${BACKUP_DIR}/the_team.db" \
  "${BACKUP_DIR}/the_team.db.sha256" \
  "${DGX_USER}@${DGX_HOST}:${DGX_DEST}/"

echo "      Transfer complete."

# PHASE 6: Remote Verification

echo ""
echo "[6/7] Verifying checksum and integrity on DGX..."
ssh "${DGX_USER}@${DGX_HOST}" bash << REMOTE_SCRIPT
set -euo pipefail
cd "${DGX_DEST}"

echo "  [DGX] Verifying SHA-256 checksum..."
sha256sum -c the_team.db.sha256
if [[ \$? -ne 0 ]]; then
  echo "  ERROR: Checksum mismatch on DGX. Transfer may be corrupted."
  exit 1
fi
echo "  [DGX] Checksum OK"

echo "  [DGX] Running SQLite integrity check..."
INTEGRITY=\$(sqlite3 the_team.db "PRAGMA integrity_check;" 2>&1)
if [[ "\$INTEGRITY" != "ok" ]]; then
  echo "  ERROR: Integrity check failed on DGX: \$INTEGRITY"
  exit 1
fi
echo "  [DGX] Integrity: OK"

echo "  [DGX] Checking journal mode..."
MODE=\$(sqlite3 the_team.db "PRAGMA journal_mode;")
echo "  [DGX] Journal mode: \$MODE"

echo "  [DGX] Row counts:"
sqlite3 the_team.db "
SELECT 'team_members', COUNT(*) FROM team_members
UNION ALL SELECT 'tasks', COUNT(*) FROM tasks
UNION ALL SELECT 'activity_log', COUNT(*) FROM activity_log
UNION ALL SELECT 'notifications', COUNT(*) FROM notifications
UNION ALL SELECT 'governance_receipts', COUNT(*) FROM governance_receipts;
"
REMOTE_SCRIPT

# PHASE 7: Summary

echo ""
echo "[7/7] Migration complete."
echo ""
echo "  Source hash  : ${SOURCE_HASH}"
echo "  Backup       : ${BACKUP_DIR}/the_team.db"
echo "  DGX location : ${DGX_USER}@${DGX_HOST}:${DGX_DEST}/the_team.db"
echo ""
echo "NEXT STEPS on DGX:"
echo "  1. Transfer the full app directory (rsync, exclude node_modules)"
echo "  2. Run: npm rebuild better-sqlite3"
echo "  3. Update DB path in app config to: ${DGX_DEST}/the_team.db"
echo "  4. Run the post-migration verification queries (Section 4 of plan)"
echo "  5. Start the application and smoke-test"
echo ""
echo "ROLLBACK: If anything fails on DGX, restore from:"
echo "  ${BACKUP_DIR}/the_team.db"
```

**Make executable and run:**

```bash
chmod +x migrate-db.sh
./migrate-db.sh max 192.168.1.100 /home/max/the-team
```

---

## Section 4 — Post-Migration Verification Queries (SQL)

Run all of these on DGX after the transfer. Compare counts against the Mac baseline.

### 4.1 Row Counts — Key Tables

```sql
SELECT 'team_members' as table_name, COUNT(*) as row_count FROM team_members
UNION ALL SELECT 'tasks',              COUNT(*) FROM tasks
UNION ALL SELECT 'activity_log',       COUNT(*) FROM activity_log
UNION ALL SELECT 'notifications',      COUNT(*) FROM notifications
UNION ALL SELECT 'task_assignments',   COUNT(*) FROM task_assignments
UNION ALL SELECT 'governance_receipts',COUNT(*) FROM governance_receipts
UNION ALL SELECT 'decisions',          COUNT(*) FROM decisions
UNION ALL SELECT 'notes',              COUNT(*) FROM notes
UNION ALL SELECT 'projects',           COUNT(*) FROM projects
UNION ALL SELECT 'llm_usage',          COUNT(*) FROM llm_usage
UNION ALL SELECT 'member_tools',       COUNT(*) FROM member_tools
UNION ALL SELECT 'linked_repos',       COUNT(*) FROM linked_repos
UNION ALL SELECT 'linked_paths',       COUNT(*) FROM linked_paths
ORDER BY table_name;
```

Expected counts (Mac baseline as of 2026-04-04):
- team_members: 173
- tasks: 1,502
- activity_log: 9,970
- notifications: 3,001
- task_assignments: 1,523
- governance_receipts: 1,981

### 4.2 Foreign Key Integrity Check

```sql
PRAGMA foreign_key_check;
```

Expected: no output (no orphaned rows). Any rows returned indicate referential integrity issues.

### 4.3 Schema Sanity — Table Count

```sql
SELECT COUNT(*) as table_count
FROM sqlite_master
WHERE type = 'table' AND name NOT LIKE 'sqlite_%';
```

Expected: **149** tables.

### 4.4 Index Count Verification

```sql
SELECT COUNT(*) as index_count
FROM sqlite_master
WHERE type = 'index' AND name NOT LIKE 'sqlite_%';
```

Expected: approximately **218** named indexes (plus auto-generated ones).

### 4.5 Verify Critical Indexes Exist

```sql
SELECT name FROM sqlite_master
WHERE type = 'index'
  AND name IN (
    'idx_activity_log_task_id',
    'idx_activity_log_created_at',
    'idx_action_items_task_id',
    'idx_active_processes_status',
    'idx_approvals_status'
  )
ORDER BY name;
```

If any expected index is missing, run `REINDEX;` to rebuild all indexes.

### 4.6 Verify Settings Are Intact

```sql
SELECT key, value FROM system_settings
ORDER BY key
LIMIT 20;
```

### 4.7 Verify team_members Roster

```sql
SELECT id, name, tier, status
FROM team_members
ORDER BY tier, name
LIMIT 20;
```

### 4.8 Most Recent Activity Log Entry

```sql
SELECT id, actor, action, created_at
FROM activity_log
ORDER BY created_at DESC
LIMIT 5;
```

This confirms the latest events transferred correctly.

### 4.9 WAL Mode Confirmation on DGX

```sql
PRAGMA journal_mode;
-- Expected: wal

PRAGMA wal_checkpoint;
-- Expected: 0|0|0

PRAGMA page_size;
-- Expected: 4096

PRAGMA encoding;
-- Expected: UTF-8
```

---

## Section 5 — WAL Mode on Linux

**WAL mode works identically on aarch64 Linux as on macOS.** No changes are needed.

Key facts:

1. **SQLite WAL uses POSIX file locks** (`fcntl()`) on Linux and macOS alike. The locking semantics are the same.

2. **WAL file format is not OS-specific.** The `.db-wal` format is part of the SQLite file spec, not tied to the OS. The same C code reads and writes it on both platforms.

3. **SHM file is NOT transferable.** The `.db-shm` file is a memory-mapped shared memory file used for inter-process coordination. It is process-local state and must never be transferred. After a clean `PRAGMA wal_checkpoint(TRUNCATE)`, both the `.wal` and `.shm` files will be zero-length or absent. On DGX, SQLite will create fresh `.wal` and `.shm` files the first time the database is opened in WAL mode.

4. **After migration, WAL mode will auto-activate.** The `journal_mode=WAL` setting is stored in the database header. When better-sqlite3 opens the file on DGX, it reads the header and enters WAL mode automatically — no `PRAGMA journal_mode=WAL` needs to be re-run.

5. **Concurrent readers on Linux.** WAL mode on Linux supports multiple simultaneous readers without blocking. This matches macOS behavior. No tuning required.

6. **Recommendation: leave WAL settings as-is.** The current `synchronous=NORMAL` with WAL is the standard high-performance configuration for this use case. Do not change it on DGX.

---

## Section 6 — App Config Update on DGX

After transferring the app code, update the database path in the app config to the DGX path. Check these files:

```bash
# Find where the DB path is configured
grep -r "the_team.db" /path/to/app --include="*.js" --include="*.json" --include="*.env" -l
```

Common locations:
- `split-server.js` — main server entry point
- `services/*.js` — service files
- `.env` or `.env.production` — environment config

Update the path from:
```
/Users/maxstewart/Desktop/The Team/the_team.db
```

To the DGX path (example):
```
/home/max/the-team/the_team.db
```

---

## Section 7 — Rollback Plan

If anything goes wrong on DGX, the Mac database is untouched. The rollback is:

**If migration is partially done (app not yet running on DGX):**
- Stop any process that may have opened the DGX copy
- Delete the DGX copy if corrupt: `rm /path/on/dgx/the_team.db`
- Diagnose the issue (checksum failure: re-transfer; integrity error: investigate Mac source)
- Re-run `migrate-db.sh` from scratch

**If the DGX app started and made writes (data divergence):**
- Stop the DGX app immediately
- Decide which copy is the authoritative source:
  - If Mac was running concurrently: neither is clean; manual merge required
  - If Mac was fully stopped before DGX started: DGX copy is authoritative, keep it
  - If DGX made only a few writes: optionally replay them from `activity_log` on DGX back to Mac
- The Mac backup at `~/Desktop/the_team_db_backup_TIMESTAMP/` is the last known-good snapshot

**To restore from backup to Mac:**
```bash
# Stop the app first
pkill -f split-server

# Restore
cp ~/Desktop/the_team_db_backup_TIMESTAMP/the_team.db \
   "/Users/maxstewart/Desktop/The Team/the_team.db"

# Verify
shasum -a 256 -c ~/Desktop/the_team_db_backup_TIMESTAMP/the_team.db.sha256

# Restart
npm start --prefix "/Users/maxstewart/Desktop/The Team/app"
```

---

## Migration Day Checklist

This is the step-by-step sequence for Max to follow on migration day.

### On Mac (before touching DGX)

- [ ] Confirm DGX is reachable: `ssh max@<dgx-ip> "echo connected"`
- [ ] Stop the app: `pkill -f split-server` (or `pm2 stop the-team-dashboard`)
- [ ] Verify no open DB connections: `lsof "/Users/maxstewart/Desktop/The Team/the_team.db"` must return empty
- [ ] Flush WAL: `sqlite3 "..." "PRAGMA wal_checkpoint(TRUNCATE);"` must return `0|0|0`
- [ ] Run integrity check: `sqlite3 "..." "PRAGMA integrity_check;"` must return `ok`
- [ ] Save baseline row counts to `~/Desktop/db-baseline-counts.txt`
- [ ] Create timestamped backup with SHA-256 checksum (Section 1.5)
- [ ] Verify WAL file is empty (zero bytes or absent)
- [ ] Run `migrate-db.sh` and watch for any errors

### On DGX (after migrate-db.sh succeeds)

- [ ] Confirm file received: `ls -lh /path/on/dgx/the_team.db` should be ~42 MB
- [ ] Verify checksum: `sha256sum -c the_team.db.sha256` must say `OK`
- [ ] Run integrity check: `sqlite3 the_team.db "PRAGMA integrity_check;"` must return `ok`
- [ ] Install Node.js (v22 LTS recommended via nvm)
- [ ] Install build tools: `sudo apt-get install -y build-essential python3`
- [ ] Transfer app code: `rsync -avz --exclude node_modules mac-host:/path/to/app/ /dgx/app/`
- [ ] Install dependencies: `npm install` (in app directory)
- [ ] Rebuild native addon: `npm rebuild better-sqlite3`
- [ ] Verify addon is Linux binary: `file node_modules/better-sqlite3/build/Release/better_sqlite3.node` must say `ELF 64-bit LSB shared object, ARM aarch64`
- [ ] Update DB path in app config (Section 6)
- [ ] Run post-migration verification queries (Section 4) and compare counts to baseline
- [ ] Run Node.js smoke test (Section 2.4)
- [ ] Start the app: `npm start` or `pm2 start`
- [ ] Access the dashboard in browser and confirm it loads
- [ ] Check activity_log for new entries being written (confirms read+write work)
- [ ] Monitor for 10 minutes: watch for WAL errors or lock errors in logs

### After Stable Operation (48 hours later)

- [ ] Confirm no data corruption: re-run Section 4 queries
- [ ] Confirm WAL behavior is healthy: `PRAGMA wal_checkpoint;` — `log` column should not be growing unboundedly
- [ ] Archive Mac backup to external storage or S3
- [ ] Decommission Mac DB (or keep as cold standby) and update `linked_paths` in team DB to reflect new DGX path

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| WAL not fully flushed — stale frames in transfer | Low (script enforces checkpoint) | High (data loss) | Script validates `busy=0` and WAL file size |
| Checksum mismatch after rsync | Very Low | High | `rsync --checksum` + remote `sha256sum -c` |
| better-sqlite3 rebuild fails (missing build tools) | Medium | Medium | `apt-get install build-essential python3` pre-step |
| App hardcodes Mac DB path | Medium | Low (startup failure only) | Section 6 grep + replace |
| Concurrent writes (Mac + DGX both running) | Low (if procedure followed) | High (data divergence) | Stop Mac app BEFORE starting DGX app |
| Node.js version mismatch causing ABI issues | Low | Medium | Use nvm, install same major version as Mac (v25) |
| DGX filesystem does not support WAL file locking | Very Low | High | Ubuntu 24.04 ext4/xfs both support POSIX fcntl locks |
