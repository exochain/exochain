# DGX Spark — Docker Production Configuration Plan
**Specialist:** Harbor (DevOps)  
**Priority:** HIGH — Complete before hardware arrives  
**Target:** NVIDIA DGX Spark, Ubuntu 24.04, ARM64/aarch64

---

## Key Findings from Source Audit

- `DB_PATH` defaults to `../the_team.db` (one level above `app/`) — env var override to `/data/the_team.db` is **critical**
- `/health` endpoint is fully implemented — returns HTTP 200 with DB latency, uptime, task pipeline counts
- `better-sqlite3` is a native addon — **`node:20-slim` (Debian/glibc) is mandatory** for ARM64; Alpine would fail
- App spawns `claude` subprocesses — **`tini` as PID 1** is required to reap zombie children and handle SIGTERM correctly

---

## File 1: `docker-compose.yml`

Place in `/opt/command-base/app/docker-compose.yml` on DGX

```yaml
version: "3.9"

services:
  command-base:
    build:
      context: .
      dockerfile: Dockerfile.prod
    image: command-base:latest
    container_name: command-base
    restart: unless-stopped
    ports:
      - "0.0.0.0:3000:3000"
    environment:
      NODE_ENV: production
      DB_PATH: /data/the_team.db
      BACKUP_DIR: /data/backups
      INBOX_PATH: /data/inbox
      OUTBOX_PATH: /data/outbox
      PORT: "3000"
    volumes:
      # Database (persistent SQLite)
      - db-data:/data
      # File uploads
      - uploads-data:/app/uploads
      # Claude CLI auth config (mounted from host)
      - claude-config:/root/.claude
      # Claude CLI binary from host (read-only)
      - /usr/local/bin/claude:/usr/local/bin/claude:ro
      - /root/.claude.json:/host-home/.claude.json:ro
    networks:
      - command-base-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s
    deploy:
      resources:
        limits:
          memory: 4g
        reservations:
          memory: 512m
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

volumes:
  db-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/command-base/data/db
  uploads-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/command-base/data/uploads
  claude-config:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/command-base/data/claude-config

networks:
  command-base-net:
    driver: bridge
```

---

## File 2: `Dockerfile.prod`

Multi-stage build for ARM64 (aarch64). Place alongside existing `Dockerfile`.

```dockerfile
# Stage 1: Builder
FROM node:20-slim AS builder

# Native addon build deps (required for better-sqlite3 on ARM64)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Stage 2: Runtime
FROM node:20-slim AS runtime

# Runtime deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled node_modules from builder (includes native .node binaries)
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app .

# Create data directory
RUN mkdir -p /data/backups

# Bootstrap entrypoint: copies claude config from host volume
RUN printf '#!/bin/sh\n\
if [ ! -f /root/.claude.json ] && [ -f /host-home/.claude.json ]; then\n\
  cp /host-home/.claude.json /root/.claude.json\n\
  echo "[Startup] Copied claude config from host"\n\
fi\n\
if [ ! -f /root/.claude.json ] && [ -d /root/.claude/backups ]; then\n\
  LATEST=$(ls -t /root/.claude/backups/.claude.json.backup.* 2>/dev/null | head -1)\n\
  if [ -n "$LATEST" ]; then\n\
    cp "$LATEST" /root/.claude.json\n\
    echo "[Startup] Restored claude config from backup: $LATEST"\n\
  fi\n\
fi\n\
exec node server.js\n' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

EXPOSE 3000

# tini as PID 1: reaps zombie claude subprocesses, handles SIGTERM correctly
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/entrypoint.sh"]
```

---

## File 3: `.dockerignore` (updated)

```
node_modules
npm-debug.log
*.db
*.db-shm
*.db-wal
backups/
test-output.log
audit-report.json
dashboard-audit.png
split-server.js
refactor-server.js
server.js.backup
server.js.pre-refactor-backup
server.js.ideas
.git
.claude
.env.local
Dockerfile*
docker-compose*.yml
dgx-plans/
```

---

## File 4: `deploy.sh` (first-boot deployment script)

Run once on DGX after files are transferred.

```bash
#!/bin/bash
set -euo pipefail

APP_DIR="/opt/command-base/app"
DATA_ROOT="/opt/command-base/data"
DB_SOURCE="$DATA_ROOT/db/the_team.db"

echo "╔══════════════════════════════════════════════════╗"
echo "║     Command Base — DGX Spark First-Boot Setup     ║"
echo "╚══════════════════════════════════════════════════╝"

# 1. Check Docker is running
if ! docker info &>/dev/null; then
  echo "ERROR: Docker is not running. Start Docker first."
  exit 1
fi
echo "✓ Docker is running"

# 2. Detect docker compose command
if docker compose version &>/dev/null 2>&1; then
  COMPOSE="docker compose"
else
  COMPOSE="docker-compose"
fi
echo "✓ Using: $COMPOSE"

# 3. Create persistent volume directories
echo "Creating data directories..."
sudo mkdir -p "$DATA_ROOT/db/backups"
sudo mkdir -p "$DATA_ROOT/uploads"
sudo mkdir -p "$DATA_ROOT/claude-config"
echo "✓ Directories created at $DATA_ROOT"

# 4. Verify database was migrated
if [ ! -f "$DB_SOURCE" ]; then
  echo "ERROR: Database not found at $DB_SOURCE"
  echo "  Run the database migration first (see query-database-migration.md)"
  exit 1
fi
echo "✓ Database present: $(du -sh "$DB_SOURCE" | cut -f1)"

# 5. Build the Docker image
echo ""
echo "Building Docker image (ARM64 native compile — takes a few minutes)..."
cd "$APP_DIR"
$COMPOSE -f docker-compose.yml build --no-cache
echo "✓ Image built"

# 6. Start the service
echo "Starting Command Base..."
$COMPOSE -f docker-compose.yml up -d
echo "✓ Container started"

# 7. Wait for health check
echo ""
echo "Waiting for health check..."
ATTEMPTS=0
MAX_ATTEMPTS=30
until curl -sf http://localhost:3000/health > /dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
    echo "ERROR: Health check failed after ${MAX_ATTEMPTS} attempts"
    echo "Logs: $COMPOSE logs command-base"
    exit 1
  fi
  printf "."
  sleep 2
done

echo ""
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║         Command Base is UP and HEALTHY!           ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "  Local:    http://localhost:3000"
echo "  Network:  http://$(hostname -I | awk '{print $1}'):3000"
echo ""
echo "Next steps:"
echo "  1. Verify: curl http://localhost:3000/health | python3 -m json.tool"
echo "  2. Nginx proxy: see alloy-nginx-proxy.md"
echo "  3. Tailscale:   see beacon-monitoring.md"
echo "  4. Backups:     see vigil-backup-strategy.md"
```

---

## Dependency Map

```
harbor-docker-production.md (THIS PLAN)
    │
    ├── BLOCKING: query-database-migration.md
    │   └── DB must be at /opt/command-base/data/db/the_team.db BEFORE deploy.sh
    │
    ├── BLOCKING: Dockerfile.prod (node:20-slim, not alpine)
    │   └── better-sqlite3 native compile requires glibc on ARM64
    │
    ├── SOFT DEP: alloy-nginx-proxy.md
    │   └── Nginx proxies port 3000 — configure after container is running
    │
    ├── SOFT DEP: beacon-monitoring.md
    │   └── /api/system/stats endpoint runs inside this container
    │
    ├── SOFT DEP: vigil-backup-strategy.md
    │   └── Backup cron targets /opt/command-base/data/db/the_team.db
    │
    └── SOFT DEP: scaffold-spawn-adaptation.md
        └── Claude CLI bind-mounted at /usr/local/bin/claude inside container
```

---

## Day 1 Execution Checklist

- [ ] Transfer app files to DGX: `rsync -avz --exclude node_modules --exclude .git ./app/ user@dgx-spark:/opt/command-base/app/`
- [ ] Run database migration (Query's plan) — DB lands at `/opt/command-base/data/db/the_team.db`
- [ ] Copy `Dockerfile.prod` and updated `docker-compose.yml` to DGX
- [ ] Copy updated `.dockerignore`
- [ ] SSH into DGX, `cd /opt/command-base/app && chmod +x deploy.sh && ./deploy.sh`
- [ ] Verify: `curl http://localhost:3000/health`
- [ ] Set up nginx reverse proxy (Alloy's plan)
- [ ] Configure Tailscale remote access (Beacon's plan)
- [ ] Verify claude CLI auth: `docker exec command-base claude --version`
- [ ] Run first manual backup (Vigil's plan)
