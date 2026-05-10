<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# Production Deployment Guide

## VPS Requirements

- **OS:** Ubuntu 22.04 LTS or later
- **RAM:** 4GB minimum (8GB recommended)
- **CPU:** 2 vCPU minimum
- **Disk:** 40GB SSD

## Prerequisites

Install the required tooling on the server:

```bash
# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Docker Compose (v2, included with Docker Engine 24+)
docker compose version

# Nginx
sudo apt install -y nginx

# Certbot for SSL
sudo apt install -y certbot python3-certbot-nginx
```

## Build and Deploy

```bash
git clone https://github.com/exochain/exochain.git
cd exochain

# Build the WASM engine
npm run build:wasm

# Start all services in detached mode
docker compose up -d
```

Verify all containers are running:

```bash
docker compose ps
```

## Environment Variables

Create a `.env` file in the project root for production overrides:

```env
NODE_ENV=production
DATABASE_URL=postgres://exochain:<strong-password>@db:5432/exochain
```

Do not commit this file to version control.

## Nginx Reverse Proxy

Create `/etc/nginx/sites-available/exochain`:

```nginx
server {
    listen 80;
    server_name exochain.example.com;

    # Web UI (static assets served by Vite preview or built output)
    location / {
        proxy_pass http://127.0.0.1:5173;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # API gateway
    location /api/ {
        proxy_pass http://127.0.0.1:3000/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/exochain /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## SSL with Let's Encrypt

```bash
sudo certbot --nginx -d exochain.example.com
```

Certbot automatically configures Nginx for HTTPS and sets up certificate auto-renewal via a systemd timer.

Verify renewal works:

```bash
sudo certbot renew --dry-run
```

## systemd Service Unit

Create `/etc/systemd/system/exochain.service` for automatic restart on boot or failure:

```ini
[Unit]
Description=ExoChain Platform
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/exochain
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
Restart=on-failure
RestartSec=10s
User=deploy

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable exochain
sudo systemctl start exochain
```

## PostgreSQL Backup Strategy

Set up automated daily backups with `pg_dump` via cron.

Create `/opt/exochain/scripts/backup-db.sh`:

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/opt/exochain/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CONTAINER=$(docker compose ps -q db)

mkdir -p "$BACKUP_DIR"

docker exec "$CONTAINER" pg_dump -U exochain exochain | gzip > "$BACKUP_DIR/exochain_${TIMESTAMP}.sql.gz"

# Retain last 30 days of backups
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete
```

Add to crontab (`crontab -e`):

```cron
0 2 * * * /opt/exochain/scripts/backup-db.sh >> /var/log/exochain-backup.log 2>&1
```

## Health Checks

Each service exposes a `/health` endpoint. Verify all services are healthy:

```bash
for port in 3000 3001 3002 3003 3004 3006 3007; do
    echo "Port $port: $(curl -sf http://localhost:$port/health || echo 'UNREACHABLE')"
done
```

## Monitoring

### Container Logs

```bash
# All services
docker compose logs -f

# Single service
docker compose logs -f gateway-api
```

### PostgreSQL Activity

Connect to the database container and inspect active connections:

```bash
docker compose exec db psql -U exochain -c "SELECT pid, state, query, query_start FROM pg_stat_activity WHERE datname = 'exochain';"
```

### Resource Usage

```bash
docker stats --no-stream
```

## Scaling

Scale individual services horizontally with Docker Compose:

```bash
# Run 3 instances of the governance engine
docker compose up -d --scale governance-engine=3
```

When scaling services behind the gateway, the gateway-api load balances across instances using Docker Compose DNS round-robin. Ensure the gateway is configured to resolve service hostnames dynamically rather than caching a single IP.

For production-grade load balancing, place an Nginx upstream block or a dedicated load balancer in front of scaled services.
