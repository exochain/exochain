# nginx Reverse Proxy — DGX Spark Deployment Plan

**Author:** Alloy (Backend Specialist)
**Date:** 2026-04-04
**Target:** Ubuntu 24.04 on NVIDIA DGX Spark (local 10 GbE + optional remote access)
**App:** Command Base — Node.js/Express on port 3000 inside Docker, WebSocket path `/ws`

---

## Overview

nginx sits in front of the Docker container and handles:
- TLS termination (HTTPS + wss://)
- HTTP → HTTPS redirect
- WebSocket upgrade proxying to `/ws`
- Rate limiting (API: 100 req/min, auth: 10 req/min)
- Gzip compression
- CORS headers for production
- File upload support up to 50 MB
- Firewall (ufw) blocking direct access to port 3000

Two certificate paths are provided — choose one:
- **Path A — Self-signed** (no domain, LAN-only or dev/staging)
- **Path B — Let's Encrypt** (you have a domain pointing at this machine)

---

## 1. nginx Installation on Ubuntu 24.04

```bash
# Update package index
sudo apt update

# Install nginx
sudo apt install -y nginx

# Verify installation
nginx -v
# Expected: nginx version: nginx/1.24.x or newer

# Enable and start the service
sudo systemctl enable nginx
sudo systemctl start nginx

# Confirm it's running
sudo systemctl status nginx
```

---

## 2. Complete nginx.conf for Command Base

Replace the entire contents of `/etc/nginx/nginx.conf`.

> **Edit in place:** `sudo nano /etc/nginx/nginx.conf`
> Or write it with: `sudo tee /etc/nginx/nginx.conf << 'NGINXEOF'` ... `NGINXEOF`

```nginx
# /etc/nginx/nginx.conf
# Command Base — DGX Spark deployment
# Generated 2026-04-04 by Alloy

user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept on;
}

http {

    ##
    # Basic Settings
    ##

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;
    server_tokens       off;   # Don't expose nginx version

    client_max_body_size 50m;  # Allow uploads up to 50 MB

    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    ##
    # Logging
    ##

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log  /var/log/nginx/error.log warn;

    ##
    # Gzip Compression
    ##

    gzip              on;
    gzip_vary         on;
    gzip_proxied      any;
    gzip_comp_level   6;
    gzip_buffers      16 8k;
    gzip_http_version 1.1;
    gzip_min_length   256;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml
        application/xml+rss
        application/atom+xml
        image/svg+xml
        font/ttf
        font/otf
        font/woff
        font/woff2;

    ##
    # Rate Limiting Zones
    # (defined in http block so they are shared across worker processes)
    ##

    # General API: 100 req/min per IP (~1.67 req/s) => use 2r/s with burst
    limit_req_zone $binary_remote_addr zone=api:10m rate=2r/s;

    # Auth endpoints: 10 req/min per IP => 1r/s with tight burst
    limit_req_zone $binary_remote_addr zone=auth:10m rate=1r/s;

    ##
    # Upstream: Docker container on 127.0.0.1:3000
    ##

    upstream commandbase {
        server 127.0.0.1:3000;
        keepalive 32;  # Keep persistent connections to the app
    }

    ##
    # Map: detect WebSocket upgrade requests
    ##

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }

    ##
    # Server: HTTP -> HTTPS redirect (port 80)
    ##

    server {
        listen 80;
        listen [::]:80;

        # Replace with your domain or DGX IP below.
        # For domain:   server_name commandbase.yourdomain.com;
        # For LAN IP:   server_name _;   (catches all)
        server_name _;

        # ACME challenge for Let's Encrypt (no-op if using self-signed)
        location /.well-known/acme-challenge/ {
            root /var/www/letsencrypt;
        }

        location / {
            return 301 https://$host$request_uri;
        }
    }

    ##
    # Server: HTTPS + WebSocket proxy (port 443)
    ##

    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;

        # Replace with your domain or DGX IP
        # For domain:   server_name commandbase.yourdomain.com;
        # For LAN IP:   server_name _;
        server_name _;

        ##
        # SSL Certificates
        # PATH A (self-signed)   -- see Section 3
        # PATH B (Let's Encrypt) -- see Section 4
        # Uncomment the appropriate block.
        ##

        # -- PATH A: Self-Signed ------------------------------------------
        ssl_certificate     /etc/nginx/ssl/commandbase-selfsigned.crt;
        ssl_certificate_key /etc/nginx/ssl/commandbase-selfsigned.key;
        # -----------------------------------------------------------------

        # -- PATH B: Let's Encrypt (comment out Path A, uncomment Path B) --
        # ssl_certificate     /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem;
        # ssl_certificate_key /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem;
        # include             /etc/letsencrypt/options-ssl-nginx.conf;
        # ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;
        # -----------------------------------------------------------------

        ##
        # SSL Hardening (applies to both paths)
        ##

        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers off;
        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;

        # HSTS (only enable after confirming HTTPS works -- hard to undo)
        # add_header Strict-Transport-Security "max-age=63072000" always;

        ##
        # Security Headers
        ##

        add_header X-Frame-Options        "SAMEORIGIN"    always;
        add_header X-Content-Type-Options "nosniff"       always;
        add_header X-XSS-Protection       "1; mode=block" always;
        add_header Referrer-Policy        "strict-origin-when-cross-origin" always;

        ##
        # CORS Headers for Production
        # Adjust allowed origin(s) to match your actual frontend origin(s).
        ##

        set $cors_origin "";
        if ($http_origin ~* "^https://(commandbase\.yourdomain\.com|localhost)$") {
            set $cors_origin $http_origin;
        }

        add_header Access-Control-Allow-Origin      $cors_origin always;
        add_header Access-Control-Allow-Methods     "GET, POST, PUT, PATCH, DELETE, OPTIONS" always;
        add_header Access-Control-Allow-Headers     "Authorization, Content-Type, X-Requested-With" always;
        add_header Access-Control-Allow-Credentials "true" always;
        add_header Access-Control-Max-Age           "3600" always;

        # Handle preflight OPTIONS fast -- don't proxy it
        if ($request_method = OPTIONS) {
            return 204;
        }

        ##
        # WebSocket: /ws endpoint
        # Matches the path in lib/broadcast.js: new WebSocketServer({ path: '/ws' })
        ##

        location /ws {
            proxy_pass         http://commandbase;
            proxy_http_version 1.1;

            # WebSocket upgrade headers
            proxy_set_header Upgrade    $http_upgrade;
            proxy_set_header Connection $connection_upgrade;

            # Pass real client info
            proxy_set_header Host              $host;
            proxy_set_header X-Real-IP         $remote_addr;
            proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # Keep WebSocket connections alive (no timeout)
            proxy_read_timeout    86400s;
            proxy_send_timeout    86400s;
            proxy_connect_timeout 10s;

            # Disable buffering for real-time traffic
            proxy_buffering off;
        }

        ##
        # Auth endpoints -- strict rate limit: 10 req/min per IP
        # Covers login, register, token refresh, password reset
        ##

        location ~* ^/api/(auth|login|register|logout|token|password) {
            limit_req zone=auth burst=5 nodelay;
            limit_req_status 429;

            proxy_pass         http://commandbase;
            proxy_http_version 1.1;
            proxy_set_header   Connection        "";
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;

            proxy_read_timeout    30s;
            proxy_connect_timeout 5s;
        }

        ##
        # API endpoints -- general rate limit: 100 req/min per IP
        ##

        location /api/ {
            limit_req zone=api burst=20 nodelay;
            limit_req_status 429;

            proxy_pass         http://commandbase;
            proxy_http_version 1.1;
            proxy_set_header   Connection        "";
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;

            proxy_read_timeout    60s;
            proxy_connect_timeout 5s;
            proxy_send_timeout    60s;
        }

        ##
        # All other requests (static assets, frontend routes)
        ##

        location / {
            proxy_pass         http://commandbase;
            proxy_http_version 1.1;
            proxy_set_header   Connection        "";
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;

            proxy_read_timeout    60s;
            proxy_connect_timeout 5s;
        }

        ##
        # Error pages
        ##

        error_page 429 /429.html;
        location = /429.html {
            internal;
            default_type text/plain;
            return 429 "Too Many Requests\n";
        }

        error_page 502 503 504 /50x.html;
        location = /50x.html {
            internal;
            default_type text/plain;
            return 502 "Service Temporarily Unavailable\n";
        }
    }
}
```

---

## 3. Path A — Self-Signed Certificate (No Domain / LAN Use)

Use this when the DGX Spark is accessed by IP address or you don't have a domain yet. Browsers will show a certificate warning — that is expected. For local team use, add a browser exception once.

```bash
# Create the SSL directory
sudo mkdir -p /etc/nginx/ssl

# Generate a 2048-bit RSA key + self-signed cert (valid 10 years)
# Update 10.0.0.1 to the actual DGX LAN IP
sudo openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/commandbase-selfsigned.key \
    -out    /etc/nginx/ssl/commandbase-selfsigned.crt \
    -subj "/C=US/ST=Local/L=DGX/O=CommandBase/CN=10.0.0.1" \
    -addext "subjectAltName=IP:10.0.0.1,IP:127.0.0.1"

# Lock down permissions
sudo chmod 600 /etc/nginx/ssl/commandbase-selfsigned.key
sudo chmod 644 /etc/nginx/ssl/commandbase-selfsigned.crt

# Verify cert
openssl x509 -in /etc/nginx/ssl/commandbase-selfsigned.crt -text -noout | grep -E "Subject:|Not After"
```

The `nginx.conf` in Section 2 already points to these paths under Path A. No further changes needed.

---

## 4. Path B — Let's Encrypt (You Have a Domain)

Prerequisites: domain DNS A record must point to the DGX Spark's public IP, and port 80 must be reachable from the internet (even temporarily).

```bash
# Install certbot and the nginx plugin
sudo apt install -y certbot python3-certbot-nginx

# Create the webroot directory for ACME challenges
sudo mkdir -p /var/www/letsencrypt

# Issue the certificate — replace YOUR_DOMAIN and YOUR_EMAIL
sudo certbot certonly --webroot \
    -w /var/www/letsencrypt \
    -d YOUR_DOMAIN \
    --email YOUR_EMAIL \
    --agree-tos \
    --no-eff-email

# Certificates will be placed at:
#   /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem
#   /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem

# Download recommended Certbot SSL options (if not already present)
sudo curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf \
    -o /etc/letsencrypt/options-ssl-nginx.conf

sudo openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048
```

After issuing the certificate, edit `nginx.conf`:
- Comment out the Path A ssl_certificate lines
- Uncomment the Path B ssl_certificate lines
- Update `server_name` to your domain

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 4.1 Auto-Renewal Cron Job

certbot installs a systemd timer automatically on Ubuntu 24.04. Verify it:

```bash
sudo systemctl status certbot.timer
# Should show: active (waiting)

# Test renewal dry-run
sudo certbot renew --dry-run
```

If the timer is absent, add a cron job:

```bash
sudo crontab -e
```

Add this line:

```
# Renew Let's Encrypt certs twice daily, reload nginx on success
0 0,12 * * * /usr/bin/certbot renew --quiet --deploy-hook "systemctl reload nginx" >> /var/log/certbot-renew.log 2>&1
```

---

## 5. nginx Systemd Service

Ubuntu 24.04 installs nginx with systemd integration by default.

```bash
# Enable on boot (done in Section 1 — repeated here for reference)
sudo systemctl enable nginx

# Start / stop / restart / reload (reload = zero-downtime config apply)
sudo systemctl start   nginx
sudo systemctl stop    nginx
sudo systemctl restart nginx
sudo systemctl reload  nginx

# Live status
sudo systemctl status nginx

# Always test config before reload
sudo nginx -t
sudo systemctl reload nginx

# View logs
sudo journalctl -u nginx -f            # live systemd log
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

---

## 6. wss:// WebSocket Proxying Verification

The app registers WebSocket clients at path `/ws` (see `lib/broadcast.js` line 9):
`new WebSocketServer({ server, path: '/ws' })`

### 6.1 CLI Test (wscat)

```bash
# Install wscat (one-time)
npm install -g wscat

# Path A (self-signed) -- skip TLS verification
wscat --connect wss://DGX_IP/ws --no-check

# Path B (Let's Encrypt) -- full TLS verification
wscat --connect wss://YOUR_DOMAIN/ws

# Expected output:
# Connected (press CTRL+C to quit)
# Broadcasts arrive as JSON: {"type":"task.updated","data":{...},"timestamp":"..."}
```

### 6.2 Browser Console Test

Open the app in a browser, then in DevTools console:

```javascript
const ws = new WebSocket('wss://' + location.host + '/ws');
ws.onopen    = () => console.log('WebSocket OPEN -- proxy working');
ws.onclose   = (e) => console.log('WebSocket CLOSED', e.code, e.reason);
ws.onerror   = (e) => console.error('WebSocket ERROR', e);
ws.onmessage = (e) => console.log('Message:', JSON.parse(e.data));
```

### 6.3 nginx Log — Confirm 101 Upgrade

```bash
sudo tail -f /var/log/nginx/access.log | grep " 101 "
# Example: 192.168.1.50 - - [04/Apr/2026:10:00:00 +0000] "GET /ws HTTP/1.1" 101 ...
```

### 6.4 curl Headers Test

```bash
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  https://DGX_IP/ws --insecure
# Expect: HTTP/1.1 101 Switching Protocols
```

---

## 7. Firewall Rules (ufw)

```bash
# Enable ufw if not already active
sudo ufw status
sudo ufw enable   # if inactive

# Allow SSH -- ALWAYS do this first to avoid locking yourself out
sudo ufw allow 22/tcp comment 'SSH'

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp  comment 'HTTP (redirect to HTTPS)'
sudo ufw allow 443/tcp comment 'HTTPS + wss://'

# Block direct access to port 3000 from outside
# (127.0.0.1 is still allowed -- nginx talks to Docker on loopback)
sudo ufw deny 3000/tcp comment 'Block direct Docker port access'

# Verify rules
sudo ufw status verbose
```

Expected output (relevant lines):

```
22/tcp   ALLOW IN  Anywhere
80/tcp   ALLOW IN  Anywhere
443/tcp  ALLOW IN  Anywhere
3000/tcp DENY IN   Anywhere
```

### Docker iptables Warning

Docker inserts its own iptables rules that can bypass ufw. The safest fix is to bind the container port to `127.0.0.1` in `docker-compose.yml`:

```yaml
# docker-compose.yml
ports:
  - "127.0.0.1:3000:3000"   # Loopback only -- ufw-safe
  # NOT: "3000:3000"         # Binds to 0.0.0.0, bypasses ufw
```

After changing, restart: `docker compose down && docker compose up -d`

Confirm the binding: `docker ps` — PORTS column should show `127.0.0.1:3000->3000/tcp`

---

## Day-1 Execution Checklist

### Pre-Flight
- [ ] SSH into DGX Spark: `ssh user@DGX_IP`
- [ ] Confirm Docker container is running: `docker ps` — Command Base container on port 3000
- [ ] Confirm app responds locally: `curl http://127.0.0.1:3000` — expect 200
- [ ] Decide certificate path: **A** (self-signed, no domain) or **B** (Let's Encrypt, have domain)
  - Path B only: confirm DNS — `dig YOUR_DOMAIN +short` must return DGX public IP

### Step 1 — Install nginx
- [ ] `sudo apt update && sudo apt install -y nginx`
- [ ] `sudo systemctl enable nginx && sudo systemctl start nginx`
- [ ] `sudo systemctl status nginx` — confirm `active (running)`

### Step 2 — Certificates
**Path A (self-signed):**
- [ ] `sudo mkdir -p /etc/nginx/ssl`
- [ ] Run `openssl req` command from Section 3 (update IP to actual DGX LAN IP)
- [ ] `ls -la /etc/nginx/ssl/` — confirm both `.crt` and `.key` exist

**Path B (Let's Encrypt):**
- [ ] `sudo apt install -y certbot python3-certbot-nginx`
- [ ] `sudo mkdir -p /var/www/letsencrypt`
- [ ] Run `certbot certonly` from Section 4 (update domain + email)
- [ ] Confirm certs at `/etc/letsencrypt/live/YOUR_DOMAIN/`

### Step 3 — Deploy nginx.conf
- [ ] Back up existing config: `sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak`
- [ ] Write new config from Section 2 to `/etc/nginx/nginx.conf`
- [ ] Update `server_name` to DGX LAN IP or your domain
- [ ] Activate correct certificate block (Path A or B — comment/uncomment as noted)
- [ ] Update CORS `$cors_origin` regex to match actual frontend origin
- [ ] `sudo nginx -t` — must output `syntax is ok` and `test is successful`

### Step 4 — Firewall
- [ ] `sudo ufw allow 22/tcp` (SSH -- do this FIRST)
- [ ] `sudo ufw allow 80/tcp`
- [ ] `sudo ufw allow 443/tcp`
- [ ] `sudo ufw deny 3000/tcp`
- [ ] `sudo ufw enable` (if not already active)
- [ ] `sudo ufw status verbose` — verify all four rules present

### Step 5 — Docker Port Binding
- [ ] `docker ps` — check PORTS column
  - If `0.0.0.0:3000->3000/tcp`: update `docker-compose.yml` to `127.0.0.1:3000:3000`
  - `docker compose down && docker compose up -d`
- [ ] Confirm: `docker ps` shows `127.0.0.1:3000->3000/tcp`
- [ ] Optional: verify port 3000 not reachable externally via `nmap -p 3000 DGX_IP` from another machine

### Step 6 — Start and Test
- [ ] `sudo systemctl reload nginx`
- [ ] `curl -I http://DGX_IP` — expect `301 Moved Permanently`
- [ ] `curl -Ik https://DGX_IP` (or `https://YOUR_DOMAIN`) — expect `200 OK`
- [ ] Test WebSocket: `wscat --connect wss://DGX_IP/ws --no-check` or `wscat --connect wss://YOUR_DOMAIN/ws`
  - Expect: `Connected`
- [ ] `sudo tail /var/log/nginx/access.log | grep 101` — confirm WebSocket upgrade logged

### Step 7 — Let's Encrypt Renewal (Path B only)
- [ ] `sudo systemctl status certbot.timer` — confirm `active (waiting)`
- [ ] `sudo certbot renew --dry-run` — confirm success
- [ ] If timer absent: add cron job from Section 4.1

### Post-Deployment Smoke Tests
- [ ] App loads in browser at `https://DGX_IP` or `https://YOUR_DOMAIN`
- [ ] Real-time updates work in Mission Control (notifications appear without page refresh)
- [ ] File upload test near 50 MB succeeds
- [ ] Rate limit test: rapid-fire 25+ requests to `/api/health` — first burst succeeds, excess returns 429
- [ ] `sudo tail -50 /var/log/nginx/error.log` — no unexpected errors

---

## Quick Reference

| Task | Command |
|------|---------|
| Test config | `sudo nginx -t` |
| Reload config (zero-downtime) | `sudo systemctl reload nginx` |
| View access log | `sudo tail -f /var/log/nginx/access.log` |
| View error log | `sudo tail -f /var/log/nginx/error.log` |
| Check ufw status | `sudo ufw status verbose` |
| Test WebSocket | `wscat --connect wss://HOST/ws --no-check` |
| Renew cert dry-run | `sudo certbot renew --dry-run` |
| nginx service status | `sudo systemctl status nginx` |
| Check Docker port binding | `docker ps` |

---

## Notes and Gotchas

**Docker bypasses ufw:** Docker writes iptables rules directly, bypassing ufw. The `deny 3000/tcp` rule alone is NOT sufficient if Docker binds to `0.0.0.0`. Binding to `127.0.0.1:3000` in `docker-compose.yml` is the only reliable fix.

**Self-signed cert + WebSocket:** Browsers enforce the same TLS rules for `wss://` as for `https://`. If using a self-signed cert, visit the HTTPS site first and accept the exception. Otherwise `wss://` connections will fail silently in the browser.

**HSTS:** The `Strict-Transport-Security` header is intentionally commented out. Browsers cache HSTS for the full `max-age` duration — enabling it prematurely on a broken HTTPS config can lock users out with no easy recovery. Enable it only after confirming HTTPS is fully stable.

**Rate limit math:**
- `zone=api rate=2r/s burst=20` — allows a burst of 20 simultaneous requests, then enforces ~120 req/min; effectively 100 req/min at steady state
- `zone=auth rate=1r/s burst=5` — allows 5 quick hits (covering a login page load + submit), then enforces ~10 req/min

**WebSocket path is hard-coded:** The app registers at `/ws` in `lib/broadcast.js`. If this ever changes, update the `location /ws` block in `nginx.conf` to match.

**keepalive on upstream:** `keepalive 32` in the upstream block keeps persistent HTTP/1.1 connections to the Node.js app, reducing TCP overhead on the 10 GbE DGX link. The `proxy_set_header Connection ""` directives in location blocks are required when using keepalive upstream connections — they clear the hop-by-hop Connection header so it is not forwarded to the app.
