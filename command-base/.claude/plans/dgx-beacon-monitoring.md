# DGX Spark — Monitoring & Remote Access Plan
**Specialist:** Beacon (DevOps — Monitoring)  
**Priority:** HIGH — Configure on Day 1  
**Target:** NVIDIA DGX Spark, Ubuntu 24.04

---

## 1. SSH Setup

### Generate key pair on Mac
```bash
# On Mac:
ssh-keygen -t ed25519 -C "max-mac-to-dgx-spark" -f ~/.ssh/dgx_spark
# (leave passphrase empty for automation, or use ssh-agent)
```

### Add to DGX authorized_keys
```bash
# On DGX (first connection via password or console):
mkdir -p ~/.ssh && chmod 700 ~/.ssh
# From Mac:
ssh-copy-id -i ~/.ssh/dgx_spark.pub user@<DGX-IP>
# Or manually append ~/.ssh/dgx_spark.pub to DGX:~/.ssh/authorized_keys
```

### SSH config on Mac (`~/.ssh/config`)
```
Host dgx-spark
    HostName <DGX-LOCAL-IP>        # Update after Tailscale: use 100.x.x.x
    User maxstewart
    IdentityFile ~/.ssh/dgx_spark
    ServerAliveInterval 60
    ServerAliveCountMax 3
    ForwardAgent yes
```

After this, connect with: `ssh dgx-spark`

### sshd hardening on DGX (`/etc/ssh/sshd_config`)
```
PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
```
Then: `sudo systemctl restart sshd`

---

## 2. Tailscale (Secure Remote Access)

Tailscale provides zero-config VPN — works behind NAT, no port forwarding needed.

### Install on DGX (Ubuntu 24.04)
```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --accept-routes
```

### Install on Mac
```bash
# Via Homebrew:
brew install --cask tailscale
# Or download from tailscale.com/download
```

### Authenticate both devices
- Log in to tailscale.com with the same account on both Mac and DGX
- Both appear in the Tailscale admin console
- MagicDNS assigns `dgx-spark` hostname automatically (accessible as `dgx-spark.tail<hash>.ts.net`)

### Update SSH config after Tailscale
```
Host dgx-spark
    HostName dgx-spark              # MagicDNS hostname (or 100.x.x.x Tailscale IP)
    ...
```

### Benefits
- Access DGX from anywhere (home, office, travel)
- Encrypted WireGuard tunnels
- No open inbound ports on DGX
- Subnet routing: can reach other LAN devices via DGX

---

## 3. System Monitoring — Netdata

Netdata is recommended over Prometheus+Grafana for its simplicity and native GPU support.

### Install Netdata on DGX
```bash
bash <(curl -Ss https://my-netdata.io/kickstart.sh) --non-interactive
```

### Configure NVIDIA GPU monitoring
```bash
# Netdata auto-detects nvidia-smi — verify:
sudo /etc/netdata/edit-config charts.d.conf
# Ensure: nvidia_smi=yes

# Test GPU data collection:
sudo -u netdata nvidia-smi --query-gpu=utilization.gpu,temperature.gpu,memory.used,memory.total --format=csv,noheader
```

### Access Netdata dashboard
- Local: `http://<DGX-IP>:19999`
- Via Tailscale: `http://dgx-spark:19999`

### Metrics monitored
- **CPU:** utilization, frequency, temperature per core
- **Memory:** used/total, swap
- **Disk:** I/O, utilization, free space per mount
- **Network:** bandwidth per interface (10 GbE + WiFi 7)
- **GPU:** utilization %, memory used/total, temperature, power draw
- **Docker:** per-container CPU, memory, network
- **App:** HTTP response times (via the `/health` endpoint probe)

---

## 4. DGX Hardware Stats API Endpoint

Add to `server.js` — new Express route returning live system stats.

### Response JSON schema
```json
{
  "timestamp": "2026-04-04T12:00:00.000Z",
  "cpu": {
    "usage_percent": 23.4,
    "cores": 72
  },
  "memory": {
    "used_gb": 18.2,
    "total_gb": 128.0,
    "usage_percent": 14.2
  },
  "disk": {
    "used_gb": 245.1,
    "total_gb": 1000.0,
    "usage_percent": 24.5
  },
  "gpu": {
    "available": true,
    "utilization_percent": 0,
    "memory_used_gb": 0.5,
    "memory_total_gb": 96.0,
    "temperature_c": 42,
    "power_draw_w": 45
  },
  "uptime_seconds": 86400,
  "docker": {
    "containers_running": 1
  }
}
```

### Implementation sketch (add to `server.js` routes)
```javascript
const os = require('os');
const { execSync } = require('child_process');

app.get('/api/system/stats', (req, res) => {
  try {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;

    const stats = {
      timestamp: new Date().toISOString(),
      cpu: {
        usage_percent: null, // populate with os.loadavg()[0] / os.cpus().length * 100
        cores: os.cpus().length
      },
      memory: {
        used_gb: +(usedMem / 1e9).toFixed(1),
        total_gb: +(totalMem / 1e9).toFixed(1),
        usage_percent: +((usedMem / totalMem) * 100).toFixed(1)
      },
      disk: getDiskStats(),
      gpu: getGpuStats(),
      uptime_seconds: Math.floor(os.uptime())
    };

    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function getGpuStats() {
  try {
    const out = execSync(
      'nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw --format=csv,noheader,nounits',
      { timeout: 3000 }
    ).toString().trim();
    const [util, memUsed, memTotal, temp, power] = out.split(', ').map(s => parseFloat(s));
    return {
      available: true,
      utilization_percent: util,
      memory_used_gb: +(memUsed / 1024).toFixed(1),
      memory_total_gb: +(memTotal / 1024).toFixed(1),
      temperature_c: temp,
      power_draw_w: power
    };
  } catch {
    return { available: false };
  }
}

function getDiskStats() {
  try {
    const out = execSync("df -BG /opt/command-base 2>/dev/null || df -BG /", { timeout: 2000 }).toString();
    const lines = out.trim().split('\n');
    const parts = lines[1].split(/\s+/);
    return {
      used_gb: parseInt(parts[2]),
      total_gb: parseInt(parts[1]),
      usage_percent: parseInt(parts[4])
    };
  } catch {
    return { used_gb: null, total_gb: null, usage_percent: null };
  }
}
```

---

## 5. Alerting Rules (Netdata health.d)

Create `/etc/netdata/health.d/command-base.conf`:

```yaml
# Memory > 90%
alarm: high_memory_usage
on: system.ram
lookup: average -1m percentage of used
units: %
every: 1m
warn: $this > 80
crit: $this > 90
info: System memory usage is critically high

# Disk > 80%
alarm: high_disk_usage
on: disk.space
lookup: average -1m percentage of used
units: %
every: 5m
warn: $this > 70
crit: $this > 80
info: Disk space critically low

# GPU temp > 85°C
alarm: gpu_overtemp
on: nvidia_smi.gpu_temp
lookup: max -1m
units: Celsius
every: 1m
warn: $this > 75
crit: $this > 85
info: GPU temperature critically high

# App health check
alarm: command_base_down
on: httpcheck.command_base_responsetime
lookup: max -5m
units: ms
every: 1m
crit: $this == 0
info: Command Base app is not responding
```

### Enable Slack notifications (`/etc/netdata/health_alarm_notify.conf`)
```bash
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/HERE"
DEFAULT_RECIPIENT_SLACK="#alerts"
```

---

## 6. Log Management

### Docker logs with rotation (already in docker-compose.yml)
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "50m"
    max-file: "5"
```

### Centralized log file
```bash
# Stream Docker logs to file (run as systemd service):
docker logs -f command-base >> /var/log/command-base-app.log 2>&1
```

### logrotate config (`/etc/logrotate.d/command-base`)
```
/var/log/command-base-app.log
/var/log/command-base-backup.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    size 100M
    create 0644 root root
}
```

### Remote log access from Mac
```bash
# Tail live logs via SSH:
ssh dgx-spark "docker logs -f command-base"

# Pull last 500 lines:
ssh dgx-spark "docker logs --tail=500 command-base"

# Search logs:
ssh dgx-spark "docker logs command-base 2>&1 | grep ERROR | tail -20"
```

---

## 7. NVIDIA DGX Tools Available

On DGX OS 7, these tools are pre-installed or available:
- **`nvidia-smi`** — GPU status, utilization, temp, memory
- **DCGM** (Data Center GPU Manager) — deep GPU health metrics, ECC errors, PCIe bandwidth
- **NIM microservices** — NVIDIA Inference Microservices for running optimized model serving
- **NVAIE** (NVIDIA AI Enterprise) — enterprise AI software stack, included with DGX

Enable DCGM metrics for Netdata:
```bash
sudo apt install datacenter-gpu-manager
sudo systemctl enable dcgm && sudo systemctl start dcgm
```

---

## Day 1 Setup Checklist

### Phase 1 — Mac Prep
- [ ] Generate SSH key: `ssh-keygen -t ed25519 -C "max-mac-to-dgx" -f ~/.ssh/dgx_spark`
- [ ] Install Tailscale on Mac
- [ ] Log in to Tailscale account

### Phase 2 — DGX Setup (via direct console or first password SSH)
- [ ] Copy SSH public key to DGX: `ssh-copy-id -i ~/.ssh/dgx_spark.pub user@<DGX-IP>`
- [ ] Harden sshd: disable password auth
- [ ] Install Tailscale: `curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up`
- [ ] Log in with same Tailscale account
- [ ] Install Netdata: `bash <(curl -Ss https://my-netdata.io/kickstart.sh) --non-interactive`
- [ ] Verify nvidia-smi in Netdata: `curl http://localhost:19999/api/v1/charts | grep nvidia`

### Phase 3 — Mac Verification
- [ ] Update `~/.ssh/config` with Tailscale hostname
- [ ] Test: `ssh dgx-spark echo "Connected via Tailscale"`
- [ ] Open Netdata: `open http://dgx-spark:19999`

### Phase 4 — API Endpoint
- [ ] Add `/api/system/stats` route to `server.js`
- [ ] Rebuild Docker image: `docker compose build`
- [ ] Restart: `docker compose up -d`
- [ ] Test: `curl http://localhost:3000/api/system/stats | python3 -m json.tool`

### Verification
- [ ] SSH works via Tailscale: `ssh dgx-spark uptime`
- [ ] Netdata shows GPU metrics
- [ ] `/api/system/stats` returns valid JSON with GPU data
- [ ] Disk/memory/CPU alerts are configured
- [ ] Logs accessible remotely: `ssh dgx-spark "docker logs --tail=20 command-base"`
