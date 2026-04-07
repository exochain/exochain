'use strict';
module.exports = function(app, db, helpers) {
  const { broadcast, localNow, createNotification, authRateLimiter, apiRateLimiter, spawnMemberTerminal } = helpers;
  const stmt = helpers.stmt || ((sql) => db.prepare(sql));

// GET /api/model-sources — list all configured model sources with live status
app.get('/api/model-sources', async (req, res) => {
  try {
    const sources = db.prepare(`SELECT * FROM model_sources ORDER BY is_local DESC, name`).all();
    const http = require('http');

    // Check each source for live models in parallel
    const enriched = await Promise.all(sources.map(source => {
      return new Promise((resolve) => {
        const url = new URL(source.endpoint + '/api/tags');
        const httpLib = url.protocol === 'https:' ? require('https') : http;
        const req = httpLib.get({ hostname: url.hostname, port: url.port, path: url.pathname, timeout: 5000 }, (resp) => {
          let body = '';
          resp.on('data', d => body += d);
          resp.on('end', () => {
            try {
              const data = JSON.parse(body);
              const models = (data.models || []).map(m => ({
                name: m.name,
                size: m.size,
                sizeGB: Math.round(m.size / 1e9 * 10) / 10,
                modified: m.modified_at,
                family: m.details?.family || null,
                parameters: m.details?.parameter_size || null,
                quantization: m.details?.quantization_level || null
              }));
              // Count running tasks on this source
              const runningTasks = db.prepare(`SELECT COUNT(*) as c FROM active_processes WHERE status = 'running' AND output_summary LIKE ?`).get(`%[${source.name}]%`)?.c || 0;
              resolve({ ...source, status: 'online', models, running_tasks: runningTasks });
            } catch (_) {
              resolve({ ...source, status: 'error', models: [], error: 'Invalid response', running_tasks: 0 });
            }
          });
        });
        req.on('error', () => resolve({ ...source, status: 'offline', models: [], running_tasks: 0 }));
        req.on('timeout', () => { req.destroy(); resolve({ ...source, status: 'offline', models: [], running_tasks: 0 }); });
      });
    }));

    res.json(enriched);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/model-sources — add a new model source
app.post('/api/model-sources', (req, res) => {
  try {
    const { name, type, endpoint, label, device, is_local, ssh_host, ssh_tunnel_port, max_concurrent } = req.body;
    if (!name || !endpoint) return res.status(400).json({ error: 'name and endpoint are required' });
    const now = localNow();
    const result = db.prepare(`INSERT INTO model_sources (name, type, endpoint, label, device, is_local, ssh_host, ssh_tunnel_port, max_concurrent, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(name, type || 'ollama', endpoint, label || name, device || null, is_local ? 1 : 0, ssh_host || null, ssh_tunnel_port || null, max_concurrent || 3, now, now);
    res.json({ id: Number(result.lastInsertRowid), success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/model-sources/:id — update a model source
app.put('/api/model-sources/:id', (req, res) => {
  try {
    const { name, endpoint, label, device, is_active, ssh_host, ssh_tunnel_port, max_concurrent } = req.body;
    const now = localNow();
    const sets = [];
    const vals = [];
    if (name !== undefined) { sets.push('name = ?'); vals.push(name); }
    if (endpoint !== undefined) { sets.push('endpoint = ?'); vals.push(endpoint); }
    if (label !== undefined) { sets.push('label = ?'); vals.push(label); }
    if (device !== undefined) { sets.push('device = ?'); vals.push(device); }
    if (is_active !== undefined) { sets.push('is_active = ?'); vals.push(is_active ? 1 : 0); }
    if (ssh_host !== undefined) { sets.push('ssh_host = ?'); vals.push(ssh_host); }
    if (ssh_tunnel_port !== undefined) { sets.push('ssh_tunnel_port = ?'); vals.push(ssh_tunnel_port); }
    if (max_concurrent !== undefined) { sets.push('max_concurrent = ?'); vals.push(max_concurrent); }
    sets.push('updated_at = ?'); vals.push(now);
    vals.push(req.params.id);
    db.prepare(`UPDATE model_sources SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/model-sources/:id — remove a model source
app.delete('/api/model-sources/:id', (req, res) => {
  try {
    db.prepare(`DELETE FROM model_sources WHERE id = ?`).run(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/model-sources/:id/pull — pull a model on a source
app.post('/api/model-sources/:id/pull', (req, res) => {
  try {
    const source = db.prepare(`SELECT * FROM model_sources WHERE id = ?`).get(req.params.id);
    if (!source) return res.status(404).json({ error: 'Source not found' });
    const { model } = req.body;
    if (!model) return res.status(400).json({ error: 'model name is required' });

    // Fire and forget — pull can take minutes
    const http = require('http');
    const url = new URL(source.endpoint + '/api/pull');
    const httpLib = url.protocol === 'https:' ? require('https') : http;
    const pullReq = httpLib.request({ hostname: url.hostname, port: url.port, path: url.pathname, method: 'POST', headers: { 'Content-Type': 'application/json' } }, () => {});
    pullReq.on('error', () => {});
    pullReq.write(JSON.stringify({ name: model, stream: false }));
    pullReq.end();

    res.json({ success: true, message: `Pulling ${model} on ${source.label}. This may take several minutes.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/model-sources/guide — setup guide for connecting external LLM devices
app.get('/api/model-sources/guide', (req, res) => {
  res.json({
    title: 'Connecting External LLM Devices',
    steps: [
      {
        title: '1. SSH Access',
        content: 'Ensure you can SSH into the device without a password. On your Mac:\n\nssh-keygen -t ed25519 (if no key exists)\nssh-copy-id user@device-ip\n\nVerify: ssh user@device-ip "hostname"'
      },
      {
        title: '2. Install Ollama on the Device',
        content: 'SSH into the device and run:\n\ncurl -fsSL https://ollama.com/install.sh | sh\n\nThis installs Ollama and starts it as a service on port 11434.'
      },
      {
        title: '3. Pull a Model',
        content: 'On the device:\n\nollama pull nemotron    # NVIDIA optimized, 42GB\nollama pull llama3      # General purpose, 4.7GB\nollama pull qwen3-coder # Code specialist, 18GB\n\nChoose based on your GPU memory.'
      },
      {
        title: '4. Set Up SSH Tunnel',
        content: 'From your Mac, create a persistent tunnel:\n\nssh -f -N -L LOCAL_PORT:localhost:11434 user@device-ip\n\nExample: ssh -f -N -L 11435:localhost:11434 user@192.168.1.35\n\nThis maps the device\'s Ollama to a local port on your Mac.'
      },
      {
        title: '5. Add as Model Source',
        content: 'In Command Base Settings → Model Sources → Add Source:\n- Name: my-device\n- Endpoint: http://localhost:LOCAL_PORT\n- Device: GPU name\n- SSH Host: user@device-ip\n- Max Concurrent: 2-3 (depends on GPU memory)\n\nCommand Base will auto-route simple tasks to this device.'
      },
      {
        title: '6. Auto-Start Tunnel on Boot (Optional)',
        content: 'Create ~/Library/LaunchAgents/com.commandbase.tunnel-DEVICE.plist with the SSH tunnel command. Set KeepAlive=true and RunAtLoad=true. Load with: launchctl load ~/Library/LaunchAgents/com.commandbase.tunnel-DEVICE.plist'
      }
    ],
    supported_devices: ['NVIDIA DGX Spark', 'Any Linux machine with NVIDIA GPU', 'Mac with Apple Silicon', 'Cloud GPU instances (SSH accessible)'],
    supported_frameworks: ['Ollama (recommended)', 'Any OpenAI-compatible API endpoint']
  });
});

// POST /api/model-sources/:id/scan — scan a source's device capabilities and recommend models
app.post('/api/model-sources/:id/scan', async (req, res) => {
  try {
    const source = db.prepare(`SELECT * FROM model_sources WHERE id = ?`).get(req.params.id);
    if (!source) return res.status(404).json({ error: 'Source not found' });

    const http = require('http');
    const scan = { source: source.name, device: source.device, capabilities: {} };

    // 1. Check what models are loaded
    try {
      const tagsUrl = new URL(source.endpoint + '/api/tags');
      const httpLib = tagsUrl.protocol === 'https:' ? require('https') : http;
      const modelsData = await new Promise((resolve) => {
        const r = httpLib.get({ hostname: tagsUrl.hostname, port: tagsUrl.port, path: tagsUrl.pathname, timeout: 5000 }, (resp) => {
          let body = ''; resp.on('data', d => body += d);
          resp.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({ models: [] }); } });
        });
        r.on('error', () => resolve({ models: [] }));
        r.on('timeout', () => { r.destroy(); resolve({ models: [] }); });
      });
      scan.installed_models = (modelsData.models || []).map(m => ({ name: m.name, sizeGB: Math.round(m.size / 1e9 * 10) / 10 }));
    } catch { scan.installed_models = []; }

    // 2. Get device hardware info via SSH (for remote) or local commands
    if (source.ssh_host) {
      try {
        const { execSync } = require('child_process');
        const sshCmd = `ssh -o ConnectTimeout=5 ${source.ssh_host}`;
        const ramGB = parseInt(execSync(`${sshCmd} "free -g 2>/dev/null | awk '/Mem:/{print \\$7}'"`, { timeout: 10000 }).toString().trim()) || 0;
        const cpus = parseInt(execSync(`${sshCmd} "nproc 2>/dev/null"`, { timeout: 10000 }).toString().trim()) || 0;
        const gpuInfo = execSync(`${sshCmd} "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null || echo 'none'"`, { timeout: 10000 }).toString().trim();
        scan.capabilities = { ram_gb: ramGB, cpus, gpu: gpuInfo !== 'none' ? gpuInfo : null, is_remote: true };
      } catch (e) { scan.capabilities = { error: e.message, is_remote: true }; }
    } else {
      // Local device
      try {
        const os = require('os');
        scan.capabilities = {
          ram_gb: Math.round(os.totalmem() / 1e9),
          free_ram_gb: Math.round(os.freemem() / 1e9),
          cpus: os.cpus().length,
          cpu_model: os.cpus()[0]?.model || 'unknown',
          platform: os.platform(),
          arch: os.arch(),
          is_remote: false
        };
      } catch { scan.capabilities = { error: 'Failed to read local hardware' }; }
    }

    // 3. Recommend models based on available memory
    const availableRAM = scan.capabilities.ram_gb || 0;
    const isGPU = !!scan.capabilities.gpu;
    // Reserve memory: 8GB for OS on local, 4GB on dedicated server
    const reserveGB = source.is_local ? 8 : 4;
    const usableGB = Math.max(0, availableRAM - reserveGB);
    // User-configurable: max % of resources to use (default 50% for local, 90% for remote)
    const maxUsagePct = source.is_local ? 0.5 : 0.9;
    const budgetGB = Math.floor(usableGB * maxUsagePct);

    const modelRecommendations = [
      { name: 'qwen2.5-coder:1.5b', sizeGB: 1.0, type: 'code', quality: 'basic', minRAM: 2 },
      { name: 'llama3:latest', sizeGB: 4.7, type: 'general', quality: 'good', minRAM: 6 },
      { name: 'deepseek-r1:8b', sizeGB: 5.2, type: 'reasoning', quality: 'good', minRAM: 7 },
      { name: 'qwen2.5-coder:7b', sizeGB: 4.7, type: 'code', quality: 'good', minRAM: 6 },
      { name: 'nemotron:latest', sizeGB: 42.5, type: 'general', quality: 'excellent', minRAM: 48 },
      { name: 'qwen3-coder:30b', sizeGB: 18.6, type: 'code', quality: 'excellent', minRAM: 24 },
      { name: 'deepseek-r1:32b', sizeGB: 20.0, type: 'reasoning', quality: 'excellent', minRAM: 26 },
      { name: 'llama3:70b', sizeGB: 40.0, type: 'general', quality: 'top', minRAM: 48 },
    ];

    scan.budget_gb = budgetGB;
    scan.max_usage_pct = maxUsagePct * 100;
    scan.recommended = modelRecommendations.filter(m => m.minRAM <= budgetGB).map(m => ({
      ...m,
      fits: true,
      already_installed: scan.installed_models.some(im => im.name === m.name),
      concurrent_possible: Math.max(1, Math.floor(budgetGB / m.sizeGB))
    }));
    scan.too_large = modelRecommendations.filter(m => m.minRAM > budgetGB).map(m => ({
      ...m, fits: false, reason: `Needs ${m.minRAM}GB, budget is ${budgetGB}GB`
    }));

    // Recommend max concurrent based on budget and installed models
    const largestInstalled = Math.max(...scan.installed_models.map(m => m.sizeGB), 0);
    scan.recommended_max_concurrent = largestInstalled > 0 ? Math.max(1, Math.floor(budgetGB / largestInstalled)) : 1;

    // Auto-update max_concurrent in DB based on scan
    if (scan.recommended_max_concurrent > 0) {
      db.prepare(`UPDATE model_sources SET max_concurrent = ?, device = ?, updated_at = ? WHERE id = ?`)
        .run(scan.recommended_max_concurrent, scan.capabilities.gpu || scan.capabilities.cpu_model || source.device, localNow(), source.id);
    }

    // Flag models that should be removed (installed but too large for budget)
    scan.should_remove = scan.installed_models.filter(im => {
      const rec = modelRecommendations.find(r => r.name === im.name);
      return rec && rec.minRAM > budgetGB;
    });

    res.json(scan);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/model-sources/auto-scan — scan all active sources and optimize
app.post('/api/model-sources/auto-scan', async (req, res) => {
  try {
    const sources = db.prepare(`SELECT * FROM model_sources WHERE is_active = 1`).all();
    const results = [];
    for (const source of sources) {
      try {
        // Internally call the scan endpoint logic
        const scanRes = await fetch(`http://localhost:${process.env.PORT || 3000}/api/model-sources/${source.id}/scan`, { method: 'POST' });
        const scanData = await scanRes.json();
        results.push(scanData);
      } catch (e) {
        results.push({ source: source.name, error: e.message });
      }
    }
    res.json({ scanned: results.length, results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/integrations — list all integrations
app.get('/api/integrations', (req, res) => {
  try {
    const rows = db.prepare(`SELECT * FROM integrations ORDER BY type ASC`).all();
    res.json(rows.map(r => ({ ...r, config: maskSensitiveConfig(JSON.parse(r.config || '{}')) })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/integrations/:type — get one by type
app.get('/api/integrations/:type', (req, res) => {
  try {
    const row = db.prepare(`SELECT * FROM integrations WHERE type = ?`).get(req.params.type);
    if (!row) return res.status(404).json({ error: 'Integration not found' });
    res.json({ ...row, config: maskSensitiveConfig(JSON.parse(row.config || '{}')) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/integrations/:type — update enabled and/or config (merges config)
app.put('/api/integrations/:type', (req, res) => {
  try {
    const existing = db.prepare(`SELECT * FROM integrations WHERE type = ?`).get(req.params.type);
    if (!existing) return res.status(404).json({ error: 'Integration not found' });

    const existingConfig = JSON.parse(existing.config || '{}');
    const newConfig = req.body.config !== undefined ? { ...existingConfig, ...req.body.config } : existingConfig;
    const enabled = req.body.enabled !== undefined ? (req.body.enabled ? 1 : 0) : existing.enabled;

    // Validate required config fields when enabling an integration
    if (enabled === 1) {
      if (req.params.type === 'sms') {
        const required = ['phone_number', 'account_sid', 'auth_token', 'twilio_number'];
        const missing = required.filter(f => !newConfig[f] || !String(newConfig[f]).trim());
        if (missing.length > 0) {
          return res.status(400).json({ error: `Cannot enable SMS: missing required fields: ${missing.join(', ')}` });
        }
      } else if (req.params.type === 'slack') {
        if (!newConfig.webhook_url || !String(newConfig.webhook_url).trim()) {
          return res.status(400).json({ error: 'Cannot enable Slack: webhook_url is required' });
        }
      }
    }

    const now = localNow();

    db.prepare(`
      UPDATE integrations SET enabled = ?, config = ?, updated_at = ? WHERE type = ?
    `).run(enabled, JSON.stringify(newConfig), now, req.params.type);

    res.json({ type: req.params.type, enabled, config: maskSensitiveConfig(newConfig), updated_at: now });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/integrations/test/:type — send a test message
app.post('/api/integrations/test/:type', async (req, res) => {
  try {
    const row = db.prepare(`SELECT * FROM integrations WHERE type = ?`).get(req.params.type);
    if (!row) return res.status(404).json({ error: 'Integration not found' });

    const config = JSON.parse(row.config || '{}');
    const testNotification = {
      title: 'Test from The Team',
      message: 'This is a test notification sent at ' + localNow()
    };

    if (req.params.type === 'sms') {
      if (!config.account_sid || !config.auth_token || !config.twilio_number || !config.phone_number) {
        return res.status(400).json({ error: 'SMS config incomplete. Provide account_sid, auth_token, twilio_number, and phone_number.' });
      }
      const result = await sendTwilioSms(config, testNotification.title + ': ' + testNotification.message);
      if (result.error) return res.status(500).json({ error: result.error });
      res.json({ success: true, message: 'Test SMS sent', sid: result.sid });

    } else if (req.params.type === 'slack') {
      if (!config.webhook_url) {
        return res.status(400).json({ error: 'Slack config incomplete. Provide webhook_url.' });
      }
      const result = await sendSlackMessage(config, testNotification.title, testNotification.message);
      if (result.error) return res.status(500).json({ error: result.error });
      res.json({ success: true, message: 'Test Slack message sent' });

    } else {
      res.status(400).json({ error: 'Test not supported for type: ' + req.params.type });
    }
  } catch (err) {
    console.error('POST /api/integrations/test error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/settings/auto-execute', (req, res) => {
  try {
    const { enabled } = req.body;
    const value = enabled ? '1' : '0';
    const now = localNow();
    const existing = db.prepare(`SELECT value FROM system_settings WHERE key = 'auto_execute_improvements'`).get();
    if (existing) {
      db.prepare(`UPDATE system_settings SET value = ?, updated_at = ? WHERE key = 'auto_execute_improvements'`).run(value, now);
    } else {
      db.prepare(`INSERT INTO system_settings (key, value, updated_at) VALUES ('auto_execute_improvements', ?, ?)`).run(value, now);
    }
    res.json({ auto_execute: value === '1' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/settings', (req, res) => {
  try {
    const rows = db.prepare(`SELECT key, value, updated_at FROM system_settings`).all();
    const settings = {};
    for (const r of rows) {
      if (isSensitiveSettingKey(r.key) && r.value) {
        settings[r.key] = { value: maskCredential(r.value), updated_at: r.updated_at, has_value: true };
      } else {
        settings[r.key] = { value: r.value, updated_at: r.updated_at };
      }
    }
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/settings/:key', (req, res) => {
  try {
    const row = db.prepare(`SELECT value, updated_at FROM system_settings WHERE key = ?`).get(req.params.key);
    if (!row) return res.status(404).json({ error: 'Setting not found' });
    // Mask sensitive settings by name + pattern (tokens, keys, secrets, passwords)
    if (isSensitiveSettingKey(req.params.key) && row.value) {
      return res.json({ key: req.params.key, value: maskCredential(row.value), has_value: true, updated_at: row.updated_at });
    }
    res.json({ key: req.params.key, value: row.value, updated_at: row.updated_at });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/settings/oauth-token', authRateLimiter, (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token required' });
    const now = localNow();
    const result = db.prepare(`UPDATE system_settings SET value = ?, updated_at = ? WHERE key = 'oauth_token'`).run(String(token), now);
    if (result.changes === 0) {
      db.prepare(`INSERT INTO system_settings (key, value, updated_at) VALUES ('oauth_token', ?, ?)`).run(String(token), now);
    }
    res.json({ key: 'oauth_token', value: '••••' + String(token).slice(-8), message: 'OAuth token updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /api/settings/openrouter-api-key — dedicated OpenRouter API key handler ──
app.put('/api/settings/openrouter-api-key', authRateLimiter, (req, res) => {
  try {
    const { key: apiKey } = req.body;
    if (!apiKey) return res.status(400).json({ error: 'API key required' });
    const now = localNow();
    const result = db.prepare(`UPDATE system_settings SET value = ?, updated_at = ? WHERE key = 'openrouter_api_key'`).run(String(apiKey), now);
    if (result.changes === 0) {
      db.prepare(`INSERT INTO system_settings (key, value, updated_at) VALUES ('openrouter_api_key', ?, ?)`).run(String(apiKey), now);
    }
    res.json({ key: 'openrouter_api_key', value: '••••' + String(apiKey).slice(-8), message: 'OpenRouter API key updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/settings/test-openrouter — verify OpenRouter API key works ──
app.post('/api/settings/test-openrouter', authRateLimiter, async (req, res) => {
  try {
    // Prefer key/base_url from request body (unsaved in-progress input) before falling back to DB
    const bodyKey = req.body && typeof req.body.api_key === 'string' ? req.body.api_key.trim() : '';
    const bodyBaseUrl = req.body && typeof req.body.base_url === 'string' ? req.body.base_url.trim() : '';

    let apiKeyValue = bodyKey;
    if (!apiKeyValue) {
      const apiKeyRow = db.prepare(`SELECT value FROM system_settings WHERE key = 'openrouter_api_key'`).get();
      apiKeyValue = (apiKeyRow && apiKeyRow.value) ? apiKeyRow.value : '';
    }
    if (!apiKeyValue) {
      return res.status(400).json({ success: false, error: 'No OpenRouter API key configured' });
    }
    const baseUrl = bodyBaseUrl || getCachedSetting('openrouter_base_url') || 'https://openrouter.ai/api/v1';
    const prefix = getCachedSetting('openrouter_model_prefix') || 'anthropic/';
    const testModel = prefix + 'claude-haiku-4-5-20251001';

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKeyValue}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://theteam.local',
        'X-Title': 'The Team - API Key Test'
      },
      body: JSON.stringify({
        model: testModel,
        messages: [{ role: 'user', content: 'Say "OK" and nothing else.' }],
        max_tokens: 10
      }),
      signal: controller.signal
    });

    clearTimeout(timeout);

    if (!response.ok) {
      const errBody = await response.text();
      return res.json({ success: false, error: `OpenRouter returned ${response.status}: ${errBody.slice(0, 200)}` });
    }

    const data = await response.json();
    const reply = data.choices?.[0]?.message?.content || '';
    res.json({ success: true, model: testModel, reply: reply.slice(0, 100), message: 'OpenRouter API key is valid' });
  } catch (err) {
    res.json({ success: false, error: err.name === 'AbortError' ? 'Request timed out (15s)' : err.message });
  }
});

app.put('/api/settings/:key', (req, res) => {
  try {
    const key = req.params.key;
    // Block sensitive keys — they have dedicated endpoints with rate limiting
    if (isSensitiveSettingKey(key)) {
      return res.status(403).json({ error: 'Use dedicated endpoint for sensitive settings' });
    }
    if (!WRITABLE_SETTINGS.includes(key)) {
      return res.status(403).json({ error: 'This setting cannot be modified directly' });
    }
    const { value } = req.body;
    if (value === undefined) return res.status(400).json({ error: 'Value required' });
    const now = localNow();
    const result = db.prepare(`UPDATE system_settings SET value = ?, updated_at = ? WHERE key = ?`).run(String(value), now, key);
    if (result.changes === 0) {
      db.prepare(`INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)`).run(key, String(value), now);
    }
    res.json({ key, value: String(value), message: 'Setting updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/llm/providers — list all providers (api_key masked)
app.get('/api/llm/providers', (req, res) => {
  try {
    const rows = db.prepare('SELECT * FROM llm_providers ORDER BY created_at DESC').all();
    const masked = rows.map(r => ({
      ...r,
      api_key: maskApiKey(r.api_key),
      config: JSON.parse(r.config || '{}')
    }));
    res.json(masked);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/llm/providers/:id — single provider (api_key masked)
app.get('/api/llm/providers/:id', (req, res) => {
  try {
    const row = db.prepare('SELECT * FROM llm_providers WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Provider not found' });
    res.json({
      ...row,
      api_key: maskApiKey(row.api_key),
      config: JSON.parse(row.config || '{}')
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/llm/providers — create a provider
app.post('/api/llm/providers', (req, res) => {
  try {
    const { name, type, base_url, api_key, default_model, config } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'name is required' });
    if (!type || !['claude', 'openai', 'ollama', 'perplexity', 'custom'].includes(type)) {
      return res.status(400).json({ error: 'type must be one of: claude, openai, ollama, perplexity, custom' });
    }
    const now = localNow();
    const configStr = JSON.stringify(config || {});
    const result = db.prepare(`
      INSERT INTO llm_providers (name, type, base_url, api_key, default_model, enabled, config, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
    `).run(name.trim(), type, base_url || null, api_key || null, default_model || null, configStr, now, now);
    res.json({
      id: Number(result.lastInsertRowid),
      name: name.trim(),
      type,
      base_url: base_url || null,
      api_key: maskApiKey(api_key || null),
      default_model: default_model || null,
      enabled: 1,
      config: config || {},
      created_at: now,
      updated_at: now
    });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint')) {
      return res.status(409).json({ error: 'A provider with that name already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/llm/providers/:id — update any fields
app.put('/api/llm/providers/:id', (req, res) => {
  try {
    const existing = db.prepare('SELECT * FROM llm_providers WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Provider not found' });

    const fields = ['name', 'type', 'base_url', 'api_key', 'default_model', 'enabled', 'config'];
    const updates = [];
    const values = [];
    for (const f of fields) {
      if (req.body[f] !== undefined) {
        if (f === 'type' && !['claude', 'openai', 'ollama', 'perplexity', 'custom'].includes(req.body[f])) {
          return res.status(400).json({ error: 'type must be one of: claude, openai, ollama, perplexity, custom' });
        }
        if (f === 'config') {
          updates.push('config = ?');
          values.push(JSON.stringify(req.body[f]));
        } else if (f === 'enabled') {
          updates.push('enabled = ?');
          values.push(req.body[f] ? 1 : 0);
        } else {
          updates.push(`${f} = ?`);
          values.push(req.body[f]);
        }
      }
    }
    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    updates.push('updated_at = ?');
    values.push(localNow());
    values.push(req.params.id);

    db.prepare(`UPDATE llm_providers SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    const updated = db.prepare('SELECT * FROM llm_providers WHERE id = ?').get(req.params.id);
    res.json({
      ...updated,
      api_key: maskApiKey(updated.api_key),
      config: JSON.parse(updated.config || '{}')
    });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint')) {
      return res.status(409).json({ error: 'A provider with that name already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/llm/providers/:id
app.delete('/api/llm/providers/:id', (req, res) => {
  try {
    const result = db.prepare('DELETE FROM llm_providers WHERE id = ?').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Provider not found' });
    res.json({ message: 'Provider deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/llm/providers/:id/test — test the connection
app.post('/api/llm/providers/:id/test', (req, res) => {
  try {
    const provider = db.prepare('SELECT * FROM llm_providers WHERE id = ?').get(req.params.id);
    if (!provider) return res.status(404).json({ error: 'Provider not found' });

    let testUrl, headers = {};

    if (provider.type === 'ollama') {
      const base = (provider.base_url || 'http://localhost:11434').replace(/\/$/, '');
      testUrl = base + '/api/tags';
    } else if (provider.type === 'claude') {
      testUrl = 'https://api.anthropic.com/v1/models';
      headers['x-api-key'] = provider.api_key || '';
      headers['anthropic-version'] = '2023-06-01';
    } else {
      // openai or custom
      const base = (provider.base_url || 'https://api.openai.com').replace(/\/$/, '');
      testUrl = base + '/v1/models';
      if (provider.api_key) {
        headers['Authorization'] = 'Bearer ' + provider.api_key;
      }
    }

    const parsed = new URL(testUrl);
    const transport = parsed.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: { ...headers, 'Content-Type': 'application/json' },
      timeout: 10000
    };

    const testReq = transport.request(options, (testRes) => {
      let body = '';
      testRes.on('data', chunk => { body += chunk; });
      testRes.on('end', () => {
        if (testRes.statusCode >= 200 && testRes.statusCode < 300) {
          let models = [];
          try {
            const data = JSON.parse(body);
            if (provider.type === 'ollama' && Array.isArray(data.models)) {
              models = data.models.map(m => m.name || m.model);
            } else if (Array.isArray(data.data)) {
              models = data.data.map(m => m.id);
            } else if (Array.isArray(data)) {
              models = data.map(m => m.id || m.name || m);
            }
          } catch (e) {
            // body may not be JSON, that's okay for a health check
          }
          res.json({ success: true, status: testRes.statusCode, models });
        } else {
          res.json({ success: false, status: testRes.statusCode, error: body.slice(0, 500) });
        }
      });
    });

    testReq.on('error', (err) => {
      res.json({ success: false, error: err.message });
    });

    testReq.on('timeout', () => {
      testReq.destroy();
      res.json({ success: false, error: 'Connection timed out' });
    });

    testReq.end();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/llm/usage — usage stats, filterable
app.get('/api/llm/usage', (req, res) => {
  try {
    const conditions = [];
    const values = [];
    if (req.query.member_id) { conditions.push('u.member_id = ?'); values.push(req.query.member_id); }
    if (req.query.provider_id) { conditions.push('u.provider_id = ?'); values.push(req.query.provider_id); }
    if (req.query.date) { conditions.push("date(u.created_at) = ?"); values.push(req.query.date); }
    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
    const rows = db.prepare(`
      SELECT u.*, p.name as provider_name, p.type as provider_type,
             m.name as member_name
      FROM llm_usage u
      LEFT JOIN llm_providers p ON u.provider_id = p.id
      LEFT JOIN team_members m ON u.member_id = m.id
      ${where}
      ORDER BY u.created_at DESC
      LIMIT 500
    `).all(...values);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/llm/usage/summary — aggregate stats
app.get('/api/llm/usage/summary', (req, res) => {
  try {
    const totals = db.prepare(`
      SELECT COUNT(*) as total_requests,
             COALESCE(SUM(prompt_tokens), 0) as total_prompt_tokens,
             COALESCE(SUM(completion_tokens), 0) as total_completion_tokens,
             COALESCE(SUM(total_tokens), 0) as total_tokens,
             COALESCE(SUM(cost_estimate), 0) as total_cost,
             COALESCE(AVG(latency_ms), 0) as avg_latency_ms
      FROM llm_usage
    `).get();

    const byProvider = db.prepare(`
      SELECT p.id, p.name, p.type,
             COUNT(*) as requests,
             COALESCE(SUM(u.total_tokens), 0) as tokens,
             COALESCE(SUM(u.cost_estimate), 0) as cost
      FROM llm_usage u
      LEFT JOIN llm_providers p ON u.provider_id = p.id
      GROUP BY u.provider_id
      ORDER BY tokens DESC
    `).all();

    const byMember = db.prepare(`
      SELECT m.id, m.name,
             COUNT(*) as requests,
             COALESCE(SUM(u.total_tokens), 0) as tokens,
             COALESCE(SUM(u.cost_estimate), 0) as cost
      FROM llm_usage u
      LEFT JOIN team_members m ON u.member_id = m.id
      GROUP BY u.member_id
      ORDER BY tokens DESC
    `).all();

    res.json({ totals, by_provider: byProvider, by_member: byMember });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/llm/usage — log a usage entry
app.post('/api/llm/usage', (req, res) => {
  try {
    const { provider_id, model, member_id, task_id, prompt_tokens, completion_tokens,
            total_tokens, latency_ms, cost_estimate, is_local } = req.body;
    if (!model || !model.trim()) return res.status(400).json({ error: 'model is required' });

    const result = db.prepare(`
      INSERT INTO llm_usage (provider_id, model, member_id, task_id, prompt_tokens, completion_tokens,
                             total_tokens, latency_ms, cost_estimate, is_local, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      provider_id || null, model.trim(), member_id || null, task_id || null,
      prompt_tokens || 0, completion_tokens || 0, total_tokens || 0,
      latency_ms || 0, cost_estimate || 0, is_local ? 1 : 0, localNow()
    );
    res.json({ id: Number(result.lastInsertRowid), message: 'Usage logged' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/credentials', (req, res, next) => {
  try {
    const rows = db.prepare('SELECT * FROM credential_vault ORDER BY created_at DESC').all();
    const masked = rows.map(r => ({
      id: r.id,
      name: r.name,
      provider: r.provider,
      key_preview: r.encrypted_value
        ? '...' + r.encrypted_value.slice(-4)
        : '...????',
      created_at: r.created_at
    }));
    res.json(masked);
  } catch (err) { next(err); }
});

// GET /api/vault — list all saved credentials (masked values only)
app.get('/api/vault', (req, res, next) => {
  try {
    const rows = db.prepare('SELECT * FROM credential_vault ORDER BY created_at DESC').all();
    const masked = rows.map(r => ({
      ...r,
      encrypted_value: maskCredential(r.encrypted_value),
      metadata: JSON.parse(r.metadata || '{}')
    }));
    res.json(masked);
  } catch (err) { next(err); }
});

// GET /api/vault/:id — single credential (masked value)
app.get('/api/vault/:id', (req, res, next) => {
  try {
    const row = db.prepare('SELECT * FROM credential_vault WHERE id = ?').get(req.params.id);
    if (!row) throw notFound('Credential not found');
    row.encrypted_value = maskCredential(row.encrypted_value);
    row.metadata = JSON.parse(row.metadata || '{}');
    res.json(row);
  } catch (err) { next(err); }
});

// GET /api/vault/:id/value — returns the FULL unmasked value (for agents to use internally)
// SECURITY: Restricted to localhost only — this endpoint must never be reachable from the network.
app.get('/api/vault/:id/value', authRateLimiter, (req, res, next) => {
  try {
    const ip = req.ip || req.socket.remoteAddress || '';
    const isLocal = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
    if (!isLocal) {
      return res.status(403).json({ error: 'This endpoint is only accessible from localhost' });
    }
    const row = db.prepare('SELECT id, name, provider, credential_type, encrypted_value FROM credential_vault WHERE id = ?').get(req.params.id);
    if (!row) throw notFound('Credential not found');
    res.json({ id: row.id, name: row.name, provider: row.provider, credential_type: row.credential_type, value: row.encrypted_value });
  } catch (err) { next(err); }
});

// POST /api/vault — save a new credential
app.post('/api/vault', authRateLimiter, (req, res, next) => {
  try {
    const { name, provider, credential_type, value, metadata } = req.body;
    if (!name || !name.trim()) throw badRequest('name is required');
    if (!provider || !provider.trim()) throw badRequest('provider is required');
    if (!value || !value.trim()) throw badRequest('value is required');
    const now = localNow();
    const metaStr = JSON.stringify(metadata || {});
    const result = db.prepare(`
      INSERT INTO credential_vault (name, provider, credential_type, encrypted_value, metadata, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(name.trim(), provider.trim(), (credential_type || 'api_key').trim(), value.trim(), metaStr, now, now);
    res.json({
      id: Number(result.lastInsertRowid),
      name: name.trim(),
      provider: provider.trim(),
      credential_type: (credential_type || 'api_key').trim(),
      encrypted_value: maskCredential(value.trim()),
      metadata: metadata || {},
      created_at: now,
      updated_at: now
    });
  } catch (err) { next(err); }
});

// PUT /api/vault/:id — update a credential's value or metadata
app.put('/api/vault/:id', authRateLimiter, (req, res, next) => {
  try {
    const existing = db.prepare('SELECT * FROM credential_vault WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Credential not found' });

    const { name, provider, credential_type, value, metadata } = req.body;
    const now = localNow();
    const fields = [];
    const vals = [];

    if (name !== undefined) { fields.push('name = ?'); vals.push(name); }
    if (provider !== undefined) { fields.push('provider = ?'); vals.push(provider); }
    if (credential_type !== undefined) { fields.push('credential_type = ?'); vals.push(credential_type); }
    if (value !== undefined) { fields.push('encrypted_value = ?'); vals.push(value); }
    if (metadata !== undefined) { fields.push('metadata = ?'); vals.push(typeof metadata === 'string' ? metadata : JSON.stringify(metadata)); }

    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    fields.push('updated_at = ?'); vals.push(now); vals.push(req.params.id);
    db.prepare('UPDATE credential_vault SET ' + fields.join(', ') + ' WHERE id = ?').run(...vals);

    res.json({ message: 'Credential updated' });
  } catch (err) { next(err); }
});

// DELETE /api/vault/:id — delete a credential (also unlinks from member_tools)
app.delete('/api/vault/:id', authRateLimiter, (req, res, next) => {
  try {
    // Unlink any member_tools referencing this vault entry
    db.prepare('UPDATE member_tools SET vault_id = NULL WHERE vault_id = ?').run(req.params.id);
    const result = db.prepare('DELETE FROM credential_vault WHERE id = ?').run(req.params.id);
    if (result.changes === 0) throw notFound('Credential not found');
    res.json({ message: 'Credential deleted' });
  } catch (err) { next(err); }
});

// GET /api/settings/default-page — get default landing page
app.get('/api/settings/default-page', (req, res, next) => {
  try {
    const row = db.prepare(`SELECT value FROM system_settings WHERE key = 'default_page'`).get();
    res.json({ default_page: row ? row.value : 'dashboard' });
  } catch (err) { next(err); }
});

// PUT /api/settings/peer_review_enabled — toggle peer review on/off
app.put('/api/settings/peer_review_enabled', (req, res) => {
  try {
    const { value } = req.body;
    if (value === undefined) return res.status(400).json({ error: 'value required' });
    const now = localNow();
    db.prepare('UPDATE system_settings SET value = ?, updated_at = ? WHERE key = ?').run(String(value), now, 'peer_review_enabled');
    invalidateCache('system_settings');
    res.json({ key: 'peer_review_enabled', value: String(value), updated_at: now });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


};
