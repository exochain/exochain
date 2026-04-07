# Nemotron Cascade 2 — vLLM Integration Plan
**Author:** Onyx (CTO) with Neural (ML Specialist) research  
**Date:** 2026-04-04  
**Hardware:** NVIDIA DGX Spark — GB10 Grace Blackwell, 128 GB unified LPDDR5x  
**Model:** Nemotron Cascade 2 (NVIDIA) via vLLM on port 8901 (OpenAI-compatible API)  
**Status:** IMPLEMENTATION READY

---

## Overview

The DGX Spark ships with Nemotron Cascade 2 pre-installed or available via NVIDIA NGC. vLLM is the inference engine — it exposes an OpenAI-compatible REST API. The integration adds:

1. A `nemotron_local` adapter in `server.js` — routes text-generation tasks to the local model
2. A `callLocalLLM()` helper — general-purpose OpenAI-compatible wrapper with fallback to Claude API  
3. A circuit breaker in `services/heartbeat.js` — monitors vLLM health and flips `local_llm_available`

The goal: **60–80% reduction in Claude API token spend** by routing non-agentic tasks locally.

---

## Part 1: vLLM Setup on DGX (if not pre-installed)

### 1.1 Verify vLLM is running

```bash
# Check if vLLM is already running on port 8901
curl http://localhost:8901/v1/models
# Expected: {"object":"list","data":[{"id":"nvidia/Nemotron-Cascade-2-15B",...}]}

# If not running, check if vLLM is installed
vllm --version
# or: python -c "import vllm; print(vllm.__version__)"
```

### 1.2 Install vLLM (if needed)

```bash
# DGX OS 7 ships with CUDA 12.x and cuDNN — vLLM installs cleanly
pip install vllm

# Or via conda (DGX may have conda pre-installed)
conda install -c nvidia vllm
```

### 1.3 Start vLLM with Nemotron Cascade 2

```bash
# Start vLLM server on port 8901 (OpenAI-compatible)
# --gpu-memory-utilization 0.7 leaves 30% for OS + app + Ollama
python -m vllm.entrypoints.openai.api_server \
  --model nvidia/Nemotron-Cascade-2-15B \
  --port 8901 \
  --host 0.0.0.0 \
  --gpu-memory-utilization 0.70 \
  --max-model-len 32768 \
  --dtype auto \
  --served-model-name "nvidia/Nemotron-Cascade-2-15B"

# To run in background persistently:
nohup python -m vllm.entrypoints.openai.api_server \
  --model nvidia/Nemotron-Cascade-2-15B \
  --port 8901 \
  --host 0.0.0.0 \
  --gpu-memory-utilization 0.70 \
  --max-model-len 32768 \
  --dtype auto \
  --served-model-name "nvidia/Nemotron-Cascade-2-15B" \
  > /var/log/vllm-nemotron.log 2>&1 &

echo "vLLM PID: $!"
```

### 1.4 Create a systemd service for vLLM (recommended)

Create `/etc/systemd/system/vllm-nemotron.service`:

```ini
[Unit]
Description=vLLM — Nemotron Cascade 2 inference server
After=network.target

[Service]
Type=simple
User=max
WorkingDirectory=/opt/command-base
ExecStart=/usr/bin/python3 -m vllm.entrypoints.openai.api_server \
    --model nvidia/Nemotron-Cascade-2-15B \
    --port 8901 \
    --host 0.0.0.0 \
    --gpu-memory-utilization 0.70 \
    --max-model-len 32768 \
    --dtype auto \
    --served-model-name nvidia/Nemotron-Cascade-2-15B
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
# Give the model time to load (large model warm-up)
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable vllm-nemotron
sudo systemctl start vllm-nemotron
sudo systemctl status vllm-nemotron
```

### 1.5 Test the endpoint

```bash
# List available models
curl http://localhost:8901/v1/models | python3 -m json.tool

# Test inference — OpenAI-compatible chat completions
curl http://localhost:8901/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "nvidia/Nemotron-Cascade-2-15B",
    "messages": [
      {"role": "user", "content": "Reply with exactly one word: READY"}
    ],
    "max_tokens": 10,
    "temperature": 0.1
  }'

# Expected response:
# {"choices":[{"message":{"content":"READY",...},...}],...}

# Test from inside Docker container
docker exec command-base curl http://host.docker.internal:8901/v1/models
```

### 1.6 Firewall (allow Docker bridge to reach vLLM)

```bash
# Docker containers use 172.17.0.0/16 by default
sudo ufw allow from 172.17.0.0/16 to any port 8901 comment 'vLLM from Docker'

# Block external access to vLLM (local inference only)
sudo ufw deny 8901/tcp comment 'Block external vLLM access'
sudo ufw allow from 127.0.0.1 to any port 8901 comment 'vLLM localhost'
```

---

## Part 2: Task Routing Strategy

### Which tasks go local vs Claude API

| Task Type | Route To | Why |
|-----------|----------|-----|
| Board decisions, ExoChain governance | Claude API | Maximum reasoning required |
| Security specialists (Lock, Threat, Breach) | Claude API | No hallucinated security advice |
| Code generation, file editing, debugging | Claude CLI | Requires tool use (Read/Edit/Bash) |
| Architecture design, complex multi-file work | Claude CLI | Local 15B models insufficient |
| Text summarization, content writing | **Nemotron local** | High quality, no tool use needed |
| Routing decisions, task classification | **Nemotron local** | Fast, lightweight |
| Tag extraction, notification generation | **Nemotron local** | Structured output, short context |
| Data analysis (text-based) | **Nemotron local** | Summarization task |
| Research summaries, reports | **Nemotron local** | No tools needed for text synthesis |

**Rule of thumb:** If it requires **tool use** (read files, run commands, edit code) → Claude CLI. If it's **pure text generation** → Nemotron local.

### Task classification function (for integration in server.js)

```javascript
// Place near the top of server.js or in a lib/llm-router.js module
function classifyLLMRoute(task) {
  const combined = ((task.title || '') + ' ' + (task.description || '')).toLowerCase();

  // Always use Claude API
  const alwaysApi = [
    'governance', 'exochain', 'board decision', 'constitutional',
    'security audit', 'penetration test', 'threat model',
    'authentication', 'access control'
  ];
  if (alwaysApi.some(kw => combined.includes(kw))) return 'api';
  if (task.priority === 'urgent' && (task.description || '').length > 1000) return 'api';

  // Always use Claude CLI (needs tool use)
  const needsTools = [
    'write code', 'edit file', 'fix bug', 'implement', 'build',
    'run test', 'debug', 'deploy', 'configure', 'install',
    'create file', 'modify', 'refactor', 'database migration'
  ];
  if (needsTools.some(kw => combined.includes(kw))) return 'claude_cli';

  // Suitable for local LLM (pure text generation)
  const localSuitable = [
    'summarize', 'classify', 'route', 'analyze text', 'review content',
    'write content', 'draft', 'describe', 'explain', 'generate report',
    'extract tags', 'create notification', 'write email', 'blog post'
  ];
  if (localSuitable.some(kw => combined.includes(kw))) return 'local';

  return 'claude_cli'; // safe default
}
```

---

## Part 3: Code Integration

### 3.1 callLocalLLM helper (add to server.js near line 14841)

This is the drop-in wrapper that targets the vLLM OpenAI-compatible endpoint.

```javascript
// ── Local LLM wrapper (vLLM / OpenAI-compatible) ─────────────────
// Targets: Nemotron Cascade 2 on port 8901 (or Ollama on 11434)
// Falls back to Claude API if local is unavailable or returns an error.

const LOCAL_LLM_CONFIG = {
  baseUrl: process.env.LOCAL_LLM_BASE_URL || 'http://localhost:8901/v1',
  model:   process.env.LOCAL_LLM_MODEL    || 'nvidia/Nemotron-Cascade-2-15B',
  timeout: parseInt(process.env.LOCAL_LLM_TIMEOUT_MS || '120000', 10),
};

// In-memory circuit breaker state
const _localLLMBreaker = {
  failures: 0,
  lastFailure: 0,
  open: false,         // true = skip local, go straight to API
  THRESHOLD: 3,        // failures before opening
  RESET_MS: 5 * 60_000 // 5 minutes before retry
};

function _checkLocalLLMBreaker() {
  if (!_localLLMBreaker.open) return false;
  if (Date.now() - _localLLMBreaker.lastFailure > _localLLMBreaker.RESET_MS) {
    _localLLMBreaker.open = false;
    _localLLMBreaker.failures = 0;
    console.log('[LocalLLM] Circuit breaker reset — retrying local inference');
    return false;
  }
  return true; // still open
}

function _recordLocalLLMFailure() {
  _localLLMBreaker.failures++;
  _localLLMBreaker.lastFailure = Date.now();
  if (_localLLMBreaker.failures >= _localLLMBreaker.THRESHOLD) {
    if (!_localLLMBreaker.open) {
      console.warn('[LocalLLM] Circuit breaker OPEN — routing all calls to Claude API');
      // Update system_settings so other parts of the app know
      try {
        db.prepare("UPDATE system_settings SET value = '0', updated_at = datetime('now') WHERE key = 'local_llm_available'")
          .run();
      } catch (e) { /* non-fatal */ }
    }
    _localLLMBreaker.open = true;
  }
}

function _recordLocalLLMSuccess() {
  _localLLMBreaker.failures = 0;
  if (_localLLMBreaker.open) {
    _localLLMBreaker.open = false;
    try {
      db.prepare("UPDATE system_settings SET value = '1', updated_at = datetime('now') WHERE key = 'local_llm_available'")
        .run();
    } catch (e) { /* non-fatal */ }
    console.log('[LocalLLM] Circuit breaker CLOSED — local inference restored');
  }
}

/**
 * callLocalLLM — send a prompt to the local vLLM/Nemotron endpoint.
 * Falls back to Claude API if local is down or circuit breaker is open.
 *
 * @param {string} prompt
 * @param {object} opts
 *   @param {string}  opts.systemPrompt   - Optional system prompt
 *   @param {number}  opts.maxTokens      - Max completion tokens (default 2048)
 *   @param {number}  opts.temperature    - Sampling temperature (default 0.2)
 *   @param {boolean} opts.forceLocal     - Skip fallback, error if local fails
 *   @param {string}  opts.taskId         - For logging
 * @returns {Promise<{text: string, source: 'local'|'api', model: string}>}
 */
async function callLocalLLM(prompt, opts = {}) {
  const localEnabled = process.env.LOCAL_LLM_ENABLED !== 'false';
  const breakerOpen = _checkLocalLLMBreaker();

  // ── Attempt local inference ─────────────────────────────────────
  if (localEnabled && !breakerOpen) {
    try {
      const messages = [];
      if (opts.systemPrompt) {
        messages.push({ role: 'system', content: opts.systemPrompt });
      }
      messages.push({ role: 'user', content: prompt });

      const body = JSON.stringify({
        model: LOCAL_LLM_CONFIG.model,
        messages,
        max_tokens: opts.maxTokens || 2048,
        temperature: opts.temperature !== undefined ? opts.temperature : 0.2,
        stream: false,
      });

      const url = new URL(`${LOCAL_LLM_CONFIG.baseUrl}/chat/completions`);
      const httpMod = url.protocol === 'https:' ? require('https') : require('http');

      const result = await new Promise((resolve, reject) => {
        const req = httpMod.request(
          url.href,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(body),
            },
            timeout: LOCAL_LLM_CONFIG.timeout,
          },
          (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => resolve({ status: res.statusCode, body: data }));
          }
        );
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('vLLM timeout')); });
        req.write(body);
        req.end();
      });

      if (result.status !== 200) {
        throw new Error(`vLLM HTTP ${result.status}: ${result.body.slice(0, 200)}`);
      }

      const json = JSON.parse(result.body);
      const text = json.choices?.[0]?.message?.content || json.choices?.[0]?.text || '';
      if (!text) throw new Error('vLLM returned empty response');

      _recordLocalLLMSuccess();
      return { text, source: 'local', model: LOCAL_LLM_CONFIG.model };

    } catch (localErr) {
      console.warn(`[callLocalLLM] Local inference failed: ${localErr.message}. Falling back to Claude API.`);
      _recordLocalLLMFailure();
      if (opts.forceLocal) throw localErr;
      // Fall through to API
    }
  }

  // ── Fallback: Claude API ────────────────────────────────────────
  if (!anthropic) {
    throw new Error('Both local LLM and Claude API unavailable (no ANTHROPIC_API_KEY)');
  }

  const messages = [];
  if (opts.systemPrompt) {
    messages.push({ role: 'user', content: `${opts.systemPrompt}\n\n${prompt}` });
  } else {
    messages.push({ role: 'user', content: prompt });
  }

  const response = await anthropic.messages.create({
    model: process.env.autonomous_model_complex || 'claude-sonnet-4-6',
    max_tokens: opts.maxTokens || 4096,
    messages,
  });

  return {
    text: response.content[0].text,
    source: 'api',
    model: response.model,
  };
}
```

### 3.2 ollama_local adapter (for Scaffold's spawn system — from dgx-scaffold-spawn-adaptation.md)

Add to server.js dispatch block near line 15342 (after gemini_local, before Claude block):

```javascript
// ── ollama_local / nemotron_local adapter ──────────────────────
if (adapterType === 'ollama_local' || adapterType === 'nemotron_local') {
  const baseUrl = adapterConfig.base_url ||
    (adapterType === 'nemotron_local'
      ? 'http://host.docker.internal:8901/v1/chat/completions'
      : 'http://host.docker.internal:11434/api/chat');
  callLocalModelAdapter(taskId, processId, memberId, member, task, adapterConfig, prompt, baseUrl);
  return { success: true, process_id: processId, member_name: member.name, mode: adapterType };
}
```

Full `callLocalModelAdapter` function to add near `callHttpAdapter`:

```javascript
async function callLocalModelAdapter(taskId, processId, memberId, member, task, adapterConfig, prompt, baseUrl) {
  const model = adapterConfig.model || LOCAL_LLM_CONFIG.model;
  const isOpenAICompat = baseUrl.includes('/v1/');

  // Build request body for either vLLM (OpenAI-compat) or Ollama native
  const body = JSON.stringify(isOpenAICompat ? {
    model,
    messages: [{ role: 'user', content: prompt }],
    max_tokens: adapterConfig.max_tokens || 4096,
    temperature: 0.3,
    stream: false,
  } : {
    model,
    messages: [{ role: 'user', content: prompt }],
    stream: false,
    options: { temperature: 0.3, num_predict: adapterConfig.max_tokens || 4096 },
  });

  try {
    const parsedUrl = new URL(baseUrl);
    const httpMod = parsedUrl.protocol === 'https:' ? https : http;

    const result = await new Promise((resolve, reject) => {
      const req = httpMod.request(baseUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
        timeout: adapterConfig.timeout_ms || 120000,
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Local model timeout')); });
      req.write(body);
      req.end();
    });

    const finishedAt = localNow();

    if (result.status === 200) {
      const parsed = JSON.parse(result.body);
      // OpenAI-compat: choices[0].message.content; Ollama native: message.content or response
      const output =
        parsed.choices?.[0]?.message?.content ||
        parsed.message?.content ||
        parsed.response ||
        '';
      handleSpawnSuccess(taskId, processId, member, task, 'local_model', output, finishedAt);
    } else {
      db.prepare(`UPDATE active_processes SET status = 'failed', completed_at = ?, output_summary = ? WHERE id = ?`)
        .run(finishedAt, `Local model HTTP ${result.status}: ${result.body.slice(0, 200)}`, processId);
      broadcast('process.failed', { process_id: processId, task_id: taskId, error: `local_model_${result.status}` });
    }

  } catch (err) {
    db.prepare(`UPDATE active_processes SET status = 'failed', completed_at = ?, output_summary = ? WHERE id = ?`)
      .run(localNow(), `Local model unavailable: ${err.message}`, processId);
    broadcast('process.failed', { process_id: processId, task_id: taskId, error: 'local_model_unavailable' });
  }
}
```

### 3.3 Assign team members to Nemotron (SQL — run after deploy)

Start conservative — text-focused members only:

```sql
-- Assign text/content specialists to Nemotron Cascade 2 via vLLM
UPDATE team_members
SET adapter_type = 'nemotron_local',
    adapter_config = '{"base_url":"http://host.docker.internal:8901/v1/chat/completions","model":"nvidia/Nemotron-Cascade-2-15B","max_tokens":4096,"timeout_ms":120000}'
WHERE name IN ('Prose', 'Echo', 'Ink');

-- Light routing/classification tasks
UPDATE team_members
SET adapter_type = 'nemotron_local',
    adapter_config = '{"base_url":"http://host.docker.internal:8901/v1/chat/completions","model":"nvidia/Nemotron-Cascade-2-15B","max_tokens":1024,"timeout_ms":60000}'
WHERE name IN ('Triage', 'Anchor');

-- Verify assignments
SELECT name, role, adapter_type FROM team_members
WHERE adapter_type IN ('nemotron_local', 'ollama_local')
ORDER BY name;
```

**Keep ALL engineering/code specialists on `claude_local`** (they need tool use):
- Alloy, Strut, Clamp, Flare, Frame, Fret, Pulse, Bind, Render, Query, Mortar, Hook, Crank
- Any specialist touching code, database, Docker, infrastructure

### 3.4 Add heartbeat monitoring for vLLM

Add to `services/heartbeat.js` — periodic health check for vLLM:

```javascript
// ── vLLM / Nemotron health check ──────────────────────────────────
let _vllmFailures = 0;
const VLLM_URL = process.env.LOCAL_LLM_BASE_URL || 'http://localhost:8901/v1';

async function checkVllmHealth() {
  try {
    const resp = await fetch(`${VLLM_URL}/models`, {
      signal: AbortSignal.timeout(5000),
    });
    if (resp.ok) {
      if (_vllmFailures > 0) {
        console.log('[Heartbeat] vLLM recovered');
        db.prepare("UPDATE system_settings SET value = '1' WHERE key = 'local_llm_available'").run();
        db.prepare(`INSERT INTO notifications (type, title, message, read, created_at)
          VALUES ('system', 'Local LLM restored', 'Nemotron/vLLM is back online', 0, datetime('now'))`).run();
      }
      _vllmFailures = 0;
      return true;
    }
    throw new Error(`HTTP ${resp.status}`);
  } catch (err) {
    _vllmFailures++;
    if (_vllmFailures >= 3) {
      db.prepare("UPDATE system_settings SET value = '0' WHERE key = 'local_llm_available'").run();
      if (_vllmFailures === 3) {
        // Create notification once, not on every check
        db.prepare(`INSERT INTO notifications (type, title, message, read, created_at)
          VALUES ('system', 'Local LLM offline', 'vLLM/Nemotron unreachable — falling back to Claude API', 0, datetime('now'))`).run();
        console.warn('[Heartbeat] vLLM offline — circuit breaker open, falling back to Claude API');
      }
    }
    return false;
  }
}

// Add to your heartbeat interval (runs every 60s):
// setInterval(checkVllmHealth, 60_000);
```

---

## Part 4: Migration Checklist

### Day 1 — DGX arrives

- [ ] SSH into DGX: `ssh max@dgx-spark`
- [ ] Run deployment script: `./deploy-to-dgx.sh`
- [ ] Verify app running: `curl http://localhost:3000/health`
- [ ] Check vLLM status: `curl http://localhost:8901/v1/models`
- [ ] If vLLM not running: `sudo systemctl start vllm-nemotron`
- [ ] Test vLLM inference (test curl from Section 1.5)
- [ ] Test from inside container: `docker exec command-base curl http://host.docker.internal:8901/v1/models`

### Phase 1 — Enable local routing (assign text members)

- [ ] Run SQL from Section 3.3 to assign Prose, Echo, Ink to nemotron_local
- [ ] Monitor `active_processes` for completion and quality for 24 hours
  ```sql
  SELECT ap.*, tm.name FROM active_processes ap
  JOIN team_members tm ON ap.member_id = tm.id
  WHERE tm.adapter_type = 'nemotron_local'
  ORDER BY ap.created_at DESC LIMIT 20;
  ```
- [ ] Compare output quality to Claude baseline

### Phase 2 — Expand if quality is good (after 1 week)

- [ ] Add Triage, Anchor to nemotron_local
- [ ] Monitor revision rates for nemotron-handled tasks
  ```sql
  SELECT t.status, t.revision_count, tm.adapter_type
  FROM tasks t
  JOIN task_assignments ta ON ta.task_id = t.id
  JOIN team_members tm ON tm.id = ta.member_id
  WHERE t.created_at > datetime('now', '-7 days')
  GROUP BY tm.adapter_type;
  ```

### Phase 3 — Code integration (requires Alloy)

- [ ] Add `callLocalLLM()` function to server.js (Section 3.1)
- [ ] Add `callLocalModelAdapter()` + dispatch case (Section 3.2)
- [ ] Add `checkVllmHealth()` to heartbeat service (Section 3.4)
- [ ] Add `local_llm_available` to `system_settings` table:
  ```sql
  INSERT OR IGNORE INTO system_settings (key, value)
  VALUES ('local_llm_available', '1');
  ```

---

## Cost Projection

Based on Neural's analysis (see `dgx-neural-local-llm.md`):

| Scenario | Monthly API Cost |
|----------|-----------------|
| Before (all Claude API) | ~$652 |
| After Phase 1 (text members local) | ~$520 |
| After Phase 2 (all eligible tasks local) | ~$130 |
| Electricity cost (vLLM at ~60W) | ~$3 |
| **Net monthly savings** | **~$519** |

Payback period on DGX hardware: **6–8 months**

---

## Dependency Map

```
nemotron-vllm-integration.md (THIS PLAN)
    │
    ├── REQUIRES: deploy-to-dgx.sh (app deployed, container running)
    ├── REQUIRES: docker-compose.dgx.yml (extra_hosts configured)
    │
    ├── PHASE 1 ONLY: No code changes — SQL adapter assignment
    │
    └── PHASE 3 (code changes):
        ├── Alloy: add callLocalLLM() + callLocalModelAdapter() to server.js
        ├── Query: add local_llm_available to system_settings
        └── Vigil (heartbeat): add checkVllmHealth() to services/heartbeat.js
```

---

*Owning executive: Onyx (CTO)*  
*Implementation owner: Alloy (server.js), Neural (model tuning), Vigil (monitoring)*
