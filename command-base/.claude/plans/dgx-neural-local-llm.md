# DGX Spark Local LLM Integration Plan
**Author:** Neural (ML Specialist)  
**Commissioned by:** Bower (SVP Product)  
**Date:** 2026-04-04  
**Hardware:** NVIDIA DGX Spark — GB10 Grace Blackwell Superchip, 128 GB unified LPDDR5x  
**OS:** Ubuntu 24.04 (DGX OS 7)  
**Status:** PLANNING — implementation pending Board approval

---

## Executive Summary

The DGX Spark presents a compelling opportunity to run high-quality open-weight models locally at near-zero marginal cost per inference. With 128 GB of unified memory shared between the CPU and the Blackwell GPU, models up to ~70B parameters (quantized) fit comfortably without page thrashing. This plan defines a tiered routing strategy that keeps Claude API for tasks that genuinely require it while offloading the large majority of routine work to local models, projecting 60–75% reduction in monthly API spend.

---

## 1. Model Recommendations

### Memory Budget

The GB10 has 128 GB of unified LPDDR5x. The OS and application layer consume roughly 8–12 GB at idle on Ubuntu 24.04. Ollama itself holds the model in VRAM-equivalent space within the unified pool. Practical ceiling for a single resident model: **~110 GB** (leaving OS + swap headroom).

| Tier | Use Case | Recommended Model | Quantization | Est. Memory Usage | Fits? |
|------|----------|-------------------|-------------|-------------------|-------|
| Heavy | Board decisions, architecture, complex multi-step code | **Claude API (Sonnet/Opus)** | N/A — API call | N/A | N/A |
| Medium-Heavy | Complex routing, long-context analysis, code review | **Llama 3.3 70B Instruct** | Q4_K_M | ~42 GB | Yes |
| Medium | Data analysis, summarization, mid-complexity code tasks | **Llama 3.1 70B Instruct** | Q4_K_M | ~40 GB | Yes |
| Light | Routing decisions, simple queries, text formatting, classification | **Qwen2.5 14B Instruct** | Q5_K_M | ~10 GB | Yes |
| Micro | Triage, tag extraction, yes/no classification, simple routing | **Mistral 7B Instruct v0.3** or **Qwen2.5 7B** | Q5_K_M | ~5 GB | Yes |
| Embedding | Semantic search, similarity, duplicate detection | **nomic-embed-text** or **mxbai-embed-large** | F16 | ~0.7 GB | Yes |

### Quantization Notes

**Q4_K_M** is the recommended default for 70B models on this hardware:
- "K" means k-quant (groups of weights share scale factors) — better quality/size tradeoff than naive Q4
- "M" (medium) uses higher precision for attention/embedding layers where it matters most
- Quality loss vs FP16: roughly 2–4% on standard benchmarks — imperceptible for routing and analysis tasks
- For 7B/14B models, **Q5_K_M** is preferred: the size savings from Q4 are less significant at small scale and Q5 recovers measurable quality at these parameter counts

**Do NOT use Q2 or Q3 on production tasks.** These quantizations cause notable coherence degradation and increase hallucination rates in instruction-following benchmarks.

### Model Selection Rationale

**Why Llama 3.3 70B over Llama 3.1 70B for medium-heavy?**
Llama 3.3 70B is Meta's improved checkpoint — same architecture, better instruction following and reasoning on standard evals (MMLU, HumanEval). Drop-in replacement with the same memory footprint.

**Why Qwen2.5 14B for light tasks over 7B?**
The 14B hits a sweet spot: it fits in ~10 GB (Q5_K_M), leaving the remainder available for OS and any concurrent processes, while scoring substantially higher than 7B models on structured output tasks (JSON, routing decisions, classification). Routing accuracy matters — a bad routing decision cascades.

**Why keep Claude API for heavy tasks?**
Tasks like Board decisions, architecture design, multi-file code generation across 3000+ line codebases, and ExoChain governance require Claude's reasoning capability and long-context coherence. Local 70B models are excellent for analysis but fall short on complex compositional reasoning and tool-use chains. The cost is justified by output quality.

---

## 2. Ollama Setup on Ubuntu 24.04 (DGX OS 7)

### 2.1 Prerequisites

The DGX OS 7 ships with CUDA 12.x and the latest NVIDIA drivers pre-installed. Verify before proceeding:

```bash
# Confirm CUDA driver and toolkit
nvidia-smi
nvcc --version

# Confirm Ubuntu version
lsb_release -a
```

Expected output: Driver >= 535, CUDA >= 12.2, Ubuntu 24.04.

### 2.2 Install Ollama

```bash
# Official install script — detects CUDA automatically on Ubuntu
curl -fsSL https://ollama.com/install.sh | sh

# Verify installation
ollama --version

# Check that Ollama sees the GPU
ollama info
# Look for: GPU: NVIDIA ... (Blackwell)
```

The install script will:
1. Install the `ollama` binary to `/usr/local/bin/ollama`
2. Create a systemd service `ollama.service`
3. Auto-detect CUDA and configure GPU backend

### 2.3 Configure Ollama for Full GPU Utilization

Edit the systemd service to expose all configuration options:

```bash
sudo systemctl edit ollama
```

Add the following under `[Service]`:

```ini
[Service]
# Use most available GPU memory — GB10 unified pool
Environment="OLLAMA_GPU_MEMORY_FRACTION=0.85"

# Keep model resident between requests (no cold-load penalty)
Environment="OLLAMA_KEEP_ALIVE=24h"

# Allow concurrent requests and multiple resident models
Environment="OLLAMA_MAX_LOADED_MODELS=2"
Environment="OLLAMA_NUM_PARALLEL=4"

# Listen on all interfaces so the app server can reach it
# (If the app runs in Docker or on a separate machine, adjust as needed)
Environment="OLLAMA_HOST=0.0.0.0:11434"

# Flash attention for Blackwell (significant throughput improvement)
Environment="OLLAMA_FLASH_ATTENTION=1"
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama
sudo systemctl enable ollama   # Start on boot

# Verify service is healthy
sudo systemctl status ollama
curl http://localhost:11434/api/tags
```

### 2.4 Pull Recommended Models

Pull models in priority order. Each pull is a one-time download; models are cached in `~/.ollama/models/`.

```bash
# Medium-heavy tier — primary workhorse (~42 GB download)
ollama pull llama3.3:70b-instruct-q4_K_M

# Light tier — fast, low-latency (~9 GB download)
ollama pull qwen2.5:14b-instruct-q5_K_M

# Micro tier — triage and classification (~5 GB download)
ollama pull qwen2.5:7b-instruct-q5_K_M

# Fallback / alternative micro
ollama pull mistral:7b-instruct-v0.3-q5_K_M

# Embedding model (~270 MB download)
ollama pull nomic-embed-text

# Verify all models loaded
ollama list
```

### 2.5 Test API Endpoint

Ollama exposes an OpenAI-compatible REST API on port 11434.

```bash
# Health check
curl http://localhost:11434/

# Test inference
curl http://localhost:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen2.5:14b-instruct-q5_K_M",
    "prompt": "Classify this task as routing/analysis/code: Assign a new task to the right specialist.",
    "stream": false
  }'

# Test OpenAI-compatible endpoint (drop-in compatibility)
curl http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen2.5:14b-instruct-q5_K_M",
    "messages": [{"role": "user", "content": "ping"}]
  }'
```

### 2.6 Firewall / Network

If the app server runs on the same machine as Ollama, no firewall changes are needed — `localhost:11434` works directly. If the app runs in Docker:

```bash
# Allow the Docker bridge to reach Ollama on the host
sudo ufw allow from 172.17.0.0/16 to any port 11434
```

If the app runs on a separate machine in the same LAN, open the port and configure `OLLAMA_HOST=0.0.0.0:11434` (already set above). Add basic auth at the nginx proxy layer for any external exposure.

---

## 3. Task Classification System

### 3.1 Design Principles

The classifier must be:
- **Fast** — the routing decision cannot add more latency than it saves. Use heuristics first; model-based classification only as a fallback.
- **Conservative** — when uncertain, route to Claude API. A wrong local inference is worse than an API call.
- **Auditable** — every routing decision is logged with the reason, so the system can be tuned over time.

### 3.2 Tier Assignment Heuristics

Apply these rules in order. First match wins.

#### Tier 1 — Always Claude API (do not attempt locally)

| Signal | Reason |
|--------|--------|
| Task involves Board-level decisions (governance, ExoChain receipts, constitutional invariants) | Requires maximum reasoning fidelity |
| Task touches security-sensitive paths (Lock, Threat, Breach specialists) | Cannot risk hallucinated security advice |
| Task is architecture design with >5 interdependent files | Local 70B models lose coherence on long dependency chains |
| `task.priority === 'urgent'` AND `task.description.length > 1000` | High-stakes, high-complexity — pay for the best |
| Multi-step tool-use chain > 15 turns | Requires sustained instruction following across long sessions |
| `autonomous_model_complex` is set to 'opus' in system_settings | Max explicitly asked for top model |

#### Tier 2 — Llama 3.3 70B Local (medium-heavy)

| Signal | Value |
|--------|-------|
| Task domain | Code review, data analysis, summarization, medium code tasks |
| Description length | 300–2000 characters |
| Priority | normal or high (non-urgent) |
| Specialist | Query, Locus, Stream, Chart, Scope, Ink, Briar |
| Expected output tokens | < 2000 |
| Latency requirement | < 30 seconds acceptable |

#### Tier 3 — Qwen2.5 14B Local (light)

| Signal | Value |
|--------|-------|
| Task type | Routing decisions, tag extraction, notification generation, simple summarization |
| Description length | < 300 characters |
| Priority | normal or low |
| Specialist | Triage, Anchor, Culture, Margin, Clause |
| Expected output | Short structured output (JSON, classification label, yes/no) |
| Latency requirement | < 5 seconds required |

#### Tier 4 — Qwen2.5 7B or Mistral 7B Local (micro)

| Signal | Value |
|--------|-------|
| Task type | Format conversion, template filling, simple extraction |
| Output | Single field, boolean, or < 100 tokens |
| Context window needed | < 2000 tokens |

#### Embedding Tasks — nomic-embed-text

- Semantic search in notes/contacts/decisions tables
- Duplicate task detection
- Tag suggestion from free text
- Similarity ranking in knowledge base lookups

### 3.3 Classification Decision Tree

```
Incoming task
     |
     v
Is it a Board/governance/security task? --- YES --> Claude API (Tier 1)
     | NO
     v
Is priority 'urgent' AND description > 1000 chars? --- YES --> Claude API (Tier 1)
     | NO
     v
Does it require >15 tool-use turns? --- YES --> Claude API (Tier 1)
     | NO
     v
Is description length > 300 AND domain is code/analysis? --- YES --> Llama 3.3 70B (Tier 2)
     | NO
     v
Is it routing/classification/tagging/notification? --- YES --> Qwen2.5 14B (Tier 3)
     | NO
     v
Is output < 100 tokens and context < 2000 tokens? --- YES --> Qwen2.5 7B (Tier 4)
     | NO
     v
Default --> Qwen2.5 14B (Tier 3)
```

### 3.4 Token Budget Heuristic

Estimated token count before sending: `Math.ceil((prompt.length + description.length) / 4)`.
- If estimated tokens > 8000 and task requires code output → bump to Tier 2 (70B).
- If estimated tokens > 24000 → always Claude API (local models degrade at extreme context lengths).

---

## 4. Cost Savings Estimate

### 4.1 Current API Cost Baseline

Based on the spawn system architecture — each task spawns a `claude --print` CLI session with `--max-turns 15` to `25`:

| Model | Input price | Output price |
|-------|-------------|-------------|
| Claude Sonnet 4.6 | $3.00 / M tokens | $15.00 / M tokens |
| Claude Opus 4.6 | $15.00 / M tokens | $75.00 / M tokens |

**Assumed current usage per task** (conservative estimate from codebase):
- Average prompt: ~3,000 tokens input
- Average output: ~1,500 tokens
- Average turns: 8
- Total per task: ~36,000 input tokens + ~12,000 output tokens

**Cost per task (Sonnet):** (36k * $3 + 12k * $15) / 1,000,000 = $0.108 + $0.18 = **~$0.29/task**
**Cost per task (Opus):** ~$1.44/task

**Assumed volume:** 50–100 tasks/day across all 68 specialists = ~75 tasks/day average.

**Monthly baseline (all Sonnet):** 75 * 30 * $0.29 = **~$652/month**
**Monthly baseline (mixed Sonnet/Opus 80/20):** ~$875/month

### 4.2 Task Distribution Analysis

Based on the task routing table in CLAUDE.md and typical workload patterns:

| Tier | Task Types | Est. % of Volume | Monthly Count |
|------|-----------|------------------|---------------|
| Tier 1 (API only) | Board, security, architecture, complex code | 20% | 450 tasks |
| Tier 2 (70B local) | Code review, analysis, data tasks | 35% | 788 tasks |
| Tier 3 (14B local) | Routing, notifications, summaries | 30% | 675 tasks |
| Tier 4 (7B local) | Classification, formatting, extraction | 15% | 338 tasks |

### 4.3 Post-Integration Cost Projection

Local inference cost: electricity (~$0.12/kWh). The GB10 draws ~60W at peak inference. A 70B Q4_K_M model on the Blackwell GPU produces ~15–25 tokens/second. A 1,500-token response takes ~75–100 seconds = ~0.002 kWh = **~$0.00024 per task**. Effectively $0.

| Tier | Monthly Tasks | API Cost Before | API Cost After | Savings |
|------|--------------|----------------|----------------|---------|
| Tier 1 (API) | 450 | $130 | $130 | $0 |
| Tier 2 (70B local) | 788 | $229 | $0.19 (electricity) | **$229** |
| Tier 3 (14B local) | 675 | $196 | $0.08 | **$196** |
| Tier 4 (7B local) | 338 | $98 | $0.02 | **$98** |
| **TOTAL** | **2,251** | **$653** | **$130.29** | **$523/month** |

**Projected monthly savings: ~$523 (~80% reduction)**
**Annual savings: ~$6,276**
**Payback period on DGX Spark hardware** (retail ~$3,000–4,000): **6–8 months**

> Note: These are conservative estimates based on Sonnet pricing. If Opus is used for any Tier 1 tasks, remaining API spend is higher and the overall savings percentage grows further since local models absorb 80% of volume regardless.

---

## 5. API Wrapper Design

### 5.1 Overview

The wrapper is a drop-in complement to the existing spawn system. It does NOT replace the full multi-turn CLI spawn (which handles tool-use chains). It targets:

1. **Short non-tool-use calls** — notifications, routing decisions, tag extraction, summaries that currently hit the Anthropic SDK directly
2. **Digest/analysis prompts** — the `spawn(cliPath, ['-p', digestPrompt, '--output-format', 'text', ...])` single-turn pattern at line 16140 in `server.js.backup`
3. **Classification calls** — any internal call asking the model to classify, route, or tag something

### 5.2 Pseudocode — `callLLM(prompt, options)`

```javascript
/**
 * callLLM — unified LLM gateway
 *
 * @param {string} prompt         - Full prompt to send
 * @param {object} options
 *   @param {string}  options.taskId        - DB task ID (for logging)
 *   @param {string}  options.memberId      - Team member ID
 *   @param {string}  options.memberName    - Team member name (for logs)
 *   @param {string}  options.priority      - Task priority: urgent/high/normal/low
 *   @param {string}  options.domain        - Task domain: code/routing/analysis/etc.
 *   @param {boolean} options.forceApi      - Skip local, always use Claude API
 *   @param {boolean} options.forceLocal    - Skip API, always use local (testing only)
 *   @param {number}  options.maxTokens     - Expected max output tokens
 *   @param {number}  options.contextTokens - Estimated input token count
 *   @param {string}  options.apiModel      - Override API model (sonnet/opus/haiku)
 * @returns {Promise<{ text, model, tier, source }>}
 */
async function callLLM(prompt, options = {}) {

  // Step 1: Classify
  const tier = options.forceApi ? 1
             : options.forceLocal ? 3
             : classifyTask(options);
  // classifyTask() implements the decision tree from Section 3.3
  // Returns: 1 (API), 2 (70B), 3 (14B), 4 (7B)

  const LOCAL_MODELS = {
    2: 'llama3.3:70b-instruct-q4_K_M',
    3: 'qwen2.5:14b-instruct-q5_K_M',
    4: 'qwen2.5:7b-instruct-q5_K_M',
  };
  const localModel = LOCAL_MODELS[tier] || null;

  // Step 2: Try local if not Tier 1
  let result = null;
  let usedModel = null;
  let usedTier = tier;

  if (tier > 1 && localModel) {
    try {
      const startMs = Date.now();

      // Check Ollama health (cached, TTL 30s to avoid hammering)
      const ollamaHealthy = await checkOllamaHealth();
      if (!ollamaHealthy) throw new Error('Ollama not reachable');

      const response = await fetch('http://localhost:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: localModel,
          prompt: prompt,
          stream: false,
          options: {
            num_predict: options.maxTokens || 2048,
            temperature: 0.2,      // Lower temp for task execution
            top_p: 0.9,
          }
        }),
        signal: AbortSignal.timeout(120_000),  // 2-minute hard cap
      });

      if (!response.ok) throw new Error(`Ollama HTTP ${response.status}`);

      const json = await response.json();
      result = json.response;
      usedModel = localModel;

      await logLLMCall({
        taskId: options.taskId,
        memberId: options.memberId,
        model: usedModel,
        tier: usedTier,
        source: 'local',
        promptTokens: json.prompt_eval_count || 0,
        completionTokens: json.eval_count || 0,
        latencyMs: Date.now() - startMs,
        success: true,
      });

    } catch (localErr) {
      // Local failed — log and fall through to API
      console.warn(`[callLLM] Local model failed (tier ${tier}, ${localModel}): ${localErr.message}. Falling back to Claude API.`);
      await logLLMCall({
        taskId: options.taskId,
        memberId: options.memberId,
        model: localModel,
        tier: usedTier,
        source: 'local',
        success: false,
        error: localErr.message,
      });
      // Fall through to API block below
    }
  }

  // Step 3: Claude API (primary for Tier 1, fallback for Tiers 2-4)
  if (result === null) {
    const apiModel = resolveApiModel(options);  // Reads system_settings
    usedModel = apiModel;
    usedTier = 1;

    try {
      const startMs = Date.now();

      const response = await anthropicClient.messages.create({
        model: apiModel,
        max_tokens: options.maxTokens || 4096,
        messages: [{ role: 'user', content: prompt }],
      });

      result = response.content[0].text;

      await logLLMCall({
        taskId: options.taskId,
        memberId: options.memberId,
        model: usedModel,
        tier: usedTier,
        source: 'api',
        promptTokens: response.usage.input_tokens,
        completionTokens: response.usage.output_tokens,
        latencyMs: Date.now() - startMs,
        success: true,
        wasLocalFallback: tier > 1,  // Flag: API used because local failed
      });

    } catch (apiErr) {
      console.error(`[callLLM] Claude API also failed: ${apiErr.message}`);
      throw apiErr;  // Both local and API failed — propagate
    }
  }

  return {
    text: result,
    model: usedModel,
    tier: usedTier,
    source: usedTier === 1 ? 'api' : 'local',
  };
}
```

### 5.3 Logging Schema (new DB table: `llm_calls`)

```sql
CREATE TABLE llm_calls (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id              INTEGER REFERENCES tasks(id),
  member_id            INTEGER REFERENCES team_members(id),
  model                TEXT NOT NULL,
  tier                 INTEGER NOT NULL,          -- 1=API, 2=70B, 3=14B, 4=7B
  source               TEXT NOT NULL,             -- 'local' | 'api'
  prompt_tokens        INTEGER,
  completion_tokens    INTEGER,
  latency_ms           INTEGER,
  success              INTEGER DEFAULT 1,         -- 1=success, 0=failure
  error                TEXT,
  was_local_fallback   INTEGER DEFAULT 0,         -- 1 if local failed and API used
  created_at           TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_llm_calls_task_id ON llm_calls(task_id);
CREATE INDEX idx_llm_calls_source  ON llm_calls(source);
CREATE INDEX idx_llm_calls_created ON llm_calls(created_at);
```

This table powers a cost dashboard: `SUM(completion_tokens) WHERE source='api'` * model_price gives live API spend; local calls show near-zero cost. The `was_local_fallback` column highlights reliability issues.

### 5.4 Circuit Breaker via system_settings

The wrapper reads `local_llm_available` from `system_settings` (via the existing `getCachedSettings()` function, TTL 10s). If Ollama fails 3 consecutive times within 5 minutes, a background check flips this flag to `'0'`. The wrapper skips the local attempt entirely until the flag returns to `'1'`, avoiding timeout cascades on the task system.

---

## 6. Risk Assessment

### 6.1 Quality Tradeoffs

| Risk | Severity | Affected Tier | Mitigation |
|------|----------|---------------|------------|
| Local 70B hallucinates on complex reasoning | Medium | Tier 2 | Keep complex code and architecture on Claude API |
| Quantization degrades structured output (JSON) | Medium | All local | Use Ollama's `format: "json"` parameter; validate output schema before use |
| Local model loses coherence at long context | High | Tier 2 | Enforce 24,000-token hard limit; escalate to API above threshold |
| Latency spikes under concurrent load | Medium | Tier 2 | Ollama queues requests; set `OLLAMA_NUM_PARALLEL=4`; monitor queue depth |
| Model cold-load latency on first request | Low | All | `OLLAMA_KEEP_ALIVE=24h` keeps models resident |
| Inconsistent instruction following vs Claude | Medium | Tier 3–4 | Tune prompts for each local model's format; test routing accuracy before go-live |

### 6.2 When NOT to Use Local Models

Never route locally when:

- **Security-sensitive decisions**: authentication flows, access control changes, ExoChain governance receipts. A wrong answer here has irreversible consequences.
- **Specialist is Lock, Threat, or Breach**: these always use Claude API.
- **Output will be directly executed without human review**: local models can produce syntactically valid but logically wrong code.
- **Task requires information from after August 2025**: local models have training cutoffs and no tool access; Claude CLI can browse.
- **Task requires multi-file edits with >5 interdependent files**: local models lose cross-file coherence. Use the full Claude CLI spawn.
- **Max explicitly flags a task as critical**: honor `forceApi: true`.
- **`autonomous_model_complex` is set to 'opus'**: Max wants the best — don't downgrade.

### 6.3 Monitoring Queries

**Local failure rate (run every 15 minutes):**

```sql
SELECT
  COUNT(*) FILTER (WHERE success = 0 AND source = 'local') AS local_failures,
  COUNT(*) FILTER (WHERE source = 'local') AS local_attempts,
  ROUND(100.0 * COUNT(*) FILTER (WHERE success = 0 AND source = 'local') /
        NULLIF(COUNT(*) FILTER (WHERE source = 'local'), 0), 1) AS failure_pct
FROM llm_calls
WHERE created_at > datetime('now', '-15 minutes');
```

Alert threshold: `failure_pct > 10%` → create notification, set `local_llm_available = '0'`.

**Quality proxy — local task revision rate:**

```sql
SELECT
  CASE WHEN lc.source = 'local' THEN 'local' ELSE 'api' END AS model_source,
  AVG(t.revision_count) AS avg_revisions,
  COUNT(*) AS task_count
FROM tasks t
JOIN llm_calls lc ON lc.task_id = t.id
WHERE t.status IN ('completed', 'delivered')
  AND t.created_at > datetime('now', '-30 days')
GROUP BY model_source;
```

If local task revision rate exceeds API revision rate by >2x, tighten classification thresholds.

### 6.4 Ollama Health Watchdog

Add to `services/heartbeat.js`: a `checkOllamaHealth()` call every 60 seconds. On failure:
1. Increment failure counter in memory
2. After 3 consecutive failures: set `system_settings.local_llm_available = '0'`
3. After 5 minutes with `local_llm_available = '0'`: attempt a single health check and restore if successful
4. Create a notification entry so Max can see Ollama is down

---

## 7. Day 1 Quick Start

Minimum viable path to get Ollama running on the DGX and serving its first inference.
Estimated time: 30–45 minutes (majority is model download).

### Step 1 — SSH into the DGX and verify GPU

```bash
nvidia-smi
# Expect: GB10 Blackwell GPU, 128 GB unified memory shown
```

### Step 2 — Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
```

### Step 3 — Pull the micro model first (fastest validation, ~5 GB)

```bash
ollama pull qwen2.5:7b-instruct-q5_K_M
```

### Step 4 — Test the endpoint

```bash
curl http://localhost:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5:7b-instruct-q5_K_M","prompt":"Reply with just the word: READY","stream":false}'
```

Expected response: `{"response":"READY",...}`

### Step 5 — Pull the primary models in the background (start these, let them run)

```bash
# Run both in background — total ~51 GB, will take ~20-40 min on good connection
nohup ollama pull qwen2.5:14b-instruct-q5_K_M > /tmp/pull-14b.log 2>&1 &
nohup ollama pull llama3.3:70b-instruct-q4_K_M > /tmp/pull-70b.log 2>&1 &

# Monitor progress
watch -n 10 'ollama list && tail -5 /tmp/pull-14b.log && tail -5 /tmp/pull-70b.log'
```

### Step 6 — Apply GPU and keep-alive configuration

```bash
sudo systemctl edit ollama
# Paste the [Service] block from Section 2.3
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

### Step 7 — Confirm all models are resident and GPU is active

```bash
ollama list
# All models should appear with their sizes

# Confirm GPU inference (should show "GPU" in the info block)
ollama info

# Test the 14B model when download completes
curl http://localhost:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5:14b-instruct-q5_K_M","prompt":"Classify: assign this to the routing specialist. Reply with one word: routing/analysis/code","stream":false}'
```

### Step 8 — Note integration endpoint

```
Local Ollama API:  http://localhost:11434
Docker bridge:     http://host.docker.internal:11434
OpenAI-compat:     http://localhost:11434/v1/chat/completions
```

Implementation of `callLLM()`, the `llm_calls` table, and the heartbeat watchdog is tracked as a follow-on task — assign to **Alloy** (backend wrapper), **Query** (DB schema), and **Vigil** (heartbeat watchdog) once this plan is approved.

---

## Implementation Roadmap (Post-Approval)

| Phase | Work | Owner | Est. Effort |
|-------|------|-------|-------------|
| Phase 1 | Create `llm_calls` DB table migration | Query | 1 hour |
| Phase 2 | Implement `classifyTask()` heuristics module | Alloy | 2 hours |
| Phase 3 | Implement `callLLM()` wrapper with Ollama + API fallback | Alloy | 3 hours |
| Phase 4 | Integrate wrapper into digest/analysis single-turn spawn points | Alloy | 2 hours |
| Phase 5 | Add Ollama health watchdog to heartbeat service | Vigil | 1 hour |
| Phase 6 | Build local vs API cost dashboard in Mission Control | Chart | 2 hours |
| Phase 7 | Tune system prompts for Qwen2.5 and Llama instruction format | Neural | 3 hours |
| Phase 8 | QA — measure routing accuracy and task revision rates | Plumb | 4 hours |

**Total estimated implementation:** ~18 specialist-hours

---

*Plan status: DRAFT — pending Board review and approval before implementation begins.*
*Questions or scope changes: route through Bower (CPO) -> Quarry -> Board.*
