# DGX Spark — Auto-Spawn Adaptation Plan
**Specialist:** Scaffold (Platform — Tooling)  
**Priority:** HIGH — Required for agents to work on DGX  
**Target:** NVIDIA DGX Spark, Ubuntu 24.04, ARM64

---

## Spawn System Audit

### Architecture
`spawnMemberTerminal` at `server.js:14906` is the single entry point (called from 14+ locations). It:
1. Loads member + task context from DB
2. Builds a prompt (3-tier: minimal/standard/full)
3. Routes to an adapter based on `member.adapter_type`
4. Records the process in `active_processes`

### Existing Adapter Dispatch (server.js:15315–15342)
```
adapterType === 'process'           → spawnProcessAdapter()   (shell subprocess)
adapterType === 'http'              → callHttpAdapter()        (HTTP POST to URL)
adapterType === 'openclaw_gateway'  → connectOpenClawAdapter()
adapterType === 'codex_local'       → spawnProcessAdapter()   (Codex CLI)
adapterType === 'gemini_local'      → spawnProcessAdapter()   (Gemini CLI)
[default: 'claude_local']           → Claude CLI spawn
```

ollama_local slots in here — pattern identical to codex_local/gemini_local.

### macOS-Specific Items (What Needs Changing)

All runtime paths (DB_PATH, INBOX_PATH, OUTBOX_PATH, PROJECT_ROOT) are env-var driven.
No server.js code changes needed for Linux path compatibility.
Only required work: correct env vars in docker-compose.yml (done in Harbor's plan) + ollama_local adapter.

---

## Option A: Pure Claude CLI on DGX

Auth methods on Ubuntu:
  Method 1 (API key): set ANTHROPIC_API_KEY in docker-compose.yml environment
  Method 2 (OAuth): claude auth login on host, bind-mount ~/.claude.json into container
  Method 3: scp ~/.claude.json from Mac to DGX, mount via Dockerfile.prod entrypoint

Pros: Zero code changes. Full Claude capability.
Cons: Still costs Claude API tokens. Requires auth refresh.

---

## Option B: Pure Ollama

Critical limitation: Ollama provides inference only — NOT the Claude Code tool framework
(Read/Edit/Write/Bash). Local models via Ollama cannot run as Code agents for engineering tasks.
Suitable ONLY for text-generation tasks.

---

## Option C: Hybrid (RECOMMENDED)

Strategy: Claude CLI for all agentic tasks (tools required). Ollama for pure text tasks (routing, summaries, content).

New SPAWN_MODE environment variable:
  SPAWN_MODE=claude   → All tasks → Claude CLI (current behavior, safe default)
  SPAWN_MODE=ollama   → All tasks → Ollama (text-only)
  SPAWN_MODE=hybrid   → Smart routing: agentic → Claude, text → Ollama

### Task classification logic

```javascript
function classifySpawnMode(task, member) {
  const agentRequired = [
    'write code', 'edit', 'fix', 'implement', 'build', 'create file',
    'run test', 'debug', 'deploy', 'configure', 'install'
  ];
  const localSuitable = [
    'summarize', 'classify', 'route', 'analyze', 'review text',
    'write content', 'draft', 'describe', 'explain'
  ];
  const combined = ((task.title || '') + ' ' + (task.description || '')).toLowerCase();
  if (agentRequired.some(kw => combined.includes(kw))) return 'claude';
  if (localSuitable.some(kw => combined.includes(kw))) return 'local';
  return 'claude'; // safe default
}
```

### New ollama_local adapter — 2 changes to server.js

**Change 1:** Add dispatch case at server.js:15342 (after gemini_local, before Claude block):

```javascript
if (adapterType === 'ollama_local') {
  callOllamaAdapter(taskId, processId, memberId, member, task, adapterConfig, prompt);
  return { success: true, process_id: processId, member_name: member.name, mode: 'ollama_local' };
}
```

**Change 2:** Add callOllamaAdapter function near callHttpAdapter (server.js:14841):

```javascript
async function callOllamaAdapter(taskId, processId, memberId, member, task, adapterConfig, prompt) {
  const ollamaUrl = adapterConfig.url || 'http://host.docker.internal:11434/api/chat';
  const model = adapterConfig.model || 'llama3.1:70b';

  try {
    const body = JSON.stringify({
      model,
      messages: [{ role: 'user', content: prompt }],
      stream: false,
      options: { temperature: 0.3, num_predict: adapterConfig.max_tokens || 4096 }
    });

    const parsedUrl = new URL(ollamaUrl);
    const httpModule = parsedUrl.protocol === 'https:' ? https : http;

    const result = await new Promise((resolve, reject) => {
      const req = httpModule.request(ollamaUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        timeout: adapterConfig.timeout_ms || 120000
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Ollama timeout')); });
      req.write(body);
      req.end();
    });

    const finishedAt = localNow();
    if (result.status === 200) {
      const parsed = JSON.parse(result.body);
      const output = parsed.message?.content || parsed.response || '';
      handleSpawnSuccess(taskId, processId, member, task, 'ollama_local', output, finishedAt);
    } else {
      db.prepare(`UPDATE active_processes SET status = 'failed', completed_at = ?, output_summary = ? WHERE id = ?`)
        .run(finishedAt, `Ollama ${result.status}: ${result.body.slice(0, 200)}`, processId);
      broadcast('process.failed', { process_id: processId, task_id: taskId, error: `Ollama ${result.status}` });
    }
  } catch (err) {
    db.prepare(`UPDATE active_processes SET status = 'failed', completed_at = ?, output_summary = ? WHERE id = ?`)
      .run(localNow(), `Ollama unavailable: ${err.message}`, processId);
    broadcast('process.failed', { process_id: processId, task_id: taskId, error: 'ollama_unavailable' });
  }
}
```

### Ollama URL from inside Docker container

Ollama runs on the DGX host. From inside the container, reach it via host.docker.internal.

Add to docker-compose.yml:
```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

### Assign a member to Ollama (SQL)

```sql
UPDATE team_members
SET adapter_type = 'ollama_local',
    adapter_config = '{"url":"http://host.docker.internal:11434/api/chat","model":"llama3.1:70b","max_tokens":4096}'
WHERE name = 'Prose';  -- Start with content/text members only
```

---

## Migration Checklist (7 Phases)

Phase 1 — Confirm no hardcoded Mac paths in server.js affect DGX:
  grep -r "/Users/maxstewart" /opt/command-base/app/server.js | grep -v "example\|comment"
  (Should return empty — all paths are env-var driven)

Phase 2 — Claude CLI auth on DGX:
  Verify entrypoint.sh copies .claude.json from bind-mounted host path
  Test: docker exec command-base claude --version
  Test: docker exec command-base claude --print "Say hello" --output-format text

Phase 3 — Install Ollama on DGX host:
  curl -fsSL https://ollama.com/install.sh | sh
  sudo systemctl enable ollama && sudo systemctl start ollama
  ollama pull llama3.1:70b   (40GB — for complex text tasks)
  ollama pull qwen2.5:7b     (4.5GB — for simple routing/classification)

Phase 4 — Test Ollama from inside container:
  docker exec command-base curl http://host.docker.internal:11434/api/tags
  (Should return model list JSON)

Phase 5 — Add ollama_local adapter to server.js:
  Insert callOllamaAdapter function after callHttpAdapter (line ~14841)
  Insert ollama_local dispatch case after gemini_local (line ~15342)
  Add extra_hosts to docker-compose.yml
  Set SPAWN_MODE=hybrid in docker-compose.yml environment
  Rebuild: docker compose build && docker compose up -d

Phase 6 — Assign one low-risk member to Ollama for testing:
  UPDATE team_members SET adapter_type='ollama_local', adapter_config='...' WHERE name='Prose';
  Monitor active_processes for completion and output quality

Phase 7 — Monitor and expand:
  Watch output quality vs Claude CLI baseline over 1 week
  Gradually assign text-focused members (Prose, Echo, Ink) to Ollama
  Keep ALL engineering/code members on claude_local

---

## Recommendation Summary

Task Type                      | Adapter       | Why
-------------------------------|---------------|----------------------------------
Code, file editing, debugging  | claude_local  | Requires tool use (Read/Edit/Bash)
Architecture, complex design   | claude_local  | Quality critical
Content writing, summaries     | ollama_local  | Text-only, Llama 3.1 70B sufficient
Routing, classification        | ollama_local  | Fast, Qwen 7B adequate
Data analysis with tool use    | claude_local  | Needs file access

Start conservative: assign Prose, Echo, Ink to Ollama first. Verify quality over 1 week.
