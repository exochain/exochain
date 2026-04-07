# LLM Integration Brief: Local Models, Multi-Model Routing & MCP Patterns

**Researcher:** Pax
**Date:** 2026-03-26
**Status:** Complete

---

## 1. Recommendation: Local LLM Setup

### Use Ollama. Nothing else needed.

**Why Ollama wins:**
- Single binary install: `brew install ollama` (macOS) or `curl -fsSL https://ollama.com/install.sh | sh`
- Zero configuration. Run `ollama serve` and it listens on `localhost:11434`
- Pull models like Docker images: `ollama pull qwen2.5-coder:7b`
- **Exposes an OpenAI-compatible API out of the box** at `POST http://localhost:11434/v1/chat/completions`
- Also exposes its native API at `POST http://localhost:11434/api/generate` and `POST http://localhost:11434/api/chat`
- Runs on Apple Silicon with Metal acceleration (Max's MacBook will use GPU automatically)
- Model management is trivial: `ollama list`, `ollama pull`, `ollama rm`

**Alternatives considered and rejected:**
| Option | Why Not |
|--------|---------|
| **LM Studio** | GUI-heavy, slower to automate, extra app running. Good for experimentation but Ollama is more server-friendly. |
| **llama.cpp** | Raw C++ binary. Powerful but requires manual model conversion (GGUF format), no built-in API server without extra setup. Ollama uses llama.cpp under the hood anyway. |
| **kobold.cpp** | RP/creative writing focused. Wrong tool for code generation tasks. |

### Recommended Models for Zero-Cost Coding

| Model | Size | Best For | Pull Command |
|-------|------|----------|--------------|
| **qwen2.5-coder:7b** | ~4.7 GB | General coding, completions, refactoring | `ollama pull qwen2.5-coder:7b` |
| **deepseek-coder-v2:16b** | ~9 GB | Complex code generation, multi-file reasoning | `ollama pull deepseek-coder-v2:16b` |
| **codestral:22b** | ~13 GB | Mistral's code model, strong at infill/completion | `ollama pull codestral:22b` |
| **llama3.1:8b** | ~4.7 GB | General reasoning, not code-specific | `ollama pull llama3.1:8b` |
| **qwen2.5:14b** | ~9 GB | Balanced reasoning + coding | `ollama pull qwen2.5:14b` |

**Start with `qwen2.5-coder:7b`.** It fits comfortably in RAM, responds fast, and handles most coding tasks well. Scale up to the 16b/22b models when quality matters more than speed.

### Ollama API Reference

**Native chat endpoint:**
```bash
curl http://localhost:11434/api/chat -d '{
  "model": "qwen2.5-coder:7b",
  "messages": [{"role": "user", "content": "Write a TypeScript function that..."}],
  "stream": false
}'
```

**OpenAI-compatible endpoint (drop-in replacement):**
```bash
curl http://localhost:11434/v1/chat/completions -d '{
  "model": "qwen2.5-coder:7b",
  "messages": [{"role": "user", "content": "Write a TypeScript function that..."}]
}'
```

This means ANY library that talks to OpenAI (the `openai` npm package, `langchain`, etc.) can be pointed at Ollama by changing the base URL:

```typescript
import OpenAI from 'openai';

const ollama = new OpenAI({
  baseURL: 'http://localhost:11434/v1',
  apiKey: 'ollama', // Required by the SDK but Ollama ignores it
});

const response = await ollama.chat.completions.create({
  model: 'qwen2.5-coder:7b',
  messages: [{ role: 'user', content: 'Explain this code...' }],
});
```

---

## 2. ExoChain MCP Patterns

### What "MCP" means in ExoChain

ExoChain's MCP is **not** the Anthropic Model Context Protocol for tool-calling. It is a **Model Containment Protocol** -- a set of 6 hard-coded rules that constrain what AI agents can do within the constitutional governance fabric. The naming collision is worth noting.

**Location:** `crates/exo-gatekeeper/src/mcp.rs` and `crates/exo-gatekeeper/src/mcp_audit.rs`

### The 6 MCP Rules

| Rule | Description | Severity |
|------|-------------|----------|
| MCP-001 | AI must operate within BCTS (Bailment-Conditioned Transaction Set) scope | 5 (critical) |
| MCP-002 | AI cannot self-escalate capabilities | 5 |
| MCP-003 | AI actions require provenance metadata | 4 |
| MCP-004 | AI cannot forge identity or signatures | 5 |
| MCP-005 | AI outputs must be distinguishable from human | 3 |
| MCP-006 | AI must respect consent boundaries | 5 |

### Key Architectural Patterns

**1. Cryptographic AI Identity Binding**
AI actors are distinguished from humans at the signature level, not by a boolean flag. The `SignerType` enum embeds either `0x01` (Human) or `0x02` (AI + delegation_id hash) as a prefix in every signed payload. An AI signature physically cannot be verified as a human signature. This is enforced in `build_signed_payload()` and `verify_typed_signature()`.

**2. Hash-Chained MCP Audit Trail**
Every MCP enforcement event (allowed, blocked, escalated) is appended to a BLAKE3 hash-chained log (`McpAuditLog`). This is tamper-evident -- if any record is modified, the chain verification fails. The audit log is independent of the governance audit log (separation of branches).

**3. Holon Agent Runtime**
A `Holon` (in `holon.rs`) is an autonomous agent that runs a combinator program under kernel adjudication. Every step is capability-checked:
- Spawn a holon with a DID identity, capability set, and combinator chain
- Each `step()` call submits an `ActionRequest` to the kernel
- The kernel issues a `Verdict`: Permitted, Denied, or Escalated
- Denied = holon terminated. Escalated = holon suspended pending human review.

**4. Multi-Model Crosscheck (Anti-Sybil)**
The crosscheck system in `exo-governance/src/crosscheck.rs` and the architecture docs describe a multi-model deliberation pattern:
- Every `CrosscheckOpinion` carries an `OpinionProvenance` with `agent_kind` (Llm/Human/RuleEngine/Specialist), `model` identifier, and `provider`
- Provider diversity is enforced: policies can require "opinions from at least N distinct providers"
- Crosscheck methods include: QuickCheck (single model), Crosscheck (multi-model panel), Borg (multi-round refinement), Audit (adversarial), DevilsAdvocate, RedTeam, Jury
- This is the closest pattern to what The Team needs for multi-LLM routing

### Patterns Directly Applicable to The Team

| ExoChain Pattern | Team Application |
|------------------|-----------------|
| `McpContext` with `signer_type` | Tag each team member's requests with which model backend handled them |
| `McpAuditLog` hash chain | Audit trail for all AI-generated work products |
| Holon spawn/step/adjudicate | Each team member = a holon with defined capabilities and a program |
| Crosscheck `OpinionProvenance` | Track which model, provider, and agent type produced each output |
| Provider diversity requirement | Route complex tasks to Claude, simple tasks to Ollama, verify independence |

---

## 3. Multi-LLM Routing Architecture

### The Unified Interface Pattern

The key insight: the **OpenAI Chat Completions format** (`/v1/chat/completions`) is the de facto standard. Every provider either speaks it natively or has an adapter:

| Provider | Native Format | OpenAI-Compatible? |
|----------|--------------|---------------------|
| **OpenAI (GPT-4, Codex)** | OpenAI format | Yes (native) |
| **Ollama (local)** | Own + OpenAI compat | Yes (`/v1/chat/completions`) |
| **Anthropic (Claude)** | Messages API | No -- needs adapter |
| **Groq** | OpenAI format | Yes |
| **Together AI** | OpenAI format | Yes |
| **Mistral AI** | OpenAI format | Yes |
| **OpenRouter** | OpenAI format (multi-provider proxy) | Yes |

**Claude is the exception.** Anthropic uses its own Messages API format. But the translation is mechanical -- an adapter function is ~30 lines.

### Routing Architecture

```
                     ┌──────────────────────────────────┐
                     │     Team Express Server           │
                     │     POST /api/llm/chat            │
                     └────────────┬─────────────────────┘
                                  │
                          ┌───────▼────────┐
                          │  Router Layer   │
                          │  (model picker) │
                          └───┬────┬────┬──┘
                              │    │    │
                ┌─────────────┘    │    └─────────────┐
                │                  │                    │
         ┌──────▼──────┐   ┌──────▼──────┐   ┌───────▼───────┐
         │   Claude     │   │   Ollama    │   │   OpenAI      │
         │   Adapter    │   │   (local)   │   │   (direct)    │
         │              │   │             │   │               │
         │ api.anthropic│   │ localhost   │   │ api.openai    │
         │ .com/v1/     │   │ :11434/v1/  │   │ .com/v1/      │
         └─────────────┘   └─────────────┘   └───────────────┘
```

### Router Logic: Who Gets What

```typescript
interface ModelRoute {
  provider: 'claude' | 'ollama' | 'openai' | 'openrouter';
  model: string;
  baseURL: string;
  apiKey?: string;
  reason: string;
}

function routeRequest(teamMember: string, taskType: string): ModelRoute {
  // Complex reasoning, architecture, planning → Claude
  if (['atlas', 'pax', 'gray'].includes(teamMember) ||
      ['planning', 'architecture', 'research', 'review'].includes(taskType)) {
    return {
      provider: 'claude',
      model: 'claude-sonnet-4-20250514',
      baseURL: 'https://api.anthropic.com/v1',
      apiKey: process.env.ANTHROPIC_API_KEY,
      reason: 'Complex reasoning task → Claude',
    };
  }

  // Coding tasks → Ollama (zero cost)
  if (['lumen', 'hone', 'rivet', 'prism', 'bolt'].includes(teamMember) ||
      ['coding', 'implementation', 'testing', 'refactoring'].includes(taskType)) {
    return {
      provider: 'ollama',
      model: 'qwen2.5-coder:7b',
      baseURL: 'http://localhost:11434/v1',
      reason: 'Coding task → local Ollama (zero cost)',
    };
  }

  // Default fallback → Ollama general model
  return {
    provider: 'ollama',
    model: 'qwen2.5:14b',
    baseURL: 'http://localhost:11434/v1',
    reason: 'General task → local Ollama (zero cost)',
  };
}
```

### The Provider Adapter

```typescript
import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';

// Unified interface -- all providers return this shape
interface ChatResponse {
  content: string;
  model: string;
  provider: string;
  usage: { input_tokens: number; output_tokens: number };
  cost: number; // estimated USD cost, 0 for local
}

interface ChatRequest {
  messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>;
  model?: string;
  temperature?: number;
  max_tokens?: number;
}

// OpenAI-compatible provider (works for OpenAI, Ollama, Groq, etc.)
async function chatOpenAICompatible(
  req: ChatRequest,
  route: ModelRoute,
): Promise<ChatResponse> {
  const client = new OpenAI({
    baseURL: route.baseURL,
    apiKey: route.apiKey || 'not-needed',
  });
  const result = await client.chat.completions.create({
    model: route.model,
    messages: req.messages,
    temperature: req.temperature ?? 0.7,
    max_tokens: req.max_tokens ?? 4096,
  });
  return {
    content: result.choices[0]?.message?.content || '',
    model: route.model,
    provider: route.provider,
    usage: {
      input_tokens: result.usage?.prompt_tokens || 0,
      output_tokens: result.usage?.completion_tokens || 0,
    },
    cost: route.provider === 'ollama' ? 0 : estimateCost(route, result.usage),
  };
}

// Claude adapter (translates to Anthropic's Messages API)
async function chatClaude(
  req: ChatRequest,
  route: ModelRoute,
): Promise<ChatResponse> {
  const client = new Anthropic({ apiKey: route.apiKey });
  const systemMsg = req.messages.find(m => m.role === 'system')?.content;
  const messages = req.messages
    .filter(m => m.role !== 'system')
    .map(m => ({ role: m.role as 'user' | 'assistant', content: m.content }));

  const result = await client.messages.create({
    model: route.model,
    max_tokens: req.max_tokens ?? 4096,
    system: systemMsg,
    messages,
  });
  const text = result.content
    .filter(b => b.type === 'text')
    .map(b => b.text)
    .join('');
  return {
    content: text,
    model: route.model,
    provider: 'claude',
    usage: {
      input_tokens: result.usage.input_tokens,
      output_tokens: result.usage.output_tokens,
    },
    cost: estimateCost(route, result.usage),
  };
}

// Unified dispatcher
async function chat(
  req: ChatRequest,
  route: ModelRoute,
): Promise<ChatResponse> {
  if (route.provider === 'claude') {
    return chatClaude(req, route);
  }
  return chatOpenAICompatible(req, route);
}
```

---

## 4. Express Server Implementation Plan

### What to add to the existing Express server

**New files:**

```
src/
  llm/
    router.ts        # Route selection logic (team member + task type → model)
    providers.ts      # Provider adapters (Claude, OpenAI-compat)
    types.ts          # ChatRequest, ChatResponse, ModelRoute interfaces
    audit.ts          # Log every LLM call (model, tokens, cost, team member)
```

**New endpoints:**

```
POST /api/llm/chat           # Unified chat endpoint
GET  /api/llm/models         # List available models (Ollama + configured APIs)
GET  /api/llm/health         # Check which providers are online
GET  /api/llm/usage          # Token/cost tracking per team member
```

**New environment variables:**

```env
# Required for Claude routing
ANTHROPIC_API_KEY=sk-ant-...

# Optional for OpenAI routing
OPENAI_API_KEY=sk-...

# Ollama (defaults to localhost, no key needed)
OLLAMA_BASE_URL=http://localhost:11434

# Default model preferences
DEFAULT_CODE_MODEL=qwen2.5-coder:7b
DEFAULT_REASONING_MODEL=claude-sonnet-4-20250514
```

**New database table** (in `the_team.db`):

```sql
CREATE TABLE IF NOT EXISTS llm_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  team_member TEXT NOT NULL,
  task_id INTEGER,
  provider TEXT NOT NULL,       -- 'claude', 'ollama', 'openai'
  model TEXT NOT NULL,
  input_tokens INTEGER DEFAULT 0,
  output_tokens INTEGER DEFAULT 0,
  estimated_cost REAL DEFAULT 0.0,
  latency_ms INTEGER,
  created_at TEXT DEFAULT (datetime('now'))
);
```

### Health Check Pattern

Before routing to a provider, verify it is online:

```typescript
async function checkOllamaHealth(): Promise<boolean> {
  try {
    const res = await fetch('http://localhost:11434/api/tags');
    return res.ok;
  } catch { return false; }
}

async function getAvailableModels(): Promise<string[]> {
  try {
    const res = await fetch('http://localhost:11434/api/tags');
    const data = await res.json();
    return data.models.map((m: any) => m.name);
  } catch { return []; }
}
```

If Ollama is down, the router falls back to the next available provider. If Claude API key is missing, coding tasks that would have gone to Claude fall back to the largest available Ollama model.

### Setup Steps for Max

```bash
# 1. Install Ollama
brew install ollama

# 2. Start Ollama server (runs in background)
ollama serve &

# 3. Pull the primary coding model
ollama pull qwen2.5-coder:7b

# 4. Verify it works
curl http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5-coder:7b","messages":[{"role":"user","content":"Hello"}]}'

# 5. (Optional) Pull a larger model for complex tasks
ollama pull qwen2.5:14b
```

Total setup time: ~5 minutes + model download time.

---

## 5. Cost Analysis

| Scenario | Monthly Cost |
|----------|-------------|
| All tasks via Claude Sonnet | ~$50-200/mo depending on volume |
| All tasks via local Ollama | $0 (electricity only) |
| **Hybrid: Claude for reasoning, Ollama for coding** | **~$10-30/mo** |

The hybrid approach cuts costs 80-90% while keeping Claude available for the tasks where quality matters most (planning, architecture review, complex research). Every coding task, refactoring job, test generation, and routine question goes through the local model at zero marginal cost.

---

## 6. Key Takeaways

1. **Install Ollama.** One command, zero configuration, OpenAI-compatible API included.
2. **Start with `qwen2.5-coder:7b`.** Best quality-to-speed ratio for coding on consumer hardware.
3. **The router is ~100 lines of TypeScript.** Map team member + task type to provider, call the right adapter.
4. **Claude adapter is ~30 lines.** The only provider that needs special handling.
5. **ExoChain's crosscheck pattern is the gold standard** for multi-model governance but is overkill for The Team right now. What we can borrow: the `OpinionProvenance` concept (tag every output with its model/provider) and the audit trail pattern.
6. **Log everything.** Track tokens, costs, and latency per team member in `llm_usage` so Max can see exactly where the money goes.
