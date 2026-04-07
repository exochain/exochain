# Claude Code Programmatic Usage Research

**Date:** 2026-03-26
**Status:** Complete

---

## 1. The `@anthropic-ai/claude-code` npm Package & SDK

### The CLI Package
**`@anthropic-ai/claude-code`** (v2.1.85) exists and is the CLI tool. It is a **bin-only** package -- it exposes `cli.js` as the `claude` command but has **no programmatic exports** (no `main`, no `exports` field in package.json). You cannot `import` from it.

```bash
npm install -g @anthropic-ai/claude-code   # installs the CLI
```

### The Agent SDK (The Real Programmatic Package)
**`@anthropic-ai/claude-agent-sdk`** (v0.2.85) is the dedicated SDK for programmatic use. There is also a Python equivalent: `claude-agent-sdk`.

```bash
npm install @anthropic-ai/claude-agent-sdk    # TypeScript/Node.js
pip install claude-agent-sdk                   # Python
```

**TypeScript usage:**
```typescript
import { query } from "@anthropic-ai/claude-agent-sdk";

for await (const message of query({
  prompt: "Find and fix the bug in auth.py",
  options: { allowedTools: ["Read", "Edit", "Bash"] }
})) {
  if ("result" in message) console.log(message.result);
}
```

**Python usage:**
```python
from claude_agent_sdk import query, ClaudeAgentOptions

async for message in query(
    prompt="Find and fix the bug in auth.py",
    options=ClaudeAgentOptions(allowed_tools=["Read", "Edit", "Bash"]),
):
    print(message)
```

**Key SDK capabilities:**
- Built-in tools (Read, Write, Edit, Bash, Glob, Grep, WebSearch, WebFetch)
- Hooks (PreToolUse, PostToolUse, Stop, SessionStart, SessionEnd)
- Subagents (spawn specialized agents with custom prompts)
- MCP server integration
- Session persistence and resumption
- Permission modes (acceptEdits, bypassPermissions, default, plan)

**IMPORTANT:** The Agent SDK requires an `ANTHROPIC_API_KEY` (from the Anthropic Console). It does **not** support OAuth/subscription auth. Anthropic explicitly states: *"Unless previously approved, Anthropic does not allow third party developers to offer claude.ai login or rate limits for their products, including agents built on the Claude Agent SDK."*

---

## 2. Authentication: How Claude Code CLI Authenticates

### Authentication Methods (in precedence order)
1. **Cloud provider credentials** -- `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_VERTEX`, or `CLAUDE_CODE_USE_FOUNDRY`
2. **`ANTHROPIC_AUTH_TOKEN`** env var -- Sent as `Authorization: Bearer` header (for LLM gateways/proxies)
3. **`ANTHROPIC_API_KEY`** env var -- Sent as `X-Api-Key` header (Console API keys, `sk-ant-api03-...`)
4. **`apiKeyHelper`** setting -- runs a shell script that returns an API key (dynamic/rotating credentials)
5. **OAuth credentials** from `/login` -- Default for Pro, Max, Team, Enterprise users

### OAuth Token Storage on macOS

**Location:** macOS Keychain (encrypted)

```
Service name: "Claude Code-credentials"
Account:      "<your-macos-username>"
Keychain:     ~/Library/Keychains/login.keychain-db
```

The stored JSON contains:
```json
{
  "claudeAiOauth": {
    "accessToken": "sk-ant-oat01-...",
    "refreshToken": "sk-ant-ort01-...",
    ...
  }
}
```

- `sk-ant-oat01-` = OAuth access token (tied to Claude.ai subscription)
- `sk-ant-ort01-` = OAuth refresh token

**On Linux/Windows:** Credentials are stored in `~/.claude/.credentials.json` (mode `0600` on Linux).

### Reading the token programmatically (macOS)
```bash
security find-generic-password -s "Claude Code-credentials" -w
```

### The `setup-token` Command
```bash
claude setup-token
```
Generates a long-lived OAuth token (valid ~1 year) that can be exported as:
```bash
export CLAUDE_CODE_OAUTH_TOKEN=<the-token>
```

---

## 3. Non-Interactive Mode (`-p` / `--print`)

The `-p` or `--print` flag runs Claude Code in non-interactive (headless) mode.

### Basic Commands
```bash
# Simple one-shot
claude -p "Explain this codebase"

# With JSON output
claude -p "List all TODO comments" --output-format json

# Streaming JSON
claude -p "Refactor auth.py" --output-format stream-json

# Restrict tools
claude -p "Review code" --allowedTools "Read,Glob,Grep"

# Specify model
claude -p "Fix the bug" --model claude-sonnet-4-6

# Budget cap
claude -p "Implement feature X" --max-budget-usd 5.00

# Skip all permission prompts (for sandboxed/trusted environments)
claude -p "Deploy the app" --dangerously-skip-permissions

# Multi-turn sessions
claude -p "Analyze architecture" --session-id "review-1" --output-format json
claude -p "Now fix the issues" --resume --session-id "review-1"
```

### Piping Input
```bash
echo "What does this do?" | claude -p
cat error.log | claude -p "Diagnose this error"
git diff | claude -p "Review this diff"
```

### Environment Variables for Non-Interactive Defaults
```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
export CLAUDE_CODE_MAX_TURNS=5
export CLAUDE_CODE_OUTPUT_FORMAT=json
export CLAUDE_CODE_MODEL=claude-sonnet-4-6
```

---

## 4. Running Claude Code in Docker

### Strategy A: API Key (Simplest, Recommended for CI/CD)
```bash
docker run --rm \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -v "$(pwd):/workspace" \
  -w /workspace \
  node:20 \
  bash -c "npm install -g @anthropic-ai/claude-code && claude -p 'Review this code' --dangerously-skip-permissions"
```

### Strategy B: OAuth Token from Host (Use Subscription, No API Key)
```bash
# On host: generate a long-lived token
claude setup-token
# Copy the output token

# In Docker:
docker run --rm \
  -e CLAUDE_CODE_OAUTH_TOKEN="<your-token>" \
  -v "$(pwd):/workspace" \
  -w /workspace \
  node:20 \
  bash -c '
    npm install -g @anthropic-ai/claude-code
    echo "{\"hasCompletedOnboarding\": true}" > ~/.claude.json
    claude -p "Review this code" --dangerously-skip-permissions
  '
```

**Critical note:** You must also set `hasCompletedOnboarding: true` in `~/.claude.json` or the container will prompt for onboarding even with the token set.

### Strategy C: Docker Desktop Sandbox (Official)
```bash
# Create a sandbox
docker sandbox create claude ~/my-project

# Run it (--dangerously-skip-permissions is enabled by default)
docker sandbox run claude -- "Review this codebase"
```

Uses the `docker/sandbox-templates:claude-code` template. Requires Docker Desktop.

### Strategy D: Devcontainer (VS Code)
Anthropic provides a reference devcontainer at:
https://github.com/anthropics/claude-code/tree/main/.devcontainer

Features:
- Node.js 20 base image
- Firewall rules restricting outbound to whitelisted domains only
- Pre-configured for `--dangerously-skip-permissions`
- ZSH, git, fzf, and development tools included

### Strategy E: Mount Host Credentials (Not Recommended)
```bash
# macOS: extract from Keychain first, write to a file, then mount
security find-generic-password -s "Claude Code-credentials" -w > /tmp/creds.json
docker run --rm \
  -v /tmp/creds.json:/root/.claude/.credentials.json:ro \
  -v "$(pwd):/workspace" \
  ...
```
This is fragile and the tokens may expire. Use Strategy A or B instead.

---

## 5. API Key Auth vs OAuth/Subscription Auth

| Aspect | API Key (`ANTHROPIC_API_KEY`) | OAuth/Subscription |
|--------|-------------------------------|-------------------|
| **Source** | Anthropic Console (platform.claude.com) | Claude.ai login (`/login`) |
| **Token prefix** | `sk-ant-api03-...` | `sk-ant-oat01-...` (access), `sk-ant-ort01-...` (refresh) |
| **Billing** | Per-token API usage billing | Flat subscription fee (Pro $20/mo, Max $100-200/mo) |
| **Rate limits** | API tier-based | Subscription tier-based (generally more generous for Max) |
| **Storage** | Environment variable or secrets manager | macOS Keychain / `~/.claude/.credentials.json` |
| **Headless/CI** | Native support, just set env var | Requires `setup-token` + `CLAUDE_CODE_OAUTH_TOKEN` + onboarding flag |
| **SDK support** | Full support in Agent SDK | NOT supported in Agent SDK (CLI only) |
| **Expiry** | Does not expire (until revoked) | Access token expires (auto-refreshed); setup-token valid ~1 year |
| **Best for** | CI/CD, automation, Agent SDK apps | Interactive development, teams with subscriptions |
| **Cost model** | Pay per token consumed | Unlimited within subscription tier limits |

### Key Distinction
- **API keys** let you pay per API call and work everywhere (CLI, SDK, Docker, CI/CD)
- **OAuth tokens** let you use your existing Claude subscription (Pro/Max/Team/Enterprise) through the CLI, but are restricted to the CLI only and cannot be used in the Agent SDK to build third-party products

---

## Quick Reference: Package Ecosystem

| Package | Purpose | Auth |
|---------|---------|------|
| `@anthropic-ai/claude-code` | CLI tool (`claude` command) | All methods |
| `@anthropic-ai/claude-agent-sdk` | Programmatic SDK (TypeScript) | API key only |
| `claude-agent-sdk` (PyPI) | Programmatic SDK (Python) | API key only |
| `@anthropic-ai/sdk` | Low-level API client | API key only |

---

## Sources
- https://code.claude.com/docs/en/authentication
- https://platform.claude.com/docs/en/agent-sdk/overview
- https://code.claude.com/docs/en/devcontainer
- https://docs.docker.com/ai/sandboxes/agents/claude-code/
- https://www.npmjs.com/package/@anthropic-ai/claude-agent-sdk
- https://www.npmjs.com/package/@anthropic-ai/claude-code
- https://github.com/anthropics/claude-agent-sdk-typescript
- https://github.com/anthropics/claude-code/issues/8938
