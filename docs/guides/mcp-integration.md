---
title: "MCP Integration Guide"
status: active
created: 2026-04-15
tags: [exochain, mcp, claude, ai, integration, guide]
---

# MCP Integration Guide

**Wire Claude (and any other MCP client) to the EXOCHAIN node over Model Context Protocol.**

The EXOCHAIN node ships an embedded MCP server exposing the full constitutional fabric: 40 tools, 6 resources, and 4 prompts. Every tool call is adjudicated by the CGR Kernel against 8 constitutional invariants and 6 MCP enforcement rules before it takes effect. AI agents do not bypass the constitution — they act inside it.

---

## Table of Contents

- [Why MCP for EXOCHAIN](#why-mcp-for-exochain)
- [Prerequisites](#prerequisites)
- [Building the node binary](#building-the-node-binary)
- [Running the MCP server](#running-the-mcp-server)
- [Claude Code configuration](#claude-code-configuration)
- [Constitutional enforcement](#constitutional-enforcement)
- [The 40 tools, by domain](#the-40-tools-by-domain)
- [The 6 resources](#the-6-resources)
- [The 4 prompts](#the-4-prompts)
- [End-to-end governance workflow](#end-to-end-governance-workflow)
- [JSON-RPC wire examples](#json-rpc-wire-examples)
- [Troubleshooting](#troubleshooting)
- [What next](#what-next)

---

## Why MCP for EXOCHAIN

Model Context Protocol (MCP) is the standard Anthropic published for giving AI agents structured access to tools, data, and prompt templates. The EXOCHAIN node implements MCP so any compliant client — Claude Desktop, Claude Code, LM Studio, or a custom agent — can drive the constitutional fabric by name.

Every request flows through the same pipeline the human-facing gateway uses: MCP middleware (the 6 rules) -> CGR Kernel (8 invariants) -> the tool's effect. An AI agent cannot forge identity, self-escalate, or act without provenance. When the kernel denies an action, the response carries the invariant name and a human-readable reason, so the agent can adapt.

---

## Prerequisites

| Requirement | Why |
|---|---|
| **Rust 1.85+** | Node compilation (`cargo build`). |
| **An MCP client** | Claude Code, Claude Desktop, or any spec-compliant client. |
| **Port 3030 free** (optional) | Only if using SSE transport. |
| **~1 GB disk** (optional) | Only if the node will persist data to `~/.exochain`. |

See [`docs/guides/GETTING-STARTED.md`](./GETTING-STARTED.md) for the full toolchain setup (cargo-deny, cargo-audit, cargo-tarpaulin). None of those are required for the MCP server specifically.

---

## Building the node binary

From the repo root:

```bash
git clone https://github.com/exochain/exochain.git
cd exochain
cargo build --release -p exo-node
```

The binary lands at `target/release/exochain`. Put it on your `PATH` for convenience:

```bash
sudo cp target/release/exochain /usr/local/bin/exochain
exochain --version
```

Expected output:

```text
exochain 0.1.0
```

---

## Running the MCP server

The `exochain mcp` subcommand starts the MCP server. Two transports are supported.

### Stdio (default)

Used by Claude Desktop and Claude Code. The server reads newline-delimited JSON-RPC from stdin and writes responses to stdout. All logs go to stderr.

```bash
exochain mcp
```

Expected stderr on startup:

```text
[exochain-mcp] Constitutional MCP server ready on stdio
[exochain-mcp] Actor: did:exo:<node-identity>
[exochain-mcp] Tools: 40
```

Flags:

| Flag | Meaning |
|---|---|
| `--actor-did <DID>` | Override the default actor DID (otherwise derived from the node's identity). |
| `--data-dir <PATH>` | Override `~/.exochain`. |

### SSE (HTTP+Server-Sent Events)

For remote clients, browsers, and debugging. The server serves MCP over HTTP on the given bind address.

```bash
exochain mcp --sse 127.0.0.1:3030
```

Expected stderr:

```text
[exochain-mcp] Constitutional MCP server ready on SSE: http://127.0.0.1:3030
[exochain-mcp] Actor: did:exo:<node-identity>
```

The SSE endpoint accepts `POST /mcp` with a JSON-RPC body and streams responses on `GET /events`.

### Quick smoke test

With the stdio server running in one terminal, pipe it a discovery request in another:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | exochain mcp
```

Expected output (truncated):

```json
{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"exochain_node_status",...}, ...]}}
```

---

## Claude Code configuration

Add the EXOCHAIN MCP server to Claude Code via your MCP config file. On macOS / Linux, the file lives at `~/.claude/mcp.json` (path may vary by Claude Code version):

```json
{
  "mcpServers": {
    "exochain": {
      "command": "exochain",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

If you built from source and did not install to `PATH`, use the absolute path:

```json
{
  "mcpServers": {
    "exochain": {
      "command": "/Users/you/dev/exochain/target/release/exochain",
      "args": ["mcp", "--actor-did", "did:exo:my-claude-agent"],
      "env": {
        "EXO_DATA_DIR": "/Users/you/.exochain"
      }
    }
  }
}
```

Restart Claude Code. The server advertises 40 tools, 6 resources, and 4 prompts. You should see them under the MCP menu.

### Claude Desktop

Claude Desktop uses the same config format at `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "exochain": {
      "command": "exochain",
      "args": ["mcp"]
    }
  }
}
```

### Remote SSE client

For HTTP-based clients, point at `http://127.0.0.1:3030/mcp` and use standard MCP JSON-RPC. The CLI flag `--sse 0.0.0.0:3030` binds publicly — do not do this without a reverse proxy enforcing TLS and auth.

---

## Constitutional enforcement

Every `tools/call` traverses this stack:

```
MCP client
    |
    v
MCP middleware (6 rules):
    Mcp001BctsScope        — declared bailment scope required
    Mcp002NoSelfEscalation — AI cannot widen its own scope
    Mcp003ProvenanceRequired — actor DID + timestamp + signature
    Mcp004NoIdentityForge  — signature type is part of signed payload
    Mcp005Distinguishable  — AI outputs flagged AI-produced
    Mcp006ConsentBoundaries — revocation is immediate
    |
    v
CGR Kernel (8 invariants):
    1. SeparationOfPowers
    2. ConsentRequired
    3. NoSelfGrant
    4. HumanOverride
    5. KernelImmutability
    6. AuthorityChainValid
    7. QuorumLegitimate
    8. ProvenanceVerifiable
    |
    v
Tool handler
    |
    v
Response (JSON-RPC result or error)
```

When enforcement blocks a call, the response includes the violated invariant name so the agent can explain it. The canonical names for all 8 invariants and all 6 rules are available as MCP resources — an agent can read them at session start to learn the rules of the fabric.

---

## The 40 tools, by domain

Tools are namespaced `exochain_<verb>`. Counts: 3+5+4+5+4+4+4+4+4+3 = 40.

### Node (3)

| Tool | Purpose |
|---|---|
| `exochain_node_status` | Liveness, uptime, version, actor DID. |
| `exochain_list_invariants` | Return all 8 constitutional invariants with descriptions. |
| `exochain_list_mcp_rules` | Return all 6 MCP enforcement rules with descriptions. |

Use these at session start to let the agent self-orient.

### Identity (5)

| Tool | Purpose |
|---|---|
| `exochain_create_identity` | Generate an Ed25519 keypair and a `did:exo:` DID. Input: `{ label? }`. |
| `exochain_resolve_identity` | Resolve a DID to its document / validity state. Input: `{ did }`. |
| `exochain_assess_risk` | Compute a risk score from evidence types. Input: `{ did, evidence_types? }`. |
| `exochain_verify_signature` | Verify an Ed25519 signature against a DID's public key. |
| `exochain_get_passport` | Fetch the agent passport for a DID (capabilities + provenance). |

### Consent (4)

| Tool | Purpose |
|---|---|
| `exochain_propose_bailment` | Propose a scoped, time-bounded consent. Input: `{ bailor_did, bailee_did, scope, duration_hours? }`. |
| `exochain_check_consent` | Is there active consent for actor+scope? Input: `{ actor_did, scope }`. |
| `exochain_list_bailments` | List bailments the agent knows about. |
| `exochain_terminate_bailment` | Revoke a bailment — effect is immediate (invariant `ConsentRequired`). |

### Governance (5)

| Tool | Purpose |
|---|---|
| `exochain_create_decision` | Open a governance decision. Input: `{ title, description, proposer_did, decision_class? }`. |
| `exochain_cast_vote` | Cast a vote (`approve`/`reject`/`abstain`) with optional rationale. |
| `exochain_check_quorum` | Tally votes against a threshold. Input: `{ decision_id, threshold }`. |
| `exochain_get_decision_status` | Return the current BCTS lifecycle state for a decision. |
| `exochain_propose_amendment` | Propose a constitutional amendment (requires elevated privilege). |

### Authority (4)

| Tool | Purpose |
|---|---|
| `exochain_delegate_authority` | Create a delegation link grantor->grantee with permissions. |
| `exochain_verify_authority_chain` | Validate a chain's topology and signatures. |
| `exochain_check_permission` | Does the agent have permission X on resource Y? |
| `exochain_adjudicate_action` | Run an action through the CGR Kernel and return a verdict. |

### Ledger (4)

| Tool | Purpose |
|---|---|
| `exochain_submit_event` | Append a signed event to the ledger. |
| `exochain_get_event` | Fetch an event by hash. |
| `exochain_verify_inclusion` | Prove a given event is in a given checkpoint. |
| `exochain_get_checkpoint` | Fetch the latest signed checkpoint. |

### Proofs (4)

| Tool | Purpose |
|---|---|
| `exochain_create_evidence` | Construct a verifier-compatible legal evidence envelope from UUID, content hash, creator DID, and creation HLC; this does not persist evidence. |
| `exochain_verify_chain_of_custody` | Verify evidence UUID/DID/hash metadata, transfer continuity, transfer reasons, and monotonic HLC timestamps. |
| `exochain_generate_merkle_proof` | Produce a verifier-compatible Merkle inclusion proof for a 32-byte event hash, returning `event_hash`, `root_hash`, and `proof_hashes`. |
| `exochain_verify_cgr_proof` | Refuses CGR proof verification until proof bytes, public inputs, checkpoint roots, validator signatures, and a production verifier are wired. |

### Legal (4)

| Tool | Purpose |
|---|---|
| `exochain_ediscovery_search` | Search the ledger for events matching a legal-discovery query. |
| `exochain_assert_privilege` | Mark documents as privileged (attorney-client, work product). |
| `exochain_initiate_safe_harbor` | Start a safe-harbor remediation flow. |
| `exochain_check_fiduciary_duty` | Evaluate whether an action would breach fiduciary duty. |

### Escalation (4)

| Tool | Purpose |
|---|---|
| `exochain_evaluate_threat` | Score a threat indicator against the threat model. |
| `exochain_escalate_case` | Open an escalation case. |
| `exochain_triage` | Triage an incoming case and route it. |
| `exochain_record_feedback` | Attach feedback to a case. |

### Messaging (3)

| Tool | Purpose |
|---|---|
| `exochain_send_encrypted` | Send an end-to-end-encrypted message to a DID. |
| `exochain_receive_encrypted` | Decrypt inbound messages. |
| `exochain_configure_death_trigger` | Configure a dead-mans-switch delivery. |

For the canonical tool list at runtime, call `tools/list` or read `exochain://tools` (see next section).

---

## The 6 resources

Resources are read-only artifacts under the `exochain://` URI scheme. Read them with `resources/read`.

| URI | MIME | Contents |
|---|---|---|
| `exochain://constitution` | `text/plain` | The BLAKE3-hashed constitution text. |
| `exochain://invariants` | `application/json` | The 8 invariants, each with `index`, `name`, `description`. |
| `exochain://mcp-rules` | `application/json` | The 6 MCP enforcement rules with descriptions. |
| `exochain://node/status` | `application/json` | Live node snapshot (uptime, actor, peer count). |
| `exochain://tools` | `application/json` | All 40 tools grouped by domain with `total: 40`. |
| `exochain://readme` | `text/markdown` | Agent-oriented quick reference. |

Example: fetch the invariants:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"exochain://invariants"}}' \
  | exochain mcp
```

Response shape:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "contents": [
      {
        "uri": "exochain://invariants",
        "mimeType": "application/json",
        "text": "{\n  \"count\": 8,\n  \"invariants\": [ ... ]\n}"
      }
    ]
  }
}
```

---

## The 4 prompts

Prompts are parameterized workflow templates. Fetch one with `prompts/get`.

| Name | Required args | Optional args | Purpose |
|---|---|---|---|
| `governance_review` | `decision_id`, `decision_title` | `summary`, `proposer_did` | Structured review of a pending decision. Tells the agent which tools to call (e.g. `exochain_check_quorum`) before answering. |
| `compliance_check` | `action`, `actor_did` | `rationale`, `resource` | Verify an action against the 8 invariants + 6 MCP rules. |
| `evidence_analysis` | `bundle_id` | `case_id`, `custodian_did`, `context` | Analyze evidence for admissibility and chain-of-custody integrity. |
| `constitutional_audit` | `scope` | `timestamp`, `auditor_did`, `focus` | Audit a subsystem against all 8 invariants. |

Each prompt returns one or more `messages` formatted for direct inclusion in the agent's context — the messages embed the named arguments and point the agent at the relevant tools.

---

## End-to-end governance workflow

A Claude agent performing a real governance operation end-to-end. In practice the agent strings these tool calls together automatically once asked "ratify this amendment".

```
1.  exochain_create_identity              -> actor DID + public key
2.  exochain_propose_bailment              -> proposal_id (scope="governance:vote")
3.  exochain_check_consent                 -> ensure active consent
4.  exochain_create_decision               -> decision_id
5.  exochain_cast_vote    (x N validators) -> record approvals
6.  exochain_check_quorum                  -> met=true at threshold
7.  exochain_verify_authority_chain        -> proposer chain valid
8.  exochain_adjudicate_action             -> kernel verdict: Permitted
9.  exochain_submit_event                  -> append decision event to ledger
10. exochain_get_checkpoint                -> fresh checkpoint root
11. exochain_verify_inclusion              -> inclusion proof for step 9
```

Each call is independently constitutional: step 5 will be denied for a duplicate voter (`QuorumLegitimate`); step 8 will be denied if the authority chain in step 7 does not match; step 1 produces provenance the kernel will require in every later step (`ProvenanceVerifiable`).

---

## JSON-RPC wire examples

The MCP protocol is JSON-RPC 2.0 over stdio or HTTP. Every request has `jsonrpc`, `id`, `method`, optional `params`. Responses carry a matching `id` and either `result` or `error`.

### Discovery: list all tools

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list"
}
```

Response (abridged):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "exochain_node_status",
        "description": "Return node status, uptime, and actor DID.",
        "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
      },
      {
        "name": "exochain_create_identity",
        "description": "Create a new DID identity with an Ed25519 keypair. ...",
        "inputSchema": {
          "type": "object",
          "properties": {
            "label": { "type": "string", "description": "Optional human-readable label for this identity." }
          },
          "additionalProperties": false
        }
      }
      // ... 38 more tools ...
    ]
  }
}
```

### Call: create identity

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "exochain_create_identity",
    "arguments": { "label": "alice" }
  }
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"did\":\"did:exo:d9c21e4b7f1a8035\",\"public_key_hex\":\"1aef...\",\"verification_method_id\":\"did:exo:d9c21e4b7f1a8035#key-1\",\"label\":\"alice\"}"
      }
    ]
  }
}
```

### Call: propose bailment

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "exochain_propose_bailment",
    "arguments": {
      "bailor_did": "did:exo:alice",
      "bailee_did": "did:exo:bob",
      "scope": "data:medical:records",
      "duration_hours": 24
    }
  }
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"proposal_id\":\"4f2a910b...\",\"bailor\":\"did:exo:alice\",\"bailee\":\"did:exo:bob\",\"scope\":\"data:medical:records\",\"status\":\"proposed\",\"expires_at\":\"1713196800000:0\"}"
      }
    ]
  }
}
```

### Call: create decision, cast vote, check quorum

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "exochain_create_decision",
    "arguments": {
      "title": "Raise quorum threshold to 3/4",
      "description": "Constitutional amendment.",
      "proposer_did": "did:exo:alice",
      "decision_class": "amendment"
    }
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "exochain_cast_vote",
    "arguments": {
      "decision_id": "9f3c2a1b...",
      "voter_did": "did:exo:v1",
      "choice": "approve",
      "rationale": "Aligns with charter."
    }
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "exochain_check_quorum",
    "arguments": {
      "decision_id": "9f3c2a1b...",
      "threshold": 2
    }
  }
}
```

A kernel denial looks like this (not a JSON-RPC `error`, but a tool result carrying `error: ...`):

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"error\":\"denied: NoSelfGrant — actor attempted to grant permissions to themselves\"}"
      }
    ],
    "isError": true
  }
}
```

### Read a resource

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "resources/read",
  "params": { "uri": "exochain://mcp-rules" }
}
```

### Get a prompt

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "prompts/get",
  "params": {
    "name": "governance_review",
    "arguments": {
      "decision_id": "9f3c2a1b...",
      "decision_title": "Raise quorum threshold to 3/4",
      "proposer_did": "did:exo:alice",
      "summary": "Move threshold from 2/3 to 3/4 for constitutional amendments."
    }
  }
}
```

Response (abridged): a filled-in multi-turn prompt instructing the agent to call `exochain_get_decision_status`, `exochain_check_quorum`, and `exochain_verify_authority_chain` before producing a recommendation.

---

## Troubleshooting

### "Server not found" in Claude Code

- Verify the binary is executable: `exochain --version` should print a version.
- Use an absolute path in `mcp.json`.
- Check Claude Code logs for the actual error — path typos are the most common cause.

### No tools appear after connecting

- Confirm `tools/list` returns 40 tools via the smoke test:

  ```bash
  echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | exochain mcp | jq '.result.tools | length'
  ```

  Expected: `40`.

- If the number is wrong, the binary is stale — rebuild with `cargo build --release -p exo-node`.

### "tool not found" error at runtime

Tool names are **case-sensitive**, prefixed `exochain_`, and snake-cased. `exochainCastVote` won't match; `exochain_cast_vote` will.

### Stdio hangs and produces no output

- All diagnostics go to stderr. Look at the terminal's stderr for `[exochain-mcp] ...` lines.
- The server reads *newline-delimited* JSON. An unterminated line will hang until EOF.
- If you're piping, ensure your producer flushes and writes `\n`.

### "JSON-RPC parse error"

- Every request must be a single-line JSON object, followed by `\n`.
- The server ignores empty lines but not multi-line JSON.

### Kernel denial with unclear reason

Every deny carries the invariant name. Common cases:

| Message substring | Cause | Fix |
|---|---|---|
| `NoSelfGrant` | Actor tried to grant itself permissions | Route the grant through a distinct grantor DID. |
| `ConsentRequired` | No active bailment for the scope | Call `exochain_propose_bailment` first. |
| `AuthorityChainValid` | Chain broken or terminal mismatch | Inspect via `exochain_verify_authority_chain`. |
| `KernelImmutability` | Tried to modify the constitution | Use the amendment proposal process instead. |
| `ProvenanceVerifiable` | Missing signature or timestamp | Ensure the calling agent's identity is set (`--actor-did`). |

### SSE returns 502 from a reverse proxy

Nginx and similar proxies buffer by default. Disable buffering on the SSE endpoint:

```nginx
location /events {
    proxy_pass http://127.0.0.1:3030/events;
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 24h;
}
```

### Rate limit / governance denial loops

If an agent repeatedly triggers the same kernel denial, read `exochain://invariants` and `exochain://mcp-rules` and feed them into the agent's context. The rule names are stable and the descriptions are designed to tell the agent exactly what to change.

---

## What next

- **Rust SDK** — [`docs/guides/sdk-quickstart-rust.md`](./sdk-quickstart-rust.md). Build callers that produce the same constitutional evidence the MCP server consumes.
- **TypeScript SDK** — [`docs/guides/sdk-quickstart-typescript.md`](./sdk-quickstart-typescript.md).
- **Python SDK** — [`docs/guides/sdk-quickstart-python.md`](./sdk-quickstart-python.md).
- **Getting Started** — [`docs/guides/GETTING-STARTED.md`](./GETTING-STARTED.md). Workspace build, CI gates.
- **Architecture** — [`docs/architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md). Three branches, BCTS lifecycle.
- **Threat model** — [`docs/architecture/THREAT-MODEL.md`](../architecture/THREAT-MODEL.md). Twelve threats and their mitigations.
- **Proofs** — [`docs/proofs/CONSTITUTIONAL-PROOFS.md`](../proofs/CONSTITUTIONAL-PROOFS.md). Ten formal proofs that the invariants hold.
- **MCP source**:
  - Tool registry — [`crates/exo-node/src/mcp/tools/mod.rs`](../../crates/exo-node/src/mcp/tools/mod.rs)
  - Resource registry — [`crates/exo-node/src/mcp/resources/mod.rs`](../../crates/exo-node/src/mcp/resources/mod.rs)
  - Prompt registry — [`crates/exo-node/src/mcp/prompts/mod.rs`](../../crates/exo-node/src/mcp/prompts/mod.rs)
  - Transport entry — [`crates/exo-node/src/mcp/mod.rs`](../../crates/exo-node/src/mcp/mod.rs)
  - CLI — [`crates/exo-node/src/cli.rs`](../../crates/exo-node/src/cli.rs)

---

Licensed under Apache-2.0. © 2025 EXOCHAIN Foundation.
