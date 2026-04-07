# CommandBase.ai

cognitiveplane.ai Hypervisor -- operational command center for AI agents under constitutional governance.

## What This Is

- **Not a dashboard.** A command center with real authority delegation, consent enforcement, trust receipts, challenge surfaces, and kill switches.
- All governance logic executes in Rust via WebAssembly (110 WASM-bridged functions).
- Every action produces a cryptographically hash-chained governance receipt.
- Constitutional invariants are enforced at the kernel level -- no overrides, no exceptions.

## Architecture

- **Express/Node.js** server with **SQLite** (WAL mode)
- **18 route modules:** analytics, calendar, companies, context, exoforge, goals, governance, gsd, ideas, members, notes, plugins, projects, refinement, research, settings, system, workspace
- **3 service layers:** exochain (WASM bridge), governance (receipt chain), heartbeat (agent liveness)
- **104 AI agent definitions** (8 board directors + department structure)
- Background worker for agent execution
- WebSocket real-time updates

## GSD Control Surfaces

21 endpoints in `app/routes/gsd.js` -- every one produces a governance receipt.

### Agent Management (5 endpoints)
| Endpoint | Method | What It Does |
|----------|--------|--------------|
| `/api/gsd/agent/verify` | POST | Verify an agent's authority chain and clearance level |
| `/api/gsd/agent/delegate` | POST | Build an authority chain from delegation links |
| `/api/gsd/agent/revoke` | POST | Terminate a bailment (revoke agent access) |
| `/api/gsd/agent/quarantine` | POST | Escalate PACE state to quarantine an agent |
| `/api/gsd/agent/reinstate` | POST | Resolve PACE and de-escalate to reinstate an agent |

### Decision Lifecycle (5 endpoints)
| Endpoint | Method | What It Does |
|----------|--------|--------------|
| `/api/gsd/decision/create` | POST | Create a new governance decision |
| `/api/gsd/decision/vote` | POST | Cast a vote in a deliberation session |
| `/api/gsd/decision/quorum` | POST | Check quorum status and verify precondition |
| `/api/gsd/decision/human-gate` | POST | Enforce human approval gate on a decision |
| `/api/gsd/decision/challenge` | POST | File a challenge against a decision |

### Constitutional Enforcement (4 endpoints)
| Endpoint | Method | What It Does |
|----------|--------|--------------|
| `/api/gsd/constitutional/enforce-tnc` | POST | Enforce all 10 TNCs and collect violations |
| `/api/gsd/constitutional/verify-chain` | POST | Verify chain of custody for evidence |
| `/api/gsd/constitutional/audit` | POST | Verify integrity of a hash-chained audit log |
| `/api/gsd/constitutional/emergency` | POST | Create and optionally ratify an emergency action |

### Identity & Cryptography (5 endpoints)
| Endpoint | Method | What It Does |
|----------|--------|--------------|
| `/api/gsd/identity/generate-keypair` | POST | Generate an Ed25519 keypair (public key only) |
| `/api/gsd/identity/sign` | POST | Sign a message with a secret key |
| `/api/gsd/identity/verify` | POST | Verify an Ed25519 signature |
| `/api/gsd/identity/shamir-split` | POST | Split a secret using Shamir's Secret Sharing |
| `/api/gsd/identity/shamir-reconstruct` | POST | Reconstruct a secret from Shamir shares |

### Holon Management (2 endpoints)
| Endpoint | Method | What It Does |
|----------|--------|--------------|
| `/api/gsd/holon/spawn` | POST | Spawn a new holon (autonomous governance agent) |
| `/api/gsd/holon/mcp-rules` | GET | Retrieve MCP governance rules |

## Running

```bash
cd command-base && npm install && npm start
# Serves on :3000
```

## Agent Registry

104 agents defined in `Team/` as Markdown profiles. Each profile specifies the agent's role, department, constitutional authority scope, and operational parameters.

- **8 board directors** -- executive governance oversight
- **Department structure** -- engineering, legal, security, compliance, research, operations, design, finance
- Archived agents in `Team/archived/`
- Research briefs in `Team/research-brief-*.md`

Every agent operates under constitutional authority delegated through the WASM bridge. Agent actions are receipt-chained and auditable.
