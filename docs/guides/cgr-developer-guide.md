# CGR Developer Guide

**Constitutional Governance Runtime — API Reference & Integration Guide**

Version: 1.0.0
Crate: `exo-gatekeeper`
Audience: Developers integrating with the CGR judicial kernel, writing new governance operations, or extending constitutional enforcement.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Calling `Kernel::adjudicate`](#2-calling-kerneladjudicate)
3. [Composing Combinator Algebra](#3-composing-combinator-algebra)
4. [Adding a New Invariant](#4-adding-a-new-invariant)
5. [MCP Enforcement for AI Agents](#5-mcp-enforcement-for-ai-agents)
6. [5-Panel AI-IRB → decision.forum Integration](#6-5-panel-ai-irb--decisionforum-integration)
7. [When to Escalate](#7-when-to-escalate)
8. [Common Mistakes](#8-common-mistakes)

---

## 1. Overview

The CGR (Constitutional Governance Runtime) is the **judicial branch** of ExoChain. It is the single enforcement point for all eight constitutional invariants. No governance operation — whether from the legislative (`exo-governance`), executive (Holons), or application (`decision-forum`) branch — bypasses it.

```
Legislative (exo-governance)
    ↓  proposes action
Executive (Holon / combinator program)
    ↓  requests adjudication
Judicial (Kernel::adjudicate)          ← you are here
    ↓  Verdict: Permitted / Denied / Escalated
Governance outcome applied (or not)
```

### Separation of Powers

| Branch | Crate | Role |
|--------|-------|------|
| Legislative | `exo-governance` | Proposes, votes, ratifies |
| Executive | `exo-gatekeeper` (Holon) | Executes combinator programs |
| Judicial | `exo-gatekeeper` (Kernel) | Adjudicates all actions |

The Kernel is **immutable after construction**. Its `constitution_hash` is BLAKE3-locked at `Kernel::new()`. No caller can modify invariant enforcement without constructing a new kernel, which requires a governance vote.

---

## 2. Calling `Kernel::adjudicate`

### 2.1 Constructing the Kernel

```rust
use exo_gatekeeper::{Kernel, InvariantSet};

// Load constitution bytes (CBOR-serialized constitutional document)
let constitution: &[u8] = /* load from exo-governance::Constitution */;

// Build with all 8 invariants active
let kernel = Kernel::new(constitution, InvariantSet::all());

// Or with a custom subset (for testing only — never in production)
let kernel = Kernel::new(constitution, InvariantSet::with(vec![
    ConstitutionalInvariant::SeparationOfPowers,
    ConstitutionalInvariant::ConsentRequired,
]));
```

> **Rule:** Always use `InvariantSet::all()` in production. Subsetting invariants bypasses constitutional enforcement.

### 2.2 Building an `ActionRequest`

```rust
use exo_gatekeeper::{ActionRequest, PermissionSet, Permission};
use exo_core::Did;

let action = ActionRequest {
    actor: Did::from("did:exo:agent-abc"),
    action: "governance:cast_vote".to_string(),
    required_permissions: PermissionSet::new(vec![
        Permission::new("vote:strategic"),
    ]),
    is_self_grant: false,     // true only if the actor is granting themselves a permission
    modifies_kernel: false,   // true only for constitutional amendment operations
};
```

**`is_self_grant`:** Set to `true` only when the action is a permission self-grant. This triggers the `NoSelfGrant` invariant check. If you set this incorrectly, the Kernel will deny legitimate operations.

**`modifies_kernel`:** Set to `true` only for operations that change the constitutional corpus (e.g., constitutional amendments). This triggers `KernelImmutability` enforcement.

### 2.3 Building an `AdjudicationContext`

The context carries all runtime evidence that the invariant checks evaluate.

```rust
use exo_gatekeeper::{
    AdjudicationContext, Role, GovernmentBranch,
    AuthorityChain, AuthorityLink, BailmentState,
    ConsentRecord, QuorumEvidence, QuorumVote, Provenance,
};

let context = AdjudicationContext {
    // Roles determine SeparationOfPowers check
    actor_roles: vec![
        Role { name: "voter".into(), branch: GovernmentBranch::Legislative },
    ],

    // Authority chain — must form unbroken topology ending at actor
    authority_chain: AuthorityChain {
        links: vec![
            AuthorityLink {
                grantor: Did::from("did:exo:root"),
                grantee: Did::from("did:exo:agent-abc"),
                permissions: PermissionSet::new(vec![Permission::new("vote:strategic")]),
                signature: /* Ed25519 signature bytes */,
                grantor_public_key: Some(/* 32-byte Ed25519 public key */),
            },
        ],
    },

    // Bailment state — must be Active for ConsentRequired
    bailment_state: BailmentState::Active {
        bailor: Did::from("did:exo:principal"),
        bailee: Did::from("did:exo:agent-abc"),
        scope: "governance".into(),
    },

    // Consent records — one must match actor and be active
    consent_records: vec![
        ConsentRecord {
            subject: Did::from("did:exo:principal"),
            granted_to: Did::from("did:exo:agent-abc"),
            scope: "governance".into(),
            active: true,
        },
    ],

    // HumanOverride flag — must be true unless explicitly waived by constitution
    human_override_preserved: true,

    // Permissions held by the actor
    actor_permissions: PermissionSet::new(vec![Permission::new("vote:strategic")]),

    // Optional — required if QuorumLegitimate invariant is in the active set
    quorum_evidence: Some(QuorumEvidence {
        threshold: 3,
        votes: vec![
            QuorumVote { voter: Did::from("did:exo:v1"), approved: true, signature: vec![1] },
            QuorumVote { voter: Did::from("did:exo:v2"), approved: true, signature: vec![2] },
            QuorumVote { voter: Did::from("did:exo:v3"), approved: true, signature: vec![3] },
        ],
    }),

    // Optional — required if ProvenanceVerifiable invariant is in the active set.
    // Set public_key to Some(32-byte Ed25519 key) to enable full cryptographic
    // signature verification (closes GAP-02). Leave None for legacy non-empty check.
    provenance: Some(Provenance {
        actor: Did::from("did:exo:agent-abc"),
        timestamp: "2026-03-30T00:00:00Z".into(),
        action_hash: blake3::hash(b"governance:cast_vote").as_bytes().to_vec(),
        signature: /* 64-byte Ed25519 signature bytes */,
        public_key: Some(/* 32-byte Ed25519 public key */),
    }),
};
```

### 2.4 Calling `adjudicate` and Handling the Verdict

```rust
use exo_gatekeeper::Verdict;

match kernel.adjudicate(&action, &context) {
    Verdict::Permitted => {
        // Proceed with the governance operation
    }

    Verdict::Denied { violations } => {
        // Log violations and reject the operation
        for v in &violations {
            tracing::warn!(
                invariant = ?v.invariant,
                description = %v.description,
                "Constitutional violation"
            );
        }
        return Err(/* your crate's error type */);
    }

    Verdict::Escalated { reason } => {
        // The action requires human review before it can proceed.
        // Route to exo-escalation for human approval.
        tracing::info!(reason = %reason, "Escalating to human review");
        escalation::request_human_review(action, context, reason).await?;
        return Ok(()); // operation is pending, not failed
    }
}
```

> **Escalation vs. Denial:** `Escalated` is **recoverable** — it means the action is valid in principle but requires human authorization (e.g., quorum threshold not yet met). `Denied` is **final** — the action violates a constitutional invariant.

### 2.5 Verifying Kernel Integrity

Before any high-stakes operation, verify the kernel has not been tampered with:

```rust
let constitution_bytes: &[u8] = /* same bytes used at construction */;
assert!(
    kernel.verify_kernel_integrity(constitution_bytes),
    "Kernel constitution hash mismatch — possible tampering"
);
```

---

## 3. Composing Combinator Algebra

The combinator algebra (`exo_gatekeeper::Combinator`) is a **pure, deterministic** reduction engine. The same input always produces the same output. It is used to compose Holon programs — sequences of governance operations that run under kernel adjudication.

### 3.1 Core Variants

```rust
use exo_gatekeeper::{Combinator, Predicate, TransformFn, RetryPolicy, Duration, CheckpointId};

// Identity — pass input through unchanged
let noop = Combinator::Identity;

// Sequence — run A then B; B receives A's output; fails fast on first error
let seq = Combinator::Sequence(vec![step_a, step_b, step_c]);

// Parallel — run all branches; all must succeed; results merged
let par = Combinator::Parallel(vec![branch_x, branch_y]);

// Choice — try each in order; first success wins; all must fail to return error
let fallback = Combinator::Choice(vec![primary, secondary, tertiary]);

// Guard — run inner only if predicate holds on input
let guarded = Combinator::Guard(
    Box::new(inner_op),
    Predicate {
        name: "requires_steward_role".into(),
        required_key: "actor_role".into(),
        expected_value: Some("steward".into()),
    },
);

// Transform — run inner, then add/overwrite a key in the output
let transformed = Combinator::Transform(
    Box::new(inner_op),
    TransformFn {
        name: "mark_approved".into(),
        output_key: "status".into(),
        output_value: "approved".into(),
    },
);

// Retry — run inner up to max_retries times on failure
let retried = Combinator::Retry(
    Box::new(fallible_op),
    RetryPolicy { max_retries: 3, current_attempt: 0 },
);

// Timeout — records budget_ms in output (enforcement at Holon layer)
let timed = Combinator::Timeout(
    Box::new(long_op),
    Duration(5_000), // 5 seconds in milliseconds
);

// Checkpoint — marks a safe resume point; records checkpoint_id in output
let checkpointed = Combinator::Checkpoint(
    Box::new(resumable_op),
    CheckpointId("vote-phase-complete".into()),
);
```

### 3.2 Reducing a Combinator

```rust
use exo_gatekeeper::{reduce, CombinatorInput};

let input = CombinatorInput::new()
    .with("actor_did", "did:exo:agent-abc")
    .with("decision_id", "dec-789")
    .with("actor_role", "steward");

match reduce(&my_combinator, &input) {
    Ok(output) => {
        let status = output.fields.get("status");
        // process output
    }
    Err(e) => {
        // GatekeeperError::CombinatorError, GuardFailed, etc.
    }
}
```

### 3.3 A Realistic Governance Operation

This composes a strategic vote operation that requires a steward role, records a checkpoint, and marks the result:

```rust
let vote_program = Combinator::Sequence(vec![
    // Guard: actor must have steward role
    Combinator::Guard(
        Box::new(Combinator::Identity),
        Predicate {
            name: "steward_required".into(),
            required_key: "actor_role".into(),
            expected_value: Some("steward".into()),
        },
    ),
    // Checkpoint: record that role check passed
    Combinator::Checkpoint(
        Box::new(Combinator::Identity),
        CheckpointId("role-check-passed".into()),
    ),
    // Transform: mark vote as cast
    Combinator::Transform(
        Box::new(Combinator::Identity),
        TransformFn {
            name: "record_vote".into(),
            output_key: "vote_status".into(),
            output_value: "cast".into(),
        },
    ),
]);
```

### 3.4 Running Under Kernel Adjudication (Holon)

Do not call `reduce()` directly for governance operations. Use a `Holon` so the kernel adjudicates every step:

```rust
use exo_gatekeeper::{Holon, spawn, step};
use exo_core::Did;

let mut holon = spawn(
    Did::from("did:exo:holon-vote-001"),
    actor_permissions,
    vote_program,
);

// Each step calls kernel.adjudicate() internally
match step(&mut holon, &input, &kernel, &adjudication_context) {
    Ok(output) => { /* step succeeded */ }
    Err(GatekeeperError::HolonError(msg)) if msg.contains("Denied") => {
        // Holon is now Terminated — do not retry
    }
    Err(GatekeeperError::HolonError(msg)) if msg.contains("Escalated") => {
        // Holon is now Suspended — route to human review, then resume
        let checkpoint = suspend(&mut holon)?;
        // ... after human approval ...
        resume(&mut holon, &checkpoint)?;
    }
    Err(e) => { /* other errors */ }
}
```

---

## 4. Adding a New Invariant

Follow these steps to add a constitutional invariant. Read `AGENTS.md §How to Add a New Invariant` for the authoritative checklist.

### Step 1: Add the variant to `ConstitutionalInvariant`

```rust
// crates/exo-gatekeeper/src/invariants.rs
pub enum ConstitutionalInvariant {
    // ... existing variants ...
    MyNewInvariant,  // add here
}
```

### Step 2: Add required context fields to `InvariantContext`

If your invariant needs new runtime evidence, add fields to `InvariantContext`:

```rust
pub struct InvariantContext {
    // ... existing fields ...
    pub my_new_evidence: bool,  // add here
}
```

Update `Kernel::adjudicate` to populate this field from `AdjudicationContext`, and add the corresponding field to `AdjudicationContext`.

### Step 3: Implement the check function

```rust
fn check_my_new_invariant(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    if !ctx.my_new_evidence {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::MyNewInvariant,
            description: "MyNewInvariant: condition not satisfied".into(),
            evidence: vec![
                format!("my_new_evidence = {}", ctx.my_new_evidence),
            ],
        });
    }
    Ok(())
}
```

### Step 4: Wire it into `check_invariant`

```rust
fn check_invariant(
    invariant: ConstitutionalInvariant,
    context: &InvariantContext,
) -> Result<(), InvariantViolation> {
    match invariant {
        // ... existing arms ...
        ConstitutionalInvariant::MyNewInvariant => check_my_new_invariant(context),
    }
}
```

### Step 5: Add to `InvariantSet::all()`

```rust
pub fn all() -> Self {
    InvariantSet {
        invariants: vec![
            // ... existing ...
            ConstitutionalInvariant::MyNewInvariant,
        ],
    }
}
```

### Step 6: Decide escalation behavior (if needed)

If this invariant should produce `Verdict::Escalated` rather than `Verdict::Denied` for a single violation, update `Kernel::adjudicate`:

```rust
// kernel.rs — escalation check
let should_escalate = violations.len() == 1 && matches!(
    violations[0].invariant,
    ConstitutionalInvariant::QuorumLegitimate
    | ConstitutionalInvariant::AuthorityChainValid
    | ConstitutionalInvariant::MyNewInvariant  // add here if needed
);
```

### Step 7: Write tests

Every invariant needs at minimum:
- A test that passes with valid context
- A test that fails with an invalid context
- A test for each evidence edge case

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_my_new_invariant_passes() { /* ... */ }

    #[test]
    fn test_my_new_invariant_fails_when_evidence_missing() { /* ... */ }
}
```

### Step 8: File a governance proposal

Adding a constitutional invariant requires council review via the AI-IRB process. See [Section 6](#6-5-panel-ai-irb--decisionforum-integration).

---

## 5. MCP Enforcement for AI Agents

All AI agents operating within ExoChain must satisfy six MCP rules before their actions are permitted by the kernel.

### 5.1 Building an `McpContext`

```rust
use exo_gatekeeper::{McpContext, McpRule};
use exo_core::SignerType;

let mcp_ctx = McpContext {
    actor_did: Did::from("did:exo:ai-agent-001"),
    signer_type: SignerType::AiAgent { delegation_id: "del-xyz".into() },
    bcts_scope: Some("governance:vote".into()),     // MCP-001: must be set
    capabilities: actor_permissions.clone(),
    action: "governance:cast_vote".into(),
    has_provenance: true,                            // MCP-003: required
    forging_identity: false,                         // MCP-004: must be false
    output_marked_ai: true,                          // MCP-005: must be true
    consent_active: true,                            // MCP-006: must be true
    self_escalation: false,                          // MCP-002: must be false
};
```

### 5.2 Enforcing MCP Rules

```rust
use exo_gatekeeper::mcp::enforce;

match enforce(&McpRule::all(), &mcp_ctx) {
    Ok(()) => { /* AI action permitted */ }
    Err(violation) => {
        tracing::error!(
            rule = ?violation.rule,
            severity = violation.severity,
            "MCP rule violation"
        );
        return Err(/* your error */);
    }
}
```

### 5.3 AI Identity Binding

The `SignerType` is **cryptographically embedded** in every signed payload. You cannot impersonate a human by passing `SignerType::Human` — the signature will be rejected because the payload prefix byte (`0x01` for human, `0x02` for AI) does not match the key material used to sign.

```rust
// Building a signed payload for an AI agent
let payload = exo_gatekeeper::mcp::build_signed_payload(
    &SignerType::AiAgent { delegation_id: "del-xyz".into() },
    message_bytes,
);
// payload = [0x02, ...message_bytes]
```

### 5.4 MCP Audit Log

All MCP enforcement outcomes must be recorded in a hash-chained audit log:

```rust
use exo_gatekeeper::{McpAuditLog, McpEnforcementOutcome};
use exo_gatekeeper::mcp_audit::{create_record, append};
use exo_core::Timestamp;
use uuid::Uuid;

let mut log = McpAuditLog::new();

let record = create_record(
    &log,
    Uuid::from_u128(0xA11D17),
    Timestamp::new(1_800_000_000_000, 0),
    McpRule::Mcp001BctsScope,
    actor_did.clone(),
    McpEnforcementOutcome::Allowed,
    Some("EU".into()), // data residency region (GDPR Chapter V)
)?;
append(&mut log, record)?;

// Verify chain integrity at any point
exo_gatekeeper::mcp_audit::verify_chain(&log)?;
```

---

## 6. 5-Panel AI-IRB → decision.forum Integration

Any significant change to the CGR — a new invariant, a combinator algebra extension, a constitutional amendment — requires review by the five-panel AI-IRB before it is merged.

### 6.1 The Five Panels

| Panel | Crate Focus | Key Questions |
|-------|-------------|---------------|
| 1 — Governance | `exo-governance`, `exo-gatekeeper` | Does this preserve SeparationOfPowers? Does it respect the 8 invariants? |
| 2 — Legal | `exo-legal` | GDPR, EU AI Act, DGCL §144 compliance? Evidence chain integrity maintained? |
| 3 — Architecture | All crates | Determinism preserved? No `HashMap`, floats, `SystemTime`? CBOR sorted? |
| 4 — Security | `exo-gatekeeper`, `exo-identity` | Cryptographic correctness? Sybil resistance? Impersonation attack surface? |
| 5 — Operations | `exo-gateway`, `exo-tenant` | TEE attestation? Circuit breaker persistence? In-memory state risks? |

### 6.2 The AI-IRB Flow

```
1. exochain-investigate-feedback
   └─ File a GitHub issue or Paperclip task with:
      - Description of the change
      - Which invariants are affected
      - Why this change is needed (governance motivation)
      ↓

2. exochain-council-review (5-panel)
   └─ Each panel reviews independently and files findings
   └─ Findings are BLAKE3-hashed and signed (T-14a attestation)
   └─ Resolution stored in governance/resolutions/CR-NNN-*.md
      ↓

3. exochain-validate-constitution (8-invariant gate)
   └─ Automated check: does the change preserve all 8 invariants?
   └─ If any invariant is weakened, the change is blocked
      ↓

4. decision.forum ratification
   └─ Constitutional amendments require quorum vote in decision.forum
   └─ Decision class: Constitutional (min 7 votes, 75% approval, 5 human voters)
   └─ On approval: constitution hash updated, new Kernel constructed
```

### 6.3 Wiring a decision.forum Vote to the Kernel

After a constitutional amendment passes in `decision.forum`, the calling code must:

1. Serialize the new constitutional corpus as CBOR with sorted keys.
2. Construct a new `Kernel` with the updated bytes.
3. Verify the old kernel's integrity one final time before retiring it.
4. Record the constitution hash change in the governance audit log.

```rust
// After decision.forum ratification
let new_constitution_bytes = ciborium::ser::to_vec_sorted(&new_corpus)?;
let new_kernel = Kernel::new(&new_constitution_bytes, InvariantSet::all());

// Retire old kernel
assert!(old_kernel.verify_kernel_integrity(&old_constitution_bytes));
tracing::info!(
    old_hash = hex::encode(old_kernel.constitution_hash()),
    new_hash = hex::encode(new_kernel.constitution_hash()),
    "Constitution amended — new kernel constructed"
);
```

### 6.4 Linking a Governance Decision to Kernel Adjudication

Every `decision.forum::DecisionObject` that touches constitutional invariants should carry the kernel's constitution hash as its `constitutional_hash` binding:

```rust
use decision_forum::DecisionObject;

let decision = DecisionObject::new(
    "Amend Invariant 3 — NoSelfGrant".into(),
    DecisionClass::Constitutional,
    *kernel.constitution_hash(), // binds this decision to the current constitution
    &clock,
);
```

This implements TNC-06: the decision is cryptographically bound to the constitution it was made under.

---

## 7. When to Escalate

Use escalation (`exo-escalation`) rather than returning an error when:

| Situation | Action |
|-----------|--------|
| `Verdict::Escalated` from `kernel.adjudicate` | Route to `exo-escalation::escalation_pathway::execute_pathway` |
| Quorum not yet met but operation is otherwise valid | Suspend Holon, wait for votes, resume |
| Authority chain is valid but human approval not yet received | File `ApprovalGate` in `governance_monitor` |
| Detection signal fired (`UnusualVoting`, `RapidDelegation`, etc.) | File signal in `exo-escalation::detection_signals`, begin review |
| Emergency action exceeds per-actor frequency limit | Block and notify governance |
| Circuit breaker tripped (>3 Critical findings in 24h) | **Halt all self-improvement cycles** until human review clears it |

Use `Verdict::Denied` (no escalation) when:

- The action is a constitutional violation with no path to legitimacy (wrong branch, self-grant, kernel modification attempt).
- Multiple invariants are violated simultaneously.
- The actor lacks any authority chain to the required permission.

---

## 8. Common Mistakes

| Mistake | Consequence | Fix |
|---------|-------------|-----|
| Setting `is_self_grant: false` when actor is granting themselves a permission | `NoSelfGrant` invariant bypassed | Always set `is_self_grant: true` for self-grant operations |
| Omitting `grantor_public_key` from authority links | Signature not verified (legacy path only checks non-empty) | Always provide `grantor_public_key` for new code |
| Using `InvariantSet::with()` in production | Some invariants not enforced | Always use `InvariantSet::all()` in production |
| Calling `reduce()` directly instead of `Holon::step()` | Kernel adjudication is bypassed | Use `Holon::step()` for all governance operations |
| Not persisting circuit breaker state | Process restart resets T-14c counter | Serialize and restore `GovernanceCircuitBreaker` timestamps on startup |
| Using `HashMap`/`HashSet` in governance code | Workspace lint error + non-determinism | Use `BTreeMap`/`BTreeSet` throughout |
| Using `SystemTime::now()` for timestamps | Non-deterministic across nodes | Use `exo_core::hlc` for all timestamps |
| Merging constitutional changes without AI-IRB review | Constitution not council-ratified | Always complete the 5-panel review before merging invariant changes |
| Treating `Verdict::Escalated` as an error | Suspends Holons that should wait for human review | Handle `Escalated` as a pending state, not a failure |
| Setting `modifies_kernel: true` for non-amendment operations | Triggers spurious `KernelImmutability` denials | Only set `true` for operations that change the constitutional corpus |

---

*This guide covers `exo-gatekeeper` v1.0. For the full crate API reference, see [docs/reference/CRATE-REFERENCE.md](../reference/CRATE-REFERENCE.md). For governance resolutions, see [governance/resolutions/](../../governance/resolutions/).*
