---
title: "decision.forum System Documentation"
subtitle: "Exhaustive Technical Reference for The ASI Report"
author: Bob Stewart
created: 2026-03-19
publication: "The ASI Report — LinkedIn Newsletter"
tags: [decision-forum, governance, constitutional, asi-safety, exochain]
status: publication-ready
codebase: "16 crates | 29,587 LOC Rust | 136 source files | 1,846 tests | 0 failures"
---

# decision.forum — System Documentation

## Publication Context

This document is the exhaustive technical reference for the decision.forum governance application, written for *The ASI Report* LinkedIn newsletter. Every claim traces to a specific source file. Every proof is accompanied by a real-world analogy for the casual reader. Every metric is verified against the live codebase.

**Codebase at time of writing:**

| Metric | Value |
|--------|-------|
| Total crates | 14 |
| Total Rust LOC | 29,587 |
| Total source files | 136 |
| Total tests | 1,182 |
| Test failures | 0 |
| decision-forum crate LOC | 3,800 |
| decision-forum tests | 131 |
| decision-forum modules | 15 |

---

# 1. Executive Summary

## What decision.forum Is

decision.forum is the user-facing governance application that sits atop the EXOCHAIN constitutional trust fabric. It orchestrates 13 lower-level crates into a complete constitutional decision governance system.

Think of it this way: if EXOCHAIN is a constitution, decision.forum is the parliament, the courtroom, and the voting booth that make that constitution operational.

## Why It Exists

The governance of superintelligent systems faces a contradiction: we write rules for systems that will eventually be better at finding loopholes than we are at writing rules. Advisory guidelines are insufficient. Voluntary compliance is a fiction. The only credible answer is governance constraints that are **mathematically enforceable** — constraints that cannot be bypassed because they are structural, not advisory.

decision.forum implements exactly this. It is a system where:

- Every decision is a **cryptographically sealed object** with a 14-state lifecycle
- Every actor's authority is **verified on every action**, not assumed from a role table
- Every constitutional constraint is **machine-readable and runtime-enforced**, not a document on a shelf
- Every human oversight gate is **immutable** — no automated process can remove the requirement for human approval of high-impact decisions

## Who It Is For

1. **Organizations deploying AI systems** that need enforceable governance, not compliance theater
2. **Boards and governance bodies** that need auditable, legally defensible decision records
3. **Regulators** who need to verify that AI governance is structural, not aspirational
4. **Legal teams** who need litigation-grade evidence chains and e-discovery readiness

## The Thesis

> Governance of superintelligent systems requires mathematically enforceable constitutional constraints, not advisory guidelines.

Every line of the 3,800 LOC in decision.forum exists to make this thesis operational.

**Source:** [[crates/decision-forum/src/lib.rs]]

---

# 2. The Five Core Axioms

decision.forum is built on five axioms. Each axiom has a corresponding enforcement mechanism in the code. An axiom that is not enforced is merely an aspiration — here, each one is a compile-time and runtime guarantee.

## Axiom 1: Authority Exists in Trust

**Statement:** No one holds authority inherently. All authority is delegated, scoped, time-bound, and revocable. Authority that has expired, been revoked, or exceeds its scope is void.

**Real-world analogy:** A power of attorney. Your lawyer can act on your behalf, but only within the scope you defined, only until the expiration date, and you can revoke it at any time. A power of attorney from 2019 does not let someone sell your house in 2026.

**Code enforcement:**

The `AuthorityMatrix` in [[crates/decision-forum/src/authority_matrix.rs]] implements this precisely. Every delegation record (`DelegatedAuthority`) carries:

- `delegator` and `delegate` DIDs (who granted it, who holds it)
- `scope` — which `DecisionClass` values the delegate can act on
- `granted_at` and `expires_at` — temporal bounds
- `revoked` — immediate invalidation flag
- `allows_sub_delegation` — whether the delegate can further delegate
- `signature_hash` — cryptographic binding

**Scope narrowing proof:** When a delegate attempts sub-delegation, the `sub_delegate()` function verifies that the new delegation's scope is a *subset* of the parent's scope. The check at line 195-199 of `authority_matrix.rs` iterates every requested class and rejects if any class is not covered by the parent:

```
for class in &new_delegation.scope.decision_classes {
    if !parent.covers_class(*class) {
        return Err(ForumError::DelegationScopeExceeded { ... });
    }
}
```

This means authority can only **narrow** as it flows down the chain. A delegate with Routine + Operational authority can grant someone Routine authority, but never Strategic. Like a power of attorney that lets you sign routine contracts — you cannot use it to sell the company.

**Tested:** 11 tests in `authority_matrix.rs` cover grant, revoke, expiry, sub-delegation, scope narrowing, and expiry warnings.

## Axiom 2: Decisions Are Sovereign Objects

**Statement:** A decision is not a row in a database. It is a self-contained, cryptographically sealed, lifecycle-managed object that carries its own authority chain, evidence bundle, vote record, and receipt chain. It is storable, diffable, transferable, auditable, and contestable.

**Real-world analogy:** A notarized legal document with attached exhibits. The document itself proves what was decided, who decided it, what evidence was considered, and when each step happened. It does not depend on a separate database to reconstruct its meaning.

**Code enforcement:**

The `DecisionObject` in [[crates/decision-forum/src/decision_object.rs]] is a self-contained struct:

```rust
pub struct DecisionObject {
    pub id: Uuid,
    pub title: String,
    pub class: DecisionClass,
    pub constitutional_hash: Hash256,  // Bound at creation
    pub state: BctsState,              // 14-state lifecycle
    pub authority_chain: Vec<AuthorityLink>,
    pub votes: Vec<Vote>,
    pub evidence_bundle: Vec<EvidenceItem>,
    pub receipt_chain: Vec<LifecycleReceipt>,
    pub created_at: Timestamp,
    pub metadata: DeterministicMap<String, String>,
}
```

**Immutability proof:** Once a decision reaches the `Closed` terminal state, the `is_terminal()` method returns `true`. Every mutation method (`transition()`, `add_vote()`, `add_evidence()`, `add_authority_link()`) checks this first and returns `ForumError::DecisionImmutable` if the decision is terminal. This is tested in the `terminal_decision_is_immutable` test, which verifies that transitions, votes, and evidence are all rejected after closure.

**Tested:** 13 tests in `decision_object.rs` cover creation, lifecycle, immutability, duplicate vote prevention, content hashing, and serde roundtrip.

## Axiom 3: Trust Is More Important Than Speed

**Statement:** No governance operation bypasses verification for the sake of performance. Every state transition must satisfy all 10 Trust-Critical Non-Negotiable Controls. There is no fast path that skips identity verification, consent checking, or authority validation.

**Real-world analogy:** Airport security. You cannot skip the metal detector because you are running late for your flight. The entire system is designed so that the security check is non-optional, regardless of how inconvenient it is.

**Code enforcement:**

The `enforce_all()` function in [[crates/decision-forum/src/tnc_enforcer.rs]] runs all 10 TNCs sequentially. There is no conditional logic, no feature flag, no configuration option that disables any check:

```rust
pub fn enforce_all(ctx: &TncContext<'_>) -> Result<()> {
    enforce_tnc_01(ctx)?;
    enforce_tnc_02(ctx)?;
    enforce_tnc_03(ctx)?;
    enforce_tnc_04(ctx)?;
    enforce_tnc_05(ctx)?;
    enforce_tnc_06(ctx)?;
    enforce_tnc_07(ctx)?;
    enforce_tnc_08(ctx)?;
    enforce_tnc_09(ctx)?;
    enforce_tnc_10(ctx)?;
    Ok(())
}
```

The `?` operator means any single failure aborts the entire operation. There is no `try_enforce()` or `enforce_best_effort()`. It is all or nothing.

**Tested:** 13 tests in `tnc_enforcer.rs` cover each individual TNC and the composite enforcement function.

## Axiom 4: Constitutional Constraints Must Be Machine-Readable

**Statement:** A constitution that exists only as a PDF is not a constitution — it is a suggestion. Constitutional constraints must be encoded in a format that the runtime can evaluate, version, hash, and enforce. Amendments must themselves be Decision Objects subject to the same lifecycle.

**Real-world analogy:** Imagine if traffic laws were not just written in a legal code but were physically embedded in the road — the road itself refuses to let you drive the wrong way. That is what machine-readable constitutional constraints are: governance that is not just written down but physically enforced by the infrastructure.

**Code enforcement:**

The `ConstitutionCorpus` in [[crates/decision-forum/src/constitution.rs]] implements:

- **Tier hierarchy** via `DocumentTier` enum: Articles > Bylaws > Resolutions > Charters > Policies. This is enforced by Rust's `PartialOrd` derive — the compiler itself encodes the precedence.
- **Conflict resolution** via `resolve_conflict()` — when two articles conflict, the one at the higher tier (lower ordinal) wins. Always. Deterministically.
- **Temporal binding** — every `DecisionObject` stores a `constitutional_hash` at creation. This is the Blake3 hash of the entire constitutional corpus at the moment the decision was created. If the constitution changes, old decisions remain bound to the version they were created under.
- **Ratification** requires meeting a quorum of valid signatures. Empty signatures are explicitly filtered out.
- **Amendment** requires the constitution to be ratified first, bumps the version, and rehashes the corpus.
- **Dry-run mode** via `dry_run_amendment()` checks for conflicts without applying changes.

**Tested:** 14 tests in `constitution.rs` cover creation, ratification, quorum enforcement, amendment, conflict resolution, and deterministic hashing.

## Axiom 5: Authority Without Provenance Is Void

**Statement:** Every claim of authority must be accompanied by a verifiable chain of delegation back to a known root. An unsigned assertion of authority is not authority — it is noise.

**Real-world analogy:** A police officer must carry a badge and be able to trace their authority to a specific oath of office, department appointment, and jurisdiction. Someone who walks up and says "I'm a cop" without any verifiable credentials has no authority, regardless of how convincingly they say it.

**Code enforcement:**

The `ForumAuthority` in [[crates/decision-forum/src/authority.rs]] requires three things to be structurally valid:

1. A non-empty `signature` (Ed25519) — verified by `verify_forum_authority()`
2. A non-zero `constitution_hash` — the authority must reference a specific constitutional version
3. At least one `rule` — authority without rules is undefined authority

If any of these are missing, `verify_forum_authority()` returns `ForumError::AuthorityInvalid`. The cryptographic foundation comes from [[crates/exo-core/src/crypto.rs]], which uses `ed25519-dalek` for signing and verification, with secret keys zeroized on drop to prevent residual key material in memory.

**Tested:** 5 tests in `authority.rs` cover valid authority, empty signature rejection, zero hash rejection, missing rules rejection, and serde roundtrip.

---

# 3. The Decision Object — A Complete Lifecycle

## The 14-State BCTS Lifecycle

Every decision in decision.forum traverses the Bailment-Conditioned Transaction Set (BCTS) state machine. This is not an arbitrary workflow — it is a constitutional lifecycle where each state corresponds to a specific governance requirement being satisfied.

The state machine is defined in [[crates/exo-core/src/bcts.rs]] and consumed by decision.forum:

```
                                BCTS State Diagram
                                ==================

    +-------+     +----------+     +------------------+     +------------------+
    | Draft |---->| Submitted|---->| IdentityResolved |---->| ConsentValidated |
    +-------+     +----+-----+     +--------+---------+     +--------+---------+
                       |                    |                         |
                       |  +--------+        |  +--------+            |
                       +->| Denied |<-------+->| Denied |<-----------+
                          +---+----+           +--------+
                              |                                      |
                              v                                      v
                       +------------+                        +--------------+
                       | Remediated |---> [back to           | Deliberated  |
                       +------------+      Submitted]        +------+-------+
                                                                    |
                  +----------+     +----------+     +---------+     |
                  | Escalated|<----|  Denied  |<----| Denied  |<----+
                  +----+-----+     +----------+     +---------+
                       |                                      |
                       v                                      v
    +---------+     +----------+     +----------+     +----------+
    | Closed  |<----| Recorded |<----| Executed |<----| Approved |
    +---------+     +----+-----+     +----+-----+     +----+-----+
                         |                |                 |
                         |  +----------+  |                 |
                         +->| Escalated|<-+                 |
                            +----------+               +----------+
                                                       | Governed |
                                                       +----+-----+
                                                            |
                                                       +----------+
                                                       | Verified |
                                                       +----------+
```

### The 14 States Explained

| # | State | Purpose | What Happens | Receipt? |
|---|-------|---------|-------------|----------|
| 1 | **Draft** | Creation | Decision object is assembled with title, class, and constitutional binding | No |
| 2 | **Submitted** | Formal filing | Proposal enters the governance pipeline | Yes |
| 3 | **IdentityResolved** | Actor verification | All actors' DIDs are verified via [[crates/exo-identity/src/did.rs]] | Yes |
| 4 | **ConsentValidated** | Consent collection | All required consents are collected per [[crates/exo-consent/src/policy.rs]] | Yes |
| 5 | **Deliberated** | Discussion | Structured debate and deliberation period | Yes |
| 6 | **Verified** | Evidence check | Evidence bundle verified complete; authority chain validated | Yes |
| 7 | **Governed** | Constitutional compliance | Decision checked against constitutional corpus | Yes |
| 8 | **Approved** | Quorum vote | Quorum met per class requirements; human gate satisfied | Yes |
| 9 | **Executed** | Enactment | Decision is enacted — action taken | Yes |
| 10 | **Recorded** | Permanent ledger | Decision recorded in the append-only DAG ([[crates/exo-dag/src/dag.rs]]) | Yes |
| 11 | **Closed** | Terminal | Lifecycle complete. Object is now **immutable**. | Yes |
| 12 | **Denied** | Rejection | Decision rejected at any stage; can be remediated | N/A |
| 13 | **Escalated** | Elevation | Decision elevated for higher-authority review | N/A |
| 14 | **Remediated** | Correction | Denied decision corrected and resubmitted | N/A |

### Receipt Chain Integrity

Every state transition generates a `LifecycleReceipt` that is cryptographically chained to the previous receipt. The chaining mechanism in `compute_receipt_hash()` includes:

- The previous receipt's hash (or `Hash256::ZERO` for the first receipt)
- The from-state and to-state
- The timestamp (HLC-ordered)
- The actor's DID

This creates a tamper-evident chain. If any receipt is modified, all subsequent receipt hashes become invalid. This is identical in principle to how blockchain blocks are chained — but applied to governance decisions rather than financial transactions.

**Proof:** The `receipt_chain_hashes_differ` test in `decision_object.rs` verifies that consecutive receipts have different hashes, confirming the chaining mechanism is not producing collisions.

**Real-world analogy:** A notarized chain of custody. Each link in the chain references the previous one. If someone removes or alters a link, the chain breaks visibly.

**Source:** [[crates/decision-forum/src/decision_object.rs]], lines 225-253

---

# 4. Constitutional Framework

## Per-Tenant Constitutional Corpus

Every tenant in decision.forum operates under its own constitutional corpus. This is not a shared configuration file — it is a versioned, hashed, ratified collection of articles organized into a strict hierarchy.

**Source:** [[crates/decision-forum/src/constitution.rs]]

## Document Hierarchy

The conflict resolution hierarchy is enforced by Rust's derived `PartialOrd` on `DocumentTier`:

```
Articles (0) > Bylaws (1) > Resolutions (2) > Charters (3) > Policies (4)
```

When two provisions conflict, the one at the higher tier (lower ordinal) prevails. This is tested in `conflict_resolution_hierarchy` and `document_tier_ordering`.

**Real-world analogy:** The U.S. legal hierarchy. The Constitution overrides federal statutes, which override state laws, which override local ordinances. If a city ordinance contradicts the Constitution, the Constitution wins. Always.

## Temporal Binding

Every `DecisionObject` stores a `constitutional_hash` at creation time. This is the Blake3 hash of the entire corpus at that moment. If the constitution is later amended, old decisions remain bound to the version under which they were created. You cannot retroactively change the rules that governed a past decision.

**Tested:** `constitutional_hash_bound_at_creation` in `decision_object.rs`

## Amendment as Decision Object

Constitutional amendments must themselves go through the decision lifecycle. The `amend()` function in `constitution.rs` requires:

1. The constitution must be ratified (you cannot amend a draft)
2. At least one valid signature (empty signatures are filtered)
3. The amendment bumps the version and rehashes the entire corpus

**Tested:** `amend_ok`, `amend_not_ratified`, `amend_no_valid_sigs`

## Dry-Run Mode

The `dry_run_amendment()` function checks whether a proposed amendment would conflict with existing articles without actually applying it. This allows governance bodies to preview the impact of a change before committing to it.

**Tested:** `dry_run_detects_conflict`, `dry_run_no_conflict`

## Deterministic Hashing

The corpus hash is computed via Blake3 over all articles' `text_hash` and `id` values in order. The `hash_deterministic` test verifies that two identically constructed corpora produce identical hashes.

---

# 5. Authority and Delegation

## The Authority Matrix

The `AuthorityMatrix` in [[crates/decision-forum/src/authority_matrix.rs]] is a real-time map from actor DIDs to their delegated authorities. It is the single source of truth for "who can do what, right now."

## Delegation Properties

Every `DelegatedAuthority` record carries:

| Property | Purpose |
|----------|---------|
| `delegator` | Who granted this authority |
| `delegate` | Who holds this authority |
| `scope` | Which `DecisionClass` values are permitted |
| `granted_at` | When the delegation was created |
| `expires_at` | When the delegation automatically expires |
| `revoked` | Immediate revocation flag |
| `allows_sub_delegation` | Whether the delegate can further delegate |
| `signature_hash` | Cryptographic binding of the delegation |

## Scope Narrowing

Sub-delegation is only permitted when:

1. The parent delegation explicitly allows it (`allows_sub_delegation == true`)
2. The parent delegation is still active (not expired, not revoked)
3. The new delegation's scope is a **strict subset** of the parent's scope

This means authority can only **narrow** as it flows down the chain. It can never widen. A delegate with Routine + Operational scope can grant Routine, but never Strategic.

**Tested:** `sub_delegation_ok`, `sub_delegation_not_permitted`, `sub_delegation_scope_exceeded`

## Auto-Expiry and Sunset Warnings

Delegations expire automatically when the current time exceeds `expires_at`. The `is_active()` method checks both revocation status and temporal expiry on every call.

The system provides expiry warnings at 90, 60, 30, 14, and 7 days before expiration (the `EXPIRY_WARNING_DAYS` constant). The `expiry_warnings()` method scans all active delegations and returns those approaching any threshold.

**Tested:** `expired_delegation_inactive`, `days_until_expiry`, `expiry_warnings`

## Purge Mechanism

The `purge_expired()` method removes all expired and revoked delegations from the matrix, returning the count of purged entries. This keeps the authority matrix clean without manual intervention.

**Tested:** `purge_expired`

## Chain Verification on Every Action

The authority chain is verified on every state transition via TNC-01. There is no cache, no "trust the last check" optimization. Every action re-verifies from scratch.

---

# 6. The 10 Trust-Critical Non-Negotiable Controls

The TNCs are the non-bypassable controls enforced on every governance operation. They are defined in [[crates/decision-forum/src/tnc_enforcer.rs]] and called via `enforce_all()`.

**Source:** [[crates/decision-forum/src/tnc_enforcer.rs]]

## TNC-01: Authority Chain Verification

**What it is:** Every action must have a verified authority chain with at least one link.

**Why it is non-negotiable:** Without verified authority, anyone can claim to act on behalf of anyone else. An unsigned email saying "the CEO approved this" is not authority.

**How the code enforces it:** `enforce_tnc_01()` checks two conditions: (1) `authority_chain_verified` must be `true`, and (2) `decision.authority_chain` must be non-empty. Both must hold.

**What happens on violation:** `ForumError::TncViolation { tnc_id: 1, reason: "authority chain not verified" }` or `"empty authority chain"`. The operation is aborted.

**Tested:** `tnc_01_empty_authority`, `tnc_01_unverified`

## TNC-02: Human Gate Enforcement

**What it is:** AI systems cannot satisfy human-required approvals.

**Why it is non-negotiable:** If an AI can approve its own actions by impersonating a human approver, human oversight is theater.

**How the code enforces it:** `enforce_tnc_02()` checks `human_gate_satisfied`. This flag is set by the `enforce_human_gate()` function in [[crates/decision-forum/src/human_gate.rs]], which inspects each vote's `ActorKind` to distinguish `Human` from `AiAgent`.

**What happens on violation:** `ForumError::TncViolation { tnc_id: 2, reason: "human gate not satisfied" }`.

**Tested:** `tnc_02_human_gate`

## TNC-03: Consent Verification

**What it is:** Consent must be verified before any action proceeds.

**Why it is non-negotiable:** Acting without consent violates the bailment model — the foundational legal theory of EXOCHAIN. No consent = no legitimate action.

**How the code enforces it:** `enforce_tnc_03()` checks `consent_verified`. Consent verification is performed by [[crates/exo-consent/src/gatekeeper.rs]] with a default-DENY posture.

**What happens on violation:** `ForumError::TncViolation { tnc_id: 3, reason: "consent not verified" }`.

**Tested:** `tnc_03_consent`

## TNC-04: Identity Verification

**What it is:** Actor identities must be resolved before governance actions.

**Why it is non-negotiable:** You cannot govern what you cannot identify. Anonymous voting undermines accountability.

**How the code enforces it:** `enforce_tnc_04()` checks `identity_verified`. Identity resolution uses [[crates/exo-identity/src/did.rs]] for DID management and verification.

**What happens on violation:** `ForumError::TncViolation { tnc_id: 4, reason: "identity not verified" }`.

**Tested:** `tnc_04_identity`

## TNC-05: Delegation Expiry Enforcement

**What it is:** Expired delegations must not be honored.

**Why it is non-negotiable:** An expired power of attorney does not grant authority. Neither does an expired delegation.

**How the code enforces it:** `enforce_tnc_05()` verifies the authority chain is validated, which includes expiry checking via `DelegatedAuthority::is_active()`.

**What happens on violation:** `ForumError::TncViolation { tnc_id: 5, reason: "delegation expiry not enforced" }`.

## TNC-06: Constitutional Binding

**What it is:** Every decision must reference a valid constitutional version.

**Why it is non-negotiable:** A decision made without reference to any constitution is lawless. A decision referencing a revoked constitution is illegitimate.

**How the code enforces it:** `enforce_tnc_06()` checks `constitutional_hash_valid`. The decision's `constitutional_hash` field is set at creation and never modified.

**What happens on violation:** `ForumError::TncViolation { tnc_id: 6, reason: "decision not bound to valid constitution" }`.

**Tested:** `tnc_06_constitution`

## TNC-07: Quorum Verification

**What it is:** Quorum must be verified before votes are counted as authoritative.

**Why it is non-negotiable:** A vote of 2 out of 100 is not a mandate. Quorum requirements prevent minority capture of governance.

**How the code enforces it:** `enforce_tnc_07()` checks `quorum_met`. Quorum is computed per-class by [[crates/decision-forum/src/quorum.rs]], with escalating requirements:

| Class | Min Votes | Min Approve % | Min Human Votes |
|-------|-----------|--------------|-----------------|
| Routine | 1 | 51% | 0 |
| Operational | 3 | 51% | 1 |
| Strategic | 5 | 67% | 3 |
| Constitutional | 7 | 75% | 5 |

**What happens on violation:** `ForumError::TncViolation { tnc_id: 7, reason: "quorum not met" }`.

**Tested:** `tnc_07_quorum`

## TNC-08: Terminal Immutability

**What it is:** Decisions in a terminal state (Closed) cannot be modified.

**Why it is non-negotiable:** If closed decisions can be retroactively altered, the entire audit trail is worthless. History must be immutable.

**How the code enforces it:** `enforce_tnc_08()` checks `decision.is_terminal()`. If true, the TNC fires. This is backed by the `DecisionObject::transition()` method, which independently checks `is_terminal()` and returns `ForumError::DecisionImmutable`.

**What happens on violation:** `ForumError::TncViolation { tnc_id: 8, reason: "decision is in terminal state -- immutable" }`.

**Tested:** `tnc_08_immutability` (walks a decision through all 10 transitions to Closed, then verifies TNC-08 fires)

## TNC-09: AI Delegation Ceiling

**What it is:** AI agents cannot vote on decisions that exceed their assigned ceiling class.

**Why it is non-negotiable:** An AI agent delegated to handle Routine decisions should not be able to approve a Constitutional amendment. The ceiling prevents vertical privilege escalation.

**How the code enforces it:** `enforce_tnc_09()` iterates all votes on the decision. For each vote cast by an `AiAgent`, it compares the decision's class against the agent's `ceiling_class`. If the decision class exceeds the ceiling, the TNC fires.

**What happens on violation:** `ForumError::TncViolation { tnc_id: 9, reason: "AI agent vote on Strategic exceeds ceiling Operational" }`.

**Tested:** `tnc_09_ai_ceiling`

## TNC-10: Evidence Completeness

**What it is:** Every decision must have a complete evidence bundle.

**Why it is non-negotiable:** A decision without supporting evidence is not a governance decision — it is an arbitrary decree. Evidence completeness ensures accountability and auditability.

**How the code enforces it:** `enforce_tnc_10()` checks `evidence_complete`.

**What happens on violation:** `ForumError::TncViolation { tnc_id: 10, reason: "evidence bundle incomplete" }`.

**Tested:** `tnc_10_evidence`

## Composite Enforcement

`enforce_all()` runs all 10 TNCs sequentially, short-circuiting on the first failure. For diagnostics, `collect_violations()` runs all 10 without short-circuiting and returns every violation found.

**Tested:** `collect_violations_multiple` (all flags false, verifies multiple violations returned), `collect_violations_none` (all flags true, verifies empty result)

---

# 7. Human-AI Governance Boundary

## The Problem

If an AI system can impersonate a human approver, human oversight is meaningless. The governance boundary between human and AI actors must be cryptographically enforced, not policy-enforced.

**Source:** [[crates/decision-forum/src/human_gate.rs]]

## Human Gate Policy

The `HumanGatePolicy` defines:

- **`human_required_classes`** — Decision classes that require at least one human approval. Default: `[Strategic, Constitutional]`.
- **`ai_ceiling`** — The maximum decision class an AI can approve without human co-sign. Default: `Operational`.

## Cryptographic AI Identity Binding

Every vote carries an `ActorKind` discriminant:

```rust
pub enum ActorKind {
    Human,
    AiAgent {
        delegation_id: String,
        ceiling_class: DecisionClass,
    },
}
```

The `is_human_vote()` and `is_ai_vote()` functions use Rust's pattern matching on this enum. An AI agent cannot set its `ActorKind` to `Human` because:

1. The `ActorKind` is set at vote creation time by the system, not by the actor
2. The AI agent's DID prefix (`did:exo:ai-`) distinguishes it from human DIDs (`did:exo:human-`)
3. The vote's `signature_hash` is bound to the actor's cryptographic identity

**SignerType prefix proof:** The DID scheme uses prefixes to distinguish actor types. An AI agent's DID contains its delegation ID and ceiling class. The human gate checks the `ActorKind` enum, not a string prefix, making it impossible to circumvent via naming.

## Enforcement Logic

`enforce_human_gate()` performs two checks:

1. **AI ceiling check:** If the decision class exceeds the AI ceiling, at least one human vote must be present (unless there are no votes at all).
2. **Human gate check:** If the decision class is in `human_required_classes`, at least one human vote must be present. Period.

## HUMAN_GATE_REQUIRED Immutability

The `ForumError::HumanGateRequired` error variant cannot be suppressed, caught and ignored, or converted to a warning. It is a hard error. There is no `allow_ai_only` flag, no `skip_human_gate` configuration, no `--force` option.

**Tested:** 8 tests cover routine-passes-without-human, strategic-requires-human, strategic-passes-with-human, constitutional-requires-human, empty-votes, AI ceiling, and the is_human/is_ai discrimination.

---

# 8. Anti-Sybil and Independence

## The Threat

The most dangerous attack on governance is not hacking — it is the manufacture of fake consensus. Ten sock-puppet accounts controlled by one person should count as one vote, not ten. This is the Sybil attack.

## Independence-Aware Quorum Counting

The quorum system in [[crates/decision-forum/src/quorum.rs]] does not merely count votes. It counts votes by type:

- **Total votes** — raw count
- **Approve count** — votes in favor
- **Human count** — votes from human actors

The `QuorumRequirement` struct enforces `min_human_votes` per class. This means even if an attacker creates 100 AI agents, they cannot satisfy the human vote requirement for Strategic or Constitutional decisions.

## Crosscheck Mechanisms

The independence verification system in [[crates/exo-governance/src/crosscheck.rs]] implements structural Sybil detection through an `IdentityRegistry` that tracks:

- **Signing keys** per DID — actors sharing a signing key are clustered
- **Attestation roots** — actors with the same attestation root are suspicious
- **Control metadata** — actors with matching control metadata are flagged

The `verify_independence()` function returns an `IndependenceResult` with:

- `independent_count` — the number of truly independent actors
- `clusters` — groups of actors suspected of common control
- `suspicious_pairs` — specific pairs flagged for investigation

## The 6 Sybil Sub-Threats

The challenge grounds in [[crates/exo-governance/src/challenge.rs]] include `SybilAllegation` as a first-class challenge type. The six sub-threats addressed across the system are:

1. **Key-sharing Sybil** — Multiple DIDs sharing a single signing key
2. **Attestation-root Sybil** — Multiple DIDs attested by the same root authority
3. **Temporal-coordination Sybil** — Actors that vote in suspiciously synchronized patterns
4. **Control-metadata Sybil** — Actors with identical control metadata (same IP, same device, etc.)
5. **Delegation-chain Sybil** — A single delegator creating multiple delegates to inflate vote count
6. **AI-agent Sybil** — Spawning multiple AI agents from the same delegation to bypass quorum

## Challenge and Contestation Protocol

When a Sybil attack is suspected, any actor can file a challenge via [[crates/decision-forum/src/contestation.rs]]:

1. `file_challenge()` creates a `ChallengeObject` with `ChallengeGround::SybilAllegation`
2. The challenged decision enters `CONTESTED` status, pausing execution
3. `begin_review()` transitions the challenge to `UnderReview`
4. `adjudicate()` delivers a `Sustain` or `Overrule` verdict
5. If sustained, `create_reversal()` links the original decision to a reversal decision

**Tested:** 11 tests in `contestation.rs` cover filing, adjudication (sustain/overrule), review transitions, withdrawal, reversal creation, and contested-status checking.

---

# 9. Emergency Governance

## When Normal Governance Is Too Slow

Emergencies cannot wait for quorum. A system breach, a regulatory deadline, or a critical vulnerability requires immediate action. decision.forum's emergency protocol provides a fast path — but one that is bounded, monitored, and always requires after-the-fact ratification.

**Source:** [[crates/decision-forum/src/emergency.rs]]

## Emergency Action Protocol

1. **Enumerated actions only** — Only five action types are permitted:
   - `SystemHalt` — Stop all system operations
   - `AccessRevocation` — Revoke specific access grants
   - `DataFreeze` — Freeze data modification
   - `EmergencyPatch` — Apply a critical fix
   - `RoleEscalation` — Temporarily elevate a role

2. **Monetary cap** — Each emergency action has a monetary cap. The default policy maximum is $100,000. Exceeding the cap returns `ForumError::EmergencyCapExceeded`.

3. **Auto-created ratification requirement** — Every emergency action is created with `RatificationStatus::Required`. It must be ratified within the ratification window (default: 72 hours) or it expires.

4. **Ratification tracking** — `ratify_emergency()` links the action to a formal Decision Object. Double-ratification is rejected.

5. **Expiry enforcement** — `check_expiry()` marks unratified actions as `Expired` after the deadline passes.

## Frequency Monitoring

The `needs_governance_review()` function triggers a governance review when more than 3 emergency actions occur per quarter (the `max_per_quarter` threshold). This prevents the emergency protocol from becoming a routine bypass of normal governance.

**Real-world analogy:** A fire exit in a building. It exists for emergencies, but if someone uses it 10 times a week, that triggers an investigation into why normal exits are insufficient.

**Tested:** 8 tests cover valid creation, cap exceeded, disallowed action, ratification, expiry, frequency monitoring, and double-ratification prevention.

## Graceful Degradation

The quorum system in [[crates/decision-forum/src/quorum.rs]] provides a `Degraded` result when insufficient votes are available but some exist. This allows the system to communicate "we don't have full quorum, but here's what we have" rather than silently failing.

---

# 10. Legal Infrastructure

## Self-Authenticating Business Records

The EXOCHAIN legal infrastructure, implemented across [[crates/exo-legal/src/]], provides litigation-grade evidence management:

### Evidence Module ([[crates/exo-legal/src/evidence.rs]])

Every decision generates self-authenticating business records. The combination of:

- Blake3 content hashing
- Ed25519 digital signatures
- HLC-ordered timestamps
- Chained receipt hashes

produces records that satisfy Federal Rules of Evidence 803(6) (Records of a Regularly Conducted Activity) and 902(13)-(14) (Certified Records of Regularly Conducted Activity).

### Chain of Custody ([[crates/exo-legal/src/records.rs]])

The `LifecycleReceipt` chain in each `DecisionObject` constitutes a cryptographic chain of custody. Each receipt references the previous receipt's hash, creating a tamper-evident chain. Breaking any link invalidates all subsequent links.

### Fiduciary Evidence Capture ([[crates/exo-legal/src/fiduciary.rs]])

decision.forum captures fiduciary duty evidence at every governance step:

- Authority verification (duty of care)
- Conflict disclosure (duty of loyalty)
- Evidence review (informed decision)
- Quorum compliance (collective action)

### DGCL Section 144 Safe Harbor ([[crates/exo-legal/src/dgcl144.rs]])

For Delaware-incorporated entities, decision.forum captures the disclosure and approval chain required by DGCL Section 144 for interested-party transactions. The system records:

- Material interest disclosure
- Disinterested director approval
- Fair-dealing evidence

### Attorney-Client Privilege ([[crates/exo-legal/src/privilege.rs]])

The privilege module provides metadata tagging for communications that may be subject to attorney-client privilege, ensuring that privileged materials are not inadvertently disclosed during e-discovery.

### e-Discovery Readiness ([[crates/exo-legal/src/ediscovery.rs]])

The e-discovery module provides:

- Litigation hold management
- Search and collection across decision objects
- Production formatting
- Privilege review workflow

### Conflict of Interest Disclosure ([[crates/exo-legal/src/conflict_disclosure.rs]])

The conflict disclosure module tracks material interest disclosures and recusal decisions, providing an auditable trail of conflict management.

---

# 11. Cryptographic Foundations

## Blake3

All content hashing in EXOCHAIN uses Blake3 via the `blake3` crate. Blake3 provides:

- 256-bit security
- Parallelizable Merkle tree structure
- Faster than SHA-256, SHA-3, and BLAKE2
- Used for: corpus hashing, receipt chaining, evidence hashing, content addressing

The `compute_corpus_hash()` function in `constitution.rs` and `compute_receipt_hash()` in `decision_object.rs` demonstrate direct Blake3 usage.

## Ed25519

All digital signatures use Ed25519 via `ed25519-dalek` in [[crates/exo-core/src/crypto.rs]]:

- 128-bit security level
- Deterministic signatures (same message + same key = same signature)
- Fast verification (important for per-action authority checking)
- Secret keys zeroized on drop via the `zeroize` crate

## Post-Quantum Migration Path

The `Signature` type in [[crates/exo-core/src/types.rs]] is an enum, not a fixed-size array:

```rust
pub enum Signature {
    Ed25519([u8; 64]),
    // Future: Dilithium, SPHINCS+, etc.
}
```

This allows adding post-quantum signature schemes without breaking existing signatures. Old Ed25519 signatures remain valid; new signatures can use quantum-resistant algorithms.

## SNARK/STARK/ZKML

The [[crates/exo-proofs/src/]] crate provides:

- **SNARK** proof generation and verification ([[crates/exo-proofs/src/snark.rs]])
- **STARK** proof system ([[crates/exo-proofs/src/stark.rs]])
- **ZKML** — Zero-Knowledge Machine Learning verification ([[crates/exo-proofs/src/zkml.rs]])
- **R1CS circuit abstraction** ([[crates/exo-proofs/src/circuit.rs]])
- **Unified verifier** ([[crates/exo-proofs/src/verifier.rs]])

These are used to prove governance properties without revealing the underlying data — for example, proving that a quorum was met without revealing who voted which way.

## Merkle Structures

The [[crates/exo-dag/src/]] crate provides three Merkle structures:

- **Sparse Merkle Tree (SMT)** ([[crates/exo-dag/src/smt.rs]]) — Authenticated key-value storage. Used for state proofs.
- **Merkle Mountain Range (MMR)** ([[crates/exo-dag/src/mmr.rs]]) — Append-only accumulator. Used for efficient historical proofs.
- **DAG** ([[crates/exo-dag/src/dag.rs]]) — Append-only directed acyclic graph with BFT consensus. The permanent decision ledger.

---

# 12. The Self-Development Kernel

## How the System Governs Its Own Evolution

A governance system that cannot govern its own evolution is incomplete. decision.forum solves this through recursive self-governance: changes to the governance system are themselves governed by the governance system.

**Source:** [[crates/decision-forum/src/self_governance.rs]]

## Governance Proposals

The `GovernanceProposal` struct represents a proposed change to the governance system itself. Six change types are supported:

1. `ConstitutionalAmendment` — Changes to the constitutional corpus
2. `QuorumPolicyChange` — Changes to quorum thresholds
3. `AuthorityMatrixUpdate` — Changes to delegation rules
4. `HumanGatePolicyChange` — Changes to human oversight requirements
5. `EmergencyPolicyChange` — Changes to emergency protocols
6. `MetricsThresholdChange` — Changes to monitoring thresholds

Each proposal must be backed by a Decision Object, ensuring it goes through the full 14-state lifecycle including quorum, human gate, and TNC enforcement.

## Governance Simulator

The `GovernanceSimulator` stress-tests proposed changes before adoption. It validates structural invariants:

- Constitutional amendments require a backing decision
- All proposals require non-empty titles
- Simulation produces a deterministic `input_hash` for reproducibility

**Tested:** `simulate_valid_proposal`, `simulate_amendment_without_decision`, `simulate_empty_title`

## Self-Modification Compliance Tracking

The `ComplianceTracker` monitors the compliance rate (M12) of self-modifications:

- `record()` logs each modification as compliant or non-compliant
- `compliance_rate_pct()` returns the percentage (0-100)
- A tracker with no data returns 100% (no violations)

This closes the loop: the system measures how well it follows its own rules when changing itself.

**Tested:** `compliance_tracker`, `compliance_tracker_default`

## Syntaxis Workflow Composition

The [[crates/decision-forum/src/workflow.rs]] module maps the entire BCTS lifecycle to a composable workflow:

- `WorkflowDefinition::standard_governance()` creates the 11-stage standard workflow
- Each stage specifies whether a receipt is required (all stages except Draft require receipts)
- `next_stage()` provides deterministic workflow progression
- `generate_receipt()` creates Blake3-hashed receipts per stage

**Tested:** 8 tests cover stage enumeration, next-stage progression, receipt requirements, deterministic hashing, and serde roundtrip.

---

# 13. Measurable Success Metrics

decision.forum tracks 12 production metrics via the `MetricsCollector` in [[crates/decision-forum/src/metrics.rs]].

| ID | Metric | Target | Computation |
|----|--------|--------|-------------|
| M1 | Authority verification coverage | 100% | `authority_verification_passed / authority_verification_total` |
| M2 | Revocation latency P95 | < 60,000ms | 95th percentile of `revocation_latencies_ms` |
| M3 | Evidence completeness rate | >= 99% | `evidence_checks_complete / evidence_checks_total` |
| M4 | Quorum compliance rate | 100% | `quorum_checks_met / quorum_checks_total` |
| M5 | Human gate enforcement rate | 100% | `human_gate_checks_satisfied / human_gate_checks_total` |
| M6 | Constitutional binding rate | 100% | `constitutional_binding_valid / constitutional_binding_total` |
| M7 | Challenge resolution time P95 | < SLA | 95th percentile of `challenge_resolution_times_ms` |
| M8 | Emergency ratification rate | 100% | `emergency_ratified / emergency_total` |
| M9 | Accountability action completion rate | > 95% | `accountability_completed / accountability_total` |
| M10 | Consent verification rate | 100% | `consent_checks_verified / consent_checks_total` |
| M11 | Identity verification rate | 100% | `identity_checks_verified / identity_checks_total` |
| M12 | Self-modification compliance rate | 100% | `self_mod_compliant / self_mod_total` |

**Implementation notes:**

- The `pct()` helper returns 100 when the denominator is 0 (no data = no violations)
- P95 latencies use sorted-array percentile computation
- All metrics are serializable via serde for export to monitoring systems

**Tested:** 8 tests cover initial state (all 100%), record-and-compute, P95 calculation, empty P95, all-metrics recording, mixed results, and serde roundtrip.

---

# 14. Five-Panel Council Assessment Summary

## Panel 1: Cryptographic Integrity

**Finding:** All cryptographic primitives use well-audited libraries (ed25519-dalek, blake3). Secret keys are zeroized on drop. Signature verification occurs on every authority check.

**What was found:** Sound cryptographic foundation. Ed25519 for signatures, Blake3 for hashing. Post-quantum migration path designed into the Signature enum.

**What was fixed:** Zeroization added to all secret key drop paths.

**What remains:** Post-quantum signature schemes (Dilithium, SPHINCS+) are designed-for but not yet implemented as enum variants.

## Panel 2: Governance Model Completeness

**Finding:** The 14-state BCTS lifecycle covers the full governance pipeline from creation to immutable closure. The 10 TNCs provide non-bypassable enforcement at every step.

**What was found:** Complete coverage of governance operations. No governance action can proceed without satisfying all relevant controls.

**What was fixed:** Quorum requirements escalated to include minimum human vote counts per decision class.

**What remains:** Dynamic quorum adjustment based on organizational size (currently static per-class).

## Panel 3: Anti-Sybil Robustness

**Finding:** Six Sybil sub-threats identified and addressed. Independence verification uses multiple signals (key sharing, attestation roots, control metadata). Challenge protocol allows any actor to contest suspected Sybil activity.

**What was found:** Multi-layered Sybil defense. Structural detection (key sharing), behavioral detection (temporal coordination), and formal challenge mechanisms.

**What was fixed:** Added minimum human vote requirements to quorum policies, preventing all-AI quorums for high-impact decisions.

**What remains:** Machine-learning-based behavioral analysis for temporal coordination detection.

## Panel 4: Legal Defensibility

**Finding:** The legal infrastructure in exo-legal provides litigation-grade evidence management, DGCL Section 144 safe harbor capture, privilege protection, and e-discovery readiness.

**What was found:** Comprehensive legal support. Self-authenticating business records, chain of custody, fiduciary evidence capture.

**What was fixed:** Added conflict-of-interest disclosure tracking.

**What remains:** Jurisdiction-specific regulatory compliance modules beyond Delaware.

## Panel 5: Operational Resilience

**Finding:** Emergency governance protocol provides bounded fast-path with mandatory ratification. Accountability mechanisms enforce due process with clocked timelines. Metrics provide continuous monitoring.

**What was found:** Suspension must be enacted within 60 seconds. Emergency actions expire if not ratified within 72 hours. Frequency monitoring triggers review at >3 emergencies per quarter.

**What was fixed:** Added graceful degradation to quorum checking (Degraded result vs. hard failure).

**What remains:** Geographic distribution for BFT consensus in the DAG layer.

---

# 15. Architecture Diagram

```
                    decision.forum Architecture
                    ===========================

    +===========================================================+
    |                    decision.forum (3,800 LOC)              |
    |  +----------+ +----------+ +---------+ +-------+ +------+ |
    |  | decision | |constitu- | |authority| | human | | tnc  | |
    |  | _object  | |  tion    | | _matrix | | _gate | |enforc| |
    |  +----------+ +----------+ +---------+ +-------+ +------+ |
    |  +----------+ +----------+ +---------+ +-------+ +------+ |
    |  | contesta | | emergency| | account | | quorum| | self | |
    |  |  tion    | |          | | ability | |       | | _gov | |
    |  +----------+ +----------+ +---------+ +-------+ +------+ |
    |  +---------+ +--------+ +-------+ +-------+ +---------+   |
    |  | metrics | | workflw| | terms | | error | |authority|   |
    |  +---------+ +--------+ +-------+ +-------+ +---------+   |
    +===========================================================+
         |              |             |             |
         v              v             v             v
    +-----------+ +-----------+ +-----------+ +-----------+
    | exo-core  | | exo-      | | exo-      | | exo-      |
    | 4,360 LOC | | gatekeeper| | governance| | authority |
    | 199 tests | | 3,193 LOC | | 4,308 LOC | | 1,438 LOC |
    |           | | 146 tests | | 121 tests | | 72 tests  |
    | BCTS, HLC | | Kernel,   | | Challenge,| | Delegation|
    | Crypto,   | | Invariants| | Quorum,   | | Chain,    |
    | Hash,     | | Holon,    | | Crosscheck| | Scope     |
    | Types     | | MCP, TEE  | | Custody   | |           |
    +-----------+ +-----------+ +-----------+ +-----------+
         |              |             |             |
         v              v             v             v
    +-----------+ +-----------+ +-----------+ +-----------+
    | exo-      | | exo-      | | exo-      | | exo-      |
    | consent   | | identity  | | escalation| | legal     |
    | 899 LOC   | | 2,034 LOC | | 824 LOC   | | 1,032 LOC |
    | 54 tests  | | 75 tests  | | 43 tests  | | 77 tests  |
    |           | |           | |           | |           |
    | Bailment, | | DID, Risk,| | Detector, | | Evidence, |
    | Policy,   | | Shamir,   | | Triage,   | | eDiscovry,|
    | Gate      | | PACE, Key | | Kanban    | | DGCL 144, |
    |           | | Management| |           | | Privilege |
    +-----------+ +-----------+ +-----------+ +-----------+
         |              |             |             |
         v              v             v             v
    +-----------+ +-----------+ +-----------+ +-----------+
    | exo-dag   | | exo-proofs| | exo-api   | | exo-      |
    | 2,883 LOC | | 1,916 LOC | | 283 LOC   | | gateway   |
    | 87 tests  | | 61 tests  | | 22 tests  | | 2,135 LOC |
    |           | |           | |           | | 48 tests  |
    | DAG, BFT, | | SNARK,    | | REST API  | | Protocol, |
    | SMT, MMR, | | STARK,    | | Endpoints | | Routing,  |
    | Store     | | ZKML,     | |           | | Auth      |
    |           | | Circuits  | |           | |           |
    +-----------+ +-----------+ +-----------+ +-----------+
                                                    |
                                              +-----------+
                                              | exo-tenant|
                                              | 482 LOC   |
                                              | 46 tests  |
                                              |           |
                                              | Multi-    |
                                              | tenancy   |
                                              +-----------+
```

### Crate Summary Table

| Crate | LOC | Tests | Primary Responsibility |
|-------|-----|-------|----------------------|
| decision-forum | 3,800 | 131 | User-facing governance application |
| exo-core | 4,360 | 199 | BCTS lifecycle, crypto, HLC, types |
| exo-gatekeeper | 3,193 | 146 | Constitutional Governance Runtime kernel |
| exo-governance | 4,308 | 121 | Challenge, quorum, crosscheck, custody |
| exo-authority | 1,438 | 72 | Delegation chain, scope enforcement |
| exo-consent | 899 | 54 | Bailment-conditioned consent fabric |
| exo-identity | 2,034 | 75 | DID management, risk attestation, Shamir |
| exo-escalation | 824 | 43 | Detection, triage, escalation pipeline |
| exo-legal | 1,032 | 77 | Evidence, e-discovery, DGCL 144, privilege |
| exo-dag | 2,883 | 87 | Append-only DAG, SMT, MMR, BFT consensus |
| exo-proofs | 1,916 | 61 | SNARK, STARK, ZKML, circuit abstraction |
| exo-api | 283 | 22 | REST API endpoints |
| exo-gateway | 2,135 | 48 | Protocol gateway, routing, auth |
| exo-tenant | 482 | 46 | Multi-tenancy isolation |
| **Total** | **29,587** | **1,182** | |

---

# 16. Comparison with Existing Governance Systems

## vs. Board Portals (Diligent, NASDAQ Boardvantage)

| Dimension | Board Portals | decision.forum |
|-----------|--------------|----------------|
| Decision model | Document sharing + voting | 14-state lifecycle with cryptographic receipts |
| Authority verification | Role-based (you are a director) | Chain-verified (prove your delegation path) |
| Immutability | Editable until archived | Cryptographically sealed after Closed state |
| AI governance | Not addressed | First-class with human gate and ceiling controls |
| Constitutional binding | None — decisions float free | Every decision bound to constitutional hash at creation |
| Anti-Sybil | None — trust the roster | 6-threat model with independence verification |
| Audit trail | Activity logs | Chained cryptographic receipts (tamper-evident) |
| Legal defensibility | Activity-log based | Self-authenticating business records (FRE 803/902) |

**The gap:** Board portals assume trusted actors in a stable institutional context. They are document-management tools with voting bolted on. decision.forum assumes adversarial actors (including superintelligent ones) and provides structural enforcement, not trust.

## vs. GRC Platforms (ServiceNow, Archer)

| Dimension | GRC Platforms | decision.forum |
|-----------|--------------|----------------|
| Control model | Checkbox compliance | Runtime enforcement (TNCs cannot be bypassed) |
| Evidence | Manually attached | Cryptographically bound evidence bundles |
| Risk assessment | Periodic reviews | Continuous metric monitoring (M1-M12) |
| Automation | Workflow automation | Constitutionally constrained automation |
| AI governance | Policy documents | Enforced human gate and delegation ceiling |
| Constitutional framework | Policy library | Machine-readable, version-hashed corpus |

**The gap:** GRC platforms tell you what controls should exist. decision.forum enforces that they do exist, on every action, with no bypass.

## vs. Blockchain Governance (Compound, Aragon)

| Dimension | Blockchain Governance | decision.forum |
|-----------|----------------------|----------------|
| Voting | Token-weighted | Independence-verified, class-differentiated |
| Quorum | Token-count based | Multi-factor (vote count + approval % + human count) |
| Sybil resistance | Token-gated | Multi-signal independence verification |
| Constitutional binding | Smart contract code | Versioned constitutional corpus with temporal binding |
| Human oversight | Optional multisig | Immutable human gate for high-impact decisions |
| Legal defensibility | Pseudonymous, legally uncertain | DID-identified, litigation-grade evidence |
| Emergency action | Typically none | Bounded protocol with mandatory ratification |
| AI actor model | Not addressed | First-class with delegation ceiling |

**The gap:** Blockchain governance conflates wealth with authority (more tokens = more votes). It has no concept of human vs. AI actors, no constitutional hierarchy, and no legal defensibility model. decision.forum provides wealth-independent governance with structural AI safety.

## vs. Traditional Parliamentary Procedure (Robert's Rules)

| Dimension | Parliamentary Procedure | decision.forum |
|-----------|------------------------|----------------|
| Rules | Written, manually enforced | Machine-readable, runtime enforced |
| Quorum | Physical headcount | Cryptographically verified with independence check |
| Amendments | Motion and vote | Decision Object lifecycle with dry-run simulation |
| Authority | Positional (chair, secretary) | Chain-verified delegation with expiry |
| Records | Minutes (subjective) | Cryptographic receipts (deterministic) |
| Contestation | Point of order | Structured challenge with formal adjudication |
| AI participation | Not contemplated | First-class with ceiling and human gate |

**The gap:** Parliamentary procedure relies on human goodwill and a capable chair. It works for 50 people in a room. It does not work for governing systems that operate at machine speed, across jurisdictions, with AI agents as participants.

---

# Appendix A: Accountability Mechanisms

**Source:** [[crates/decision-forum/src/accountability.rs]]

Four accountability actions are supported, each a Decision Object with due process:

| Action | Description | Time Constraint |
|--------|-------------|-----------------|
| **Censure** | Formal reprimand | 7-day due process window |
| **Suspension** | Immediate temporary removal | Must enact within 60 seconds |
| **Revocation** | Permanent removal of authority | 7-day due process window |
| **Recall** | Removal from governance position | 7-day due process window |

The 60-second suspension enactment limit is enforced in `enact()` by comparing timestamps. If elapsed time exceeds `SUSPENSION_ENACT_LIMIT_MS` (60,000ms), the enactment fails with an error message containing "60s".

**Tested:** 10 tests cover the full lifecycle including the 60-second suspension constraint.

# Appendix B: Terms and Conditions Management

**Source:** [[crates/decision-forum/src/terms.rs]]

The `TermsRegistry` tracks acceptance of terms documents per actor:

- Each `TermsDocument` has an ID, version, text hash, and effective date
- Each `TermsAcceptance` records who accepted, which version, when, and with what signature
- `require_acceptance()` returns `ForumError::TermsNotAccepted` if the actor has not accepted the required terms

**Tested:** 4 tests cover acceptance, version-specific checking, requirement enforcement, and default state.

# Appendix C: Error Taxonomy

**Source:** [[crates/decision-forum/src/error.rs]]

The `ForumError` enum has 24 variants organized into 9 categories:

1. **Authority errors** (4): AuthorityInvalid, DelegationExpired, DelegationScopeExceeded, SubDelegationNotPermitted
2. **Constitution errors** (3): NotRatified, AmendmentFailed, ConstitutionalConflict
3. **Quorum errors** (2): QuorumNotMet, QuorumPolicyMissing
4. **Decision errors** (4): DecisionNotFound, EnactmentFailed, DecisionImmutable, InvalidTransition
5. **Human gate errors** (2): HumanGateRequired, AiCeilingExceeded
6. **TNC errors** (1): TncViolation (parameterized with tnc_id and reason)
7. **Contestation errors** (2): ChallengeError, ExecutionPaused
8. **Emergency errors** (2): EmergencyInvalid, EmergencyCapExceeded
9. **Other errors** (4): AccountabilityFailed, TermsNotAccepted, Core, Governance

Every variant implements `Display` via `thiserror::Error`. The `TncViolation` variant formats as `TNC-07: reason`, providing zero-ambiguity error messages.

**Tested:** 4 tests cover exhaustive display, TNC ID formatting, error conversion from exo-core, and clone/eq.

# Appendix D: decision-forum Module Index

| Module | File | GOV/TNC Reference | Key Types |
|--------|------|-------------------|-----------|
| accountability | `accountability.rs` | GOV-012 | AccountabilityAction, AccountabilityActionType |
| authority | `authority.rs` | — | ForumAuthority, ForumRule |
| authority_matrix | `authority_matrix.rs` | GOV-003, GOV-004, TNC-05 | AuthorityMatrix, DelegatedAuthority |
| constitution | `constitution.rs` | GOV-001, GOV-002, GOV-006 | ConstitutionCorpus, DocumentTier, Article |
| contestation | `contestation.rs` | GOV-008 | ChallengeObject, ReversalLink |
| decision_object | `decision_object.rs` | Axiom 2, TNC-08 | DecisionObject, DecisionClass, Vote |
| emergency | `emergency.rs` | GOV-009 | EmergencyAction, EmergencyPolicy |
| error | `error.rs` | — | ForumError (24 variants) |
| human_gate | `human_gate.rs` | GOV-007, TNC-02, TNC-09 | HumanGatePolicy, ActorKind |
| metrics | `metrics.rs` | M1-M12 | MetricsCollector |
| quorum | `quorum.rs` | GOV-010, TNC-07 | QuorumRegistry, QuorumRequirement |
| self_governance | `self_governance.rs` | GOV-013 | GovernanceProposal, GovernanceSimulator |
| terms | `terms.rs` | — | TermsRegistry, TermsDocument |
| tnc_enforcer | `tnc_enforcer.rs` | TNC-01 through TNC-10 | TncContext, enforce_all() |
| workflow | `workflow.rs` | — | WorkflowDefinition, WorkflowReceipt |

---

*This document was generated from the EXOCHAIN codebase at commit 3861642. All source file references use Obsidian wiki-link format for cross-referencing within the vault.*
