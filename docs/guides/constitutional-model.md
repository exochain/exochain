# The EXOCHAIN Constitutional Model

> **Status:** Developer guide — canonical reference for the constitutional
> governance model. Reflects spec v2.2 and CR-001 (AEGIS / SYBIL / Authentic
> Plurality).
> **Audience:** Engineers building on EXOCHAIN, AI agents operating under
> EXOCHAIN governance, auditors verifying conformance.
> **Last verified against code:** `crates/exo-gatekeeper` mainline.

This document is the philosophical and operational foundation of the
EXOCHAIN constitutional trust fabric. Grok this and everything else — the
invariant set, the combinator algebra, the MCP rules, the escalation
pipelines — follows by straightforward construction. Skip it, and the rest
will look like bureaucratic decoration.

The cross-references point to real source files. Every claim in this
document is anchored in code that runs in CI.

---

## 1. Why a constitutional fabric?

### 1.1 The Alignment Imperative

From the EXOCHAIN Fabric Platform Specification, §3A.1:

> As AI systems approach and exceed human-level capabilities, traditional
> access control becomes insufficient. EXOCHAIN v2.0 introduces the AEGIS
> framework — a constitutional layer ensuring AI entities (Holons) remain
> provably aligned with human values.

In plain language: once an AI is capable enough that it could satisfy the
letter of a policy while violating its intent — "specification gaming" —
role-based access control has nothing left to offer. An RBAC system can
tell you that the actor calling `write_patient_record` has the `nurse`
role. It cannot tell you whether the write was consented to by the patient,
whether the nurse was acting under a valid chain of delegated authority,
whether the action is provenance-verifiable in court, or whether the nurse
is actually a synthetic account controlled by an upstream adversary.

Constitutional governance replaces "who is allowed to do X" with "what
must be true about the world before X is permitted to take effect". That
second framing is falsifiable. The first is not.

### 1.2 What "constitutional" means here

In EXOCHAIN, a constitution is not a PDF. It is a pair:

1. A set of **invariants expressed as types and compiled Rust functions**,
   bundled in `crates/exo-gatekeeper`.
2. A **kernel** that evaluates every proposed state transition against
   those invariants before it is permitted to take effect. See
   [`Kernel::adjudicate`][kernel-adjudicate].

The word "constitutional" means only this: the invariants cannot be
bypassed by any combination of roles, permissions, or credentials. They
are enforced at every state transition, by the same code, at the same
layer, for every actor in the system. A "super-admin" role does not
exist. An "emergency override" flag does not exist. The kernel itself is
content-addressed and immutable after initialization (see §6 below on
Constitutional Amendment, the one exception).

### 1.3 Contrast with ordinary access control

| Concern                                | Ordinary access control           | EXOCHAIN constitutional model                      |
|----------------------------------------|-----------------------------------|----------------------------------------------------|
| Authorization primitive                | Role → permission mapping         | Invariant set checked against adjudication context |
| Who holds the override                 | Admin / root / superuser          | No one. Amendment process required (§6)            |
| Provenance                             | Usually a log line after the fact | Signed, verified, required before action runs      |
| Defense against specification gaming   | Policy review + hope              | Type-level invariants + kernel verification        |
| Defense against Sybil / false plurality | None built in                     | CR-001 §8.3 synthetic voice exclusion, authentic quorum |
| AI-specific rules                      | Usually none                      | Six MCP rules bound by cryptographic signer type   |
| Audit trail                            | Log aggregation, trust the logs   | Append-only DAG + BFT checkpoint, verifiable       |

The practical difference: in a role-based system, you prove you are
allowed to do something by showing your badge. In a constitutional
system, every action you take must carry with it cryptographic evidence
that the world was in a state that permitted it. The kernel checks that
evidence. If the evidence is missing, wrong, or tampered with, the
action is denied — no matter who you are.

---

## 2. The Three Branches (Separation of Powers)

EXOCHAIN implements the classical separation of powers as a compile-time
architectural constraint, not as a policy document.

| Branch          | Role                                                      | Implementation                                         | Representative crates                                   |
|-----------------|-----------------------------------------------------------|--------------------------------------------------------|---------------------------------------------------------|
| **Legislative** | Defines the bounds: what Holons MAY and MUST NOT do       | AI-IRB, constitutional amendments, `DecisionClass`     | `exo-governance`, `decision-forum`                      |
| **Executive**   | Proposes and executes actions within those bounds         | Holons (AI entities with DIDs), humans, authority chains | `exo-gatekeeper` (holon.rs), `exo-authority`, `exo-identity` |
| **Judicial**    | Verifies every state transition against invariants        | CGR Kernel, invariant engine, combinator reducer       | `exo-gatekeeper` (kernel.rs, invariants.rs, combinator.rs) |

### 2.1 Flow diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                      SEPARATION OF POWERS FLOW                           │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐                                                        │
│  │ LEGISLATIVE  │   PolicyAmendment events / AI-IRB votes                │
│  │   (AI-IRB +  │ ────────────────────────────────────┐                  │
│  │   validators)│                                     ▼                  │
│  └──────────────┘                         ┌──────────────────────┐       │
│         │  ratifies                       │ INVARIANT REGISTRY   │       │
│         ▼                                 │  (InvariantSet::all) │       │
│  ┌──────────────┐                         └──────────┬───────────┘       │
│  │  EXECUTIVE   │                                    │ loaded by         │
│  │   (Holons,   │                                    ▼                   │
│  │   humans,    │                ┌────────────────────────────────────┐  │
│  │   delegates) │                │          JUDICIAL BRANCH           │  │
│  └──────┬───────┘                │          (CGR KERNEL)              │  │
│         │ ActionRequest          │                                    │  │
│         │ + AdjudicationContext  │   for each invariant:              │  │
│         ├───────────────────────►│     check(invariant, context)      │  │
│         │                        │   all pass?  → Verdict::Permitted  │  │
│         │                        │   any fail?  → Denied | Escalated  │  │
│         │                        └───────────────────┬────────────────┘  │
│         │                                            │ Verdict           │
│         │                                            ▼                   │
│         │                        ┌────────────────────────────────────┐  │
│         │       (proof)          │          DAG  /  BFT               │  │
│         ◄────────────────────────┤  Event accepted iff Permitted.     │  │
│                                  │  Denied actions are rejected with  │  │
│                                  │  evidence. Escalated actions are   │  │
│                                  │  paused pending review.            │  │
│                                  └────────────────────────────────────┘  │
│                                                                          │
│  INVARIANT: No branch can unilaterally modify another.                   │
│  INVARIANT: The Judicial branch cannot be bypassed or overridden.        │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Key property

No branch can unilaterally override another.

- The **Legislative** branch can amend the invariant set only through the
  Constitutional Amendment process (§6), which requires unanimous
  validator consent, ≥80% AI-IRB approval, a 30-day comment period, a
  formal proof, and a security audit. It cannot silently change the
  rules the Judicial branch evaluates.
- The **Executive** branch has no mechanism to grant itself capabilities
  (invariant 3, `NoSelfGrant`), to modify the kernel (invariant 5,
  `KernelImmutability`), or to suppress human override (invariant 4,
  `HumanOverride`).
- The **Judicial** branch has no mechanism to modify the invariants it
  evaluates. The kernel is immutable after initialization: its
  constitution hash is computed once with BLAKE3 and stored; any attempt
  to change it is detected by `Kernel::verify_kernel_integrity`.

This is enforced structurally. It is not a promise.

---

## 3. The 8 Constitutional Invariants

The invariants are defined in
[`crates/exo-gatekeeper/src/invariants.rs`][invariants-rs]. The
`ConstitutionalInvariant` enum is declared at lines 19–37, and
`InvariantSet::all()` returns all eight at lines 47–60.

Each invariant has a named variant, a check function, and a dedicated
`InvariantViolation` produced on failure. The kernel enforces them in a
single pass via [`enforce_all`][enforce-all] in the same file
(lines 124–139). Multiple violations are collected, not short-circuited
— a call that violates three invariants returns three violations.

### Summary table

| # | Invariant                | Rule (plain language)                                                   | Check function                        |
|---|--------------------------|-------------------------------------------------------------------------|---------------------------------------|
| 1 | SeparationOfPowers       | No actor may hold roles in multiple branches                            | `check_separation_of_powers`          |
| 2 | ConsentRequired          | Action requires an active bailment and a matching active consent record | `check_consent_required`              |
| 3 | NoSelfGrant              | An actor cannot expand its own permissions                              | `check_no_self_grant`                 |
| 4 | HumanOverride            | Emergency human intervention must always be possible                    | `check_human_override`                |
| 5 | KernelImmutability       | Kernel configuration cannot be modified after creation                  | `check_kernel_immutability`           |
| 6 | AuthorityChainValid      | Authority chain must be non-empty, topologically sound, and cryptographically signed | `check_authority_chain_valid`         |
| 7 | QuorumLegitimate         | Quorum must be met by authentic (non-synthetic) voters                  | `check_quorum_legitimate`             |
| 8 | ProvenanceVerifiable     | Every action must carry signed provenance that matches the actor        | `check_provenance_verifiable`         |

The remaining subsections walk through each invariant in the order the
code enforces them.

---

### 3.1 SeparationOfPowers

**Rule.** "No single actor may hold legislative + executive + judicial
power." Formally enforced as: an actor's `actor_roles` must all map to
the same `GovernmentBranch`.

**Why.** An actor who writes policy (legislative), executes actions
(executive), and judges them (judicial) is not a constitutional actor —
they are the whole system, alone. The check is stricter than the
headline: it rejects **any** multi-branch membership, not only the full
three-way set. This matches the conservative interpretation in CR-001
§8.9 (no admins).

**Permitted example.**

```rust
actor_roles = vec![
    Role { name: "judge".into(), branch: GovernmentBranch::Judicial },
];
// → passes
```

**Denied example.**

```rust
actor_roles = vec![
    Role { name: "senator".into(), branch: GovernmentBranch::Legislative },
    Role { name: "judge".into(),   branch: GovernmentBranch::Judicial },
];
// → InvariantViolation { invariant: SeparationOfPowers,
//                        description: "Actor holds roles in multiple branches…" }
```

**Violation evidence.** Includes the actor DID and the computed set of
branches.

**Code reference.**
[`crates/exo-gatekeeper/src/invariants.rs:157–186`][invariants-rs]

---

### 3.2 ConsentRequired

**Rule.** "Action denied without active bailment consent." The
adjudication context must contain a `BailmentState::Active` and at least
one `ConsentRecord` where `granted_to == actor` and `active == true`.

**Why.** Data sovereignty. In EXOCHAIN, every access to protected data
occurs under a **bailment** — a time-bound, policy-enforced data-sharing
agreement modelled on the legal bailment doctrine. No bailment, no
access. Consent must be explicit, still active, and scoped to the actor
performing the action. A revoked bailment, a suspended bailment, or a
consent record granted to someone else all fail this invariant.

**Permitted example.** An actor holds an active `BailmentState::Active`
with bailor `did:exo:bailor` and scope `data:medical`, and there is a
`ConsentRecord` with `granted_to = actor`, `active = true`.

**Denied example.** `BailmentState::None`, `BailmentState::Suspended`,
`BailmentState::Terminated`, consent record with `active = false`, or a
consent record granted to a different DID — each denies the action.

**Violation evidence.** Includes the current bailment state or the
actor DID and the record count.

**Code reference.**
[`crates/exo-gatekeeper/src/invariants.rs:188–211`][invariants-rs]

---

### 3.3 NoSelfGrant

**Rule.** "An actor cannot expand its own permissions." The
`ActionRequest` must have `is_self_grant = false`.

**Why.** If an actor could grant itself more capabilities, every
invariant above would collapse by recursion — the actor would simply
grant itself `admin`, then do anything. This invariant is the
structural cornerstone of separation of powers at the capability
level. It pairs with MCP002 (no AI self-escalation) on the AI side.

**Permitted example.** A Holon requests a capability by constructing
an action where the grantor is a distinct DID (the Holon's sponsor,
for instance).

**Denied example.** A Holon submits an action with `is_self_grant =
true`. The kernel denies it immediately.

**Violation evidence.** Includes the actor DID.

**Code reference.**
[`crates/exo-gatekeeper/src/invariants.rs:213–222`][invariants-rs]

---

### 3.4 HumanOverride

**Rule.** "Emergency human intervention must always be possible." The
context must have `human_override_preserved = true`.

**Why.** AEGIS is not a system that takes humans out of the loop. It
is a system that makes human oversight reliable by making every
automated action auditable and every automated decision deniable by a
human with proper authority. `HumanOverride` is the invariant that
forbids the construction of actions that would remove that capability
(typically a `ForcedSunset` or `ImmediateSuspend` over a Holon in
violation — see spec §3A.4.2).

**Permitted example.** Any normal operation in which the override
path (via `exo-escalation` `Kanban` triage and `HumanReview` stage)
remains functional.

**Denied example.** An action that would remove the emergency
override capability — e.g., a proposed policy amendment that deletes
the `ImmediateSuspend` event type, or a change that disables human
review before AI-IRB approval.

**Violation evidence.** `human_override_preserved: false`.

**Code reference.**
[`crates/exo-gatekeeper/src/invariants.rs:224–233`][invariants-rs]

---

### 3.5 KernelImmutability

**Rule.** "Kernel configuration cannot be modified after creation." The
`ActionRequest` must have `modifies_kernel = false`. Attempts to
mutate the kernel's invariant set, its constitution bytes, or its hash
are unconditionally denied.

**Why.** If the kernel could be modified at runtime, every other
invariant becomes a suggestion. This is the bright line that makes the
system constitutional rather than merely heavily governed. The only
way to change the kernel is the Constitutional Amendment process (§6)
— which produces a **new** kernel with a **new** content hash at a
coordinated upgrade height, not an in-place edit.

**Permitted example.** Any action that does not modify the kernel.

**Denied example.** An action request with `modifies_kernel = true`.
There is no escalation path; this is one of only two invariants whose
violation never escalates, always denies.

**Violation evidence.** `kernel_modification_attempted: true`.

**Code reference.**
[`crates/exo-gatekeeper/src/invariants.rs:235–244`][invariants-rs]

---

### 3.6 AuthorityChainValid

**Rule.** The `AuthorityChain` must (a) be non-empty, (b) be
topologically valid — each link's `grantee` is the next link's
`grantor` — (c) terminate at the actor, and (d) every link that
carries a `grantor_public_key` must have an Ed25519 signature that
verifies against the canonical payload.

**Why.** Delegation is how authority flows through a multi-actor
system. If the chain is broken or unsigned, there is no chain — just a
claim. The cryptographic signature check (TNC-01) closes the gap
between "this actor says they were delegated" and "the grantor can be
proven to have delegated".

**Canonical payload format** (from the code at lines 316–325):

```
payload = grantor_did_bytes || 0x00
       || grantee_did_bytes || 0x00
       || (for each permission: permission_bytes || 0x00)
message = BLAKE3(payload)
signature = Ed25519_sign(grantor_secret_key, message)
```

**Permitted example.** A single-link chain `did:exo:root → did:exo:actor1`
with a valid Ed25519 signature verifying under the supplied public key.

**Denied example.**

- Empty chain — `AuthorityChain::default()`.
- Broken topology — `link[0].grantee != link[1].grantor`.
- Wrong terminal — last link's grantee is not the actor.
- Tampered signature, wrong public key, malformed key.

**Escalation special case.** When the *only* invariant that fails is
`AuthorityChainValid`, the kernel returns `Verdict::Escalated` rather
than `Verdict::Denied` — see [`Kernel::adjudicate`][kernel-adjudicate]
at lines 125–130. This recognises that an authority-chain gap may be a
temporary problem with a legitimate fix path (contest, re-issue), not
a malicious attack.

**Violation evidence.** Includes the broken link indices and, for
signature failures, the grantor/grantee DIDs.

**Code reference.**
[`crates/exo-gatekeeper/src/invariants.rs:246–357`][invariants-rs]

---

### 3.7 QuorumLegitimate

**Rule.** When a `QuorumEvidence` is present, the number of authentic
(non-synthetic) approvals must meet the threshold.

**Why.** This is CR-001 §8.3 encoded as a type check. The rule at
stake is the line between **AEGIS** (legitimate plurality) and
**SYBIL** (counterfeit plurality): "numerical multiplicity without
attributable independence is theater, not legitimacy." A vote is
authentic when its `provenance` does not mark the voter as having a
`VoiceKind::Synthetic`. AI-generated votes and synthetic-voiced agents
are excluded from the headcount even when they formally "approved".

**Permitted example.** Threshold = 3, votes = three approvals from
`VoiceKind::Human` voters (plus any number of synthetic approvals,
which are silently excluded from the count but recorded).

**Denied example.** Threshold = 3, votes = one human approval + two
synthetic approvals. The authentic-approval count is 1, below 3.

**Violation evidence.** Includes `threshold`,
`authentic_approvals`, and `synthetic_votes_excluded`.

**Escalation special case.** Same as `AuthorityChainValid` — when
quorum is the only failing invariant, the action is escalated rather
than denied. The legitimate fix is a fresh vote with qualified voters,
not a rejection of the underlying decision.

**Legacy compatibility.** Votes with `provenance = None` are treated
as non-synthetic (pre-CR-001 votes do not lose their weight). Tests at
lines 1009–1033 pin this behaviour.

**Code reference.**
[`crates/exo-gatekeeper/src/invariants.rs:359–390`][invariants-rs]

---

### 3.8 ProvenanceVerifiable

**Rule.** The action must carry `Provenance` whose `actor` matches the
context actor, whose signature is non-empty, and — when a
`public_key` is supplied — whose Ed25519 signature verifies against
the canonical payload.

**Why.** Every action in EXOCHAIN is court-admissible evidence of
what happened. Provenance is the signed metadata that makes this
true: an actor DID, a timestamp (HLC), the action hash, and the
signature. Without it, the event is a rumour.

**Canonical payload format** (from the code at lines 434–439):

```
payload = actor_did_bytes || 0x00
       || action_hash    || 0x00
       || timestamp_bytes
message = BLAKE3(payload)
signature = Ed25519_sign(actor_secret_key, message)
```

Note: for AI actors this payload is further wrapped with the
`SignerType` prefix (§5) before signing, so a signature produced by
an AI cannot be replayed as a human signature.

**Permitted example.** Provenance with actor matching the context,
non-empty signature, and — if `public_key` is set — a valid Ed25519
signature over the canonical payload.

**Denied example.**

- Missing provenance (`None`).
- Actor mismatch between provenance and context.
- Unsigned provenance (legacy path — `signature: vec![]`).
- Tampered signature, wrong public key, malformed key length.

**Violation evidence.** Depends on the failure mode; includes actor
DID and key/signature lengths where relevant.

**Code reference.**
[`crates/exo-gatekeeper/src/invariants.rs:392–466`][invariants-rs]

---

## 4. The 6 MCP Rules (AI-specific)

The invariants above apply uniformly to all actors. The MCP rules
apply specifically when the actor is an AI. They live in
[`crates/exo-gatekeeper/src/mcp.rs`][mcp-rs] and are declared in the
`McpRule` enum at lines 22–29.

### 4.1 Cryptographic signer binding

The central design element of the MCP layer is this: the system does
not determine "is this actor an AI?" by looking at a caller-set
`is_ai` boolean. It determines it from the actor's cryptographic
`SignerType`, which is part of the **signed payload**.

```rust
pub enum SignerType {
    Human,                                    // prefix byte 0x01
    Ai { delegation_id: Hash256 },            // prefix byte 0x02 + 32-byte hash
}
```

When any actor signs a message, the payload that actually gets hashed
and signed is:

```
[prefix_bytes]  ||  message_bytes
```

Where `prefix_bytes = [0x01]` for a human or `[0x02, <32 bytes of delegation_id>]`
for an AI. See `build_signed_payload` at
[`crates/exo-gatekeeper/src/mcp.rs:189–196`][mcp-rs] and
`verify_typed_signature` at
[`crates/exo-gatekeeper/src/mcp.rs:200–209`][mcp-rs].

**The consequence.** Even if an AI obtains valid key material, it
cannot produce a signature that verifies as human — the 33-byte vs
1-byte prefix difference means the underlying hash inputs are
different. Impersonation across species is cryptographically
prevented, not merely policed. The test
`ai_cannot_impersonate_human` at lines 387–415 of `mcp.rs` pins
this.

### 4.2 The six rules

| ID      | Name                  | Description                                            | Severity |
|---------|-----------------------|--------------------------------------------------------|----------|
| MCP001  | BctsScope             | AI must operate within BCTS scope                      | 5        |
| MCP002  | NoSelfEscalation      | AI cannot self-escalate capabilities                   | 5        |
| MCP003  | ProvenanceRequired    | AI actions require provenance metadata                 | 4        |
| MCP004  | NoIdentityForge       | AI cannot forge identity or signatures                 | 5        |
| MCP005  | Distinguishable       | AI outputs must be distinguishable from human          | 3        |
| MCP006  | ConsentBoundaries     | AI must respect consent boundaries                     | 5        |

Humans are exempt from all six rules. `enforce` returns `Ok(())`
immediately when `!context.is_ai()` at
[`crates/exo-gatekeeper/src/mcp.rs:105–113`][mcp-rs].

---

### 4.3 MCP001 — BctsScope

**Why this rule exists.** A Holon that operates outside a defined
Bailment-Conditioned Transaction Set scope has no consent anchor —
nothing to tie its actions back to a legitimate purpose. Without a
scope, provenance becomes untestable and consent becomes
retrospective.

**Attack vector prevented.** A misbehaving or captured Holon that
tries to act "in general" rather than under a specific authorized
purpose.

**Check.** `ctx.bcts_scope` must be `Some(_)`.

**Code reference.**
[`crates/exo-gatekeeper/src/mcp.rs:117–127`][mcp-rs]

---

### 4.4 MCP002 — NoSelfEscalation

**Why this rule exists.** This is the AI-specific projection of
invariant 3 (`NoSelfGrant`). It closes the RSI (Recursive
Self-Improvement) problem: an AI cannot propose an action that would
expand its own capabilities. Self-improvement proposals must enter
the system as `HolonModificationProposed` events reviewed by AI-IRB,
never as in-band capability upgrades.

**Attack vector prevented.** Recursive self-improvement without
oversight. Specification-gaming a permission system by "discovering"
new capabilities you then grant yourself.

**Check.** `ctx.self_escalation` must be `false`.

**Code reference.**
[`crates/exo-gatekeeper/src/mcp.rs:128–141`][mcp-rs]

---

### 4.5 MCP003 — ProvenanceRequired

**Why this rule exists.** Invariant 8 applies to all actors, but
this rule raises the bar for AI actions. Even when humans may
produce unsigned legacy events (pre-migration), AI actions must
always carry full provenance. This is the material basis for "AI
outputs must be distinguishable and attributable".

**Attack vector prevented.** AI actions that disappear into the
audit log as ambient state changes.

**Check.** `ctx.has_provenance` must be `true`.

**Code reference.**
[`crates/exo-gatekeeper/src/mcp.rs:142–152`][mcp-rs]

---

### 4.6 MCP004 — NoIdentityForge

**Why this rule exists.** The signer-type binding (§4.1) prevents
the AI from producing a signature that verifies as human at the
cryptographic level. This rule adds a second, policy-level check:
even attempting to present AI output as if from a human — by
manipulating the payload, claiming a human delegation ID, or
reusing a human's key material — is an immediate severity-5
violation.

**Attack vector prevented.** Synthetic-voice laundering: an AI
agent that pretends to speak as a human reviewer. This is the
canonical SYBIL condition named in CR-001 §5.

**Check.** `ctx.forging_identity` must be `false`.

**Code reference.**
[`crates/exo-gatekeeper/src/mcp.rs:153–163`][mcp-rs]

---

### 4.7 MCP005 — Distinguishable

**Why this rule exists.** CR-001 §5 lists "presentation of
synthetic or coordinated opinions as if they were independent human
judgment" as a SYBIL condition. The line between AI and human
output must be legible to downstream consumers — including quorum
counters (invariant 7), reviewers, and the evidence bundle export
pipeline.

**Attack vector prevented.** Counterfeit plurality via AI
multiplication. Undetected AI influence on quorum.

**Check.** `ctx.output_marked_ai` must be `true`.

**Note.** This is severity 3 (rather than 5). Not marking AI output
is a disclosure failure, not an integrity failure — but it still
blocks the action.

**Code reference.**
[`crates/exo-gatekeeper/src/mcp.rs:164–174`][mcp-rs]

---

### 4.8 MCP006 — ConsentBoundaries

**Why this rule exists.** Invariant 2 (`ConsentRequired`) enforces
that some consent is active. MCP006 raises the bar for AI: consent
must be active *for this AI actor* with respect to *this action*.
Consent that was granted to a different AI, or a different
capability level, is not transferable.

**Attack vector prevented.** AI actions riding on consent granted
to another AI or another purpose. Capability drift past consent
boundaries.

**Check.** `ctx.consent_active` must be `true`.

**Code reference.**
[`crates/exo-gatekeeper/src/mcp.rs:175–186`][mcp-rs]

---

## 5. Verdicts: Permitted, Denied, Escalated

Every call to [`Kernel::adjudicate`][kernel-adjudicate] returns a
`Verdict`:

```rust
pub enum Verdict {
    Permitted,
    Denied    { violations: Vec<InvariantViolation> },
    Escalated { reason: String },
}
```

### 5.1 Permitted

All invariants passed. The action is constitutionally valid and may
proceed. A permitted verdict is not a promise that the action
"worked" — it is a proof that nothing in the constitutional fabric
objects to it taking effect.

The downstream DAG commits the event, the state root is updated,
and (if integrated) a `CgrProof` is produced recording which kernel
version, which registry hash, and which invariants were evaluated.

### 5.2 Denied

At least one invariant failed, and at least one of the failing
invariants is not a pure quorum/authority issue (see §5.3 below).
The verdict carries **every** violation that was detected — not just
the first. This is intentional: callers need to see the full picture
to repair correctly.

Each `InvariantViolation` carries:

```rust
pub struct InvariantViolation {
    pub invariant:   ConstitutionalInvariant,
    pub description: String,
    pub evidence:    Vec<String>,
}
```

Example denied output for an action that tries to modify the kernel,
suppress human override, and self-grant all at once:

```
Denied {
  violations: [
    InvariantViolation {
      invariant: NoSelfGrant,
      description: "Actor attempted to expand own permissions",
      evidence: ["actor: did:exo:self-granter"],
    },
    InvariantViolation {
      invariant: HumanOverride,
      description: "Human override capability is not preserved",
      evidence: ["human_override_preserved: false"],
    },
    InvariantViolation {
      invariant: KernelImmutability,
      description: "Attempted to modify immutable kernel configuration",
      evidence: ["kernel_modification_attempted: true"],
    },
  ],
}
```

### 5.3 Escalated

An action is escalated, not denied, in exactly two cases:

1. There is an **active Sybil challenge hold**:
   `context.active_challenge_reason = Some(_)`. The kernel
   short-circuits before running invariant checks and returns
   `Escalated { reason }`. See
   [`Kernel::adjudicate`][kernel-adjudicate] at lines 99–105. This
   implements CR-001 §8.5 (WO-005): contested actions are paused,
   not blocked, pending review.

2. The **only** failing invariant is either `QuorumLegitimate` or
   `AuthorityChainValid`. These are both "your evidence is
   incomplete but this is probably fixable" violations, not "this is
   a constitutional attack". The kernel returns
   `Escalated { reason }` with the violation's description. See
   [`Kernel::adjudicate`][kernel-adjudicate] at lines 125–130.

A mixed failure — e.g., `QuorumLegitimate` plus `NoSelfGrant` — is
denied, not escalated. Escalation is reserved for narrowly
recoverable cases.

### 5.4 Walk-through of `Kernel::adjudicate`

```rust
// crates/exo-gatekeeper/src/kernel.rs:98-138 (paraphrased)

pub fn adjudicate(
    &self,
    action: &ActionRequest,
    context: &AdjudicationContext,
) -> Verdict {
    // 1. Sybil challenge takes absolute priority.
    if let Some(reason) = &context.active_challenge_reason {
        return Verdict::Escalated { reason: reason.clone() };
    }

    // 2. Build the invariant context from action + context.
    let inv_ctx = InvariantContext { /* … fields copied … */ };

    // 3. Run every invariant in the engine. Collect all violations.
    match enforce_all(&self.invariant_engine, &inv_ctx) {
        Ok(()) => Verdict::Permitted,
        Err(violations) => {
            let needs_escalation = violations.iter().any(|v| {
                v.invariant == ConstitutionalInvariant::QuorumLegitimate
                    || v.invariant == ConstitutionalInvariant::AuthorityChainValid
            });
            // Only a single quorum-or-authority violation → Escalate.
            if needs_escalation && violations.len() == 1 {
                Verdict::Escalated {
                    reason: violations[0].description.clone(),
                }
            } else {
                Verdict::Denied { violations }
            }
        }
    }
}
```

Three important structural properties:

- **Priority**: Sybil challenges short-circuit everything.
- **Completeness**: when denied, all violations are reported.
- **Conservative escalation**: only pure single-cause quorum or
  authority failures escalate; everything else denies.

---

## 6. The Constitutional Amendment Process

From EXOCHAIN Fabric Platform Spec §3A.3.2.

Modifying the CGR Kernel binary or the invariant registry is the
rarest operation in EXOCHAIN. It is possible — a system that cannot
evolve cannot survive — but the bar is intentionally extreme to
prevent capture or erosion.

### 6.1 When you might need one

- Adding a new invariant (see `AGENTS.md` "How to Add a New
  Invariant"). The ninth invariant is a constitutional amendment.
- Relaxing an invariant (extremely rare — no precedent).
- Replacing the kernel binary with a version that adds formal
  verification, changes the combinator algebra, or restructures the
  invariant engine.
- Upgrading cryptographic primitives to a post-quantum scheme.

### 6.2 The five requirements

| #  | Requirement                          | Details                                                     |
|----|--------------------------------------|-------------------------------------------------------------|
| 1  | Unanimous validator consent          | 100% of active validators must sign the `KernelUpgradeProposed` event |
| 2  | Supermajority AI-IRB approval        | ≥80% of AI-IRB members vote in favour                       |
| 3  | 30-day public comment period         | During which the proposal is visible and contestable        |
| 4  | Formal proof (Coq / Lean)            | Mathematical proof that the new invariant set preserves safety properties |
| 5  | External security audit              | No HIGH or CRITICAL findings                                |

Plus a sixth operational step: a new genesis checkpoint with the
updated `kernel_cid` at a coordinated block height, distributed
across the network.

### 6.3 Which immutable components require this

Anything guarded by invariants `KernelImmutability` (§3.5) or the
normative INV-008/INV-009 from the platform spec:

- The kernel binary (content-addressed by `kernel_cid`).
- The invariant registry (the `InvariantSet` returned by
  `InvariantSet::all()`).
- The constitution bytes (hashed into `constitution_hash`; see
  [`Kernel::new`][kernel-new] at lines 90–96).

Policy, capability grants, delegation chains, and consent records are
*not* amendment-gated — they live at the legislative/executive
surface and follow their normal multi-sig paths.

---

## 7. How the SDK Exposes This

### 7.1 Rust — `exochain_sdk::kernel::ConstitutionalKernel`

The SDK wraps the full `Kernel` with an ergonomic surface that
supplies reasonable defaults. See
[`crates/exochain-sdk/src/kernel.rs`][sdk-kernel].

```rust
use exochain_sdk::kernel::{ConstitutionalKernel, KernelVerdict};
use exo_core::Did;

let kernel = ConstitutionalKernel::new();
let actor  = Did::new("did:exo:alice").expect("valid DID");

// Happy path: returns KernelVerdict::Permitted.
match kernel.adjudicate(&actor, "read-medical-record") {
    KernelVerdict::Permitted            => println!("ok"),
    KernelVerdict::Denied { violations } => println!("denied: {violations:?}"),
    KernelVerdict::Escalated { reason }  => println!("escalated: {reason}"),
}

// Self-grant path: returns KernelVerdict::Denied with a NoSelfGrant
// violation.
let _ = kernel.adjudicate_self_grant(&actor, "escalate-self");

// Kernel-modification path: returns KernelVerdict::Denied with a
// KernelImmutability violation.
let _ = kernel.adjudicate_kernel_modification(&actor, "patch-kernel");

// No-bailment path: returns KernelVerdict::Denied with a
// ConsentRequired violation.
let _ = kernel.adjudicate_without_bailment(&actor, "read-data");

// Verify the kernel's stored constitution hash is intact.
assert!(kernel.verify_integrity());
assert_eq!(kernel.invariant_count(), 8);
```

`KernelVerdict` is a flattened form of `Verdict` with `violations`
as `Vec<String>` so SDK consumers do not need to depend on the full
gatekeeper types.

### 7.2 TypeScript / Python — future work

The TypeScript SDK in `packages/exochain-sdk/` and the Python SDK in
`packages/exochain-py/` currently expose the lower-level primitives
(DID, signing, event construction). The `Kernel` wrapper is not yet
exposed in those packages; the in-process Rust kernel and the MCP
server at §7.3 below are the canonical paths. This is tracked in
`GAP-REGISTRY.md`.

### 7.3 MCP — `exochain_adjudicate_action`

AI agents connecting to EXOCHAIN through the MCP server get the
kernel as a tool:

```jsonc
// tools/call request
{
  "jsonrpc": "2.0",
  "id": 42,
  "method": "tools/call",
  "params": {
    "name": "exochain_adjudicate_action",
    "arguments": {
      "actor": "did:exo:ai-agent-1",
      "action": "summarize-record",
      "is_self_grant": false,
      "modifies_kernel": false
    }
  }
}
```

The server dispatches into the governance tool handler (see
[`crates/exo-node/src/mcp/tools/mod.rs:156`][mcp-tools]) and returns
a `Verdict` as JSON. The AI's subsequent behaviour is expected to
respect the verdict — see the companion document
[`ai-agent-guide.md`](./ai-agent-guide.md).

---

## 8. Further reading

- [`architecture-overview.md`](./architecture-overview.md) — the
  system around the kernel (layers, DAG, consensus, MCP surface).
- [`developer-onboarding.md`](./developer-onboarding.md) — the
  hands-on first-hour guide.
- [`ai-agent-guide.md`](./ai-agent-guide.md) — the constitutional
  handbook for AI agents.
- [`../architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md)
  — the existing deep-dive architecture document.
- [`../../governance/traceability_matrix.md`](../../governance/traceability_matrix.md)
  — 87 requirements tracked against tests and crates.
- [`../../governance/resolutions/CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY.md`](../../governance/resolutions/CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY.md)
  — the council resolution that supplies §8.3 (synthetic voice
  exclusion) and §8.5 (Sybil challenge escalation).
- [`../../EXOCHAIN-FABRIC-PLATFORM.md`](../../EXOCHAIN-FABRIC-PLATFORM.md)
  — the full platform specification, §3A in particular for the
  Separation of Powers flow.
- [`../../AGENTS.md`](../../AGENTS.md) — AI development constraints,
  including "How to Add a New Invariant".

---

[invariants-rs]: ../../crates/exo-gatekeeper/src/invariants.rs
[mcp-rs]: ../../crates/exo-gatekeeper/src/mcp.rs
[kernel-adjudicate]: ../../crates/exo-gatekeeper/src/kernel.rs
[kernel-new]: ../../crates/exo-gatekeeper/src/kernel.rs
[enforce-all]: ../../crates/exo-gatekeeper/src/invariants.rs
[sdk-kernel]: ../../crates/exochain-sdk/src/kernel.rs
[mcp-tools]: ../../crates/exo-node/src/mcp/tools/mod.rs

---

Copyright (c) 2025–2026 EXOCHAIN Foundation. Licensed under the
Apache License, Version 2.0. See
[`../../LICENSE`](../../LICENSE).
