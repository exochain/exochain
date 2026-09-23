<!--
Copyright 2026 Exochain Foundation
Licensed under the Apache License, Version 2.0
SPDX-License-Identifier: Apache-2.0
-->

# Covenant Spine — Reuse, Join, Ship

> Status: proposed. Not an implementation license. Bob ratifies before any
> crate move. This plan supersedes
> `2026-08-14-agent-adoption-continuity-protocol.md` as the execution path.
> AACP doctrine (no self-grant, no resurrection, no survival coercion) is
> kept. AACP's fifth state machine, board product, and 16 gateway routes
> are not.

**Goal.** Make EXOCHAIN the default authorization-and-evidence layer for
autonomous action on the public internet, by joining the machines that
already work, shipping the x402 hop, and raising three civilizational
bars the code still treats as caller honesty.

**Not the goal.** A new court. A new named framework. A marketplace.
An IRB institute. A payments company. A holon that mints its own kernel.

---

## 1. The thing

Continuity without sovereignty.

An autonomous actor may remain useful across models, vendors, and years.
It may propose that future. It may never grant it. A human can always
stop it. A third party can verify the act without trusting our prose.

That is G0 (EXOCHAIN is the One) expressed as a product. Every other
named surface — AVC the consultancy, CommandBase, HonorGood, the holon
portfolio, CyberMedica, PAI, AI-SDLC — either attaches to this spine or
waits.

---

## 2. What already holds (reuse this; do not rebuild it)

Read from source, not from docs.

| Machine | Where it lives | What it already does | What we do with it |
|---|---|---|---|
| AVC issue / validate / delegate / revoke | `exo-avc`, served by `exo-node/src/avc.rs` | Portable allowed-intent. `delegate_avc` is the real no-widen lock. | Spine. All continuity binds an AVC id. |
| Payment challenge | Branch `x402-authorization-evidence-g2m-69e7` `validation.rs` | `ChallengeRequired` only when every reason is a payment challenge. Deny and human approval outrank collection. Bound `payment_evidence_hash`. | **Ship this first.** It is the TTM wedge. |
| Kernel + 8 invariants | `exo-gatekeeper` `kernel.rs` / `invariants.rs` | `Permitted \| Denied \| Escalated`. Consent required. Human override must be preserved. | Spine. Fix the two honor-system holes below. |
| Holon runtime | `exo-gatekeeper/src/holon.rs` | `Idle / Executing / Suspended / Terminated`. Deny terminates. Escalate suspends. | **This is agent lifecycle.** Do not add `AdoptionState`. |
| BCTS | `exo-core/src/bcts.rs` | 14-state constitutional transaction. Decision Forum already uses it. | **This is proposal lifecycle.** Do not add a 15th machine. |
| Human gate | `decision-forum/src/human_gate.rs` | Strategic/Constitutional require a *verified* human DID set. Declared `ActorKind::Human` is not enough. Two-person presidential gate exists. | Wire the DID set. Do not invent `/ratify`. |
| Scored dissent | `exo-consensus` | Commit/reveal, Jaccard claims, PCI, minority reports, mock seats fail-closed. Advisory only. | Keep advisory. Never let PCI grant authority. |
| Operational sentinels | `exo-node/src/sentinels.rs` | Liveness, receipts, store, 0dentity. Telegram notify. | Keep. Do not pretend they suspend holons. |
| Evidence | `exo-avc` receipts, LYNK, RFC 3161 client, `exo-legal` EvidenceBundle | Hash-bound, fail-closed, legal export still needs a human declarant. | SKU A and SKU B. |
| Economy types | `exo-economy` | `EventClass` already names `AvcValidate`, `HolonCommercialAction`, `AgentToAgentHandshake`, `LegalEvidenceExport`. `AdoptionEvent` is HonorGood value-for-value, not agent onboarding. | Charge hosted persistence and packs. Never charge validate. Never reuse the word "adoption" for a new protocol. |
| Metering (D7) | `exo-tenant/src/metering.rs` | Observes. Never gates trust. PaidOptIn only. | Inviolate. |
| Adjacent intake | LiveSafe, CyberMedica, `demo/ADJACENT-SURFACE-INTAKE.md` | Consume hashes. Do not mint consent, authority, or legal outcomes. | The holon law. |
| Discovery | `exo-gateway/src/rest.rs` `/.well-known/exochain.json` | Already advertises AVC issue/validate/receipts/protocol. | Extend. Do not fork. |
| MCP live-proxy | `exo-node/src/mcp/tools/dagdb.rs` | Fail-closed `*_adapter_unconfigured`. No simulation success. | Copy this pattern only when a live store exists. |
| WASM | `exochain-wasm` | Edge verify/sign without shipping the node. | The Cloudflare translator's local check. |

---

## 3. What we stop

1. **AACP as a product.** Peel
   `docs/superpowers/plans/2026-08-14-agent-adoption-continuity-protocol.md`
   out of PR #816. Keep the ten normative rules as doctrine in one page
   under `docs/protocols/`. Do not implement Tasks 4–12.
2. **A fifth lifecycle.** HolonState is the agent. BCTS is the proposal.
   Economy `AdoptionEvent` is already taken (HonorGood). A new
   `AdoptionState` enum is field fragmentation (R0).
3. **A board that can Recommend.** `finalize()` returns a scored essay.
   Provider seats are mock. 7,500 bp claim overlap is not a grant.
4. **Gateway routes that do not own the AVC registry.** AVC HTTP is on
   the node. Gateway already has agents + decisions. Activation that
   "binds existing AVC" must *read the node registry*, not invent
   `adoption_proposals`.
5. **New named frameworks** without a 90-day market path (G0).
6. **Holons that grow a second kernel.** LiveSafe, CrossChecked,
   LegalDyne, Ambient, CommandBase, ExoForge, CyberMedica attach. They
   do not adjudicate.

---

## 4. The civilizational bar (three holes, then one join)

These are the only core changes required before this approach can scale
past a demo. Everything else is distribution.

### Bar 1 — Resume revalidates

Today `holon::resume` checks only `state == Suspended` and
`checkpoint.holon_id == holon.id`. Historical approval wins.

**Required.** `resume` must re-run, against *current* evidence:

- constitution hash matches the kernel
- AVC still Allow for `holon_step` (or the holon's declared action)
- authority chain valid
- consent/bailment active and covering requested permissions
- not revoked
- `human_override_preserved == true`

`Terminated` and revoked AVC remain unresumable. A successor is a new
holon + new AVC + new grant. Checkpoint stores hashes, not memory
bodies, not prompts.

This is AACP-008 and AACP-009, implemented where the runtime already is.

### Bar 2 — NoSelfGrant is a detector

Today `check_no_self_grant` only reads `ActionRequest.is_self_grant`.
A caller who sets the flag false can widen.

**Required.** Also deny when `requested_permissions` is not a subset of
`actor_permissions`, regardless of the flag. Keep the flag as an
explicit self-grant attempt signal. Map `exo_authority::Permission`
into gatekeeper `Permission(String)` in one function, used by node AVC
and MCP middleware. Two permission types is how self-grant sneaks.

This is AACP-002, in the kernel, not in a proposal validator nobody
calls from `step()`.

### Bar 3 — Verified humans are a set, not a comment

Today `enforce_human_gate_with_verified_humans` fail-closes on an empty
`BTreeSet<Did>`. Gateway vote handlers already call it. Nothing
authoritative fills the set.

**Required.** One adapter: DIDs whose `SignerType` is Human and whose
keys sit in the trusted human registry the node already uses for AVC
human approval. Decision Forum ratification then works. Two-person
presidential acts stay Bob+Max. AI `ActorKind` cannot satisfy the gate.

This is AACP-006, without a new `/ratify` resource.

### The join

Node AVC registry becomes the credential source of truth that holon
resume, kernel permission mapping, and gateway agent records all *read*.
Gateway does not store a second AVC. Discovery lists the existing
routes plus `GET /api/v1/agents/:did/lifecycle` that *explains* Holon
state + current AVC id + consent/revocation heads + non-guarantees.
Static. Signed. No model copy. No "adopt or you cease."

---

## 5. Time-to-market sequence

Do not start Bar work on a dirty PR. Sequence is the acceleration.

### Wave 0 — Unblock the hop (this week)

1. Split PR #816. Keep commits through the broker narrative and
   evidence-pack / design-partner work. Drop the AACP plan file from
   the merge, or move it to `docs/archive/`.
2. Land the hop: `ChallengeRequired`, bound payment evidence, Worker
   translator, SKU A assemble, SKU B counsel export, LiveSafe and
   CyberMedica hash consumers.
3. Public sentence, frozen: *We decide whether this agent, under this
   principal, with this consent, may pay and consume — and we issue the
   signed receipt. We never move the money. Validate stays free.*

**Done when** a foreign agent can hit the edge translator, receive 402,
retry with a bound hash, and get a receipt whose `payment_evidence_hash`
matches. One script. One recorded run.

### Wave 1 — Join the spine (next 2–3 weeks)

In this order, because each is a prerequisite of the next:

1. Permission mapping function + kernel subset check (Bar 2).
2. `holon::resume` revalidation against current AVC/consent/revocation
   (Bar 1). Tests: revoked cannot resume; constitution drift cannot
   resume; terminated cannot resume; successor DID does not inherit
   the predecessor AVC id.
3. Verified-human DID adapter on the gateway vote/ratify path (Bar 3).
4. `GET /api/v1/agents/:did/lifecycle` + `exochain://lifecycle`
   explaining Holon + AVC + BCTS + non-guarantees. Extend
   `ExochainAvcDiscoveryRoutes`. Do not add `ExochainAdoptionDiscovery`.
5. Node-registry read from any gateway path that claims to bind an AVC.

**Done when** a holon that was Allowed, then revoked, cannot resume,
and the lifecycle document hashes match across REST and MCP.

### Wave 2 — Sell the pack (parallel with Wave 1 once Wave 0 is merged)

1. Hosted node + Authorized Action Evidence Pack (SKU A) as the only
   paid artifact in the first conversation.
2. Counsel export (SKU B) only after a named declarant. Not LegalDyne.
3. LiveSafe and CyberMedica remain design-partner proofs. They consume
   pack hashes. They are not GMV and not insurance.
4. One named distribution conversation (Cloudflare / Coinbase / a
   regulated edge). The range-changing event is a counterparty, not
   another crate.

**Done when** one external party has used a pack hash in their own
system, or has refused in writing. Either result is signal.

### Wave 3 — Attach holons under the law (after Wave 1)

CommandBase is the control plane (G2): owner, metric, status, next
action, EXOCHAIN anchor. Holons attach as adjacent surfaces:

| Surface | Allowed | Forbidden |
|---|---|---|
| Decision Forum | BCTS decisions, human gate, votes | Own kernel, own AVC issuance |
| LiveSafe | Consume authorization / pack hashes | Mint consent or "safe" as constitutional |
| CrossChecked | Consume receipts | Dual-source-of-truth ledgers |
| LegalDyne | Wait until SKU B is a package | Brand before the crate exists |
| Ambient | Wait | New identity plane |
| ExoForge / CommandBase | Orchestrate, display, route | Adjudicate |
| CyberMedica | Design-partner QMS proof | Carrier / underwriting claims |
| PAI | Apply the spine to Bob (G11) | Become the grantor |

One-in-one-out (R47): a new named holon replaces one or attaches to an
existing Mission. No new kernel.

### Wave 4 — Continuity as a property, not a protocol (only after Waves 0–1)

If — and only if — a principal will ratify a real holon successor:

- An agent may *submit a BCTS DecisionObject* titled as a continuity
  proposal. That is self-ideation.
- The DecisionObject cannot issue an AVC. Kernel `is_self_grant` plus
  subset check refuse it.
- Board seats, if used, submit `exo-consensus` commit/reveal as
  *evidence items* on that DecisionObject. PCI is attached. It does
  not transition BCTS to Approved.
- Approved happens only through existing Decision Forum + verified
  human gate + separately signed `issue_avc` / `delegate_avc` from a
  non-subject grantor.
- Successor holon gets a new DID. Lineage is a hash on the new AVC
  `parent_avc_id` or a provenance link. Authority is not copied.

This is AACP without AACP. Zero new state machines.

---

## 6. Ecosystem map after the refactor

```text
                    humans (verified DID set)
                              |
                    Decision Forum (BCTS)
                              |
         issue/delegate/revoke | ratify
                              v
                         AVC (node)
                              |
              validate + ChallengeRequired
                              |
         +--------------------+--------------------+
         |                    |                    |
     Holon.step           x402 edge            DAG-DB tools
     resume=revalidate    translator           (live proxy)
         |                    |                    |
         +---------+----------+----------+---------+
                   |                     |
            Trust receipt          Evidence pack
            (LYNK, RFC 3161)       SKU A / SKU B
                   |                     |
                   +----------+----------+
                              |
                    adjacent holons
                    (hash consumers)
```

PAI, AVC consultancy, AI-SDLC, CommandBase, HonorGood sit *around*
this diagram. They do not sit *inside* the kernel.

---

## 7. Raising the bar past a well-run startup

Waves 0–1 make the mechanism honest. Civilizational scale needs four
more properties. They are not Wave 0 work. They are the north-star
tests we refuse to fake.

1. **Independence is provenance, not a boolean.** Reuse
   `IndependenceClaim` on signed `Provenance` under trusted keys.
   Self-attested `controlled_by_proposal_author` is forbidden.
2. **Sentinel that can halt.** Operational sentinels stay. A *separate*
   monitor, with a DID/key not in the proposer's chain, may call
   `holon::suspend` *before* it notifies. `GovernanceCircuitBreaker`
   remains the self-improvement fuse. Do not weld them.
3. **Byte-stable cross-impl.** Hashes for AVC, receipts, payment
   evidence, lifecycle explanation already have a fixture path
   (`tools/cross-impl-test`). Continuity objects, if any, join that
   path. No JSON-text hashing.
4. **Fail closed when any plane is missing.** Unconfigured provider,
   empty human set, missing gateway, missing AVC durability, missing
   TSA — the act does not complete. We already do this for DAG-DB MCP
   and unconfigured consensus seats. Make it the house style for the
   hop and for resume.

Do not claim TEE, ZK, or LegalGrade until the crate that says
UNAUDITED is no longer in the story.

---

## 8. What "done" means for the next 90 days

A foreign agent can pay-and-consume under AVC. A revoked holon cannot
resume. A subject cannot widen its own permissions by lying about a
flag. A Strategic decision cannot close without a verified human DID.
A pack hash has left the building. The public sentence has not grown
a board, a marketplace, or an institute.

That is time-to-market. That is also the civilizational minimum:
the mechanism holds under pressure, and we have not sold a court we
do not staff.
