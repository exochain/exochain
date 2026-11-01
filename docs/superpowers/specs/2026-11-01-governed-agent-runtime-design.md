# Governed agent runtime

This extends the EXOCHAIN intelligence runtime from main `3d0941b`. Existing
models act as bounded, reviewed, receipted agents under core authority.

## Design

Extend the canonical LYNK adapter rather than adding a parallel policy engine.
The Rust AVC generic receipt endpoint already verifies the subject action signature,
current credential/ancestor revocation, consent, constraints, emergency-stop standing,
and trusted receipt time. Add a domain-separated response attestation to its
finalized Allow responses. Bind the complete submitted request, decision, receipt,
and finality tuple. Attach it inside the existing transaction before committing.
The LYNK usage receipt endpoint and signature domain remain unchanged.

Production MCP dispatch requires a caller-signed AVC action request for an exact
canonical-CBOR commitment to tenant, actor, server, tool, arguments and idempotency
key. Only the core's pinned-validator-signed Allow response permits dispatch.
Authorizers supply signed request material, never local authorization decisions.
A durable journal claims an idempotency key atomically before dispatch; duplicate,
concurrent, restarted, or uncertain attempts cannot silently execute again. A
post-execution usage receipt still gates output release. Receipt retry never retries
the tool. Redirects are rejected and cancellation is checked at dispatch boundaries.

The agent runner consumes receipted planner and independent reviewer responses,
validates structured proposals, binds review to the exact proposal hash, and sends
only allow-listed tools through the governed MCP adapter. Models cannot provide
credentials, authorize themselves, extend limits, or assert completion without
review. The loop declares max_iterations (1..25), an explicit reviewed-completion
stop condition, and an escalation result. It stops after two matching failed
validations. It has finite model/tool call budgets and propagates cancellation.
All timestamps come from host HLC inputs. No automatic execution retry occurs.

## Trust boundary and limitations

Changed Rust node paths are EXOCHAIN core. LYNK paths are core runtime adapters.
Design/plan documents are governance implementation evidence. No adjacent product
is changed. No new constitutional invariant or permission is introduced.

Host configuration, signing callbacks, HLC source, transport authentication, model
selection and storage are trusted operator inputs. Models and tool output are
untrusted data. The runner is advisory until it receives real signed authority.
The process cannot cancel an already committed external side effect or promise
distributed exactly-once execution. Journal storage must be shared by all workers
in a scope; an interrupted attempt needs human reconciliation, not replay. A
revocation concurrent with the interval after authorization requires enforcement at
the target itself. These are explicit limits, not constitutional guarantees.

## Approaches considered

An independent orchestration/policy service would duplicate canonical enforcement.
A Rust-only state machine would not connect the existing live model/tool adapters.
The selected approach extends the existing Rust authority endpoint and TypeScript
runtime adapter together, with separate commits and cross-language verification.
The shared receipt fixture validates the core and adapter changes together.

## Acceptance

Tests prove denial, tampered attestations, wrong request binding, missing authority,
replay, cancellation, loop exhaustion and failed review produce zero external tool
dispatches. A successful reviewed run uses real adapter logic with deterministic
HTTP fixtures and returns verified receipts. No live customer action is needed for
tests. Package checks and applicable Rust gates are recorded honestly; unrun or
blocked gates preclude release-readiness claims.
