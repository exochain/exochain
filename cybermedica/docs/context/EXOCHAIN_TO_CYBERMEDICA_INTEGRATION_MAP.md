# Exochain to CyberMedica Integration Map

CyberMedica may integrate only with verified Exochain primitives through narrow adapters. This map is not a product architecture; it is a control surface for deciding what CyberMedica can build against after local Exochain truth commands and adapter tests pass.

## Integration Policy

| Rule | Requirement | Evidence basis |
|---|---|---|
| Adjacent surface boundary | CyberMedica is separate from Exochain core and cannot expand the trusted computing base by proximity. | `AGENTS.md` |
| Verified primitive only | Every Exochain-backed feature must cite source path, enabled runtime path, and test. | `AGENTS.md`, `docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md` |
| No raw sensitive anchoring | Raw PHI, PII, sponsor-confidential, privileged, or source document content must not be written to immutable receipts, DAG payloads, external anchors, health endpoints, debug output, or telemetry. | `crates/exo-node/src/provenance.rs`, `crates/exo-legal/src/evidence.rs`, `AGENTS.md` |
| Baseline development required now | CyberMedica should develop domain models, service contracts, adapter interfaces, deterministic fixtures, contract tests, inactive trust-state UI, and fail-closed behavior before institutional root activation. | User clarification, `crates/exo-root/*` |
| Production trust activation gated | Root-backed production claims require verified root trust bundle after 13-certifier DKG and 7-of-13 signing. This gate does not block baseline development. | `crates/exo-root/src/ceremony.rs`, `dkg.rs`, `signing.rs`, `bundle.rs`, `portal.rs` |
| TDD bar | Implementation must be TDD-first with >90% scoped coverage and near-100% trust-boundary coverage. | User instruction, `.github/workflows/ci.yml`, `tools/test_coverage_policy.sh` |

## CyberMedica Need Mapping

Implementation stance: every row below may be developed now as a CyberMedica service contract with deterministic tests and inactive production trust state. The `Allowed Claim After Tests` column describes the claim that becomes available only after the named adapter/runtime/deployment evidence is present.

| CyberMedica Need | Exochain Primitive | Source Path | Adapter Needed? | MVP | Risk | Required Tests | Allowed Claim After Tests |
|---|---|---|---|---|---|---|---|
| Tenant isolation | Tenant registry, tenant status/config, gateway tenant routes | `crates/exo-tenant/src/tenant.rs`, `crates/exo-gateway/src/rest.rs` | Yes | Yes | Registry metadata does not alone prove storage isolation. | tenant A cannot read/write tenant B; suspended tenant denied; tenant id tampering denied | tenant-aware access control |
| Clinical research site identity | Exochain DID | `crates/exo-identity/src/did.rs`, `crates/exo-gateway/src/auth.rs` | Yes | Yes | Identity proofing source not fully specified. | valid DID signature accepted; malformed DID rejected; stale timestamp rejected; wrong key rejected | verified Exochain DID-authenticated actor |
| User identity | DID plus human gate | `crates/exo-identity/src/did.rs`, `crates/decision-forum/src/human_gate.rs` | Yes | Yes | Self-declared human is insufficient. | human DID allow-list positive/negative; AI actor cannot satisfy human gate | externally verified human approval |
| Role authority | AuthorityChain and PermissionSet | `crates/exo-authority/src/chain.rs`, `permission.rs`, `delegation.rs` | Yes | Yes | Clinical role taxonomy not mapped. | role-to-permission mapping; expired delegation denied; revoked delegation denied; NoSelfGrant denied | authority-chain-gated action |
| Delegation logs | DelegationAuditEvent | `crates/exo-authority/src/delegation.rs` | Yes | Yes | Audit persistence and retention need deployment decision. | hash chain continuity; signed revocation; non-cyclic delegation; scope attenuation | auditable delegation history |
| Participant consent | Bailment, ConsentPolicy, ActiveConsent | `crates/exo-consent/src/bailment.rs`, `policy.rs`, `gatekeeper.rs` | Yes | Yes | Clinical consent/legal consent equivalence needs review. | missing consent denied; active consent allowed; revoked consent denied; expired bailment denied | consent-gated action |
| Support access grants | Bailment type and consent gate access log | `crates/exo-consent/src/bailment.rs`, `gatekeeper.rs` | Yes | Yes | Break-glass can leak privileged data if not fail-closed. | grant required; reason required; revocation immediate; access log hash/sequence verified | audited support access |
| Evidence object hashing | Canonical CBOR hash, Hash256, Evidence | `crates/exo-core/src/hash.rs`, `crates/exo-core/src/types.rs`, `crates/exo-legal/src/evidence.rs` | Yes | Yes | Metadata can identify participant even without raw content. | same input same hash; changed input changed hash; raw PHI fixtures absent from anchor; evidence hash rejects zero | hash-backed evidence object |
| Chain of custody | Evidence custody chain | `crates/exo-legal/src/evidence.rs` | Yes | Yes | Custodian transfer errors can undermine admissibility. | wrong custodian denied; monotonic timestamp enforced; custody digest deterministic | custody-tracked evidence |
| Document version receipts | TrustReceipt, DAG node, receipt store | `crates/exo-core/src/types.rs`, `crates/exo-dag/src/dag.rs`, `crates/exo-node/src/store.rs` | Yes | Yes | Payload storage path must be constrained. | version hash deterministic; receipt.action_hash matches committed node hash; receipt query returns metadata only | receipt-backed document version |
| QMS control approval | Gatekeeper invariants, quorum, Decision Forum | `crates/exo-gatekeeper/src/invariants.rs`, `crates/exo-governance/src/quorum.rs`, `crates/decision-forum/src/*` | Yes | Yes | Bypassing Decision Forum would dilute governance claim. | verified quorum required; missing provenance denied; human gate for strategic/constitutional decisions; raw transition denied | governed QMS control approval |
| Protocol launch gate | DecisionObject, WorkflowReceipt, human gate, TNCs | `crates/decision-forum/src/decision_object.rs`, `workflow.rs`, `human_gate.rs`, `tnc_enforcer.rs` | Yes | Yes | AI must not be final authority. | strategic/constitutional gate requires human; AI ceiling enforced; TNC evidence completeness | human-governed launch gate |
| Enrollment gate | Consent, authority, Decision Forum | `crates/exo-consent`, `crates/exo-authority`, `crates/decision-forum` | Yes | Yes | Consent/authority mismatch can allow improper enrollment. | consent invalid denies; role invalid denies; quorum invalid denies; challenge pauses gate | governed enrollment gate |
| CAPA closure | Decision Forum, governance audit, TrustReceipt | `crates/decision-forum/src/*`, `crates/exo-governance/src/audit.rs`, `crates/exo-core/src/types.rs` | Yes | Yes | Premature closure without evidence. | evidence required; human approval required; terminal state immutable; closure receipt generated | receipt-backed CAPA closure |
| Sponsor/CRO export | Evidence manifest, TrustReceipt, custody digest | `crates/exo-legal/src/evidence.rs`, `crates/exo-core/src/types.rs` | Yes | Yes | Export may disclose PHI/sponsor-confidential content. | manifest contains hashes/metadata only; redaction fixtures; export receipt hash; tenant boundary | diligence export receipt |
| Audit event receipts | Governance AuditEntry, TrustReceipt, DAG | `crates/exo-governance/src/audit.rs`, `crates/exo-core/src/types.rs`, `crates/exo-dag/src/dag.rs` | Yes | Yes | Operational DB logs may be confused with immutable receipts. | operational log differs from receipt; receipt signed; hash chain verifies | immutable audit evidence |
| AI review provenance | AVC receipt or ordinary TrustReceipt for AI advisory action | `crates/exo-avc/src/receipt.rs`, `crates/exo-consensus/src/lib.rs`, `crates/exo-core/src/types.rs` | Yes | Yes, as assistant only | AVC scope and AI ceiling need product decision. | AI recommendation receipt; human final approval required; AI cannot close gate | AI-assisted review provenance |
| Deterministic scoring | no-float lint, integer scoring, basis points | `Cargo.toml`, `crates/exo-consensus/src/lib.rs`, `crates/exo-economy/src/lib.rs` | Yes | Yes | Frontend/runtime may introduce floating point. | repeatability; no float source guard; boundary values; integer rounding policy | deterministic score calculation |
| Privacy-preserving anchors | hash-only evidence/provenance | `crates/exo-node/src/provenance.rs`, `crates/exo-legal/src/evidence.rs`, `crates/exo-dag/src/dag.rs` | Yes | Yes | Hash metadata can still be sensitive. | PHI/PII fixture search in receipts/DAG/API; no payload endpoint; metadata minimization | privacy-preserving hash anchor |
| Root-backed production authority | RootTrustBundle, threshold signing | `crates/exo-root/src/bundle.rs`, `signing.rs`, `portal.rs` | Yes | No until activation evidence | Root ceremony may be absent or incomplete. | root bundle verify; threshold signature verify; certifier roster; deployment evidence | root-backed authority, only after activation |
| Gateway call path | DID-authenticated gateway routing | `crates/exo-gateway/src/auth.rs`, `routes.rs`, `server.rs` | Yes | Yes if selected | Runtime adapter coverage exclusions. | gateway unavailable fails closed; auth invalid fails closed; consent middleware denies | gateway-mediated enforcement |
| Node receipt path | receipt insert/load and provenance | `crates/exo-node/src/store.rs`, `provenance.rs`, `api.rs` | Yes | Yes if selected | DB/runtime deployment unverified. | receipt signature non-empty; action hash sync; receipt query by actor; no payload disclosure | node-backed receipt storage |
| Runtime readiness and health | gateway/node/root/receipt/Decision Forum/privacy readiness contract | `src/runtime-readiness.mjs`, `crates/exo-gateway/src/server.rs`, `crates/exo-node/src/store.rs`, `crates/decision-forum/src/*`, `crates/exo-root/src/bundle.rs` | Yes | Yes | Process health can mask trust failure, and health output can disclose protected content or secret material. | process health separated from trust readiness; root/receipt/Decision Forum/privacy states distinct; health payload redacted on protected fields; runtime secrets fail closed | trust-readiness health contract |
| WASM/browser path | Exochain WASM bridge | `crates/exochain-wasm/*`, `.github/workflows/ci.yml` | Yes | Not by default | Browser path increases PHI exposure. | export sync; fail-closed browser errors; no secret exposure | browser adapter, only if verified |

## Primitives CyberMedica Must Avoid for Trust Claims Until Verified

| Primitive or Surface | Source path | Reason |
|---|---|---|
| ZK proofs | `crates/exo-proofs/src/lib.rs` | Explicitly unaudited, pedagogical, and default-off. |
| CrossChecked anchoring | `crates/exo-node/src/api.rs` | Default-off because proof URL/signature/tenant/authority verification is not established. |
| Raw admin governance | `crates/exo-node/src/api.rs` | Default refusal unless unaudited feature is enabled. |
| 0dentity device/behavior axes | `crates/exo-node/src/zerodentity/*` | Disabled behind unaudited feature flags. |
| Economy settlement | `crates/exo-economy/src/lib.rs` | Settlement scaffold with zero launch guarantee. |
| CommandBase enforcement | `command-base/*`, `AGENTS.md` | Adjacent surface not inventoried in this seed. |
| ExoForge/Archon as authority | `docs/guides/ARCHON-INTEGRATION.md`, `exoforge/*`, `.archon/*` | Process/tooling docs do not prove core enforcement. |

## Minimum Adapter Contract Tests

Every CyberMedica Exochain adapter must prove:

1. It fails closed when Exochain is unavailable, returns an error, times out, rejects auth, rejects consent, rejects authority, rejects quorum, or cannot create a receipt.
2. It cannot mint, cache, simulate, or override consent, authority, quorum, provenance, root authority, or Decision Forum outcomes outside Exochain enforcement.
3. It never writes raw PHI, PII, sponsor-confidential, privileged, or source document content into receipts, anchors, DAG payloads, telemetry, health, logs, debug endpoints, or exported diligence bundles.
4. It records operational database state separately from immutable Exochain receipts.
5. It includes source path, primitive, receipt path, test id, and PRD id for every trust claim.
