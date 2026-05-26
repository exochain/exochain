# Exochain Council Review for CyberMedica Open Questions

Prepared on 2026-05-23 for CyberMedica baseline feature development.

This is a council-style development disposition, not a binding constitutional council act. It uses Exochain source, Exochain council panel documents, and the local ExoForge council-style triage script to separate:

- questions that can be resolved by standing Exochain doctrine and code;
- questions that can be given a safe baseline development default;
- questions that require Bob, root operators, legal counsel, clinical governance, or production deployment owners.

Baseline development must proceed using the consensus defaults below. Production Exochain/root-backed trust claims remain gated by `docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md`.

## Method

Sources used:

| Source | Path | Use | Binding? |
|---|---|---|---:|
| Open question register | `docs/context/EXOCHAIN_OPEN_QUESTIONS_FOR_BOB.md` | Input question set | No |
| Governance panel | `docs/council/PANEL-1-GOVERNANCE.md` | Authority, quorum, human gate, contestation lens | No |
| Legal panel | `docs/council/PANEL-2-LEGAL.md` | evidence, custody, consent, records, admissibility lens | No |
| Architecture panel | `docs/council/PANEL-3-ARCHITECTURE.md` | deterministic architecture, tenant, proof, DAG lens | No |
| Security panel | `docs/council/PANEL-4-SECURITY.md` | threat, authority chain, human gate, audit continuity lens | No |
| Operations panel | `docs/council/PANEL-5-OPERATIONS.md` | deployment, monitoring, Syntaxis, operations lens | No |
| ExoForge council CLI | `exoforge/bin/exoforge-council-review.js`, `exoforge/lib/panels.js` | non-binding heuristic triage | No |
| Exochain code | `crates/exo-root`, `exo-core`, `exo-consent`, `exo-authority`, `exo-gatekeeper`, `exo-governance`, `exo-legal`, `exo-dag`, `exo-node`, `decision-forum` | implementation evidence | Yes for source truth |

Executed local command:

```bash
node exoforge/bin/exoforge-council-review.js \
  --stdin \
  --json \
  --type governance \
  --affected cybermedica,decision-forum,exo-root,exo-gateway,exo-node,exo-consent,exo-authority,exo-tenant \
  < /Users/bobstewart/dev/exochain/cybermedica/docs/context/EXOCHAIN_OPEN_QUESTIONS_FOR_BOB.md
```

Result: non-binding `heuristic_triage`; `binding_review=false`; aggregate verdict `REJECTED`; Governance vetoed because the full packet touches constitutional compliance, delegation, and amendment language. Legal and Operations approved; Security approved with conditions; Architecture rejected because kernel/Merkle/state-transition areas require full regression review. Interpretation: the packet is safe for baseline development only when production claims stay gated, adapter paths fail closed, and root/authority decisions with no repo answer are escalated.

## Consensus Rule

For this artifact, council-style consensus exists when all five lenses can support a baseline development default without needing a human fact that is absent from the repo. Consensus does not equal production activation. It means CyberMedica can build the feature path now with inactive trust states, contract tests, fail-closed adapters, and clear claim gates.

Escalation is required only where the missing answer is an institutional fact, legal position, accountable owner, production environment, or root ceremony artifact that the repository cannot determine.

## Council Disposition by Question

| ID | Council-style disposition | Baseline development default | Production claim gate | Escalate to Bob? |
|---|---|---|---|---:|
| ROOT-001 | No consensus possible on the actual certifier roster. Code requires exactly 13 unique certifiers. | Implement `RootCertifierRoster` contract and verifier UI/state as empty or inactive until supplied. | 13 rostered independent certifiers and validated uniqueness. | Yes |
| ROOT-002 | Consensus on evidentiary requirements, not on storage location. | Implement artifact registry contract for roster, DKG transcript, signed envelopes, root trust bundle, verifier result, and immutable audit hash. | Chosen production artifact store and retention policy. | Yes |
| ROOT-003 | Consensus. Activation is a verifier event, not a calendar date. | Implement `trust_state = inactive | pending | verified | failed`, default inactive. | Verified root bundle + 100% DKG transcript + 7-of-13 signature + deployed verifier pass. | No |
| ROOT-004 | No consensus on deployment endpoint. | Implement environment-configured `RootTrustBundleProvider` with fail-closed missing/unverified state. | Production endpoint, credentials, health/readiness, and root bundle source. | Yes |
| ROOT-005 | No consensus on accountable human owner. | Implement incident-owner fields and runbook placeholders as required config. | Named owner, backup owner, escalation path, rollback/disablement authority. | Yes |
| ID-001 | No consensus on external proofing provider. | Implement `VerifiedHumanProvider` interface; Decision Forum human gate fails closed when provider is absent. | Selected provider/source of verified human DID status. | Yes |
| ID-002 | Consensus. Every actor performing governed action or sensitive access needs an Exochain DID or DID-mapped identity. | Require DID-mapped identity for PI, sub-I, CRC, QA, sponsor/CRO monitor, auditor, support engineer, AI agent, admin. | Production identity proofing and provisioning evidence. | No |
| ID-003 | Consensus on mapping principle; exact clinical role matrix is domain policy. | Map governance board roles to `Role`; map operational clinical permissions to `Permission`; keep both distinct. | Final clinical role matrix and authority policy. | Yes |
| ID-004 | Consensus on allowed delegation pattern. | Use scoped, time-bounded, revocable chains; support access is time-boxed; AI cannot create delegations or satisfy human gates. | Final organization-specific delegation limits. | No |
| ID-005 | Consensus. Quorum is for governance decisions; authority/consent is for routine operations. | Quorum: QMS control approval, launch, enrollment, CAPA closure, consent/support policy, production trust activation. Authority/consent: routine document/evidence operations. | Any exception to this split. | No |
| CONSENT-001 | Consensus on primitive mapping. | Participant informed consent uses consent policy + bailment terms; site data custody uses custody/processing bailment; support access uses emergency/processing bailment; sponsor export uses export/processing grant; AI review uses processing/delegation with human final authority. | Legal approval of consent language. | No |
| CONSENT-002 | Consensus on receipt structure; clinical legal sufficiency needs counsel. | Receipt binds consent artifact hash, version, actor DID, authority chain, bailment/consent refs, timestamp, revocation path, and no raw PHI. | Final legally approved participant consent template/control. | Yes |
| CONSENT-003 | Consensus. Revocation is immediate, fail-closed, and append-only. | On revocation, future access denies, active support grants terminate, revocation receipt/log persists, historical receipts remain immutable. | None unless policy wants grace periods, which council disfavors. | No |
| PRIV-001 | Consensus on prohibited classes. | Prohibit raw PHI/PII, direct identifiers, sponsor-confidential content, privileged legal material, source-document body text, credentials, secrets, private keys, raw signatures where unnecessary, and free-text clinical notes from immutable anchors/logs/telemetry. | Site/sponsor-specific field catalog. | No |
| PRIV-002 | Consensus on minimum metadata posture. | Export/anchor metadata should be hash, artifact type, version, tenant-scoped pseudonymous ID, actor DID or role hash, HLC timestamp, custody digest, receipt ID, and classification label. | Sponsor/CRO export template. | No |
| DF-001 | Consensus. Decision class maps to risk and governance impact. | Routine: low-risk operational action. Operational: site/QMS workflow action. Strategic: protocol launch, enrollment gate, CAPA closure, support policy. Constitutional: trust fabric, root, tenant constitution, control framework changes. | Any product-specific class override. | No |
| DF-002 | Consensus. Decision Forum is required for high-governance gates. | Require Decision Forum for QMS control approval, protocol readiness, launch, enrollment, CAPA closure, consent policy change, support access policy, and production trust activation. | None for baseline. | No |
| DF-003 | Consensus. Exochain council is product/trust governance, not a clinical IRB. | CyberMedica may model IRB-like review workflows, but must not claim to be an IRB or substitute for a regulated IRB. | If CyberMedica will make IRB-equivalence claims. | Yes, only if such a claim is intended |
| DF-004 | Consensus. Challenge standing should be broad for affected parties, but adjudication must be independent. | Allow affected participants, site governance, sponsor/CRO oversight, QA, auditors, and authorized support/security to file. Review by independent human governance role; sustain/overrule by verified quorum; withdrawal by filer before adjudication if no safety/legal hold issue. | Final standing policy. | No |
| DF-005 | Consensus on mandatory evidence bundle. | Require source artifact hashes, control objective, authority chain, consent/bailment refs, risk assessment, alternatives/no-action rationale, human review evidence, quorum result, audit trail, decision rationale, PHI boundary attestation, AI provenance if used. | Sponsor/CRO-specific export additions. | No |
| RT-001 | Consensus for baseline; production endpoint remains open. | Build adapter abstraction with server-side gateway/node primary path, SDK for typed integration, no browser/WASM trust path for PHI by default. | Selected production endpoint and deployment topology. | Yes |
| RT-002 | Consensus. Operational state and immutable receipts are separate. | CyberMedica DB stores mutable app state; Exochain node/DAG/receipt store records immutable hashes, decisions, custody digests, and provenance references. | Final storage vendor and retention settings. | No |
| RT-003 | Consensus. Health must separate process availability from trust readiness. | Implement process health, dependency health, receipt readiness, Decision Forum readiness, root readiness, and privacy-boundary self-checks as distinct states. | Production monitoring destination and on-call owner. | Yes |
| RT-004 | Consensus on separation; no consensus on provider. | CyberMedica secret scope must be separate from Exochain root/bootstrap/signing keys; missing/malformed secrets fail closed. | Secret manager/provider, owners, rotation cadence. | Yes |
| RT-005 | Consensus. CI must be stricter at trust boundaries. | Require unit, integration, adapter contract, privacy fixtures, no raw sensitive anchoring, tenant isolation, consent revocation, authority/RBAC, Decision Forum human gate, receipt determinism, coverage >90%, near-100% trust-boundary coverage. | None for baseline. | No |
| ADJ-001 | Consensus. CommandBase is not enforcement for CyberMedica baseline. | Treat CommandBase as out of scope unless separately inventoried as an adjacent cockpit. | If Bob wants CommandBase in product scope. | Yes, only if desired |
| ADJ-002 | Consensus. ExoForge/Archon can assist work, not authorize it. | Treat outputs as untrusted inputs requiring human review, source validation, tests, and bounded workflow rules. | None for baseline. | No |
| ADJ-003 | Consensus. Syntaxis is design-time until registry-to-code verification passes. | Use Syntaxis for workflow exploration and contract generation only; do not claim Syntaxis-backed runtime enforcement yet. | Registry-to-code test suite and generated workflow pass. | No |
| ADJ-004 | Consensus. Build a CyberMedica regulated UI around verified APIs rather than exposing un-inventoried Exochain web UI. | CyberMedica owns the clinical QMS UI; Exochain UI surfaces remain out of trust path until inventoried. | If Bob wants to reuse Exochain web UI. | Yes, only if desired |
| ADJ-005 | Consensus. Use ordinary TrustReceipt for AI review provenance first; AVC may be supported as bounded credential if tested. | AI remains assistant; human gate final; record AI recommendations with TrustReceipt and optional AVC adapter contract. | If AVC is required in first release claims. | No |

## Consensus Development Defaults

These defaults are approved for baseline feature development:

1. Build CyberMedica now against source-identified Exochain service contracts.
2. Default production trust state is inactive until root and adapter evidence verify.
3. Use Exochain DID mapping for every governed actor and AI agent.
4. Use authority chains for role/delegation, not app-only RBAC.
5. Use consent/bailment for participant consent, support access, sponsor export, and AI processing boundaries.
6. Use Decision Forum for QMS control approval, protocol readiness, launch, enrollment, CAPA closure, consent policy changes, support access policy, and production trust activation.
7. Keep raw PHI/PII/sponsor-confidential/privileged content out of immutable receipts, DAG payloads, logs, telemetry, debug, health, and exports.
8. Use CyberMedica's own regulated UI; do not rely on CommandBase or un-inventoried Exochain web surfaces for enforcement.
9. Use ExoForge/Archon/Syntaxis as untrusted development aids until their runtime adapter paths are verified.
10. Use ordinary TrustReceipt for AI review provenance; AVC can be an adapter contract but AI remains non-final.

## Non-Consensus Items

The council-style process cannot resolve these because they require institutional facts or production choices:

| Escalation ID | Open question IDs | Required Bob/root/operator input |
|---|---|---|
| ESC-ROOT-ROSTER | ROOT-001 | 13 certifier identities and independence basis. |
| ESC-ROOT-ARTIFACT-STORE | ROOT-002 | Authoritative storage location for roster, DKG transcript, envelopes, root trust bundle, and verifier evidence. |
| ESC-ROOT-DEPLOYMENT | ROOT-004 | Production root bundle provider/deployment endpoint. |
| ESC-ROOT-OWNER | ROOT-005 | Accountable root ceremony and incident-response owner. |
| ESC-HUMAN-PROOFING | ID-001 | Source/provider for externally verified human DID status. |
| ESC-ROLE-MATRIX | ID-003 | Final clinical role matrix and authority policy. |
| ESC-CONSENT-LEGAL | CONSENT-002 | Legal-approved clinical consent template/control language. |
| ESC-RUNTIME | RT-001 | Production runtime topology and canonical adapter endpoint. |
| ESC-OPS-SECRETS | RT-003, RT-004 | Monitoring destination, on-call owner, secret manager, rotation owner. |
| ESC-OPTIONAL-ADJACENT | ADJ-001, ADJ-004, ADJ-005 | Whether CommandBase, Exochain web UI, or AVC must be first-release product scope. |

Only these non-consensus items should be escalated to Bob in conversation.
