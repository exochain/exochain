# Exochain Council Escalations for Bob

The Exochain council-style review resolved the development defaults for the open-question register. Baseline CyberMedica development should proceed without waiting on these answers. The items below are escalated only because they require institutional facts, legal decisions, production ownership, or product-scope choices that the repository cannot determine.

| Escalation ID | Decision Needed | Why Council Could Not Resolve It | Development Default Until Answered |
|---|---|---|---|
| ESC-ROOT-ROSTER | Name the 13 rostered independent certifiers and independence basis. | `crates/exo-root` requires exactly 13 certifiers, but the repo cannot name them. | Build roster contract and trust-state UI; root-backed production trust remains inactive. |
| ESC-ROOT-ARTIFACT-STORE | Choose authoritative storage for roster, DKG transcript, signed envelopes, root trust bundle, and verifier evidence. | Council can define evidence requirements, not the production artifact store. | Build artifact registry interface with fail-closed missing/unverified state. |
| ESC-ROOT-DEPLOYMENT | Choose the production root bundle provider/deployment endpoint CyberMedica will query. | Code has root portal/verifier concepts, but production topology is a deployment choice. | Implement configurable `RootTrustBundleProvider`; default inactive. |
| ESC-ROOT-OWNER | Name root ceremony owner, backup owner, incident path, and rollback/disablement authority. | Accountable ownership is institutional, not inferable from code. | Require owner fields in runbooks/config before production activation. |
| ESC-HUMAN-PROOFING | Select the source/provider for externally verified human DID status. | Decision Forum human gate requires externally verified humans, but the repo does not choose a proofing provider. | Implement `VerifiedHumanProvider` interface; human-gated actions fail closed without provider evidence. |
| ESC-ROLE-MATRIX | Approve the final clinical role matrix and authority policy. | Council can map principles, but clinical operating policy is product/legal/organizational. | Use conservative default: board/governance roles map to `Role`; operational duties map to `Permission`; no self-grant. |
| ESC-CONSENT-LEGAL | Approve clinical consent template/control language for participant consent receipts. | Exochain can bind artifacts and consent receipts; clinical legal adequacy needs legal/clinical approval. | Build receipt shape around artifact hash, version, DID, authority, consent refs, revocation path, and no raw PHI. |
| ESC-RUNTIME | Select canonical production runtime topology and adapter endpoint. | Council supports gateway/node server-side adapter as baseline, but deployment topology is an ops/product choice. | Build adapter abstraction for gateway/node; SDK for typed integration; no browser/WASM PHI trust path by default. |
| ESC-OPS-SECRETS | Choose monitoring destination, on-call owner, secret manager, and rotation owner. | Operational ownership and secret-provider choice are deployment decisions. | Separate CyberMedica secrets from Exochain root/bootstrap/signing keys; missing secrets fail closed. |
| ESC-OPTIONAL-ADJACENT | Decide whether CommandBase, Exochain web UI, or AVC must be first-release product scope. | Council consensus is to avoid these for baseline unless Bob explicitly wants them in scope. | CyberMedica owns its regulated UI; CommandBase/web UI out of enforcement path; TrustReceipt used for AI provenance, AVC optional only if tested. |

## Default Build Direction

Proceed with baseline CyberMedica feature development using the council consensus defaults in `docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md`.

Do not wait on final root bundle verification, certifier roster, production endpoints, or secret-provider selection to build domain models, service contracts, adapter interfaces, deterministic fixtures, contract tests, inactive trust-state UI, or fail-closed behavior.
