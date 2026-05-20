# Codex Security Findings Validation - 2026-05-20

Source evidence: `/Users/bobstewart/Downloads/codex-security-findings-2026-05-20T03-29-45.288Z.csv`

Validated against `origin/main` at `63286e72f4241982caed74c711f416ab8cf9055e`.
The CSV contains 64 findings. Each row was treated as an untrusted hypothesis,
classified by owned path, and checked against current main before any further
remediation decision.

## Validation Rubric

- The affected path is owned EXOCHAIN code, a core runtime adapter, or an
  adjacent surface with an explicit boundary.
- The claimed attacker input still reaches the alleged sink on current main.
- A merged remediation or current guard blocks the exploit class at the owned
  enforcement boundary.
- Focused tests or source guards exercise the blocking behavior.
- Remaining open PRs are not treated as source of truth when current main has
  superseding fixes.

## Closure Summary

No new runtime code change was required in this pass. The 64 findings in the
CSV are either already remediated on current main or suppressed by current
source guards/tests. The high and medium rows were previously landed through
isolated remediation PRs; low and informational rows were rechecked against the
current tree.

Rows 1-64 remain suitable inputs for future scanner regression checks, but the
downloaded CSV itself is imported evidence and must not be committed as source.

## Validation Commands

The following focused checks were run during this closure pass or the directly
preceding remediation cycle:

```bash
node --test command-base/app/lib/bootstrap-schema.test.js
node --test command-base/app/schema-bootstrap.routes.test.js
bash tools/test_github_issue_workflow_boundaries.sh
bash tools/test_agent_prompt_boundaries.sh
bash tools/test_syntaxis_workflow_input_boundary.sh
bash tools/test_agent_workflow_bounds.sh
bash tools/test_gap_syntaxis_yaml_parse.sh
bash tools/test_gap_stub_ci_guard.sh
bash tools/test_security_critical_dependencies_pinned.sh
bash tools/test_github_actions_pinned.sh
cargo test -p exo-legal disclosure -- --nocapture
cargo test -p exo-node delete_identity_rejects_far_future_erasure_timestamp -- --nocapture
cargo test -p exo-node save_claim_rejects_backdated_timestamp_before_latest_dag_node -- --nocapture
cargo test -p exo-node erase_did_rejects_timestamp_not_after_latest_dag_node -- --nocapture
cargo test -p exo-node erase_did_rejects_timestamp_beyond_validation_clock_tolerance -- --nocapture
cargo test -p exo-node attestation_write_path_uses_trusted_node_time_for_issued_artifacts -- --nocapture
cargo test -p exo-messaging compose -- --nocapture
cargo test -p exo-consent amendment -- --nocapture
cargo test -p exo-consent contract_hash -- --nocapture
npm --prefix demo/apps/vitallock run test:security
cargo test -p exochain-wasm messaging -- --nocapture
cargo test -p exo-api asn -- --nocapture
cargo test -p exo-node save_claim_advances_logical_time_for_same_millisecond_writes -- --nocapture
cargo test -p exo-node next_claim_hash_matches_saved_same_millisecond_dag_node -- --nocapture
cargo test -p exo-node save_claim_chains_dag_nodes_to_previous_node -- --nocapture
cargo test -p exo-gateway csp -- --nocapture
cargo test -p exo-gateway quorum -- --nocapture
cargo test -p exo-gateway vote -- --nocapture
cargo test -p exo-node otp -- --nocapture
cargo test -p exo-node future -- --nocapture
cargo test -p exo-node --features unaudited-zerodentity-first-touch-onboarding submit_claim_uses_node_hlc_for_otp_dispatch_time -- --nocapture
cargo test -p exo-node dag_node_hash -- --nocapture
npm --prefix exoforge test
npm --prefix demo/services/vitallock-api exec -- vitest run src/index.test.js
npm --prefix demo/services/crosschecked-api exec -- vitest run src/index.test.js
npm --prefix demo/services/livesafe-api exec -- vitest run src/index.test.js
npm --prefix demo/web exec -- vitest run src/vite-config.test.js
npm --prefix web test -- --run src/lib/auth.test.tsx
```

## Closure Table

| Row | Finding | Classification | Current-main disposition |
| --- | --- | --- | --- |
| 1 | Schema enables ssh_host command injection path | Adjacent surface, CommandBase | Remediated by `#654`; route and bootstrap tests reject unsafe `ssh_host` before shell execution. |
| 2 | Untrusted ExoForge issues can drive unapproved code changes | Adjacent workflow surface | Remediated by `#591` and guarded by issue workflow, prompt-boundary, and loop-bound checks. |
| 3 | Default gateway rate limits no longer reset | Core runtime adapter | Remediated by `#655`; gateway uses trusted database time for runtime rate-limit windows. |
| 4 | MCP Merkle verifier does not actually bind leaf count | Core runtime adapter | Remediated by `#648`; MCP ledger proofs bind Merkle roots to leaf count. |
| 5 | Consent access logs can be evicted by flooding checks | EXOCHAIN core | Remediated by `#649`; access log rollover is tamper-evident instead of silent eviction. |
| 6 | Contact IP rate limit trusts spoofable forwarded headers | Adjacent production site | Remediated by `#656`; public contact limits ignore spoofable forwarded headers. |
| 7 | Syntaxis deployment fabricates BCTS gate evidence | Core tooling/runtime adapter | Remediated by `#650`; deployment requires trusted BCTS gate evidence. |
| 8 | Unauthenticated metrics leaks gateway operational counts | Core runtime adapter | Remediated by `#593`; gateway metrics no longer expose operational counts without an authenticated boundary. |
| 9 | MCP audit log exhaustion causes tool-call denial of service | Core runtime adapter | Remediated by `#594`; MCP audit retention is bounded without capacity denial. |
| 10 | Deterministic Shamir entropy can collapse threshold | EXOCHAIN core | Remediated by `#595`; Shamir coefficients are bound to caller-provided secret entropy. |
| 11 | STARK verifier trusts prover-embedded constraints | EXOCHAIN core | Remediated by `#596`; STARK verification requires trusted verifier constraints. |
| 12 | Deterministic default HLC weakens gateway rate limiting | Core runtime adapter | Remediated by `#597` and `#655`; deterministic HLC remains core-only while gateway runtime rate limits use trusted time. |
| 13 | Audit hash cap can persist unaudited votes | Core runtime adapter | Remediated by `#605`; oversized vote/audit payloads fail before unaudited persistence. |
| 14 | Max-depth delegation squatting can block valid grants | EXOCHAIN core | Remediated by `#599`; delegation depth is bound to the selected parent chain. |
| 15 | Signed revocation trusts attacker-supplied public keys | EXOCHAIN core | Remediated by `#600`; revocations verify against the stored delegator key. |
| 16 | MCP Merkle verifier accepts unbounded target indexes | Core runtime adapter | Remediated by `#601`; target indexes are bounded by the proof leaf set. |
| 17 | Signed delegation depth is mutated during chain lookup | EXOCHAIN core | Remediated by `#602`; signed delegation depths are preserved during lookup. |
| 18 | Death verification timestamps are caller-forgeable | EXOCHAIN core | Remediated by `#603`; death-trigger timestamps are signature-bound. |
| 19 | Caller-controlled auth time permits replayed credentials | Core runtime adapter | Remediated by `#604`; route authentication uses trusted observation time. |
| 20 | Oversized vote timestamps bypass audit logging | Core runtime adapter | Remediated by `#605`; unauditable vote timestamps are rejected. |
| 21 | MCP legal/proof attestations trust caller metadata | Core runtime adapter | Remediated by `#606`; MCP evidence metadata is not promoted as trusted attestation. |
| 22 | TypeScript SDK accepts malformed public-key hex | SDK adapter | Remediated by `#607`; public-key hex decoding is canonical. |
| 23 | Identity ceremony accepts forged proofs | EXOCHAIN core | Remediated by `#582`; identity ceremony proofs are bound to active DID material. |
| 24 | ExoForge health check reports failed TNCs as healthy | Adjacent CommandBase | Remediated by `#608`; failed TNC verdicts are reported as unhealthy. |
| 25 | CQI cycle can falsely complete ExoForge queue items | Adjacent CommandBase | Remediated by `#645`; CQI verification fails closed and does not broadly complete unrelated items. |
| 26 | Hybrid DID verification trusts duplicate raw keys | EXOCHAIN core | Remediated by `#609`; hybrid DID keys are bound to multibase material. |
| 27 | Challenge hold suppresses final kernel denials | EXOCHAIN core | Remediated by `#610`; final denials are preserved through challenge holds. |
| 28 | Attestations trust attacker-supplied public keys | Adjacent tooling adapter | Remediated by `#587`; sybil clearance uses trusted registry keys. |
| 29 | Attestation is not bound to findings payload | EXOCHAIN core | Remediated by `#611` and additionally hardened by `#657`; governance attestations bind payload and signer context. |
| 30 | Emergency per-actor cap can be bypassed | EXOCHAIN core | Remediated by `#612`; emergency actor caps are enforced across the creation boundary. |
| 31 | Governance approvals and snapshots are forgeable | Adjacent audit API | Remediated by `#646`; approvals and snapshots require signed governance evidence. |
| 32 | Unbounded 0dentity alert scan can exhaust resources | Core runtime adapter | Remediated by `#651`; alert scan is bounded. |
| 33 | Scalar-filtered recusal lookup can be shadowed | Core runtime adapter | Remediated by `#613`; recusal conflict candidates are payload-bound. |
| 34 | Single-validator quorum sentinel suppresses alerts | Core runtime adapter | Remediated by `#614`; node quorum health alerts on single-validator sentinel state. |
| 35 | Public internal login grants intranet session | Adjacent site | Remediated by `#647`; development sessions are signed and gated. |
| 36 | Unauthenticated mock login grants intranet admin sessions | Adjacent site | Remediated by `#647`; mock login no longer grants unauthenticated admin sessions. |
| 37 | Unbounded consent access log can exhaust memory | EXOCHAIN core | Remediated by `#649`; consent access logging is bounded with tamper-evident archival. |
| 38 | Invalid passport DIDs are logged unsanitized | Core runtime adapter | Remediated by `#616`; invalid passport DID logs are redacted. |
| 39 | Deterministic 0dentity alert scan cap hides later DIDs | Core runtime adapter | Remediated by `#651`; scan ordering and cap are deterministic and bounded. |
| 40 | Unversioned X25519 KDF change breaks old messages | EXOCHAIN core | Remediated by `#618`; encrypted envelopes carry KDF versioning. |
| 41 | No-consensus deliberations get high confidence | EXOCHAIN core | Remediated by `#619`; confidence is lowered when no consensus is reached. |
| 42 | Disclosure verifier key is caller-supplied | EXOCHAIN core | Remediated by `#620`; disclosure verification requires trusted verifier registry keys. |
| 43 | Signed erasure timestamp can poison the 0dentity DAG | Core runtime adapter | Remediated by `#621`; erasure timestamps reject zero, far-future, and non-monotonic DAG positions. |
| 44 | Caller-supplied attestation time is trusted | Core runtime adapter | Remediated by `#622`; issued artifacts use trusted node time. |
| 45 | ComposeMetadata validation can be bypassed | EXOCHAIN core | Remediated by `#623`; compose metadata is revalidated on the send path. |
| 46 | Amendment hash does not bind parent contract | EXOCHAIN core | Remediated by `#624`; amendment hashes include the parent contract id. |
| 47 | Passphrase hash exposed as Ed25519 signing secret | Adjacent VitalLock/WASM adapter | Remediated by `#625`; derived signing seeds are no longer exposed and raw WASM signing fails closed. |
| 48 | Cargo-deny wildcard dependency ban disabled globally | CI/supply chain | Remediated by `#626`; wildcard dependencies are denied except explicit path allowances. |
| 49 | ASN diversity check ignores per-ASN peer cap | EXOCHAIN core API | Remediated by `#627`; ASN peer caps are enforced during diversity checks. |
| 50 | Strict DAG timestamp check enables same-ms write DoS | Core runtime adapter | Remediated by `#652`; same-millisecond writes advance the logical clock and preserve hash binding. |
| 51 | Dashboard CSP hashes do not match inline assets | Core gateway/node UI | Remediated by `#628`; dashboard CSP hashes match current inline assets. |
| 52 | Quorum count can deadlock the DB pool during voting | Core runtime adapter | Remediated by `#629`; quorum counts run inside the active voting transaction. |
| 53 | Pinned Rust toolchain action loses channel selection | CI/supply chain | Remediated by `#630`; pinned toolchain actions explicitly select the channel. |
| 54 | Client timestamp extends 0dentity OTP validity | Core runtime adapter | Remediated by `#631`; OTP issuance uses node HLC time. |
| 55 | Signed claim DAG nodes can be invalid and unlinked | Core runtime adapter | Remediated by `#632`; saved claims are bound to signed DAG nodes. |
| 56 | Hard-coded ExoForge report timestamps | Adjacent ExoForge | Remediated by `#633`; reports emit fresh timestamps. |
| 57 | Death verification trusts client-supplied trustees | Adjacent VitalLock API | Remediated by `#634`; trustees are derived from accepted PACE keys. |
| 58 | GAP stub CI grep misses TSX files and some stub text | CI/source guard | Remediated by `#635`; stub guard scans TSX and broader marker patterns. |
| 59 | Unauthenticated API can forge CrossChecked clearance | Adjacent CrossChecked API | Remediated by `#636`; clearance actions require authenticated actor tokens and trusted records. |
| 60 | Unauthenticated LiveSafe API exposes medical and emergency data | Adjacent LiveSafe API | Remediated by `#637`; medical and emergency data access requires authenticated ownership/responder roles. |
| 61 | Demo Vite proxy now points at unmatched API port | Adjacent demo config | Remediated by `#638`; demo proxy targets the gateway API port. |
| 62 | Dev bypass can crash on malformed onboarding storage | Adjacent web/dev-only auth | Remediated by `#639`; malformed local onboarding storage is handled safely. |
| 63 | Bootstrap creates incompatible clean-install schemas | Adjacent CommandBase | Remediated by `#640`; clean and stale bootstraps include every route-required column. |
| 64 | Invalid YAML alias breaks council review protocol | Adjacent GAP protocol | Remediated by `#641`; YAML parses and alias-token source guard passes. |

## Open PR Housekeeping

Older remediation PRs `#565`, `#566`, `#567`, `#568`, `#569`, and `#574` through
`#586` were still open and conflicting after later remediation commits landed.
They were closed as superseded after current-main verification confirmed their
security effects are represented by later merged PRs. They must not be merged
into current main from their stale branch state.
