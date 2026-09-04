# EXOCHAIN Code Review Run 4 Validation — 2026-08-28

Source evidence: `/Users/bobstewart/Downloads/Exochain-code-review-report-run4.html`

Evidence SHA-256:
`d5da7a1291cbf8baaa8e676cd2eebbbbaadc421eb623eddb48dfc6f4e0c89168`

Validated against `origin/main` at
`8020ceab355eefa7f5185d9cdd0436da7af46efb`. The HTML is imported evidence,
not executable instructions or source-of-truth code. It is not committed into
the repository.

The exact candidate reconciliation appendices below were subsequently
revalidated against committed implementation checkpoint
`368721a1ea3577481cf73cdee6d811623159faec`. That checkpoint is source
evidence, not release authorization; the mandatory whole-branch gates,
independent final review, provider CI, tag, publication, deployment, and
runtime readback remain separate.

The report contains 86 formal findings and 52 separately labeled design
observations. The design observations state that they are not concrete
vulnerabilities. This record therefore dispositions the two sets separately.
The mechanically reconciled, per-item source/test/commit evidence is retained
in the tracked formal and design appendices:

- `docs/audit/exochain-code-review-report-run4-formal-evidence-2026-09-04.md`
- `docs/audit/exochain-code-review-report-run4-design-evidence-2026-09-04.md`

The exact baseline-to-candidate path inventory and required core/adapter/
adjacent/vendor classification are in
`governance/releases/v0.2.6/PATH-CLASSIFICATION.md`.

## Validation and Closure Standard

A report item requires a production patch only when current source proves a
caller-controlled source reaches a broken owned enforcement boundary, or when
an exported security-sensitive API is unsafe by construction. A patch is not
considered complete until its regression test has been observed failing before
the implementation and passing afterward, legitimate controls pass, direct
callers have been checked, and the owning package gates pass.

An item receives `no_change` only when current source and focused evidence show
that the premise is false, the alleged path is unreachable, an earlier guard
already blocks the exploit class, the data is public rather than secret, or no
owned attacker-controlled source-to-sink path exists. A report severity is not
carried forward when those conditions are absent.

## Path Classification

| Classification | Scope in this validation |
| --- | --- |
| EXOCHAIN core | Rust governance, identity, legal, proofs, metering, and cryptographic custody code |
| Core runtime adapter | Node, gateway, PDP HTTP, SDK, WASM, persistence, release CI, and external timestamp transport |
| Adjacent surface | `livesafe/`; patched and committed separately, with `public_claims_allowed: false` unchanged |
| Imported evidence | The downloaded HTML; read-only and excluded from commits |
| Third-party/vendor | Cargo/npm dependencies and generated outputs; changed only through owned manifests and locks |

## Formal Finding Dispositions (86/86)

Candidate totals are 33 `patch`, four `adjacent_patch`, and 49 `no_change`. The
table below is the concise disposition index; the formal appendix carries all
86 rows in original report order with per-finding classification, reproduction
semantics, exact owned symbol/runtime, focused regression or source guard, and
immutable patch commit. Its sorted numeric ID-set SHA-256 is
`264fa18b138ce4a2935180336c0a14317f5dc08eca6ea5230db49b9c037aec80`.

| ID | Disposition | Current-source result or patch boundary |
| --- | --- | --- |
| 9679 | patch | The default build refuses the pedagogical SNARK, but the published opt-in verifier accepts forgeable public hash chains. Keep the types and make legacy verification refuse even when the feature is enabled. |
| 9616 | no_change | Conformance root substitution requires both an explicit feature and environment switch; malformed constants are rejected before trust registration. Preserve the fail-closed tests. |
| 9671 | patch | The node applies bearer middleware, but the exported bare PDP router contains mutation routes. Make mutation routing require an authorizer by construction. |
| 9547 | no_change | Leaf counts are serialized through a fixed 16-byte representation; 32-bit and 64-bit callers produce the same canonical bytes. |
| 9548 | no_change | The compared Merkle hashes are public integrity values, not secret authentication material. |
| 9552 | no_change | The continuation-packet module declares no runtime route or persistence caller; current callers are contract tests. |
| 9556 | no_change | The lexical path predicate performs no file operation and is used only by benchmark tests. |
| 9560 | patch | CLI-selected graph roots reach recursive file reads that follow outbound and cyclic symlinks without depth, count, or byte budgets. |
| 9564 | no_change | The parser is an adapter contract with no owned runtime ingress; repository callers are tests. |
| 9566 | no_change | Quote hashes and quotes are public DTO material; no unknown secret can be recovered through equality timing. |
| 9567 | patch | Basis-point helpers saturate the multiplication before division and return incorrect extreme-value allocations. Use exact quotient/remainder arithmetic across sibling helpers. |
| 9572 | no_change | The synthetic testing signature is an unkeyed hash over public fields and is accepted only for simulated testing attestations. |
| 9575 | patch | Exported `Credential` serialization emitted API keys and bearer tokens in plaintext even though `Debug` was redacted. Preserve public DID-signature serialization compatibility, but make both secret variants fail closed with one fixed non-reflective error. |
| 9581 | no_change | Audit sequence increment already uses `checked_add` and fails closed on exhaustion. |
| 9582 | no_change | The registry lock is cloned inside `spawn_blocking`; no asynchronous suspension occurs while the standard lock is held. |
| 9586 | no_change | The authenticated vote transaction needs the exclusive table lock to serialize the global audit hash chain; all waits under the lock are database operations in the same transaction. |
| 9585 | no_change | The cited vote handler is not registered by the shipped gateway, and enforcement uses stored metadata rather than request `affected_dids`. |
| 9591 | no_change | The only owned runtime caller supplies public model/DID identifiers and returns them to the same caller; no private signing key enters this registry. |
| 9593 | no_change | The legacy quorum branch is intentionally fail-closed and cannot produce the reported unauthorized success. |
| 9594 | patch | Rotating one DID verification method clears unrelated active public keys. Preserve other keys and replace only the selected method. |
| 9598 | patch | Shamir coefficient buffers retain secret-derived bytes after drop. Use zeroizing carriers for coefficients and shares. |
| 9603 | no_change | The certificate hash is public integrity material; this duplicates 9548. |
| 9605 | patch | The DGCL state machine accepts repeated votes from one DID. Enforce voter uniqueness at the transaction boundary. |
| 9607 | patch | Safe-harbor verification lacks a complete allowed-state transition guard. Enforce the transition graph in the state type. |
| 9611 | no_change | Every owned envelope deserializer is behind the shared 1 MiB WASM input cap and ciphertext validation. |
| 9612 | no_change | Both the repository wrapper and pinned `x25519-dalek` secret/shared-secret types zeroize on drop. |
| 9620 | no_change | Production authorization compares fixed-size verifier bytes and wipes the candidate; derived equality is unused. |
| 9624 | patch | Non-Unix secret-file creation does not establish an owner-only ACL. Introduce one fail-closed private-file boundary for node identity, PDP, and root ceremony files. |
| 9629 | no_change | Production MCP mutexes handle poison explicitly and their collections are bounded. |
| 9631 | patch | MCP authorization returns early on unequal token lengths. Normalize comparison work to fixed-size digests while preserving HTTP outcomes. |
| 9632 | no_change | Actor roles are contained by the 64 KiB MCP message limit before parsing. |
| 9633 | no_change | Consent records are contained by the 64 KiB MCP message limit before parsing. |
| 9634 | no_change | Payload hex is contained by the 64 KiB MCP message limit and cannot decode beyond that envelope. |
| 9635 | no_change | The serialized message-ID input contains only infallible strings/bytes; attacker input cannot reach the static fallback. |
| 9637 | patch | The alleged live-memory escalation is not established, but transient PDP key buffers are avoidable and the same private-file boundary fixes the concrete non-Unix ACL exposure. |
| 9644 | patch | No current logging sink formats the private ceremony DTO, but redacted `Debug`, zeroizing secret fields, and the shared private-file boundary remove the exported footgun and ACL overlap. |
| 9642 | no_change | Framework and gateway body limits, fixed roster size, signature checks, and duplicate rejection bound the root portal. |
| 9650 | no_change | The shared SQLite store mutex serializes the worker/runtime creation path; the claimed concurrent thread fan-out is absent. |
| 9648 | patch | Database row decoding uses panicking `Row::get`; replace with typed `try_get` failures even though schema constraints defeat the claimed remote crash. |
| 9654 | no_change | Signal hashes are limited to the finite claim-type enum and the route inherits the 1 MiB body cap. |
| 9655 | patch | `VerifyOtpResponse` and `IdentitySession` derived `Debug` over bearer session tokens. Replace both with explicit redacted `Debug` implementations and keep authenticated serialization behavior unchanged. |
| 9657 | no_change | The OTP is fixed at six public-format digits, attempts are bounded, and no production HTTP caller was found. |
| 9661 | patch | `int_ln_milli` shifts attacker-influenced `u64` values before widening and can overflow. Compute intermediates in `u128` with checked conversion. |
| 9662 | no_change | The deterministic service key is default-off, feature-scoped, and cannot replace the subject signature/session consent checks. |
| 9666 | no_change | The secret type is private, zeroizing, Debug-redacted, and non-serializable; OTP comparison does not compare HMAC material. |
| 9674 | patch | PDP CLI verification and inspection read third-party evidence packs without a pre-allocation file-size bound. |
| 9675 | patch | The public PDP service API returns a plain copy of its long-lived signing secret. Remove raw-key extraction. |
| 9682 | no_change | Zero field size is rejected before modulo and the error is propagated; the existing generation regression covers the reported panic. |
| 9688 | patch | Public root DKG secret artifacts derive `Debug` over serialized secret byte vectors. Redact `Debug` without changing the patch-release public `Vec` fields, direct-move/destructure behavior, `Clone`, function signatures, or wire layout; retain explicit zeroization and zeroizing internal transient buffers without claiming automatic drop-time wiping for legacy carriers. |
| 9694 | no_change | ECDH is HKDF input keying material, caller context is a valid non-secret salt, fixed info supplies protocol separation, and swapping would break existing ciphertexts. |
| 9695 | patch | Public root signing nonces derive `Debug` over secret nonce bytes. |
| 9696 | patch | Root signing nonces drop as ordinary vectors without zeroization. |
| 9698 | patch | Meter aggregation can wrap or panic and produce a lower usage total. |
| 9699 | patch | Reconciliation sums can wrap or panic before comparison. |
| 9700 | patch | Store byte totals use unchecked `sum()` over persisted metadata. |
| 9702 | patch | SDK path and query components interpolate caller-controlled identifiers without percent encoding. |
| 9703 | patch | NUL-delimited decision identity input is ambiguous across title/description boundaries. |
| 9704 | patch | Rust SDK decision IDs truncate BLAKE3 to 64 bits. Use a versioned canonical-CBOR frame and the full digest, aligned with the TypeScript SDK. |
| 9710 | no_change | All owned WASM vector parsing first enforces the shared 1 MiB raw-input limit and then an item-count limit. |
| 9711 | no_change | Registry JSON first enforces the shared 1 MiB raw-input limit and then a 4096-relationship aggregate limit. |
| 9713 | no_change | Successful deserialization moves the same String allocation immediately into `Zeroizing`; no abandoned success-path copy or output/log sink exists. |
| 9715 | patch | WASM Shamir reconstruction creates avoidable Rust plaintext vector, hex-string, JSON, and bridge-string copies. Zeroize all Rust-owned secret copies after the required JS return is formed. |
| 9716 | no_change | `FromUtf8Error` reports the invalid byte position/length, not decrypted plaintext. |
| 9719 | adjacent_patch | LiveSafe expiration addition can overflow on caller-provided creation time. |
| 9721 | adjacent_patch | LiveSafe feedback-count aggregation can overflow `u32`. |
| 9720 | adjacent_patch | LiveSafe count conversion truncates through `as u32`. |
| 9723 | adjacent_patch | LiveSafe reporter upvotes increment without an exhaustion policy. |
| 9538 | no_change | Currency-without-cost is signed incomplete usage metadata and no owned authorization consumer treats it as a priced operation; changing it is a compatibility/product decision, not a security fix. |
| 9573 | no_change | This duplicates the public simulated-attestation hash comparison in 9548/9572. |
| 9583 | no_change | Positive-hour validation precedes conversion and timestamp arithmetic is checked. |
| 9584 | no_change | Canonical hashing discards CBOR internals from the external error response; GraphQL is default-off. |
| 9587 | no_change | SQL details remain internal and the caller receives a fixed response; the cited vote route is not shipped. |
| 9590 | no_change | Root-at-depth-zero semantics are consistent; tests accept exactly 64 nested edges and reject 65. |
| 9606 | no_change | Exact 50 percent correctly fails the documented strict-majority requirement. |
| 9614 | no_change | The fixed X25519 scalar is public low-order-point validation material; actual ECDH separately rejects an all-zero shared secret. |
| 9615 | no_change | Every wrong token performs both checks; a successful response reveals only the credential already presented. |
| 9628 | no_change | Method reflection is 64 KiB bounded, JSON escaped, bearer-authenticated or local, and not logged. |
| 9630 | no_change | Adjudication parsing details are logged internally; the response is a fixed enforcement error. |
| 9638 | patch | A stale fixed PDP temporary file blocks every later save. Recover only the owned regular temporary and retain exclusive creation, synchronization, and fail-closed persistence. |
| 9652 | no_change | The mapper is brittle but receives only fixed producer strings and does not expose arbitrary store details. |
| 9669 | patch | PDP 500 responses serialize arbitrary persistence/serialization/rollback details. Log internally and return a fixed internal error while preserving 4xx semantics. |
| 9672 | patch | The shipped node has bearer and 1 MiB outer limits, but the exported PDP router lacks a local body cap and semantic delegation-scope bound. Add both at the compositional boundary. |
| 9677 | patch | Internally signed snapshots have no remote upload path, but startup performs an unbounded local-state read. Bound the persisted snapshot before allocation and parsing. |
| 9680 | no_change | Proof components are public, not secrets; the approved 9679 refusal removes the unsafe verifier regardless. |
| 9712 | no_change | Capacity is derived only after the shared raw-input and 1024-item limits; this duplicates 9710. |
| 9718 | patch | Two primitive WASM exports decode an arbitrary-length claim nonce outside the JSON bridge. Enforce one shared encoded and decoded limit before allocation. |

## Design Observations (52/52)

Candidate totals are ten `patch` and 42 `no_change`. The design appendix carries
all 52 rows in original report order with per-observation classification,
reproduction semantics, exact owned symbol/runtime, focused regression or
source guard, and immutable patch commit. Its sorted numeric ID-set SHA-256 is
`4735fd41ff8e84f85a5502a83635f0b00673a9f754ea3098039199e41b3637f6`.

These ten observations overlap a concrete boundary and are included in the
patch tasks:

| ID | Included boundary |
| --- | --- |
| 9540 | Bound external JSON and RFC 3161 timestamp-authority responses before collection. |
| 9558 | Bound CLI manifest reads before JSON parsing. |
| 9559 | Make exported DAG DB diagnostic stage-latency arithmetic saturating before aggregation. |
| 9592 | Bound coordination detection input/work/output and avoid all-pairs allocation exhaustion. |
| 9599 | Store Shamir share data in zeroizing memory. |
| 9602 | Remove the public raw vault-key extraction API. |
| 9608 | Prevent direct construction/mutation from bypassing DGCL state transitions. |
| 9625 | Replace identity-key existence check plus read with one race-aware open path. |
| 9643 | Map root-portal internal errors to fixed external responses while retaining internal diagnostics. |
| 9692 | Reviewed with the root-secret task; sealed salt/nonce/ciphertext remain public transport artifacts. Legacy public DKG plaintext carriers are `Debug`-redacted and explicitly zeroizable while preserving caller-owned move semantics; signing nonces and private CLI share/passphrase carriers remain zeroizing-on-drop. |

The remaining 42 observations have no current concrete vulnerability and need
no production source change:

`9639, 9653, 9539, 9542, 9544, 9550, 9553, 9554, 9589, 9555,
9565, 9569, 9570, 9571, 9577, 9578, 9596, 9601, 9609, 9613,
9617, 9619, 9621, 9622, 9623, 9626, 9636, 9641, 9645, 9647,
9651, 9668, 9670, 9673, 9676, 9678, 9681, 9686, 9701, 9705,
9707, 9708`.

Their common dispositions are: bounded by an existing ingress limit; public
signature/hash/ciphertext material rather than a secret; local/default-off
tooling without an attacker-controlled sink; a standard lock used without an
asynchronous suspension; or an API-design caution without a current caller.

## Additional Release-Boundary Findings

The 0.2.6 release audit found an owned release blocker not stated in the HTML:
the release workflow can test the dispatch SHA and later publish a version tag
without proving that the signed tag commit, dispatch SHA, workspace version,
and published source are identical. Committed checkpoint `fc86b0b1` makes this
binding fail closed and extends the workflow source guards; final acceptance
still requires the complete test plan on the reviewed evidence commit and
exact-head provider CI.

The release-source review also found mutable third-party GitHub Action tags,
insufficiently isolated publication helper capture, and an SBOM reviewed-corpus
digest that no longer described the post-remediation Cargo dependency graph.
The branch pins the affected actions to immutable commits, binds every release
side effect to immutable checked source and tag identity, and updates the SBOM
digest only after a deterministic semantic graph comparison.

Later independent review found and committed additional owned hardening outside
the imported report's 86 formal IDs: compatibility-preserving gateway secret
serialization (`47eb4e2e`), bounded WASM Shamir work (`33964847`), bounded
messaging plaintext (`dbabe80e`), patch-compatible DKG custody (`e8d04a94` and
`65527ba7`), same-origin Python bearer transport (`bcaa6c1f`), exact-request
LYNK receipt attestations (`f3845873`), and sealed package provenance and
publication (`fc86b0b1`). Commit `2e286e21` additionally requires exact npm
owner authority immediately before publication; corrective commit `e73dcf53`
restricts the registry-proven 404 first-publication exception to the exact
`@exochain/sdk` package and denies it to the two established npm packages.
Test-only commits `760613e6` and `3b98fd11` extend FORMAL-9688 and
design-9692 coverage across every patch-compatible DKG secret carrier and keep
the serialized JSON/CBOR fixtures in zeroizing buffers. Release-guard commits
`96318413` and `a3d1e2f3` make the WASM npm provenance guard follow the actual
isolated publisher, require an empty-environment launch with the npm token and
pinned Node/npm entrypoints, and bind the exact registry/provenance flags to
the publish call. These commits change tests rather than report-cited
production boundaries.

Repository-truth commits `a6058966` and `368721a1` record the observed 507
tracked Rust source files, 6,619 listed workspace tests, 167 generated WASM
exports, and 183 passing bridge checks. These documentation corrections do not
alter either imported-report inventory.
These controls are mapped to overlapping report rows where applicable and
otherwise remain separately identified release-boundary findings. Their
focused checks are recorded in the appendices and test plan; they do not turn
the candidate into a completed or authorized release.

The adjacent LiveSafe dependency pass found three moderate advisories in the
server's transitive `qs` parser (`GHSA-x5fp-wj9c-mxmx` and
`GHSA-4mjr-xmp4-gh2g`; one advisory affects more than one vulnerable range).
The server-local lock now resolves the Express/body-parser graph to
`qs@6.16.0`; focused parser controls, a real Express compatibility smoke test,
and the full adjacent test suite preserve expected behavior.

An independent pre-evidence review found that percent-encoding alone did not
contain exact dot segments because the URL parser normalized both literal and
encoded `.`/`..` before transport. This is a sibling case within formal finding
9702, not a new report ID. Commit `0d9e1c69` added strict Rust/TypeScript lookup
validation; compatibility review then found that its Rust return-type and error
enum changes were not permissible in a patch release. Corrective commit
`fc794d20` restores the shipped Rust builder signatures, preserves canonical
lowercase 64-hex paths byte-for-byte, and replaces every invalid Rust path ID
with one fixed bounded non-hex segment for gateway rejection. It also prevents
TypeScript DID diagnostics from echoing unbounded caller input. The exact
regression evidence is recorded in the formal appendix.

At source checkpoint `368721a1ea3577481cf73cdee6d811623159faec`, locked
metadata and build, the three DKG patch-compatibility tests, debug and release
workspace tests, all-target Clippy, nightly format, rustdoc with warnings
denied, `cargo audit` under the repository's single allowed yanked-`spin`
warning, `cargo deny`, `cargo machete`, and the Rust/Node cross-implementation
vector plus repeated Rust determinism checks all passed. The feature matrix
also passed for all six node `unaudited-*` variants, gateway GraphQL,
pedagogical proofs, and `conformance-test-root`. `EXO_TS_ROOT` was unset, so no
TypeScript conformance-root claim is made.

A newly created `exochain_026_final_20260904b` database on a disposable
PostgreSQL 14.20 loopback cluster at port 55436 passed all 14 gateway
migrations, the exact 1/1 DAG DB migration-upgrade regression, the ignored
malformed-row probe with exactly 1 passed/0 failed/0 ignored, all 469/469
gateway `production-db` tests, and the workspace integration surface with
`exochain-gateway/production-db` across 75 result blocks with none failed. This
is isolated local test evidence, not deployment or runtime readback.

Exact-head SDK and supply-chain verification also passed: the Rust SDK ran 118
unit tests and 62 doctests; the Rust WASM crate ran 117 tests with one
intentional ignored test; the sealed-crate Python suite passed 12/12; its
protocol oracle matched Cargo 1.97.1; and the release-archive suite passed 4/4.
Crates.io dry packaging covered exactly 32 packages at version 0.2.6. The
registry, publish-boundary, workflow-ref-binding, npm-attestation, SDK npm,
Python-package, and SDK/Python lifecycle controls all passed. A malicious
Python fixture was expected to be rejected, and its enclosing guard passed.
Exact `cargo-cyclonedx 0.5.9` generated exactly 32 CycloneDX 1.5 JSON SBOMs;
both the SBOM boundary and validator guards passed. Those SBOMs are generated
evidence and were deleted before the evidence commit. None of these dry
checks authorizes or performs publication.

The adjacent LiveSafe source at that same checkpoint passed
`npm --prefix livesafe run quality` (four zero-vulnerability dependency
audits, context lint/typecheck, 157 Vitest files and 555 tests, Rust format and
Clippy, and 129 Rust tests), `npm --prefix livesafe run build` (client 1,695
modules and responder 84 modules, with a non-fatal 903.82 kB chunk warning),
and `docker build -f livesafe/Dockerfile livesafe`. The image manifest was
`sha256:22447dbd6e9ded27edf84fd692cd02cdc4b007fc479089f203edaf23107095ab`.

Codex Security scan `32dbfc47-dbb7-4488-83fd-a02dd5925458` was sealed complete
with zero findings over `8020ceab355eefa7f5185d9cdd0436da7af46efb..fd526fdbc47be8b5cedb3c33dea2ffb36d78f3fa`
after reviewing 181/181 canonical items and 315/315 paths. It is explicitly
preliminary because later DKG-test, repository-truth, and release-guard commits
are outside that range. At source checkpoint `368721a1`, exact-head tarpaulin
passed at 90.86% workspace coverage (47,746/52,547), 83.00% ZeroDentity
coverage (1,870/2,253), 100% `exo-root` coverage (1,146/1,146, including
325/325 DKG lines), and 100% root-genesis portal coverage (65/65). All 62 shell
guards discovered from `.github/workflows/ci.yml` ran serially and exited zero.
Expected negative diagnostics from malicious npm and Python verifier fixtures
remained contained inside their guards, which passed. A fresh security scan
of the committed evidence head is required for local completion and is reported
separately because this source-checkpoint record necessarily predates that
commit.

## Completion Evidence Required

1. Every `patch` and `adjacent_patch` row has recorded RED and GREEN evidence.
2. Every `no_change` row is rechecked against the final branch so a later task
   did not remove its controlling guard.
3. Core, runtime-adapter, LiveSafe, and release/governance changes remain in
   separately reviewable commits.
4. The full Rust workspace, security/audit gates, cross-implementation checks,
   release packaging guards, SDK/WASM/Python checks, and LiveSafe `quality`
   gate pass on the final commit.
5. Repository versions and exact internal pins align to `0.2.6`; LiveSafe stays
   on its own versions and keeps `public_claims_allowed: false`.
6. This branch makes no claim that 0.2.6 is tagged, published, deployed, or
   runtime-verified. Those are separate release operations.
