# Fixed 0.2.7 publication recovery validation

## Scope and identities

This is publication-tooling repair, not a product rebuild or a new product
version. Every changed path is EXOCHAIN core release tooling, its regression
tests, CI, or owned governance documentation. No adjacent surface, package
payload, dependency lock, product tag, or original artifact is changed.

- Original product source: `666c578f719d1e54fce95d6831a3af92ea80df93`.
- Preserved product tag object: `be47589ec7dbefe821ada35ed0a89dedc9751953`.
- Fixed original producer run: `35257955565`, attempt **1**, not canceled attempt 2.
- A future signed `v0.2.7-recover.N` dispatch identifies the actual reviewed
  recovery controller. It cannot impersonate the original product commit.
- Imported original evidence remains outside source control. The curated
  `RECOVERY-MANIFEST.json` records the exact accepted identities and digests.

## Reproduced failures and repairs

1. The frozen npm 10.9.2 CLI omits verified attestation bundles even after a
   successful signature audit. Real old/new CLI regression tests establish the
   exact Node 24.15.0/npm 11.12.1 publisher contract. Seven original packaging
   runtime pins stay unchanged.
2. Registry visibility previously exhausted approximately 50 seconds after a
   successful upload. The bounded check now performs at most 25 read attempts,
   with 15-second waits, and never repeats an upload. Conflicts and non-absence
   provider errors remain terminal.
3. The new publisher emits Sigstore v0.3 single-certificate provenance, whereas
   the verifier understood only v0.2 certificate-chain representation. Exact
   installed-source execution proved this before upload. The canonical verifier
   now accepts only those two matching representations, retaining all actual
   audit, subject, source, workflow/ref/SHA, SAN and transparency conditions.
4. Recovery consumes only the seven original transport artifacts and forty
   fixed inner files. It verifies original producer/CI/approval evidence,
   original native cryptographic attestations, all 32 public Rust checksums,
   both signed identities, and each package's canonical structure.
5. Existing WASM is acceptance-only. LYNK/SDK and Python may publish only missing
   original bytes. GitHub release recovery accepts exact existing assets or
   uploads missing assets to a draft; it cannot replace conflicting assets.
   Durable bounded receipts preserve unknown mutation outcomes.

## Local evidence on 2026-09-18

Commands were executed in the existing remediation worktree with
`CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`, and dev/test/release debug info set
to zero. No new worktree or alternate full Cargo target was created.

Passed:

- `cargo build --workspace --release --locked`
- `cargo test --workspace --locked`
- `cargo test --workspace --release --locked`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo +nightly fmt --all -- --check`
- `cargo doc --workspace --no-deps --locked`
- `cargo audit` and `cargo deny check`
- `tools/cross-impl-test/compare.sh`: one Rust/Node canonical hash vector and
  two normalized Rust repeatability runs. A separate external TypeScript
  implementation was not configured; no such conformance result is claimed.
- All 64 CI-derived shell guard commands, including normal-release guards.
- Recovery tests: custody 17, import 15, workflow 7, Python workspace stage 4,
  GitHub recovery/client 10, npm recovery 24, plus the Python orchestration and
  strict package/provenance suites.
- Both npm provenance formats and 54 added rejection cases, alongside existing
  canonical verifier tests. Locally generated certificate fixtures are strictly
  structural/identity tests, not cryptographic publication proof.
- Fresh credential-free actual npm CLI tests: the old runtime's real output is
  rejected for the expected missing field; the exact new runtime audits and
  accepts original WASM 0.2.7 with its original source/ref and SRI.
- Two independent real Sigstore checks accepted public foreign-package v0.3
  provenance using the new publisher's exact bundled verifier. This confirms
  real format/cryptographic compatibility, not EXOCHAIN owner or release proof.

Local evidence roots include
`/private/tmp/exochain-027-recovery-validation.UYDXP7`,
`/tmp/exochain-task4a-evidence.pXoHAi`,
`/tmp/exochain-027-task4c-real-check`, and
`/tmp/exochain-027-recovery-inventory.phRMjt`.
Raw provider records, archives, generated test reports and credentials are not
committed. Failed regression attempts are retained separately from passing
results; they were not overwritten or relabeled.

## September 21 hosted credential contract repair

Recovery dry run [35374367647](https://github.com/exochain/exochain/actions/runs/35374367647)
at controller `fd627beb4bd44cac706f9ee03a42e419b5af2b50` passed 41 jobs,
including both genuinely approved environment gates and signed-tag verification.
Import then rejected the run-provided credential before any artifact fetch:
`release recovery import failed: malformed read-only GitHub credential`.
WASM acceptance and all remaining publication jobs were skipped. No successful
artifact-custody or publication result is inferred from those earlier gates.

The importer incorrectly restricted the transport token to letters, digits and
underscores. GitHub's [April 24 token-format notice](https://github.blog/changelog/2026-04-24-notice-about-upcoming-new-format-for-github-app-installation-tokens/)
documents the variable-length `ghs_APPID_JWT` format for Actions-issued tokens.
Its punctuation is incompatible with that restriction. The actual credential
was never extracted or decoded; the failure was reproduced with invented
Bearer-token fixtures.

The correction accepts opaque [RFC 6750 section 2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1)
Bearer transport syntax, without token-prefix, token-content or token-length
assumptions. Quotes, backslashes, whitespace, controls, non-ASCII input and
interior padding remain rejected before any network process or file creation.
Authorization remains on curl's stdin only, restricted to the fixed GitHub
endpoints and absent from public requests and artifact-storage redirects.

All changed paths are **EXOCHAIN core**: `tools/import_release_recovery_027.sh`,
its existing import and workflow regression tests, `.github/workflows/ci.yml`, and this governance
record. No Rust runtime, adjacent surface, product payload, manifest digest,
dependency, published version, signed product tag, or existing maintenance tag
changes. Determinism and the eight constitutional invariants are unchanged;
no authority, consent, approval, signature or custody check is bypassed.

Test and acceptance plan:

1. Reproduce the invalid restriction before changing production code. The new
   valid-punctuation fixtures failed, while injection-rejection fixtures passed.
2. Run all 18 import tests, covering legacy and punctuated opaque strings,
   variable length, malformed padding, injection, credential-free public reads,
   and constant-output contract-check success/failure. These pass locally.
3. Run the recovery, retirement, release shell guards and full workspace gates
   on the integrated-main repair branch with the existing low-disk build cache.
4. Require exact-head hosted CI, including the new credential-contract step.
   That step runs only on trusted pushes or workflow dispatches, not PR events,
   and uses a contents-read-only job token with the real constructor. It makes
   no requests, persists no token, and prints only acceptance/rejection.
   Synthetic local tests are not proof of hosted credential acceptance.
5. Obtain legitimate integration review, then create a new signed maintenance
   tag for the corrected controller. Preserve `v0.2.7-recover.1` and both product
   tags. Do not rerun the unchanged failing controller or republish any bytes.
6. Repeat protected dry acceptance on the new controller, then live recovery
   only after complete success. Read back every registry and release asset;
   complete the independently reviewed 0.2.3 retirement before claiming closure.

Local worktree acceptance completed on September 21: all nine core commands
listed in the September 18 section (including release-mode tests, audit, deny
and cross-implementation comparison), all 64 CI-derived shell guards, seven
recovery/retirement Python suites, and fresh old/new npm CLI contract checks
passed. After the independent review correction, all 18 import tests and all
8 workflow tests passed again. The cross-implementation result covers one
Rust/Node hash vector and two identical normalized Rust test runs; an external
TypeScript implementation was not configured. Existing `block 0.1.6` future-
compatibility and dependency-policy warning output is retained, not described
as zero warnings. Evidence is under `/private/tmp/exochain-027-token-validation.o1aU6q`.
The first core gates recorded base `2a5f59c9222eb309fe1cd3b464eca92b06558101`
with the repair in the worktree; later gates recorded signed repair commit
`e3e042b1c29a6eda8129cc9bc9540181f3c47804`. Rust source, dependencies and Cargo
configuration were identical throughout. This is local worktree validation,
not a claim of exact-head hosted CI or completed publication.

## Review and required live acceptance

Independent reviews covered the import/custody boundary, npm recovery receipts,
strict v0.3 parsing, Python orchestration, root dispatcher and workflow, Python
stage exceptions, and GitHub recovery. Review found and corrected malformed
shell continuations, missing uncertain-write receipts, absent real-client tests,
overconstraint of GitHub's non-authoritative `target_commitish` response, and
placement of Python crypto tests outside the declared hash-locked test lane.
Each correction has a regression test or explicit existing guard.

Local macOS validation does not substitute for the hosted Ubuntu publisher,
pinned Python 3.13.7, Linux coverage, GitHub OIDC, PyPI Trusted Publishing, actual
maintainer reviews, signed maintenance tag, or the two protected environments.
Full exact-head CI and those real approvals remain mandatory. After legitimate
integration, run the read-only recovery dry run before its protected live run.
Read back every provider and all release assets before claiming completion.

At this checkpoint, all 32 Rust versions and original WASM are public; the
remaining two npm packages, Python distributions and GitHub Release are not
claimed complete. Issue 822 retirement remains separately scoped to its
reviewed controller and exact replacement/yank readbacks. No runtime deployment
or executable-native-archive claim is made.
