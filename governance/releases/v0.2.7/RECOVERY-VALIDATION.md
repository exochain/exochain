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
