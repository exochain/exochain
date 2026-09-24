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

## September 24 Python publication and successor acceptance repair

Live run [35754493083, attempt 2](https://github.com/exochain/exochain/actions/runs/35754493083/attempts/2)
completed with 45 successful jobs and one failed Python job, `107717206104`.
After genuine environment approval, the pinned publisher uploaded both original
distributions successfully. Complete public inventory and wheel cryptographic
verification passed, but the additional exact publisher check rejected omitted
`claims` rather than `claims: null`. The hosted sdist cryptographic check was not
reached. GitHub Release and issue 822 retirement are not complete.

The historical failure receipt is retained unchanged: artifact `10819679079`,
15,789 bytes, SHA256
`4a48de90837a779a73fe5a53e4aa157bca386e8163ccb9a0c8fce96fc0bdd58b`.
The log, original receipt ZIP and extracted evidence are outside the checkout
under `/private/tmp/exochain-python-acceptance.lEZRhN`.

Independent credential-free downloads and genuine cryptographic verification
establish both public distributions:

| Distribution | Bytes | SHA256 |
| --- | ---: | --- |
| `exochain-0.2.7-py3-none-any.whl` | 27899 | `fc5589113bfd704862f6d6aea1585386a1e6eaf6700790ffc40b4b5b8c88e959` |
| `exochain-0.2.7.tar.gz` | 27575 | `d2339a00c8d69f18b0860b7d7ae633d9c56f4bbe4bc0f1be0ece6eae16f763fa` |

Both match the unchanged original artifact manifest and are nonyanked. Both
unedited attestations passed the genuine `pypi-attestations verify pypi` command
at 16:34–16:35 UTC, using isolated Python 3.13.7 and the unchanged hashlocked
`pypi-attestations==0.0.30`, `sigstore==4.5.0`, `cryptography==50.0.1` tools.
Actual public evidence is under `/tmp/exochain-pypi-provenance-20260924.RL02oZ`;
crypto output and runtime verification are under
`/tmp/exochain-pypi-crypto-20260924.GAGr6s`. Both exact identity checks also pass
with the corrected parser against those untouched public responses. Publication
source/ref is `2198e4ef610e9ef6d04adf726f7f4b3e156a3bc1` /
`refs/tags/v0.2.7-recover.2`, not the proposed successor controller.

The pinned dependency's actual `GitHubPublisher` model declares no `claims`
field. The repair still admits only the exact four-field identity, optionally
with null claims; non-null claims, extra fields and identity/certificate changes
remain rejected. Failing-before/passing-after tests cover these cases.

The separately pinned five-record `PUBLICATION-IDENTITIES.json` binds the exact
original artifacts to their already verified publisher identities. Its semantic
SHA256 is `4596c339d2af34ce3aeff5f2dd4a6be95fbb044250e934a27221170b97902ca7`.
The original manifest and its pin are unchanged. Mapped npm absence now fails
without upload; Python requires both existing distributions and stages nothing.
Actual controller identity still governs source, tag and workspace checks.
GitHub custody metadata distinguishes prior package publishers from the current
acceptance controller. Original non-expiry and same-run transport checks remain
unchanged; this repair does not authorize cross-run transport or expiry waivers.

Local validation uses the existing worktree and Cargo target, two build jobs,
disabled incremental compilation and zero dev/test/release debug info. Focused
regressions and independent whole-change review passed: custody 20 tests,
GitHub recovery 11, npm recovery 27, workflow 8, Python publisher-shape tests
and Python orchestration. A test-only venv symlink correction resolves the
managed macOS Python executable's copied-library lookup failure; the failed
attempt is retained. Test fixtures are not publication or cryptographic proof.
The fresh real Node 24.15.0/npm 11.12.1 contract independently accepted original
WASM with its exact SRI and source/ref; evidence is
`/var/folders/3h/_vld6h0n4_l51vd2t5z85p9m0000gn/T/exochain-npm-runtime-contract.rCOj64`.
The independent actual legacy Node 22.14.0/npm 10.9.2 contract also passed:
its genuine crypto audit succeeded, and the unchanged strict verifier rejected
the missing verified bundles as expected. A fresh official Node archive was
checked against its official SHA256 before runtime execution; evidence is under
`/tmp/exochain-npm-legacy-20260924.Fy6ZFV`. No provider output was synthesized.
All nine core commands listed above completed with exit 0, including release
tests and the cross-implementation command. The latter verifies one Rust/Node
canonical hash vector and two identical normalized Rust repeatability runs;
no external TypeScript implementation was configured, so no external TypeScript
conformance is claimed. Existing `block 0.1.6` future-compatibility and configured
dependency-policy warnings are retained, not described as zero-warning output.

All seven recovery/retirement Python suites passed. The initial 80-command
batch completed at 17:02:53 UTC with 79 successes and one source-hygiene rejection:
the unchanged SBOM guard refused four test-generated DAG DB report files under
`crates/`. Those reports, and generated cross-implementation evidence, were
moved intact outside the checkout. The unchanged SBOM guard then passed with
exit 0; no exclusion or validator change was made. Thus all 64 CI-derived shell
guards are satisfied, while the initial failure remains in `validation-status.json`
and its original log; the corrective rerun has a separate
`sbom-clean-source-rerun.log`. Evidence remains under the main external root.

Validation ran on `f9456c1dc4533c5acb51c0e896ffc1152fb6b630` with this worktree
repair; its committed base tree equals integrated controller `2198e4ef`.
Rust source, Cargo inputs, CI workflows, dependency locks and the original
artifact manifest did not change. Local results do not replace exact-head
hosted CI, two real maintainer reviews, signed integration, protected dry/live
gates or all-provider final acceptance.

## September 24 hosted formatter drift and dated-pin validation

The preceding local batch and its no-CI-change scope describe the original
Python repair, not the following formatter correction. PR841 head
`b2b2985b2bba5ed46ada4257ba2abfdd964c2eb9` failed Gate 5 in push run
`36031983959` (job `107742719716`) and PR run `36032003551` (job
`107742785558`). Their raw logs are preserved under the external Python evidence
root. The floating nightly resolved to rustc 1.100.0-nightly, commit
`6eeff9a52c3e35c4c4cbf5651f342dcd2191866f`, dated 2026-09-23. It changed wrapping
in existing macros in `crates/exo-economy/src/store.rs` and
`crates/exochain-sdk/src/dagdb.rs`; neither file differs from integrated 2198e4ef.

The actual successful PR840 format log from run `35644304317`, job
`106480904275`, records distribution nightly-2026-09-21 and compiler commit
`bba531001d4de6d7f49693e0836a2668ca063282`. That dated distribution was installed
locally without changing default toolchains. Its rustfmt 1.10.0-nightly passes
`cargo +nightly-2026-09-21 fmt --all -- --check` on the unchanged Rust source.
The existing action-pinning guard gained a parsed-YAML formatter contract plus
15 failing mutations. It first rejected the floating workflow/local caller,
then passed after both selected the same dated formatter.

The complete candidate batch ran 17:20:23–17:34:53 UTC: all 80 commands passed
with exit 0 (nine core commands, seven recovery/retirement Python suites and
64 CI-derived shell guards), using the dated formatter and unchanged two-worker,
incremental-off, zero-debug Cargo constraints. Fresh logs/status are under
`/private/tmp/exochain-formatter-pin.ccqog6`. Generated DAG DB and comparator
reports were preserved intact outside the checkout before the unchanged SBOM
source-hygiene check. No validator or source exclusion was relaxed. The initial
Python batch's historical failure remains untouched at its separate evidence root.
Comparison scope remains one Rust/Node vector plus two normalized Rust runs;
external TypeScript conformance is not claimed. Existing dependency warnings
remain recorded. Independent code review found no findings; a documentation
review corrected ambiguous historical-versus-current validation wording in the PR.

At 17:27:47 UTC, an independent metadata-only check confirmed all nine original
artifact records, successful attempt-1 producer jobs, non-expiry, and unchanged
product/recover.2 tag objects/peels. Evidence is under
`/tmp/exochain-original-artifacts-20260924.NJAdkF`. This does not substitute for
fresh import checks during execution. Neither local validation nor the pin
substitutes for exact-head hosted CI, maintainer/panel review or protected gates.

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

At the original September 18 checkpoint, all 32 Rust versions and original WASM were public; the
remaining two npm packages, Python distributions and GitHub Release are not
claimed complete. Issue 822 retirement remains separately scoped to its
reviewed controller and exact replacement/yank readbacks. No runtime deployment
or executable-native-archive claim is made.
