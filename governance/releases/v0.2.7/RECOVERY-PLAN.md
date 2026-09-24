# EXOCHAIN 0.2.7 recovery implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Complete the original 0.2.7 publication with verified original bytes and
an honestly identified, reviewed recovery controller.

**Architecture:** Reuse canonical source, tag, package and registry guards.
Separate the maintenance controller's identity from the fixed product artifact
identity. Keep recovery in release.yml so the configured PyPI workflow identity
does not change.

**Tech Stack:** GitHub Actions, Bash, Python standard library, Node/npm, existing
Sigstore/npm and PEP 740 verification tools.

**Spec:** `governance/releases/v0.2.7/RECOVERY-DESIGN.md`.

## Global Constraints

- Product version remains 0.2.7; no package payload or third-party lock changes.
- Product source is 666c578f719d1e54fce95d6831a3af92ea80df93.
- Preserve v0.2.7 object be47589ec7dbefe821ada35ed0a89dedc9751953 and v0.2.6.
- Controller SHA is the real dispatch SHA, never the original artifact SHA.
- Full CI, two independent environments, signed maintenance tag and review remain required.
- Reuse this worktree/cache; no new worktrees; retain at least 4 GiB free.
- Every Cargo-invoking command sets CARGO_BUILD_JOBS=2, CARGO_INCREMENTAL=0,
  CARGO_PROFILE_DEV_DEBUG=0, CARGO_PROFILE_TEST_DEBUG=0, CARGO_PROFILE_RELEASE_DEBUG=0.
- All changed paths are EXOCHAIN core release tooling, CI, tests or governance.
- No synthetic verified bundles, credential extraction, protection bypass or runtime deployment claims.

## Task 1: Prove and correct the actual npm runtime contract

Files: `tools/test_release_npm_runtime_contract.sh` (new),
`tools/publish_release_npm_package.sh`, `tools/test_release_npm_config_boundary.sh`,
`tools/test_release_workflow_ref_binding.sh`, `.github/workflows/release.yml`,
`.github/workflows/ci.yml`.

Interface: test script takes explicit Node and npm CLI paths, executes a
credential-free install/audit of fixed WASM0.2.7 and calls the unchanged registry
attestation verifier with its actual JSON. It must never invoke publish.

- [x] Add a regression using the real pinned npm10.9.2 audit and record its
  expected rejection by the existing verifier. Use the exact published SRI and
  source/ref; do not substitute manufactured `verified` records.
- [x] Prove exact official Node24.15.0 with bundled npm11.12.1 passes the same
  complete command. Fail on runtime-version mismatch before any test network
  request. Keep isolated user/global configuration files distinct.

```sh
env -i PATH=/usr/bin:/bin \
  RELEASE_TEST_NODE=/absolute/verified/node \
  RELEASE_TEST_NPM=/absolute/verified/npm-cli.js \
  bash tools/test_release_npm_runtime_contract.sh
```

- [x] Pin only the three credentialed npm publisher runtimes to that exact
  proven distribution. Preserve seven Node22.14.0 build/preparation pins and
  their bundled npm10.9.2 packaging contract. Preserve full tool-root capture.
- [x] Integrate the actual CLI test into hosted CI before publication; update
  old guard assumptions to distinguish build and publisher runtimes explicitly.
- [x] Extract the visibility polling into a behavior-testable function, with
  25 attempts and 15-second sleeps, fail-closed handling of non404/mismatched
  responses, and no repeated upload. Test immediate/delayed/exhausted visibility
  without actually sleeping or contacting an authenticated registry.
- [x] Run real positive/negative CLI tests, existing npm registry/config guards,
  shell syntax and relevant workflow guards. Commit only task files and report
  RED/GREEN commands and retained evidence paths for independent review.

## Task 2: Fixed original artifact custody and controller identity

Files: `governance/releases/v0.2.7/RECOVERY-MANIFEST.json`,
`tools/verify_release_recovery_027.py`, `tools/verify_release_recovery_027.sh`,
`tools/test_release_recovery_027.py`.

Interfaces: the JSON manifest records fixed version/tag/source/run/attempt,
successful producing job IDs/names, artifact IDs/names/zip SHA256 and strict
per-file names/sizes/SHA256. Include the complete successful original reusable
CI job IDs/names, both original approval jobs and signed-tag gate, native
attestation job, and exactly 32 Rust archive SHA256 values from column 3 of the
original preflight TSV (column 4 is not the crates.io archive checksum).
The Python CLI validates `manifest`, `origin`,
`artifacts`, `product-tag` and `rust-registry` modes; it returns JSON or a
nonzero error, never shell code. The shell wrapper captures helpers from actual
GITHUB_SHA and composes unchanged controller source/tag/signer checks with
fixed original-product signature and remote identity checks.

- [x] Independently review the artifact inventory obtained from original
  run35257955565/attempts/1, not current attempt2. Record only factual owned
  manifest fields; do not commit downloaded logs/archives/scanner output.
  Artifact API workflow_run metadata does not itself identify a producing job or
  attempt: require explicit attempt1 job membership and the reviewed fixed
  artifact-ID/digest/producer mapping. Never infer this from latest-run metadata.
- [x] Write stdlib unittest cases before implementation. Positive fixtures
  specify literal values; negative cases change one identity/digest/file/job
  boundary at a time. A wrong original producer must fail even when bytes hash.

```sh
python3 -B tools/test_release_recovery_027.py
```

- [x] Implement bounded duplicate-key-rejecting JSON parsing, exact schema and
  inventory validation, regular-file/no-link checks, strict safe extraction,
  per-file digest checks and successful original-producer evidence. Use fixed
  HTTPS provider endpoints, never manifest-provided executable commands/URLs.
- [x] Verify original product tag object/peel/signature separately without
  changing GITHUB_SHA or relaxing verify_release_tag.sh. Test controller/product
  substitution, changed original tag, wrong signer and wrong maintenance tag.
- [x] Test each existing public Rust version against its exact original archive
  digest with no credential and no Cargo process. Missing/yanked/mismatched
  records fail before remaining registry mutations.
- [x] Run full focused tests and original signer/source/tag regression guards;
  commit only task files and submit the immutable diff for review.

## Task 3: Strict Python partial-publication preflight

Files: `tools/verify_python_release_package.py` and
`tools/test_verify_python_release_package.sh`.

Interface: add `recovery-preflight RESPONSE PACKAGE VERSION MANIFEST`, emitting
bounded JSON `{"existing":[FILENAMES],"missing":[FILENAMES]}` in manifest order.
This validates a genuine HTTP200 registry response only; the caller handles404
separately. It is a metadata preflight, not cryptographic provenance acceptance.
Keep `registry-response` strict and silent on successful complete acceptance.

- [x] Add tests for no files, either single file, both files, extra file,
  duplicate record, wrong package/version/hash/size, boolean size, yanked file
  and malformed response. Assert the actual CLI exit/output, not source text.
  Full-inventory `registry-response` must continue rejecting partial inventory.
- [x] Run before implementation and retain the expected unknown-command failure.
- [x] Reuse the canonical strict JSON reader/manifest parser and extract common
  registry metadata validation without weakening any existing complete check.
  Reject yanked records; require a real positive integer size (not bool).
  Do not fetch URLs, stage files, install packages or verify signatures here.
- [x] Run all existing verifier tests and new partial cases with the repo's
  configured Python test dependencies; retain RED/GREEN commands and outputs.
  Review the exact two-file diff independently before workflow wiring.

```sh
bash tools/test_verify_python_release_package.sh
```

## Task 4: Wire protected recovery, preserve exact publication acceptance

Files: `.github/workflows/release.yml`, `.github/workflows/ci.yml`,
`tools/publish_release_npm_package.sh`,
`tools/test_publish_release_npm_registry_validation.sh`,
`tools/test_release_recovery_027.py`, `tools/test_release_recovery_npm.sh`,
`tools/import_release_recovery_027.sh`, `tools/test_import_release_recovery_027.py`,
`tools/run_release_recovery_027.sh`, `tools/test_release_recovery_workflow.py`,
`tools/recover_release_python_027.sh`, `tools/test_recover_release_python_027.sh`,
`tools/verify_release_recovery_python_stage.py`,
`tools/test_release_recovery_python_stage.py`,
`tools/recover_github_release_027.py`, `tools/test_recover_github_release_027.py`,
and recovery design/manifest records. Existing ref-binding, dry-run, publication
and Python lifecycle guards must explicitly account for these recovery paths.

Interfaces: operation is exactly `release` (default) or `recover-0.2.7`.
Recovery accepts only version0.2.7 and refs/tags/v0.2.7-recover.N (positive N).
The manifest is captured from controller source; no caller artifact overrides.
Existing npm publisher receives a manifest-validated recovery context, never
arbitrary expected-provenance environment overrides. WASM expects original
source/ref and must be acceptance-only. Newly uploaded LYNK/SDK/Python expect
the actual controller source/ref. Normal publication retains exact equality.

- [x] First write workflow DAG and publisher behavioral regressions for mode
  exclusion, missing CI/approval dependencies, credential leakage, wrong input,
  existing WASM zero upload and missing WASM rejection.
- [x] Add the recovery lane to release.yml with unchanged full reusable CI and
  both protected gates. Pin existing actions by their immutable SHAs. Import
  exact original artifacts in a read-only token/no-OIDC job and verify original
  native attestations. Do not rebuild any payload.
- [x] Use fresh protected publication runners and rehash/rebind source, both
  tags, manifest and bytes immediately before mutation. Preserve exact owner,
  signature and provenance acceptance. Public audit commands use no token.
- [x] Keep the existing pinned Python publisher action directly in release.yml.
  Consume Task3's `recovery-preflight` exact missing manifest filenames;
  verify every existing file's provenance before staging missing files.
  Invoke the unchanged full-inventory final verifier with actual controller
  source/ref. Test neither/one/both existing distributions and a conflicting file.
- [x] Gate original-tag GitHub Release creation on every successful provider
  acceptance; reuse original native archives/SBOMs and include explicit custody
  evidence. Existing assets must match exactly or fail without replacement.
- [ ] Exercise normal and recovery paths, all focused guards and the complete
  low-disk core gates. Perform an independent whole-branch review, fix findings,
  and request the required exact-head maintainer reviews. Neither local tests
  nor this plan is permission to bypass those reviews.
- [ ] After legitimate reviewed integration, sign a new maintenance tag, run
  the token-free recovery dry run, then live publication behind actual protected
  approvals. Read back all providers and release assets before reporting done.
  Preserve receipts and continue separately approved issue822 retirement.

## Task 5: Exact Python publisher shape and reviewed prior-publication acceptance

Classification: all changed source, tests and governance records are EXOCHAIN
core release tooling. Original payloads, dependency locks, artifact manifest,
tag identities, source import and expiry checks remain unchanged. Evidence stays
outside the checkout. Continue under the standing autonomous-fix authorization;
normal independent reviews and protected approvals still gate execution.

- [x] Preserve failed Python job107717206104 and receipt10819679079. Independently
  download both public distributions, verify original hashes/sizes, and run the
  genuine hashlocked PEP740 verifier using Python3.13.7 against unedited evidence.
- [x] Reproduce absent-claims rejection with a failing canonical verifier test.
  Permit exactly absent/null claims; reject nonnull claims, unknown fields,
  missing/changed identity fields and certificate/attestation mismatches.
- [x] Add a separate five-record PUBLICATION-IDENTITIES.json. Preserve the
  artifact manifest and its pin. Reuse the existing strict custody parser with
  an independent publication-record pin and exact artifact cross-binding.
- [x] Exercise failing-to-passing npm/Python tests for successor acceptance of
  only the mapped source/ref; missing mapped publications must fail without
  upload or staged distributions. Capture all identities from actual controller
  source, retaining real controller SHA/ref for every source/tag/staging guard.
- [x] Correct the GitHub receipt/body attribution and test distinct prior
  publishers versus the current acceptance/GitHub Release controller.
- [x] Run complete focused release/retirement guards, normal core gates, actual
  old/new npm CLI contracts and independent whole-change review. Preserve the
  initial generated-report SBOM guard failure and its successful unchanged-guard
  rerun after moving test evidence intact outside the checkout.
- [ ] Submit signed commits and obtain normal exact-head maintainer reviews/CI.
- [ ] After reviewed integration, create a new signed maintenance tag and run
  separate protected dry/live executions. Original imports must still satisfy
  fresh non-expiry checks; no cross-run transport reuse or waiver is included.
- [ ] Independently accept all providers and 35 GitHub assets, then execute the
  separately approved issue822 retirement. Local fixes do not complete release.

Ordinary resumption stays on one maintenance ref/commit. A later controller may
not use an arbitrary or either-identity provenance override. Dry-run jobs never
receive publisher secrets or job-level OIDC. New same-run transport ZIPs are
verified against original inner-file digests, not the original transport ZIP hash.

## Task 6: Reproducible full-workspace formatter after hosted nightly drift

Classification: EXOCHAIN core CI, local validation tooling and owned developer
documentation. No Rust product source, build/test compiler, dependency lock,
payload, release workflow, protection or provenance policy changes.

- [x] Preserve both PR841 format failures and compare their actual compiler
  identity with the last successful exact-source hosted PR840 format job.
- [x] Add a parsed-YAML formatter contract and negative mutation regressions;
  observe rejection of the existing floating configuration before changing it.
- [x] Pin only formatter installation and invocation to nightly-2026-09-21,
  update repo_truth and its failure mock, and align README/AGENTS commands.
  Retain full --all -- --check and the required constitutional gate dependency.
- [x] Run all core, recovery/retirement and CI-derived source gates against the
  final candidate; retain actual logs and independently review the complete diff.
- [ ] Sign and push the repair normally to PR841; obtain fresh exact-head CI
  and both real maintainer reviews, including applicable Operations, Governance
  and Architecture CODEOWNERS approval, before integration or maintenance tag.

## Exact npm emission compatibility

This section records the earlier publisher repair before public LYNK/SDK
acceptance. The retained mode below performs public readback only.

The real audit of the original WASM proves consumption of its v0.2 bundle, not
the format generated by a new npm 11.12.1 publication. The bundled libnpmpublish
11.1.3, sigstore 4.1.0 and bundle 4.0.0 generate the v0.3 media type and single
certificate representation. The v0.2-only verifier rejects that representation.

Before uploading any missing npm version, extend only the canonical verifier
and its existing tests to admit the exact v0.2/chain and v0.3/single-certificate
pairs. Reject mixed, ambiguous, extra and malformed certificate layouts; retain
the actual successful npm cryptographic audit prerequisite and every exact
subject, source, workflow, ref, SAN and transparency requirement. Use installed
runtime serialization and real public format evidence separately from explicitly
labeled structural regression fixtures. No synthetic fixture is publication or
cryptographic proof. Independently review this repair before publication.

## September 24 approved retained-custody implementation

The original recovery tasks above are historical. Their original import still
rejects expired original artifacts, so this plan now incorporates the separately
approved `RETAINED-RECOVERY-PLAN.md` contract. The fixed
`recover-0.2.7-retained` operation consumes only the pinned, freshly available
retained payload and custody artifacts. It validates historical pre-expiry
original import and matching current original metadata without treating old
ZIPs as freshly acquired. Its 40 payload files are matched to the unchanged
manifest; it cannot rebuild, repack or republish any package.

Implementation through signed `e2c138a6c5d9d947240ecd363aa1ab87adcb5e41`
adds strict retained record/origin/transport/receipt checks, read-only
acceptance for 32 Rust versions and five mapped public files, and distinct
`retained-acceptance` and live-only `retained-github` workflow jobs. All five
public package checks run in both dry and live acceptance. The latter job
requires exact current-attempt direct receipt artifact outputs, repeats source,
transport and public-state checks, and reuses the journaled 35-asset GitHub
writer. Its release-environment write authority never enters the read-only
acceptance job. Normal release and original recovery gates remain separate.

Tasks 1–3 each received independent task reviews without remaining blocking
findings. The complete final candidate still requires the focused and
CI-derived suites, low-disk core gates, independent whole-branch review,
exact-head hosted CI and two actual non-author maintainer approvals. Subsequent
signed-tag, protected dry/live execution, fresh provider/asset acceptance and
issue 822 retirement are separate release actions, not results of this source
plan. Record the exact final run and any failures in dated immutable-head
evidence rather than promoting earlier fixtures or planning downloads to hosted
proof.
