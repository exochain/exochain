# EXOCHAIN 0.2.7 recovery implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

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

- [ ] Add a regression using the real pinned npm10.9.2 audit and record its
  expected rejection by the existing verifier. Use the exact published SRI and
  source/ref; do not substitute manufactured `verified` records.
- [ ] Prove exact official Node24.15.0 with bundled npm11.12.1 passes the same
  complete command. Fail on runtime-version mismatch before any test network
  request. Keep isolated user/global configuration files distinct.

```sh
env -i PATH=/usr/bin:/bin \
  RELEASE_TEST_NODE=/absolute/verified/node \
  RELEASE_TEST_NPM=/absolute/verified/npm-cli.js \
  bash tools/test_release_npm_runtime_contract.sh
```

- [ ] Pin only the three credentialed npm publisher runtimes to that exact
  proven distribution. Preserve seven Node22.14.0 build/preparation pins and
  their bundled npm10.9.2 packaging contract. Preserve full tool-root capture.
- [ ] Integrate the actual CLI test into hosted CI before publication; update
  old guard assumptions to distinguish build and publisher runtimes explicitly.
- [ ] Extract the visibility polling into a behavior-testable function, with
  25 attempts and 15-second sleeps, fail-closed handling of non404/mismatched
  responses, and no repeated upload. Test immediate/delayed/exhausted visibility
  without actually sleeping or contacting an authenticated registry.
- [ ] Run real positive/negative CLI tests, existing npm registry/config guards,
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

- [ ] Independently review the artifact inventory obtained from original
  run35257955565/attempts/1, not current attempt2. Record only factual owned
  manifest fields; do not commit downloaded logs/archives/scanner output.
  Artifact API workflow_run metadata does not itself identify a producing job or
  attempt: require explicit attempt1 job membership and the reviewed fixed
  artifact-ID/digest/producer mapping. Never infer this from latest-run metadata.
- [ ] Write stdlib unittest cases before implementation. Positive fixtures
  specify literal values; negative cases change one identity/digest/file/job
  boundary at a time. A wrong original producer must fail even when bytes hash.

```sh
python3 -B tools/test_release_recovery_027.py
```

- [ ] Implement bounded duplicate-key-rejecting JSON parsing, exact schema and
  inventory validation, regular-file/no-link checks, strict safe extraction,
  per-file digest checks and successful original-producer evidence. Use fixed
  HTTPS provider endpoints, never manifest-provided executable commands/URLs.
- [ ] Verify original product tag object/peel/signature separately without
  changing GITHUB_SHA or relaxing verify_release_tag.sh. Test controller/product
  substitution, changed original tag, wrong signer and wrong maintenance tag.
- [ ] Test each existing public Rust version against its exact original archive
  digest with no credential and no Cargo process. Missing/yanked/mismatched
  records fail before remaining registry mutations.
- [ ] Run full focused tests and original signer/source/tag regression guards;
  commit only task files and submit the immutable diff for review.

## Task 3: Wire protected recovery, preserve exact publication acceptance

Files: `.github/workflows/release.yml`, `.github/workflows/ci.yml`,
`tools/publish_release_npm_package.sh`,
`tools/test_publish_release_npm_registry_validation.sh`,
`tools/test_release_recovery_027.py`, `tools/verify_python_release_package.py`,
`tools/test_verify_python_release_package.sh`, and recovery design/manifest records.

Interfaces: operation is exactly `release` (default) or `recover-0.2.7`.
Recovery accepts only version0.2.7 and refs/tags/v0.2.7-recover.N (positive N).
The manifest is captured from controller source; no caller artifact overrides.
Existing npm publisher receives a manifest-validated recovery context, never
arbitrary expected-provenance environment overrides. WASM expects original
source/ref and must be acceptance-only. Newly uploaded LYNK/SDK/Python expect
the actual controller source/ref. Normal publication retains exact equality.

- [ ] First write workflow DAG and publisher behavioral regressions for mode
  exclusion, missing CI/approval dependencies, credential leakage, wrong input,
  existing WASM zero upload and missing WASM rejection.
- [ ] Add the recovery lane to release.yml with unchanged full reusable CI and
  both protected gates. Pin existing actions by their immutable SHAs. Import
  exact original artifacts in a read-only token/no-OIDC job and verify original
  native attestations. Do not rebuild any payload.
- [ ] Use fresh protected publication runners and rehash/rebind source, both
  tags, manifest and bytes immediately before mutation. Preserve exact owner,
  signature and provenance acceptance. Public audit commands use no token.
- [ ] Keep the existing pinned Python publisher action directly in release.yml.
  Add a narrowly named `recovery-preflight` operation that returns the exact
  missing manifest filenames only after rejecting extra/conflicting existing
  files; verify every existing file's provenance before staging missing files.
  Invoke the unchanged full-inventory final verifier with actual controller
  source/ref. Test neither/one/both existing distributions and a conflicting file.
- [ ] Gate original-tag GitHub Release creation on every successful provider
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

Ordinary resumption stays on one maintenance ref/commit. A later controller may
not use an arbitrary or either-identity provenance override. Dry-run jobs never
receive publisher secrets or job-level OIDC. New same-run transport ZIPs are
verified against original inner-file digests, not the original transport ZIP hash.
