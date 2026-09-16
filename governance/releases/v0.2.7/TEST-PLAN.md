# EXOCHAIN 0.2.7 release correction

## Authority and classification

The maintainer selected 0.2.7 on 2026-09-16 and required that the existing
`v0.2.6` tag remain unchanged. Its signed object is
`4da502f8dc5a32a844c8e9e8d9990daeac339222`, pointing to
`cb81064f7089faf8a598fdcb0ff033865d4993bf`. That source was merged through
PR #836; live run 35131939792 failed Gate 9 before publication and was canceled.

The original security-remediation scope and issue dispositions remain in
`governance/releases/v0.2.6/`; their historical evidence is not rewritten.
0.2.7 inherits that remediation, fixes the publication-truth assertion and
aligns all release package versions. It is not yet a published release.

- `tools/` publication validators/tests and their CI integration: EXOCHAIN core.
- Cargo manifests, first-party lock entries and Rust SDK version: EXOCHAIN core.
- npm/Python/WASM manifests, locks and SDK version constants: core runtime adapter.
- README, versioning, changelog and release governance records: EXOCHAIN core
  release documentation; committed separately from implementation changes.
- No adjacent surface, imported report, vendor source or constitutional runtime
  algorithm is changed by this correction.

## Root cause and regression

`tools/test_repo_truth.sh` incorrectly inferred the latest published release
from the highest local Git tag. Tag creation is required before publication,
so the signed but unpublished 0.2.6 candidate invalidated the truthful 0.2.4
publication claim. Tag visibility also differed between shallow branch and
tag checkouts. Neither hiding tags nor changing signed source identity repairs
that assertion.

The correction validates a dated, reviewed provider-readback snapshot, separate
from Git tags. CI checks the snapshot's structure and README consistency; it
does not claim to make a new live provider observation. Snapshot updates require
actual provider readback and must never be generated from tags alone.

The initial normalized snapshot records public readbacks from
2026-09-16T18:29:40Z through 18:29:42Z: GitHub's `/releases/latest` endpoint and
complete six-entry release listing identify 0.2.4; all 32 canonical crates
and both named npm packages returned HTTP 200 with 0.2.4 as their latest
version. Sources: `https://api.github.com/repos/exochain/exochain/releases/latest`,
`https://crates.io/api/v1/crates/{package}`, and
`https://registry.npmjs.org/{percent-encoded-package}`. The GitHub release ID
is 372519985, published 2026-08-18T17:15:29Z. This is an owned summary of actual
provider observations, not a copy of external reports or generated scan output.
Archive bytes were not downloaded or rehashed by this snapshot check; it does
not establish deployed/runtime state or publication of the newer candidate.

Regression acceptance:

1. Reproduce the legacy newest-tag comparison failure against unchanged source.
2. Run `python3 tools/test_published_release_claim.py` before the validator exists
   (RED), then after implementing it (GREEN).
3. Exercise identical claims with no Git repository, a publication tag, newer
   annotated candidate/correction tags, and a newer prerelease tag.
4. Reject absent/malformed/duplicate-key snapshots, invalid timestamps,
   drafts/prereleases, mismatched provider versions, empty/duplicate inventories,
   unsupported names, and mismatched/undated/duplicate README publication claims.
5. Run `bash tools/test_repo_truth.sh` with the real preserved 0.2.6 tag visible.
6. Run `RELEASE_VERSION_EXPECTED=0.2.7 bash tools/test_release_version_alignment.sh`
   before and after the version-only correction, preserving all third-party locks.

## SBOM corpus correction

The first 0.2.7 CI runs (35139889500 and 35139885789) generated all 32
SBOMs, then correctly rejected the regression suite's stale `--version 0.2.6`.
Its pinned corpus digest was also still for 0.2.6. The earlier local invocation
had archived committed HEAD at 0.2.6 while the version bump was uncommitted;
that pass did not establish validation of the 0.2.7 SBOM corpus.

The test now binds a reviewed 0.2.7 corpus and rejects working-source/archive
disagreement before generation. This correction changes only EXOCHAIN core
test tools and this governance record. The production SBOM validator, CI
workflow, dependencies, source/tag binding and protected approvals are unchanged.

Independent offline generation with cargo-cyclonedx 0.5.9 reproduced the old
`cb81064f7089` digest
`d085e1ae94fb41ba802c58ff6a0c40ddb67086e23f1a9649bb2645d4f7768319`.
Two separate `1a42883a7cc1` source archives produced byte-identical 0.2.7
canonical files with digest
`abdb895d4795a54dd5950368ad31da551b211da39ce9361ae669522aebd9ed4f`.
All 32 documents are identical after narrowly normalizing only first-party
versions, references/purls and output filenames. All 612 distinct third-party
component identities and 631 registry lockfile packages are unchanged, as are
all other fields and dependency edges. The digest is reviewed evidence, not
automatically accepted from the generator during a test.

Acceptance commands:

- `python3 -B tools/test_release_sbom_fixture.py`: reject unreviewed versions,
  staged/unstaged source changes and untracked Cargo-discovered source before
  Cargo or SBOM generation. Run negative fixtures before the fix (RED) and
  after the source guard (GREEN).
- `bash tools/test_verify_release_sbom.sh`: validate the complete real corpus,
  all existing adversarial mutations, repeated output and relocated paths.
- `bash tools/test_release_sbom_boundary.sh`: preserve the release boundary
  checks and run the source-fixture regressions in existing CI Gate 9.
- Repeat version alignment, repository truth, workspace release build/debug
  tests, all-target Clippy, format and warning-denied documentation locally;
  require fresh exact-head hosted CI before integration.

## Integration and release acceptance

Run the inherited required workspace build, debug/release tests, Clippy,
nightly format, warning-denied rustdoc, audit/deny, repository guards, SDK tests
and cross-implementation comparator. Reuse the existing target directory;
monitor free disk space and do not create build copies or new worktrees.
Hosted CI must pass on the exact signed correction commit, including native
platform and supply-chain lanes. Review the complete correction diff and obtain
the two required maintainer PR approvals. Do not transfer earlier approvals.

After reviewed integration, sign `v0.2.7` at the exact accepted commit. Check
the original 0.2.6 tag object/peeled commit again, then verify the new tag with
the configured key and authoritative remote guards. Dispatch live publication
once and retain both independent environment approvals. Verify all 32 Rust,
three npm and one Python distributions, provenance and GitHub Release before
claiming completion. Issue #822's 31 published 0.2.3 retirement targets remain
in scope and require protected execution plus individual yanked readback.

No deployment is claimed without an identified target and runtime verification.
