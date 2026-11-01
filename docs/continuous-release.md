<!-- Copyright 2026 Exochain Foundation -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Continuous release readiness

The constitutional CI workflow validates each push, pull request and release
dispatch. Its readiness record identifies the exact commit that passed the
quality gates. Publication remains the separate, manually dispatched release
workflow with its existing signed-tag, two-environment, provenance and exact
artifact checks.

## Fast feedback

The test, coverage, SBOM, integration, platform and feature-matrix jobs start
independently of the release build. These 12 jobs (21 matrix lanes) consume no
build-job artifacts. Their caches remain separate, and every job, including the
release build, remains required by `All Constitutional Gates`. The WASM bridge
retains its real dependency on the WASM artifact build. Runner capacity determines
the wall-clock benefit; checks can now run even when the build later fails.

The hygiene job also caches Rust dependencies and build outputs for its workspace
test-inventory compilation, using the existing pinned Rust cache action.

LYNK runs in parallel with the Rust gates on Node 20.0.0, the package's declared
minimum, and Node 24.15.0, the pinned publication runtime. Each lane installs from
the package lock with dependency lifecycle scripts disabled, typechecks, runs
the full test suite, builds and checks the package contents, and dry-packs the
package. A failed lane blocks `All Constitutional Gates`. Each lane has a
15-minute timeout; the other lane continues after a failure to preserve useful
compatibility diagnostics.

The Node 24 lane additionally runs `npm run test:coverage`, enforcing the
package's 95% line, 95% function and 90% branch thresholds. Node 20 runs the full
test suite without claiming support for the newer coverage-threshold flags.

The npm cache stores downloaded dependencies and uses the package lock as its
dependency key. Every lane runs `npm ci`; it never restores `node_modules` or
release artifacts from a cache.

A new update to a pull request cancels that pull request's previous CI run.
Concurrency groups include the calling workflow and event type. Pushes and
release dispatches use their unique run ID, so one release cannot cancel another
or be cancelled by ordinary PR activity. All existing Rust, Python, security,
coverage, platform and packaging gates remain required.

## Candidate evidence

After `All Constitutional Gates` succeeds, `Release Candidate Readiness` checks
out `github.sha` without persisting credentials and runs the existing strict
release source verifier. It verifies the Git object graph, commit identity,
tracked bytes, file modes, index and clean checkout before recording readiness.
The job uploads `release-candidate.json` under the artifact name:

```text
release-candidate-<commit-sha>-<run-id>-<run-attempt>
```

The JSON includes the source commit, workspace version, repository, workflow
reference, run identity and run URL. Its `publication_authorized` field is always
`false`. Missing or unsuccessful gate results, malformed run identity and source
mismatches prevent evidence creation. A missing upload fails the job. Artifact
names distinguish retries and uploads cannot overwrite an earlier record;
retention is 14 days.

For pull requests, the commit identifies the tested merge commit. It is not
evidence for a later merge or release commit. Readiness evidence is an operational
index to a CI run, not a signed attestation or a release artifact. The release
workflow does not consume it to skip checks, approve publication or reuse build
outputs. Once a release commit and its signed tag are ready, run the existing
release dispatch for that exact commit; both configured environment gates and
the full release verification still apply.

## Validation

The new boundaries are covered by:

```bash
python3 -B tools/test_continuous_release.py
```

The regression tests reject cancelled, skipped, failed and missing gate results;
malformed identities; source SHA mismatches; modified checkout bytes; cancellation
that could affect release runs; bypassed LYNK checks; and candidate jobs detached
from the complete gate. Existing release boundary tests remain unchanged.

Path classification: `.github/workflows/ci.yml`,
`tools/write_ci_candidate.py`, `tools/test_continuous_release.py` and this document
are **EXOCHAIN core** CI gates and their supporting tooling/documentation. This
change adds no adjacent surface, publication credentials or automated release
trigger.
