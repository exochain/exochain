# Protected 0.2.3 Retirement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Retire exactly the 31 published broken 0.2.3 crates through source-bound, independently approved registry operations.

**Architecture:** A separate maintenance controller reuses the existing source,
tag, signer and namespace-owner guards. A fixed-scope standard-library helper
preflights, applies and verifies the bounded batch without build lifecycle code.

**Tech Stack:** Python 3.13.7 standard library; GitHub Actions on ubuntu-24.04;
existing Node 22.14.0 namespace guard; existing Bash/Git/OpenPGP source guards.

**Spec:** `governance/releases/v0.2.7/RETIREMENT-DESIGN.md`.

## Global Constraints

- Fixed target version 0.2.3; fixed replacement version 0.2.7.
- Exactly 31 canonical crates, excluding exochain-pdp.
- No product tag, accepted product commit, runtime or dependency changes.
- No credential extraction, approval bypass, alternate endpoint, undo or automatic mutation retries.
- Both existing protected environments gate live writes; actual dispatch SHA is never spoofed.
- Reuse the existing worktree and target directory; no new worktrees or build copies.

### Task 1: Fixed-inventory registry helper

**Files:** Create `tools/retire_crates_023.py` and `tools/test_retire_crates_023.py`.

**Interfaces:** The helper exports `CRATES` (ordered tuple of 31 names),
`RetirementError`, and `retire(apply: bool, token: str | None, request, emit)`.
`request(method, path, token=None)` returns parsed JSON using bounded HTTPS;
`emit(record)` receives safe dictionaries for receipts. CLI `--inventory`
prints one fixed name per line, default/no option performs public preflight,
and `--apply` requires `CARGO_REGISTRY_TOKEN`. No other operational arguments.

- [ ] Write failing tests before implementation. A target read with wrong
  `version.crate`, `version.num`, boolean-as-ID, nonboolean `yanked` or invalid
  checksum must reject; a missing last replacement must cause zero DELETEs.
  Use literal records such as
  `{"version":{"id":123,"crate":"exochain-core","num":"0.2.3","checksum":"a"*64,"yanked":false}}`.
  The transport double supplies real API-shaped data and records operations;
  assertions cover actual state-machine results and effects, not its existence.
- [ ] Run `python3 -B tools/test_retire_crates_023.py`; retain RED evidence.
- [ ] Implement the exact full inventory from the canonical ownership guard
  minus PDP, strict JSON/network boundary, complete-batch preflight, per-item
  recheck, authenticated DELETE only for unyanked targets, independent readback,
  and safe failure/completion receipts. A dry run never needs or sends a token.
- [ ] Cover already-yanked idempotence, wrong replacement identity, target
  checksum/ID changes, HTTP/redirect/auth failures, non-true `ok`, duplicate
  keys/depth/size bounds, token-injection bytes, partial failure and safe rerun.
  Public requests must never include Authorization; no retry after unknown
  mutation result. Mutation endpoint/method must be exactly the fixed yank API.
- [ ] Run focused tests and `python3 -B tools/retire_crates_023.py --inventory`;
  inspect all names, self-review, and commit only these two files with signing.

### Task 2: Protected workflow, custody and CI integration

**Files:** Create `.github/workflows/retire-0.2.3.yml`,
`tools/run_retirement_023.sh`, and `tools/test_retirement_workflow.py`;
modify only Gate 9 in `.github/workflows/ci.yml` to run both new test files.

**Interfaces:** The runner consumes real GITHUB_* identity, `RETIREMENT_TAG`,
`DRY_RUN` (exact true/false), repository signing variables, configured allowed
owners and the Cargo token only on apply. It emits JSONL receipts outside the
checkout. It invokes Task 1's CLI and the existing exact-target namespace guard.

- [ ] Write a workflow/runner regression test proving invalid dispatch ref,
  SHA, tag, dry-run value, missing approval dependencies and broad credential
  scope fail closed. Use actual YAML structure and isolated Git fixtures for
  runner behavior; do not execute registry writes in tests.
- [ ] Run `python3 -B tools/test_retirement_workflow.py` for RED evidence.
- [ ] Add a dispatch-only workflow with required maintenance-tag input and
  dry_run default true, concurrency group `retire-crates-0.2.3` without
  cancellation, reusable full CI, separate `release`/`release-second` gates,
  and fresh final runner. Pin existing action SHAs/tool versions. Check out
  github.sha with no persisted credentials. Keep Cargo token only on apply.
- [ ] Implement the runner using existing source/tag/signer checks. Require
  live ref `refs/tags/v0.2.7-retire-0.2.3.N` and exact dispatch/HEAD agreement.
  Load helpers from verified immutable commit bytes, use isolated keyring and
  clean process environments, validate all fixed namespace owners before apply,
  and ensure no repository lifecycle/downloaded executable receives credentials.
  Preserve receipts on failure. Never use an input as shell source.
- [ ] Run both new test files, existing release source/tag/signer/namespace
  guards, actionlint when available, and required core build/test/lint/fmt/doc
  gates using existing cache. Resolve every actionable review finding.
- [ ] Commit changes separately from the design/plan documentation; return to
  the unchanged product release branch after saving the maintenance branch.
  Open a separate reviewed PR without modifying PR #837's source. No execution
  or issue closure is authorized merely by the existence of this controller.

### Task 3: Deterministic existing source-guard fixture cleanup

**Files:** Modify `tools/test_release_workflow_ref_binding.sh` only.

**Evidence:** Retirement validation observed the existing stat-cache cleanup
fail after the actual source guard correctly rejected altered bytes. A
deterministic isolated Git reproduction proved that `git restore` could trust
the same stale metadata used to conceal the mutation, leaving modified bytes
behind and allowing subsequent negative tests to fail for the wrong reason.

- [ ] Preserve the raw-byte rejection assertion and all existing negative
  tests. Make cleanup force materialization of the committed tracked blob,
  then verify the actual file hash against the immutable fixture commit.
  Do not use a cached Git status/diff result as the cleanup proof.
- [ ] Retain the observed failing deterministic reproduction, prove corrected
  cleanup for both timing conditions, and run the complete source-ref suite.
  No production helper, product branch, dependency or release tag changes.
- [ ] Self-review, commit this test-only correction separately with signing,
  and obtain focused independent review before controller integration.

## Publication and execution acceptance

After the product release and controller are independently accepted: update
issue #822's actual scope/panel, verify 0.2.7 provider publication, create the
controller's signed maintenance tag, perform a public dry run, then a separate
live dispatch with both real approvals. Retain each receipt and independently
read all 31 yanked flags before closing the governance issue.
