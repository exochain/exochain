# EXOCHAIN Paid-Work Preservation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve paid EXOCHAIN G00 work in one labeled, reviewable Git branch without modifying existing worktrees.

**Architecture:** An isolated worktree adds one `work-in-progress/` preservation package containing byte-exact artifacts, working-tree snapshots, a registry, and a reproducible SHA-256 manifest. The package is documentation/imported-evidence only and is published through a draft pull request.

**Tech Stack:** Git, POSIX shell utilities, SHA-256, Markdown

**Spec:** `docs/superpowers/specs/2026-08-25-exochain-paid-work-preservation-design.md`

## Global Constraints

- Preserve all source worktrees unchanged.
- Preserve copied artifact bytes and modes.
- Do not commit secret material.
- Do not claim preserved material is release-ready or operative unless its own label says so.
- Do not merge automatically.

---

### Task 1: Freeze and copy paid-work artifacts

**Files:**
- Create: `work-in-progress/exochain-v0.3.0-g00/governing/`
- Create: `work-in-progress/exochain-v0.3.0-g00/candidate/`
- Create: `work-in-progress/exochain-v0.3.0-g00/historical/`
- Create: `work-in-progress/exochain-v0.3.0-g00/contaminated-state/`

**Interfaces:**
- Consumes: authenticated external artifacts and read-only Git working trees
- Produces: byte-exact preservation copies and deterministic state snapshots

- [x] Recompute source hashes, byte lengths, modes, file counts, and symlink counts.
- [x] Copy available authenticated material without editing it; record exact
  prior bindings and a missing-source disposition when a source is absent.
- [x] Export each relevant working-tree diff and name-status inventory without changing its source.
- [x] Recompute destination bindings and fail on any copy mismatch.

### Task 2: Add labels, registry, and team handoff

**Files:**
- Create: `work-in-progress/exochain-v0.3.0-g00/README.md`
- Create: `work-in-progress/exochain-v0.3.0-g00/REGISTRY.md`
- Create: `work-in-progress/exochain-v0.3.0-g00/HANDOFF.md`

**Interfaces:**
- Consumes: Task 1 artifact paths and bindings
- Produces: human-readable status and continuation instructions

- [x] Classify each artifact set as issued governance, non-operative intake, uncommitted candidate, historical failed evidence, contaminated state, or future work.
- [x] State that preservation is not approval, merge, release readiness, or executable authority.
- [x] Give the next IDE a short, source-first handoff that preserves dirty worktrees.

### Task 3: Seal, validate, commit, and publish

**Files:**
- Create: `work-in-progress/exochain-v0.3.0-g00/MANIFEST.sha256`

**Interfaces:**
- Consumes: complete preservation package from Tasks 1 and 2
- Produces: verified Git commit, pushed branch, and draft pull request

- [x] Run a redacted secret scan over every file proposed for commit and stop on a validated secret.
- [x] Generate the sorted relative-path SHA-256 manifest excluding only itself.
- [x] Replay the manifest from a fresh command and verify path count and byte count.
- [x] Run `git diff --check` and confirm the branch changes only preservation/spec/plan paths.
- [x] Stage only the reviewed paths, commit, push with tracking, and open a draft pull request.
