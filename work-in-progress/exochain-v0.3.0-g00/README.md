# EXOCHAIN v0.3.0 G00 paid-work preservation

This directory is the central, reviewable holding area for EXOCHAIN work that
was outside committed history on 2026-08-25.

It is a preservation package, not a merge decision and not a claim that every
artifact is current, operative, passing, or release-ready. Source artifacts are
kept byte-for-byte. Their status is recorded in `REGISTRY.md` instead of being
written into the artifacts.

The local `.gitattributes` disables whitespace normalization only for copied
governing records and raw patch snapshots so their source hashes remain valid.
Authored registry and handoff files keep normal repository whitespace checks.

## What is here

- `governing/`: six authenticated directives, incident records, and planning
  intakes.
- `current-worktrees/main-uncommitted/`: a restorable patch for 25 tracked
  modifications plus byte-exact copies of 16 untracked files from the primary
  EXOCHAIN checkout.
- `current-worktrees/pr-817-deletions/`: a snapshot of 140 tracked deletions.
- `current-worktrees/release-integration-deletions/`: a second snapshot of the
  same 140 tracked deletions in another worktree.
- `missing-sources/`: exact prior bindings for G00 material whose source
  directories were no longer present when this package was created.
- `MANIFEST.sha256`: the sorted relative-path digest list for this package,
  excluding only the manifest itself.

## Rules for the team

1. Do not edit preserved artifacts in place. Copy a source into an authorized
   implementation branch and retain its original digest.
2. Do not apply a patch blindly. Review its base commit, path classification,
   secrets posture, and tests first.
3. Treat `current-worktrees/main-uncommitted/` as adjacent-surface work because
   it is primarily under `intelwar/`; it is not EXOCHAIN core by proximity.
4. Treat the two deletion snapshots as contaminated-state evidence, not as an
   instruction to delete those paths.
5. Preserve `missing-sources/` records until an exact matching source is found
   or the owner makes a documented disposition.

Start with `HANDOFF.md`, then `REGISTRY.md`.
