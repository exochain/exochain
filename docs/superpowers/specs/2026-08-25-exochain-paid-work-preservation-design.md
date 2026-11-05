# EXOCHAIN Paid-Work Preservation Design

## Goal

Give the EXOCHAIN team one reviewable Git branch containing the paid G00 work
that is currently outside committed history, without changing or cleaning any
existing worktree.

## Design

Create `work-in-progress/exochain-v0.3.0-g00/` on the isolated branch
`agent/exochain-paid-work-registry`. Copy source artifacts byte-for-byte into
clearly labeled folders, add a registry and cryptographic manifest, and retain
working-tree deltas as patches plus path inventories. Historical evidence is
preservation material, not current release evidence or executable authority.

## Safety boundaries

- Do not reset, clean, restore, stash, stage, or edit any existing worktree.
- Do not merge this branch automatically.
- Do not copy credentials, tokens, private keys, environment dumps, browser
  state, keychain data, or process arguments.
- Scan the preservation set for secret-like content before committing.
- Preserve copied source bytes and file modes; label status in adjacent index
  files rather than modifying the artifacts.
- Keep source code unchanged. This branch adds preservation and handoff
  material only.

## Acceptance

- The branch contains the six authenticated directives/intakes and snapshots
  of relevant current working-tree deltas. For the removed guard candidate and
  historical G00 workspace, it contains their exact last authenticated tuples
  and an explicit missing-source disposition rather than a reconstruction.
- A registry classifies every top-level artifact set.
- A sorted SHA-256 manifest verifies every preserved file other than itself.
- Secret scanning, manifest replay, `git diff --check`, and tracked-path scope
  checks pass before commit.
- The branch is pushed and exposed through a draft pull request.
