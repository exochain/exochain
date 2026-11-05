# Team handoff

Use branch `agent/exochain-paid-work-registry` as the preservation index.

1. Read `README.md`, `REGISTRY.md`, and verify `MANIFEST.sha256`.
2. Choose one workstream. Do not combine EXOCHAIN core, runtime adapters,
   adjacent surfaces, imported evidence, and contaminated deletion cleanup in
   one implementation commit.
3. Create a clean branch from the workstream's stated base commit.
4. If using a preserved patch, apply it only to a disposable branch, review
   every path, run a secret scan, and execute the surface's focused tests.
5. Keep the preservation branch unchanged. Put implementation and review in a
   separate PR.

The highest-value immediately recoverable work is the primary checkout
snapshot in `current-worktrees/main-uncommitted/`. It contains Intelwar
adjacent-surface changes and must pass the repository's adjacent-surface intake
and regression-firewall rules before integration.
