# Gauntlet F-148 Consensus Liveness Validation

Date: 2026-05-15

## Classification

- Finding: F-148, consensus liveness assumptions undocumented.
- Report source: imported evidence from `Exochain Gauntlet Findings`.
- Owned paths reviewed:
  - `crates/exo-dag/src/consensus.rs`
  - `docs/guides/architecture-overview.md`
  - `tools/test_consensus_liveness_docs.sh`
- Path classification: EXOCHAIN core and EXOCHAIN core tooling/docs.

## Current-Main Disposition

The finding is stale in current `main`. The current DAG consensus documentation
states the liveness boundary explicitly:

- `exo-dag::consensus` documents that it does not implement leader election or
  view-change.
- Progress is conditional on eventual delivery of proposals and votes, quorum
  online validators, valid validator public-key resolution, and an outer reactor
  advancing rounds on the configured timeout.
- Permanent partitions, insufficient online validators, or missing validator
  keys preserve safety by refusing commitment rather than claiming progress.
- The architecture guide repeats the same boundary and avoids claiming HotStuff
  view-change behavior.

## Verification Evidence

Commands run from `/Users/bobstewart/dev/exochain`:

```bash
bash tools/test_consensus_liveness_docs.sh
cargo test -p exo-dag round_advancement -- --nocapture
```

Both commands passed on current `main`.

## Source Guard

`tools/test_consensus_liveness_docs.sh` fails if the architecture guide claims
`view-change on timeout` or describes current DAG consensus as a `BFT-HotStuff
derivative`. It also requires the architecture guide to contain `Current liveness
boundary` and the consensus module docs to contain `Liveness assumptions` plus
`does not implement leader election or view-change`.

## Remediation Result

No production code change was required. The reported absence of consensus
liveness documentation did not reproduce against current `main`.
