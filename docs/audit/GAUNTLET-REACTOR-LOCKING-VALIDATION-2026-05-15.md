# Gauntlet F-153 Reactor Locking Validation

Date: 2026-05-15

## Classification

- Finding: F-153, reactor store/state mutexes have no documented lock-ordering
  invariant.
- Report source: imported evidence from `Exochain Gauntlet Findings`.
- Owned path reviewed: `crates/exo-node/src/reactor.rs`.
- Path classification: core runtime adapter.

## Current-Main Disposition

The finding is stale in current `main`. The reactor module now documents its
shared synchronous mutex model and the required critical-section discipline:

- `SharedReactorState` protects consensus state.
- `Arc<Mutex<SqliteDagStore>>` protects local DAG persistence.
- Async reactor paths must enter these mutexes only through
  `with_reactor_state_blocking` or `with_store_blocking`.
- Synchronous critical sections are moved onto `tokio::task::spawn_blocking`.
- Reactor workflows must never hold both mutexes at the same time.
- Workflows that need data from both sides must snapshot, release, then acquire
  the other mutex in a separate blocking section before async send, broadcast,
  or timer work.

## Verification Evidence

Commands run from `/Users/bobstewart/dev/exochain`:

```bash
cargo test -p exo-node reactor_documents_locking_model_and_single_mutex_sections -- --nocapture
cargo test -p exo-node reactor_async_store_access_uses_spawn_blocking -- --nocapture
cargo test -p exo-node reactor_async_state_access_uses_spawn_blocking -- --nocapture
```

All commands passed on current `main`.

## Source Evidence

`crates/exo-node/src/reactor.rs` includes source guards that:

- require the locking model documentation;
- require the single-mutex rule;
- require the safe snapshot/release/acquire workflow wording;
- reject direct async store mutex locking;
- reject direct async reactor-state mutex locking.

## Remediation Result

No production code change was required. The reported absence of a reactor
lock-ordering invariant did not reproduce against current `main`.
