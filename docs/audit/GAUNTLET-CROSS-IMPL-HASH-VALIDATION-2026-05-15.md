# Gauntlet F-143 Cross-Implementation Hash Validation

Date: 2026-05-15

## Classification

- Finding: F-143, cross-implementation hash compatibility test absent.
- Report source: imported evidence from `Exochain Gauntlet Findings`.
- Owned paths reviewed:
  - `tools/cross-impl-test/compare.sh`
  - `tools/cross-impl-test/index.js`
  - `tools/cross-impl-test/compare_unit_test.sh`
  - `crates/exo-core/tests/cross_impl_hash_vectors.rs`
- Path classification: EXOCHAIN core tooling and EXOCHAIN core tests.

## Current-Main Disposition

The reported absence is stale in current `main`. The repository now includes a
cross-implementation canonical hash harness that:

- creates bounded default vectors when no vector directory is present;
- runs the Rust `exo-core` golden-vector test;
- runs the local Node.js vector checker over the same canonical CBOR bytes;
- rejects missing hash vectors;
- rejects placeholder harness language in `compare.sh`;
- compares two normalized Rust workspace test summaries for deterministic output.

## Verification Evidence

Commands run from `/Users/bobstewart/dev/exochain`:

```bash
./tools/cross-impl-test/compare.sh --verbose
bash tools/cross-impl-test/compare_unit_test.sh
```

The first `compare.sh` run inside the sandbox failed before hash-vector execution
because socket-backed `exo-node` tests returned `Operation not permitted`.
The same command was rerun with elevated permissions, and it passed:

- Rust workspace tests passed.
- Rust canonical hash vectors passed.
- Node canonical hash vectors passed.
- Rust/Node canonical hash vectors: 1/1 verified.
- Rust determinism was verified with two identical normalized test summaries.

`compare_unit_test.sh` also passed. Its output includes an intentional bad-vector
case where the harness reports `Rust canonical hash vectors failed`; the script
exits successfully only after confirming that failure is detected.

## Proof Gap

The external TypeScript `exo` implementation was not available in this checkout:
`compare.sh` warned that `EXO_TS_ROOT` was unset and skipped external TypeScript
repository tests. The current validation proves the owned Rust and local Node.js
hash-vector paths exist and execute; it does not prove compatibility with an
unavailable external repository.

## Remediation Result

No production code change was required. Generated `tools/cross-impl-test/vectors`
and `tools/cross-impl-test/results` artifacts from the local validation run were
deleted and were not committed.
