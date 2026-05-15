# Gauntlet F-152 Combinator Architecture Remediation

Date: 2026-05-15

## Classification

- Finding: F-152, combinator enum names mismatch `ARCHITECTURE.md`.
- Report source: imported evidence from `Exochain Gauntlet Findings`.
- Owned paths changed:
  - `docs/architecture/ARCHITECTURE.md`
  - `tools/test_architecture_combinator_alignment.sh`
- Path classification: EXOCHAIN core documentation and EXOCHAIN core tooling.

## Current-Main Disposition

The finding reproduced on current `main`. `docs/architecture/ARCHITECTURE.md`
described an S/K/I/B/C basis and propositional operators that are not the
current `exo-gatekeeper::Combinator` enum. The implemented engine exposes:

- `Identity`
- `Sequence`
- `Parallel`
- `Choice`
- `Guard`
- `Transform`
- `Retry`
- `Timeout`
- `Checkpoint`

## Remediation

The architecture document now describes the implemented, bounded
governance-oriented combinator algebra and its deterministic reduction
semantics. It no longer claims the current engine is an S/K/I/B/C basis or that
`NOT`, `AND`, `OR`, `IMPLIES`, `FORALL`, `EXISTS`, `EQUALS`, `LESS_THAN`, `GTE`,
and `LOOKUP` are implemented combinator terms.

`tools/test_architecture_combinator_alignment.sh` was added as a source guard.
It requires the architecture guide to document every implemented combinator term
and rejects the stale S/K/I/B/C and propositional-operator descriptions.

## TDD Evidence

The new guard was added before the documentation fix and failed with:

```text
ARCHITECTURE.md must document implemented combinator term: Identity
```

After the documentation update, the guard passed.

## Verification Evidence

Commands run from `/Users/bobstewart/dev/exochain`:

```bash
bash tools/test_architecture_combinator_alignment.sh
cargo test -p exo-gatekeeper combinator -- --nocapture
```

Both commands passed after remediation.
