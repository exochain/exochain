---
name: verify-bcts-lifecycle
description: "Formally check that every EXOCHAIN BCTS path from Draft to Executed has passed identity, consent, deliberation, verification, governance, and approval. Use when a change touches BctsState::valid_transitions, BctsState::can_transition_to, or Transaction::transition."
---

# Verify the BCTS path to Executed

Every path from Draft to Executed passes IdentityResolved, ConsentValidated, Deliberated, Verified, Governed, and Approved first.

Harm: a skipped gate can execute a bailment without identity, consent, or governance.

The check explores every transition `Transaction::transition` accepts. The state space is the 14 `BctsState` values, so the exploration covers every reachable path, not a sample. It uses an adjudicator that allows every structurally legal transition, so a denial from the gatekeeper is outside this check.

## When a change touches this

Read the diff. The covered code is:

- `crates/exo-core/src/bcts.rs` — `BctsState::valid_transitions`, `BctsState::can_transition_to`, `Transaction::transition`

The harness is `crates/exo-core/tests/bcts_consent_before_execution.rs`, functions `explore` and `every_path_to_executed_passed_identity_consent_and_governance`.

Last confirmed at commit `2c5fac88f01435bd3cf1ba7d9ad5d324e1d020d8`. If a later commit changes any covered function, this verification needs another look. Move that commit forward only after you confirm the harness still calls `Transaction::transition` for every candidate successor of every reached state, and the command below passes on that commit.

## Run

From the repository root:

```bash
cargo +1.98.1 test -p exochain-core --test bcts_consent_before_execution
```

A passing run prints `1 passed`. The tool is this exhaustive test because the lifecycle is a finite function in Rust. A separate TLA+ copy would stay green when `valid_transitions` changes. The specs in `tla/` are not this check.

## Read a failure

- `path A -> B -> Executed reaches Executed without ...` is a bug in the state machine. The path is the sequence `Transaction::transition` accepted. Do not remove a gate from `GATES` to make it pass.
- `no path from Draft reaches Executed after ...` means the legal happy path is gone. Report that. Do not delete the requirement that Executed be reachable.
- `transition X -> Y failed outside the state machine` means the harness hit a clock, hash, or DID error. That is a harness failure, not a license to ignore the path.
- `transition to X left the transaction in Y` means `transition` reported success and stored a different state. That is a bug in `Transaction::transition`.

A broken `Draft` successor list that also allows `Executed` fails with:

`path Draft -> Executed reaches Executed without IdentityResolved, ConsentValidated, Deliberated, Verified, Governed, Approved`

That scratch edit was reverted. The checked code passes.

## Update an intended change

If the new edges still visit all six gates before Executed, re-run the command. On a pass, set the sync commit in this skill to the commit you just checked.

If the change is supposed to execute a bailment without one of those gates, stop and report the conflict. Change `GATES` only when the user explicitly accepts that constitutional change.

## Out of scope

One transaction. No receipt-chain check, no adjudicator denial, no concurrent transactions, and no edge that appears only after all six gates are already on the path. A new edge from Recorded back to Executed is not rejected by this check.

After merges that touch the covered functions without re-running this command, use `/maintain-formal-verification-skill`.
