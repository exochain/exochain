# EXOCHAIN AI Consensus

`exo-consensus` is the deterministic multi-model deliberation crate used by the
decision forum layer. It records structured model positions, computes convergence
from explicit key claims, runs optional devil advocate review, emits minority
report evidence, and hashes rounds/results with domain-separated canonical CBOR.

This crate is not a constitutional kernel and does not grant authority. It
produces deliberation evidence that must still be adjudicated by EXOCHAIN core
consent, authority, provenance, quorum, and gatekeeper paths before any governed
action proceeds.

## Runtime Contract

The public session flow is:

1. Construct a `Panel` for a `DecisionClass`.
2. Provide deterministic structured model responses through
   `DeterministicResponseProvider`.
3. Execute one or more rounds with caller-supplied nonzero HLC timestamps.
4. Finalize with caller-supplied nonzero HLC completion time.
5. Treat the `DeliberationResult` as evidence, not executable authority.

The session fails closed when required structured evidence is missing or invalid:

- missing model response;
- empty `position_text`;
- empty explicit `key_claims`;
- `confidence_bps` above 10,000;
- missing required devil advocate review;
- serious devil advocate objection without reasons;
- finalization before any round;
- missing or empty synthesis evidence;
- zero or inconsistent caller-supplied timestamps;
- count conversion overflow.

## Deterministic Evidence Model

All scoring input must be structured before it enters this crate. The crate does
not parse free-form model prose into claims. Each `ModelDeliberationResponse`
provides:

- `position_text`;
- explicit `key_claims`;
- `confidence_bps` in basis points.

Claim sets are canonicalized by trimming, lowercasing, sorting, and
deduplicating through `BTreeSet`. Empty claims are removed. All map-like
containers use deterministic ordering. No floating-point arithmetic is used;
scores are integer basis points in the range 0 through 10,000.

Round and result hashes are computed through `exo_core::hash::hash_structured`
with explicit domain tags:

- `exo.consensus.model_response.commitment.v1`;
- `exo.consensus.deliberation_round.v1`;
- `exo.consensus.deliberation_result.v1`.

Serialization errors propagate as `ConsensusError::HashSerialization`; the hash
path must not fall back to JSON, empty bytes, or `Hash256::ZERO`.

## Convergence

`calculate_convergence` compares canonical key-claim sets:

- empty input returns `0`;
- all-empty claim sets return `0`;
- one non-empty position returns `10,000`;
- multiple positions score `shared_claims * 10,000 / total_unique_claims`.

`consensus_claims_at_threshold` returns the canonical claims whose support
across models meets the panel threshold.

## Panel Confidence Index

The panel confidence index is an integer basis-points score with three weights:

| Component | Weight | Calculation |
|---|---:|---|
| Model agreement | 5,000 | agreeing panelists divided by total panelists |
| Speed of convergence | 3,000 | faster convergence across `max_rounds` earns more credit |
| Devil advocate | 2,000 | awarded only when no serious objection is found |

The implementation clamps malformed inputs so the panel confidence index cannot
exceed 10,000. `minority_reports_count` reduces the agreeing-panelist count at
finalization.

## Minority Reports

A minority report is produced when a model position lacks enough consensus
claims to meet the panel threshold. The report records:

- dissenting model ID;
- round number;
- dissenting position text;
- missing structured consensus claims;
- divergence score in basis points.

Empty consensus-claim sets do not produce minority reports because there is no
structured majority evidence to compare against.

## Trust Boundary

`exo-consensus` may help rank and explain deliberation evidence, but it cannot:

- mint consent records;
- expand actor permissions;
- satisfy quorum by itself;
- sign DAG consensus votes;
- bypass gatekeeper invariants;
- replace human override or constitutional adjudication.

Any caller that exposes this crate over an API, MCP tool, UI, or automation must
label its output as deliberation evidence and must fail closed if the downstream
EXOCHAIN core authority path rejects, times out, or is unavailable.
