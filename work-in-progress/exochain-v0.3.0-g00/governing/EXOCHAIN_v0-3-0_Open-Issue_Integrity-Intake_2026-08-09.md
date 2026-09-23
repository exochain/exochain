# EXOCHAIN v0.3.0 open-issue integrity intake

Status: **DRAFT release-integrity intake; non-operative**

This record preserves a read-only snapshot of the open issues in
[`exochain/exochain`](https://github.com/exochain/exochain) and defines the
minimum disposition required before EXOCHAIN v0.3.0 may be represented as
release-ready. It does not modify an issue, authorize source development,
broaden G00, ratify a successor charter, or authorize publication or release
operations.

## Snapshot binding

- Snapshot date: `2026-08-09`
- Repository: `exochain/exochain`
- Default branch: `main`
- Observed `main` head:
  `86e9a029b7a62417b658b04d0def7a979e21fc8b`
- Open issue count returned by the read-only GitHub query: `4`
- GitHub mutations performed: `0`

The snapshot must be refreshed at the start of formal successor-plan authoring
and again immediately before any general-availability decision. Every issue
open in either refreshed snapshot must be explicitly classified and disposed;
no newly opened issue may be silently omitted.

## Required v0.3.0 issue dispositions

| Issue | Classification | v0.3.0 disposition | Release posture |
| --- | --- | --- | --- |
| [#789 — Block v0.2.2 publication until two-person release approval is enforced](https://github.com/exochain/exochain/issues/789) | EXOCHAIN release-control integrity | Rebind the control to v0.3.0 and prove two distinct approving principals, self-review disabled, and admin bypass disabled before any publication job can start. Preserve API readback and an actual stopped-then-approved dry-run trace. | `RELEASE_BLOCKER` |
| [#810 — CGR reduction traces are never produced](https://github.com/exochain/exochain/issues/810) | EXOCHAIN core evidence and admissibility | Implement a deterministic, replayable, canonical-CBOR CGR reduction trace and real bundle/reference/verifier path, or obtain a unanimous SPEC/QUAL/ADV/VER ruling that narrows the release claim and specification before release. The enterprise-class default is implementation, not silent claim reduction. | `INTEGRITY_REQUIRED` and blocking for any evidence-grade CGR claim |
| [#811 — ExoChained conformance contract pins 16 anchors](https://github.com/exochain/exochain/issues/811) | Imported external conformance contract affecting core/runtime-adapter boundaries | Review all nine requirements and 16 anchors against the frozen v0.3.0 candidate; adopt a repository-owned, versioned anti-drift contract or formally reject/correct each non-authoritative anchor with evidence. Test the final contract against the exact release commit. | `INTEGRITY_REQUIRED` |
| [#812 — exochain-core 0.2.3 does not build from crates.io](https://github.com/exochain/exochain/issues/812) | EXOCHAIN core packaging and downstream supply-chain integrity | Reproduce from a fresh downstream project without the workspace lockfile, write RED packaging/consumer tests, repair the dependency surface, and prove clean builds with and without a TLS consumer across the supported toolchain matrix. | `RELEASE_BLOCKER` |

## Mandatory tests-first acceptance evidence

### Issue #789 — two-person publication control

1. Preserve a read-only control-plane RED showing that the current release
   path can reach a publication gate without two independently enforced
   approvals, or showing the exact current missing protection.
2. Configure two genuinely distinct approvals through separately protected
   environments or an equivalent protection mechanism. A single one-of-many
   reviewer list is not two-person approval.
3. Prove self-review is unavailable and administrator bypass is disabled for
   both approval controls.
4. Demonstrate that a dry-run release cannot enter any publish job with zero or
   one approval and that the same frozen candidate can proceed only after two
   distinct principals approve.
5. Bind the repository, workflow commit, environment/ruleset configuration,
   actor identities, run identifiers, timestamps, and sanitized API readback
   into the release evidence package.

No live publication is required to prove this gate, and no publication is
authorized by this intake.

### Issue #810 — CGR evidence path

1. First reproduce that real combinator reduction produces no durable trace,
   no per-step invariant verdicts, no bundle-carried trace reference, and no
   verifiable kernel attestation.
2. Freeze RED tests for deterministic ordered step capture, invariant-result
   completeness, canonical serialization, replay identity, tamper rejection,
   bundle inclusion, event emission, signature verification, and fail-closed
   behavior when any required proof material is absent.
3. Implement the smallest canonical core path that causes the unchanged RED
   tests to pass. Do not replace the current fail-closed verifier with a
   hash-only or shaped-placeholder success.
4. Establish one authoritative expansion of `CGR` in the release contract and
   detect conflicting operative definitions.
5. Prove byte-identical traces and proof identifiers for identical inputs
   across repeated executions and supported platforms.

If implementation is independently found unsafe or constitutionally
incompatible for v0.3.0, SPEC-G00, QUAL-G00, ADV-G00, and VER-G00 must
unanimously bind the exact claim/specification reduction, and the release must
omit every claim that depends on an implemented CGR trace. Silence is not a
disposition.

### Issue #811 — conformance-contract ownership

1. Treat `apexvelocitycatalyst/exochained-toolkit` as imported evidence, not as
   authority to change EXOCHAIN.
2. Re-run every external anchor against the exact frozen v0.3.0 candidate and
   verify behavior, not only symbol presence.
3. Classify each anchor as the canonical enforcement boundary, an incidental
   implementation detail, or invalid. Record the rationale and owning test.
4. Place the accepted contract and anti-drift verification under an explicitly
   owned EXOCHAIN compatibility boundary, or publish a deterministic rejection
   mapping that the external contract can consume.
5. Prove fail-closed behavior for credential trust, subject-key binding,
   canonical action signatures, receipt success, governance validation,
   durability/timestamp requirements, DAG DB route use, and the WASM adapter.

### Issue #812 — published-crate consumer integrity

1. Reproduce the reported failure from a new empty Cargo project using the
   published dependency versions and no EXOCHAIN workspace lockfile.
2. Add a release test that packages the actual v0.3.0 crates, installs them
   through a local registry or equivalently isolated package source, resolves
   a fresh lockfile, and builds a minimal consumer.
3. Add an independent consumer that includes a normal `reqwest`/`rustls` TLS
   stack so a pre-release `pkcs8` family cannot be hidden by the workspace
   lockfile.
4. Test the supported minimum Rust version and the release toolchain. Record
   the full dependency tree and prove that no incompatible pre-release
   transitive edge is required.
5. Run the complete core crypto, identity, packaging, audit, deny, and release
   suites after the minimal dependency correction.

## Issue-completion rule

An issue's GitHub state is coordination metadata, not completion evidence. An
issue may be treated as addressed for v0.3.0 only when a frozen disposition
record binds:

- the exact issue URL and snapshot body hash;
- current-code reproduction against the authorized release branch;
- RED-first evidence where code changes are required;
- the exact implementing or claim-correcting commit;
- focused and full-suite verification;
- independent SPEC, QUAL, ADV, and VER decisions appropriate to the lane;
- release-note and claim-ledger consequences; and
- the final issue state read back from GitHub when GitHub operations are later
  separately authorized.

Closing, relabeling, or commenting on an issue does not satisfy these gates by
itself. Conversely, an issue may remain open for tracking after its v0.3.0
scope is resolved only if the frozen disposition identifies the remaining
non-release work and the Council unanimously finds it non-blocking.

## Global release gate

The v0.3.0 release decision must fail closed unless:

1. every issue in the opening and pre-GA snapshots has one frozen disposition;
2. every `RELEASE_BLOCKER` is fully satisfied;
3. every `INTEGRITY_REQUIRED` item is implemented and verified or has a
   unanimous, evidence-backed claim/specification disposition;
4. no issue was omitted because it lacked a label, assignee, milestone, or
   linked pull request;
5. GitHub, package registry, signing, deployment, and publication evidence is
   obtained only under the authority applicable to those external operations;
   and
6. the final release manifest names all issue dispositions and their evidence
   roots.
