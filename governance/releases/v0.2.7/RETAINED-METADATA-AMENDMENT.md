# EXOCHAIN 0.2.7: unavailable-original-metadata custody amendment

Date: 2026-09-25. Status: independently technically reviewed design awaiting
human approval, not implemented.

## 1. Decision and authority

Bob authorized preparation and independent technical review of this amendment
by replying “fuck. yes” to the request to prepare a separately reviewed plan for
unavailable original metadata, without rebuilding or republishing packages.
That response does not approve this as-yet-unreviewed written design,
implementation, integration, a tag, another execution, live completion, or
retirement. This document is the planning deliverable. No code or existing
custody record is changed by it.

The decision requested is whether to accept a tightly bounded loss of **fresh
original metadata visibility** for the four fixed records below. Their
historical identities would instead be established by the already pinned,
pre-expiry custody archive, while their present unavailability is recorded
honestly. This is a changed evidence requirement, not a repair that preserves
the old requirement, and not proof that GitHub deleted records because of expiry.

Recommendation: add the explicit operation `recover-0.2.7-retained-404`, backed
by a separately pinned metadata policy. Reuse the canonical retained importer,
verifiers, producer, and GitHub writer. The existing `recover-0.2.7` and
`recover-0.2.7-retained` operations keep their current behavior, including
rejection of unavailable original metadata. There is no automatic fallback.

## 2. Observed failure and evidence limits

Retained dry run [36091900371](https://github.com/exochain/exochain/actions/runs/36091900371),
attempt 1, executed controller `4ebfee81fe2a49bb32f0cf2a70b6775e8ae5c289`
on `v0.2.7-recover.3`. It completed with failure, updated at
2026-09-25T18:22:24Z: 41 successful jobs, one failed job, 28 skipped jobs.
Both genuine protected approvals and hosted signed-tag verification succeeded.
The approval API records Max (`mstewartbz`) and Robert (`robst3w`) but supplies
no approval timestamps; gate execution times are not approval timestamps.

Acceptance job 108195931992 logged at 18:22:20Z:

```text
release recovery import failed: unexpected provider HTTP status
```

The log does not identify the failed endpoint or HTTP status. Independent
configured-CLI reads observed at 18:26:07 UTC returned 404 for the four original
metadata IDs in section 4 and 200 for the other five originals. Both retained
metadata records returned 200 and exactly matched their entire pinned,
nonexpired records. This establishes a current mandatory prerequisite failure;
it does not prove which request failed inside the hosted job. The current
receipt upload and all package/GitHub writer jobs were skipped. The complete
nine-artifact inventory contained no retained acceptance receipt. The dry run
is not accepted and must not be rerun unchanged.

Source confirms the contract: `fetch_origin_records` in
`tools/import_release_recovery_027.sh` fetches all nine original records;
`verify_retained_origin` in `tools/verify_release_recovery_027.py` requires all
nine, allowing only the current `expired` field to differ from history. The
live GitHub writer imports that same acquisition code. Relaxing only the
producer would leave the writer inconsistent and is expressly insufficient.

GitHub documents Actions read permission for artifact metadata. Its documented
410 response belongs to the archive download endpoint, not a license to accept
410 from metadata. A 404 remains ambiguous, including possible access
concealment. See [GitHub artifact REST documentation](https://docs.github.com/en/rest/actions/artifacts?apiVersion=2022-11-28#get-an-artifact).
No alternate credentials, hosted-token extraction, or protected retry is part
of this amendment.

## 3. Alternatives and residual risk

| Alternative | Consequence | Disposition |
| --- | --- | --- |
| Keep the current contract and stop | Preserves fresh comparison of all nine originals; recovery cannot proceed while four remain unavailable. | Safe baseline if this amendment is rejected. |
| Explicit fixed-four exception with authenticated retained history and fresh current observations | Removes fresh immutable-field comparison only where an approved ID returns 404 after its recorded expiry; retains every other acceptance gate. | Recommended, subject to human acceptance of that evidentiary loss. |
| General post-expiry fallback, silent substitution, or broader credential search | Could conceal unrelated access failures, conflicts, or disappearing records; could silently expand authority. | Rejected. |

Even with successful positive controls, the proposed path cannot determine why
the four requests return 404 or freshly detect changes to unavailable metadata.
It cannot claim uninterrupted provider metadata visibility. The retained
payload contains 40 extracted original files, **not** the seven original ZIP
envelopes or either Rust preparation ZIP. Their original envelopes cannot be
freshly rehashed from this transport, and the missing Rust reproduction archive
cannot be reconstructed by this plan. Historical producer evidence and current
retained-byte/native/publication checks are distinct evidence layers, not
equivalent claims. A human who requires fresh availability of all original
records should reject this amendment and leave release completion stopped.

## 4. Exact scope and immutable evidence basis

Only these four original metadata IDs may return 404 in the new operation:

| Original artifact | ID | Recorded expiry (UTC) | SHA-256 of historical metadata member |
| --- | --- | --- | --- |
| WASM npm | 10518086890 | 2026-09-24T20:09:34Z | `23a1d7f70d0da078e712fe0844f5c52101cd9b03e510941f6c758508a6e73245` |
| Native x86_64 | 10518128532 | 2026-09-24T20:19:17Z | `d465cde79dd2ecd25a46cf065841a5d8eef5792f8a0d91bdf70c10a888caf93d` |
| Native aarch64 | 10517978596 | 2026-09-24T20:19:29Z | `dcec5cb76b7875501c83c343957a4ccded7501142d009412e54ce82d517531ad` |
| Rust reproduction preparation | 10517854663 | 2026-09-24T20:24:33Z | `ea27bd26387b0335aa33a9931d432a749ed834222ffd085d370bd1d7d1a26bf9` |

Each member is `artifact-metadata/<ID>.json` in fixed custody artifact
10780480598. The other five IDs—10517981432, 10518080916, 10517457207,
10517966616, and 10517459550—must still return 200 and match. A fifth missing
record is a stop, not an extension of this policy. Any subset of the approved
four can be unavailable; all nine returning exact 200 is also valid.

Keep all three existing owned records and their semantic pins unchanged:

| Record | Existing semantic SHA-256 |
| --- | --- |
| `RECOVERY-MANIFEST.json` | `17c77eafa0ea34fa7437cbc0d6988f561d686e330bee8c17cfe0e6a354e1bec4` |
| `PUBLICATION-IDENTITIES.json` | `4596c339d2af34ce3aeff5f2dd4a6be95fbb044250e934a27221170b97902ca7` |
| `RETAINED-CUSTODY.json` | `7f2eac05d0fea00a29a1ea3ebf7605eee7ab66905a40d8e016ef50510c2c038a` |

Proposed new owned record: `RETAINED-METADATA-POLICY.json`, schema
`exochain-retained-metadata-policy-027/v1`. It binds the new operation, these
three semantic pins, repository identity, exactly the four IDs/member hashes/
recorded expiries above, original attempt 1, retaining attempt 1, and the two
fixed retained artifact IDs. Its full strict schema and independently embedded
semantic digest must cover every nested field. The digest is calculated from
the actual reviewed record during implementation; no fabricated digest is
presented here. Unknown keys, wrong types, duplicates, reordered identity
inventories, caller-supplied IDs, or an operation/policy mismatch fail. The
unchanged retained record's old `mode` describes that historical record; it
does not implicitly enable the exception. The new policy explicitly composes
with it. No environment flag can widen the four-ID set.

The retained inputs remain exactly:

| Input | Artifact ID | Bytes / outer SHA-256 | Expires (UTC) |
| --- | --- | --- | --- |
| Original extracted files | 10779404529 | 147126946 / `eb4138638b9305b406fb50f5e49e205982611af6bcba9aedf92bb34dd7d06b5a` | 2026-09-30T22:33:27Z |
| Historical custody evidence | 10780480598 | 81581 / `1eb8514f9ead70a13e6e1c620d69c359cdb77a332772f400f9ca104ac30a2bb3` | 2026-10-23T22:33:31Z |

Both require fresh entire metadata equality and `expired=false`, plus current
time strictly before expiry. No retention extension, alternate artifact,
expired-original archive access, new payload transport, or local-file fallback.
The payload expiry is the effective earliest deadline, not a deadline that can
be waived if review or approvals take longer.

## 5. Canonical acquisition and observation contract

### 5.1 Historical identity is validated, not invented

Use the existing strict ZIP parser on newly downloaded fixed retained archives
in actual execution. Keep exact outer digests/sizes, bounded streaming,
40 payload members and 60 custody members, exact path/mode/compression/member
hashes, signed 32-bit data descriptors and all existing anti-ambiguity checks.
No ZIP repacking or archive execution. Empty historical command outputs remain
empty historical evidence, not cryptographic proof.

Run the unchanged historical-origin verifier on all nine authenticated
historical metadata records, original run 35257955565 attempt 1, its complete
62-job inventory, 57 required successful jobs including 35 CI jobs, and the
original producer identities. Independently fetch the current explicit
attempt-1 run/jobs and verify the same required identity/completeness/success
facts. Do not accidentally read original attempt 2, which was canceled.

Freshly verify retaining run 35754493083 attempt 1 and its complete 68-job
inventory, pinned controller `2198e4ef610e9ef6d04adf726f7f4b3e156a3bc1`,
`v0.2.7-recover.2` tag object, workflow bytes, and successful producer
107409656991. Its import ended 2026-09-23T22:33:27Z, before original expiries;
payload upload ran 22:33:27–22:33:30Z and custody upload 22:33:30–22:33:32Z.
Validate actual step ordering and artifact creation chronology, not just these
quoted times. The retaining run's later overall failure remains a failure;
only the successful relevant producer is accepted. Original, retaining and
current controller/tag identities and applicable genuine signatures remain
mandatory. Historical receipt text is not fresh native/package crypto proof.

### 5.2 Current observations are a distinct, typed record

Add one scoped original-metadata fetch routine to the canonical transport. Do
not make the generic GET or archive methods accept 404. The routine constructs
only the nine fixed original metadata URLs internally, uses the normally
configured job credential, and records the actual HTTP status from transport,
not a JSON field or caller assertion. Keep existing response-size, header,
timeout, no-redirect, private-file and credential-stripping safeguards.

Each ordered original observation contains its fixed ID, endpoint role,
request-start/request-finish UTC times, actual status, and exactly one variant:

- `present`: HTTP 200 and the actual parsed current metadata. Compare all
  fields with the authenticated historical object, with only the existing
  strictly boolean `expired` exception. A malformed or conflicting 200 is a
  failure; never downgrade it to unavailable.
- `unavailable_404`: HTTP 404, allowed only for a policy-listed ID when request
  start is at or after its pinned historical expiry. Bind the historical
  member/hash separately. There is **no current metadata object** and no
  invented current `expired` value. State only that historical expiry elapsed
  and the current authenticated request returned 404.

Reject every other status, including 401, 403, 410, 429 and 5xx, redirects,
timeouts, truncated/ambiguous status, duplicate fields, malformed timestamps,
wrong IDs or a ninth-record omission. A 404 body is not metadata and confers
no authority; discard it within the existing bounded transport lifecycle.
Diagnostics expose only endpoint role, fixed numeric ID and status/failure
class. Never log tokens, authorization/config input, headers, response bodies,
redirect locations, signed blob URLs, or arbitrary exception strings.

These timestamps are operational evidence, not Rust governance-runtime time.
Capture them in the hosted acquisition process under the actual in-progress
job and current-run identity; reject reversed or future times. Do not require
the current job to have completed while it is capturing observations. Later
receipt consumption or independent dry-run inspection binds producer times to
its authoritative successful job/import-step completion and upload chronology.
For v2, finalize `checked_at` after the last successful observation/check and
require all producer observations to finish no later than `checked_at`, which
must precede or equal upload start. Validate writer capture against its actual
in-progress identity, then its completed-job chronology at independent final
acceptance. The new code must not introduce system time into production Rust
governance logic. Test code supplies deterministic operational timestamps.

### 5.3 Positive controls, freshness and transition handling

At the start and end of each full acquisition, fetch the explicit original and
retaining run/job inventories and both retained metadata objects with the same
credential as the original observations. All must return 200, satisfy their
existing identity contracts and be complete. Read all nine originals before
and after the expensive acceptance checks. Require the same normalized
availability/identity vector across the two observations; retained metadata
must remain exactly pinned and nonexpired. The other five exact 200 records
provide additional controls. A successful control does not prove that an
individual 404 means deletion; the residual ambiguity remains disclosed.

Do not carry local diagnostic observations into a hosted run. Do not retry a
failed status until it happens to pass. Bound request loops to the fixed
inventories and the existing complete-pagination limits; rate limiting or
timeouts stop acceptance, not authorize more credentials or larger bounds.

The read-only producer emits acceptance only after the final fresh observations,
all current crypto/public checks and source/file rechecks pass. The live-only
writer uses three explicit stages, reusing the canonical receipt routines:

1. Validate the direct handoff against actual writer run/attempt/controller/
   operation/policy context and authoritative successful producer/upload plus
   current artifact metadata. This is preliminary provenance validation, not
   full receipt acceptance and not permission to publish.
2. Perform canonical writer acquisition to obtain independently validated
   historical evidence and fresh current observations.
3. Validate the actual receipt ZIP bytes and strict members, producer raw
   observations/chronology and every expected binding against that authenticated
   history. Compare the producer-final normalized vector to the writer's
   vector. Only then permit fresh public acceptance/readback and the separately
   authorized mutation boundary.

Factor shared validation where necessary; do not fabricate an origin input to
make stage 1 call a verifier that requires stage 2 evidence. Any 200-to-404 or
404-to-200 transition, including otherwise eligible IDs, stops this execution
before further writes;
neither stale observations nor a newly enlarged exception set are acceptable.

Preserve the writer's existing `rebind()` calls before each mutation and at
final readback. Extend them to freshly read both retained metadata objects and
all nine original observations, verify the same normalized vector and ensure
retained nonexpiry/source/file identity. Full run/job controls are required at
writer acquisition and final acceptance; unchanged explicit run/job identity is
also rechecked if a rebind encounters any mismatch, without attempting the
pending write. No retry or continuation follows that mismatch. This is a
bounded sequence of reads for at most the existing 35 assets, not a monitoring
loop. A final failure after earlier successful writes leaves an accurately
journaled partial/uncertain completion and stops; it does not roll back,
overwrite, republish, or silently resume.

## 6. Receipts, public disclosure and permissions

Use a versioned current observation schema
`exochain-retained-original-observations-027/v1` and a new current acceptance
binding profile `retained-027/v2` for this explicit operation only. Require
both custody and acceptance receipt members to agree on the exact operation,
policy digest, actual run/attempt/controller/ref/tag, original/retaining
identities, and normalized vector. Reject v1 as authorization for the new
operation and v2 for either old operation. Strict keys/types, bounded sizes,
canonical serialization and existing digest conventions remain enforced.

The normalized vector includes fixed ID, availability variant/status,
historical member hash, and, for 200, the digest of actual current metadata.
It deliberately excludes per-request timestamps. Full raw observations remain
in the two-member current receipt with producer chronology and are validated
individually, including the later successful producer/upload API evidence.
Writer observations are separately recorded with writer chronology. Compare
stable bindings across jobs, not newly generated timestamps;
never drop the timestamp validation merely to make receipts compare equal.

Keep the existing direct producer upload handoff: actual artifact ID/digest
from this run and attempt, exact two receipt members, successful producer and
upload step chronology, current artifact metadata identity/size/digest and
nonexpiry. No lookup-by-name fallback, historical receipt, agent verdict or
local check substitutes for it. A failure produces no success acceptance
receipt. Do not reuse the absent receipt from run 36091900371.

For the new operation, version the stable public `RECOVERY-CUSTODY.json` to
`exochain-release-retained-custody/v2`, adding the new policy identity and
explicit disclosure that four selected post-expiry original metadata records
may be unavailable and historical identity is not current metadata visibility.
Bind this policy in the release body as well. Do not embed per-run status,
timestamps or fresh observations into this stable public asset. Keep the
two-native + 32-SBOM + custody = **35** asset inventory and exact no-overwrite
rules. If an existing release/body/asset conflicts with the newly expected
identity, stop. This design does not authorize modifying a conflicting public
release. Old-operation v1 public output remains unchanged.

The producer runs both in dry and live with contents/actions/attestations read
only, no package credential or OIDC, and no GitHub writer path. The writer is
live-only, contents write/actions read, without package credentials/OIDC.
Signed controller verification, full reusable CI, genuine `release` approval
by Max and `release-second` by Robert or tazmon95 remain mandatory, with
self-review prevented and admin bypass disabled. Prior run approvals are not
automatically approval of a new run or this amendment.

Every execution still verifies both native attestations, all five public
package files with genuine crypto and exact mapped publisher identities,
all 32 Rust versions/checksums/nonyanked state, package structures, public
bytes and owners, and exact GitHub preflight/final readback. No build/repack/
upload of any package; reusable CI still builds/tests source. Unknown external
write outcome stops subsequent writes and requires independent reconciliation.

## 7. Implementation boundaries after written design approval

All proposed policy, tooling, workflow, test and governance paths are
**EXOCHAIN core**. Retained ZIPs, provider responses and logs are **imported
evidence**, read-only and never committed as source. No adjacent surface,
Rust product code, dependency lock, runtime adapter or retirement workflow is
in scope. Search the canonical implementations before adding any helper;
this design does not authorize a second importer or verifier.

The dependency-ordered implementation units, each requiring regression tests
and independent technical review, are:

1. New strict policy and observation contracts in
   `tools/verify_release_recovery_027.py`, owned new policy record, and
   `tools/test_release_recovery_027.py`. Preserve existing three records and
   original/v1 validator behavior. Introduce scoped reusable validation, not a
   broad missing-field allowance.
2. Canonical scoped transport/acquisition and bounded safe diagnostics in
   `tools/import_release_recovery_027.sh`, with executable transport tests in
   `tools/test_import_release_recovery_027.py`. Reuse existing public/native
   acceptance helpers; explicit new-mode plumbing in `run_release_recovery_027.sh`,
   `verify_release_recovery_027.sh`, `publish_release_npm_package.sh`, and
   `recover_release_python_027.sh` must remain acceptance-only, not publication.
3. Versioned current receipt/live rebind/stable public disclosure in
   `tools/recover_github_release_027.py` and its tests; dispatch option,
   validation, source capture, conditional jobs and direct receipt outputs in
   `.github/workflows/release.yml`. Reuse retained jobs rather than duplicate
   the DAG. Extend workflow/ref-binding/credential-boundary guards for the new
   exact operation. Every call site comparing operation or schema must be
   enumerated and tested, including no-write dry behavior.
4. Reconcile current recovery design/plan/validation/test documentation with
   this explicit exception, preserving historical failures and the old mode's
   strict contract. Run full validation and whole-change independent review;
   obtain two genuine non-author exact-final-head maintainer approvals and
   exact-head hosted CI before normal integration. Verify integrated tree and
   signature before requesting separately applicable execution authority.

Approval of this written design permits preparation of the detailed
implementation plan. The human reviews that plan and selects its execution
method before implementation and reviewed PR preparation start. Neither
planning approval substitutes for exact-head human reviews, protected
approvals, or separately applicable release execution authority. No approval
is claimed by this document's creation or agent review.

## 8. Test and acceptance plan

Write the negative/positive regressions before changing each enforcement
boundary; observe their real failures, then implement and observe passes.
Fixtures prove parser/control behavior, never production crypto or publication.

| Boundary | Required positive checks | Required rejection checks |
| --- | --- | --- |
| Policy/activation | Explicit new operation, all nine 200; each eligible ID alone 404; all four 404 | Any fifth ID, arbitrary policy/ID, missing or extra key, bool-as-integer, duplicate ID, wrong digest, old-operation activation, policy tampering |
| Transport/status | Actual bounded 200 metadata and actual allowed 404 with five positive original controls | 200 JSON claiming 404, redirect, 401/403/410/429/5xx, timeout/truncation, unbounded body/header, malformed status, credential or signed-URL leakage; 404 in retained/run/jobs/receipt/registry endpoints |
| Time/observations | Requests after each historical expiry and within actual hosted job; exact stable before/after vectors | Early 404, inverted/future/out-of-job time, copied old observations, clock/chronology conflict, omitted record, 200 conflict, invented metadata for 404, 200/404 transition |
| Historical custody | Actual pinned two ZIPs, 40 payload/60 evidence members, all nine historical metadata, original and retaining explicit attempts and complete jobs | Altered ZIP/member/hash/profile, original or retaining SHA/ref/tag/attempt/step mismatch, incomplete or duplicate jobs, false producer success, pre-expiry chronology failure, unpinned retaining workflow |
| Retained lifetime | Both entire pinned metadata before/after and current bytes exact/nonexpired | Either missing/expired, changed expiry/size/digest/identity, time equal to or beyond expiry, local/alternate artifact fallback |
| Receipt separation | Current same-attempt direct upload ID/digest; different genuine per-job timestamps with equal normalized binding | Replay across attempt/run/controller/ref/operation/policy; name-only selection; failed producer/upload; wrong upload chronology; v1/v2 confusion; changed vector or missing observation; forged crypto success |
| Writer/no-write boundaries | Same canonical producer/writer rules, fresh writer public checks, 35 exact assets, journaled completion | Writer on dry, package credential/OIDC, build/stage/publish route, bad receipt before public/writer calls, changed metadata immediately before any write, existing conflicting asset/body, unknown mutation followed by another write |
| Compatibility | All existing original/v1 positive suites and normal publication control tests still pass | Both old recovery operations continue rejecting unavailable original metadata; no broadened generic GET or archive behavior |

Focused suites include the existing `tools/test_release_recovery_027.py`,
`tools/test_import_release_recovery_027.py`,
`tools/test_recover_github_release_027.py`,
`tools/test_release_recovery_workflow.py`, and the existing npm/Python,
signature, workflow-ref-binding, credential and receipt boundary guards.
Derive the exact complete command inventory from the final source and CI;
do not copy the prior 84-command result as a result for new code.

Run all required core build/debug+release test/clippy/dated-format/audit/deny/doc
and cross-implementation gates, every CI-derived Python suite and shell guard,
and actual new/legacy npm runtime contracts. Every Cargo-invoking command,
including nested fixture commands, uses `CARGO_BUILD_JOBS=2`,
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, `CARGO_PROFILE_RELEASE_DEBUG=0`; maintain at least
4 GiB free. Preserve generated test evidence outside the checkout without
altering SBOM guards. Record ignored tests and cross-implementation scope
honestly; local checks do not replace Linux coverage or hosted provider proof.

After legitimate reviewed integration and separate execution authority, a new
unused signed maintenance tag on the verified integrated controller can run
the explicit new operation in protected dry mode. Independently inspect the
complete same-attempt job inventory, signed tags, actual typed observations,
current native/all-five-public crypto and 32 Rust checks, exact direct hosted
receipt ID/digest/bytes and successful producer/upload chronology, with
`dry_run=true`, `mutation_attempted=false`, and writer jobs skipped. A green
workflow without these receipts is not dry acceptance. Only after complete
dry acceptance request applicable live authority; only after complete live
provider/GitHub acceptance consider separately authorized retirement.

## 9. Planning validation and handoff

This design was prepared in the existing worktree at
`a97d66fca28fc66e01bd3394af807768a5856d96`, tree
`8db54df8f4bc57a7b00936eece2a03766f7548b1`, which is also the reviewed
integrated controller's tree. The original dirty checkout was not used.

Main and an independent evidence auditor read and rehashed the actual retained
ZIPs already preserved for planning. Main additionally ran the unchanged
`verify_retained_zip` on both profiles and `read_historical_custody`: 40 payload
members and 60 custody members passed; historical origin reports seven artifact
and two Rust-preparation identities, 57 successful required jobs and 35 CI jobs.
Its `current_crypto_verified` result is **false**. This is a read-only planning
check of preserved bytes, not a fresh download, a current hosted acceptance
receipt, a fresh crypto run, or an execution fallback.

The failure snapshot and raw job logs are preserved in the ignored existing
ledger `.superpowers/sdd/RETAINED-RECOVERY-PLAN/`; its progress record tracks
source/evidence audits and the separate whole-design review. No implementation
tests are claimed for this document-only change. Prior failed runs, genuine
approvals and publication evidence retain their actual chronology and meaning.

Independent whole-design review by `missing_metadata_design_review` found no
Critical or Important blocker. Its two nonblocking clarifications—staged
receipt validation and in-progress observation capture versus completed-job
validation—were incorporated and independently confirmed resolved. The review
examined this full document, the canonical retained plan and actual relevant
source/test boundaries. It made no edits or execution requests. The report is
preserved in the ignored ledger as `missing-metadata-design-review.md`.
This is technical review, not human design approval or release authorization.
