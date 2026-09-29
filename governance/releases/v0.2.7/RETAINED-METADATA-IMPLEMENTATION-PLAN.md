# Retained Missing-Metadata Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Execution approval:** Bob directly said “plan approved with subagents” on September 26, 2026. This approves the reviewed plan at SHA-256 `862d93aabc22c9895e9b77946a02017170601cf86af32ef3c77433ce3595b38d` for subagent-driven implementation and reviewed PR preparation. The prior planning-only wording below is historical and superseded for that scope only. No release tag, dispatch, live publication or retirement authority is granted. Execution ledger: `.superpowers/sdd/RETAINED-METADATA-IMPLEMENTATION-PLAN/progress.md`; prior planning and release evidence stays preserved in its original ledger.

**Implementation snapshot — September 26:** Tasks1–3 are implemented, independently reviewed with their findings resolved, locally unit-validated and signed. The four operating-document changes in Task4 Step1 are independently reviewed. To satisfy the exact clean signed-source and unchanged SBOM gates, the complete documentation candidate is signed before the final full validation, fresh read-only evidence and whole-change review. Those later checks and the reviewed PR/CI/human gates remain unchecked in this source snapshot; their actual results and exact eventual head/tree are recorded in the preserved execution ledger and self-contained PR handoff. Any later source correction requires a newly reviewed candidate and complete validation again. No future pass, current hosted receipt or release acceptance is asserted by this snapshot.

**Goal:** Implement the approved, explicitly selected four-ID missing-metadata policy without rebuilding or republishing packages, while retaining current custody, cryptographic acceptance, and protected GitHub completion.

**Architecture:** Extend the canonical retained verifier, importer, package acceptance helpers, and existing retained workflow jobs. Keep historical metadata separate from typed current observations; authenticate the direct receipt handoff before writer acquisition, then validate receipt bytes and compare stable identity vectors before public checks or writes. Both older recovery operations retain their exact strict contracts.

**Tech Stack:** Existing Python 3.13.7 verifier/importer, Bash dispatch and credential boundaries, Node 24.15.0/npm 11.12.1 public verification, GitHub Actions, and existing unittest/shell regression suites. No new dependency or production Rust change.

**Spec:** [RETAINED-METADATA-AMENDMENT.md](RETAINED-METADATA-AMENDMENT.md), approved by Bob's direct “approved” on September 25, 2026, following the status handoff that explicitly described design approval as permission to prepare this detailed plan. Approved bytes: 29009; SHA-256 `a96a3900660d63ea53e90b39daac8efb3db7b5d5137072f7e17478f59d50f5f3`. Preserve those bytes; the design's original awaiting-approval wording is historical.

## Global Constraints

- **Current authority: detailed planning only.** This plan is not implemented or approved for execution. Human review of this plan and selection of execution method precede implementation and reviewed PR preparation. No commit, push, PR mutation, integration, tag, rerun, dispatch, live release, or retirement is authorized by the design approval.
- Use only `/Users/bobstewart/.codex/worktrees/exochain-release-0.2.6-security-remediation`, branch `bob-stewart/release-0.2.7-token-contract`, planning HEAD `a97d66fca28fc66e01bd3394af807768a5856d96`, tree `8db54df8f4bc57a7b00936eece2a03766f7548b1`. Preserve the dirty original `/Users/bobstewart/dev/exochain`. No new worktree, build copy, or branch switch.
- New operation: `recover-0.2.7-retained-404`; version: `0.2.7`. Old operations `recover-0.2.7` and `recover-0.2.7-retained` remain strict. No automatic fallback or general “allow missing” flag.
- No package rebuild, repack, staging, upload, republication, alternate artifact, local payload fallback, new payload transport, retention extension, expiry waiver, protected credential extraction, protection change, impersonation, or existing-tag move.
- All proposed owned paths are **EXOCHAIN core**. ZIPs, provider responses and logs are **imported evidence**, read-only and never committed as source. No adjacent surface, runtime adapter, product Rust, dependency lock, or retirement workflow change.
- Preserve the three existing records and semantic pins: manifest `17c77eafa0ea34fa7437cbc0d6988f561d686e330bee8c17cfe0e6a354e1bec4`; publications `4596c339d2af34ce3aeff5f2dd4a6be95fbb044250e934a27221170b97902ca7`; retained custody `7f2eac05d0fea00a29a1ea3ebf7605eee7ab66905a40d8e016ef50510c2c038a`. Their existing schema/mode values do not change.
- Retained payload ID **10779404529**, 147126946 bytes, SHA-256 `eb4138638b9305b406fb50f5e49e205982611af6bcba9aedf92bb34dd7d06b5a`, expiry **2026-09-30T22:33:27Z**; custody ID **10780480598**, 81581 bytes, SHA-256 `1eb8514f9ead70a13e6e1c620d69c359cdb77a332772f400f9ca104ac30a2bb3`, expiry **2026-10-23T22:33:31Z**. Both entire metadata records must remain exact, nonexpired and strictly before expiry at every required check.
- Preserve the strict 40-member payload/60-member custody ZIP profiles, all nine authenticated historical metadata records, original run **35257955565 attempt 1** (62 jobs, 57 required successful including 35 CI), and retaining run **35754493083 attempt 1** (68 jobs), including successful producer **107409656991** and its actual import/upload chronology. Later overall failure is not relabeled.
- Preserve original/retaining/current source and tag verification and configured signer `96B889DAE73CD7C511CCDE28897119B7198789EC`. Do not spoof source/ref/job identity. Operational evidence uses strict UTC seconds, not production Rust system time.
- Genuine native attestations for both archives, all five public package-file crypto checks and mapped identities, all 32 Rust checksums/nonyanked versions, exact bytes/owners/structures, and GitHub preflight/final readback remain required. Fixtures and historical/local evidence are not current hosted acceptance.
- Preserve exactly **35** GitHub assets: two native archives, 32 SBOMs, one custody asset. No overwrite of a conflicting body/asset. Unknown write outcome stops subsequent writes and preserves the mutation journal.
- Every local Cargo-invoking command, including nested fixtures: `CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_RELEASE_DEBUG=0`; maintain **4 GiB** free. Never rerun/overwrite historical validation sessions or evidence.
- Failed dry run **36091900371 attempt 1**, controller `4ebfee81fe2a49bb32f0cf2a70b6775e8ae5c289`, tag `v0.2.7-recover.3`, remains failed with no acceptance receipt. Both human gates and signed-tag check already passed; do not reopen them or rerun that unchanged controller.
- Keep the existing ten-minute heartbeat active and quiet while unchanged. Do not mutate the nearly full canonical PR835 checkpoint or old PR841 body.

## Review Focus

1. A 200 body that claims “404” must never become absence, and transport failures must not disclose credentials or signed URLs — Task 2 transport tests.
2. An eligible record reappears or disappears between producer, writer, or a later individual asset upload — Task 3 rebind tests stop the pending write and retain partial history.
3. Different legitimate producer/writer request timestamps with identical availability must compare equal, without permitting replay/out-of-job timestamps — Task 1 vector/chronology tests and Task 3 staged receipt tests.
4. Preliminary receipt provenance must work without historical-origin input but cannot itself authorize public acceptance or publication — Task 1 profile tests and Task 3 call-order tests.
5. A late failure after earlier successful writes must not become silent retry, overwrite, rollback, or a falsely complete release — Task 3 journal/final-readback tests.

---

## File and interface map

All paths below are relative to the sole worktree above. Existing line anchors describe planning HEAD, not a promise that line numbers survive edits.

| Unit | Owned files | Responsibility |
| --- | --- | --- |
| 1 | New `governance/releases/v0.2.7/RETAINED-METADATA-POLICY.json`; `tools/verify_release_recovery_027.py`; `tools/test_release_recovery_027.py` | Strict policy, typed observations, historical/current composition, v2 receipt validation primitives |
| 2 | `tools/import_release_recovery_027.sh`; `tools/run_release_recovery_027.sh`; `tools/verify_release_recovery_027.sh`; `tools/publish_release_npm_package.sh`; `tools/recover_release_python_027.sh`; `tools/test_import_release_recovery_027.py`; `tools/test_release_recovery_npm.sh`; `tools/test_recover_release_python_027.sh`; the shared stable-metadata function and its tests in Unit3's writer files | Narrow actual-status acquisition, fresh controls, acceptance-only child operation and final producer receipts |
| 3 | `tools/recover_github_release_027.py`; `tools/test_recover_github_release_027.py`; `.github/workflows/release.yml`; `tools/test_release_recovery_workflow.py`; `tools/test_release_workflow_ref_binding.sh`; `tools/test_release_version_input_boundary.sh` | Three-stage writer, stable v2 public disclosure, mutation rebind, existing DAG/direct outputs/credential guards |
| 4 | Existing `governance/releases/v0.2.7/RECOVERY-DESIGN.md`, `RECOVERY-PLAN.md`, `RECOVERY-VALIDATION.md`, `RETAINED-RECOVERY-PLAN.md`; this plan and the unchanged approved amendment | Reconciled operating documentation, full validation evidence, independent whole-change review and conditional reviewed integration |

Units execute sequentially; only read-only reviews/audits run in parallel. One implementer owns a unit's paths at a time; main alone stages/signs after the worker stops. Unit 1 defines v2 receipt primitives before Unit 2 emits v2 receipts, resolving the producer's dependency on Unit 3 without duplicating a verifier. Unit 3 may make a narrowly reviewed integration correction to Unit 1/2 interfaces, with their focused regressions rerun.

### Fixed policy representation

Use strict JSON object keys `schema, operation, manifest_sha256, publications_sha256, retained_sha256, repository, original, retaining, retained_artifact_ids, unavailable_originals`.

- `schema="exochain-retained-metadata-policy-027/v1"`, `operation="recover-0.2.7-retained-404"`; three digests are the existing semantic pins above.
- `repository={name:"exochain/exochain", id:1116455646, owner_id:129763194}`.
- `original={run_id:35257955565, attempt:1}`; `retaining={run_id:35754493083, attempt:1}`.
- `retained_artifact_ids=[10779404529,10780480598]`.
- Each ordered `unavailable_originals` item has exactly `id, historical_member, historical_sha256, expires_at`. Member is `artifact-metadata/<id>.json`; use this exact order and these values:

| ID | expires_at | historical_sha256 |
| --- | --- | --- |
| 10518086890 | 2026-09-24T20:09:34Z | 23a1d7f70d0da078e712fe0844f5c52101cd9b03e510941f6c758508a6e73245 |
| 10518128532 | 2026-09-24T20:19:17Z | d465cde79dd2ecd25a46cf065841a5d8eef5792f8a0d91bdf70c10a888caf93d |
| 10517978596 | 2026-09-24T20:19:29Z | dcec5cb76b7875501c83c343957a4ccded7501142d009412e54ce82d517531ad |
| 10517854663 | 2026-09-24T20:24:33Z | ea27bd26387b0335aa33a9931d432a749ed834222ffd085d370bd1d7d1a26bf9 |

The other five IDs **10517981432, 10518080916, 10517457207, 10517966616, 10517459550** always require exact 200. Calculate the new policy's semantic digest from the actual implemented record using the existing `semantic_digest` convention; embed that resulting literal as `RETAINED_METADATA_POLICY_SHA256` and independently recompute it during review. No runtime self-pinning or caller-supplied replacement digest.

### Shared v2 data contracts

These names refer to strict JSON-shaped Python dictionaries, not new dependencies or a second model layer. Use existing duplicate-rejecting JSON parsing, exact type/key helpers and strict UTC parser throughout.

- **Observer**: exactly `run_id, run_attempt, controller_sha, controller_ref, controller_tag_object, job_id, job_name, job_started_at`, bound to the actual hosted run and authoritative in-progress job. Positive integers reject bools; SHA/ref/tag follow current identity contracts. Allow only the actual retained producer or retained writer job role. No completed-job assertion at capture time.
- **Observation**: exactly `id, endpoint_role, request_started_at, request_finished_at, status, variant, historical_member, historical_sha256`, plus `metadata` **only** for status 200/variant `present`. Role is the literal `original-artifact-metadata`; 404 uses variant `unavailable_404` and has no metadata or expired field. Ordered inventories use ascending numeric ID across the exact nine originals. Obtain every historical member hash from the authenticated custody profile; the four policy hashes must also match.
- **Pass**: exactly `observed_at, records`, with exactly nine Observations; `job_started_at <= request_started_at <= request_finished_at <= observed_at <= verifier_now`. Request starts for 404 must be at/after that policy expiry. A 200 must equal authenticated historical metadata except the existing strictly boolean expired rule; assess that rule at request finish and stop if a pass/vector changes at the boundary.
- **Observations**: exactly `schema, operation, policy_sha256, observer, before, after`; schema `exochain-retained-original-observations-027/v1`. The two Pass vectors must agree. Their timestamps may differ, and both passes are individually validated.
- **Vector**: ordered list of objects with exactly `id, variant, status, historical_sha256`, plus `metadata_sha256` only for 200. Digest actual current metadata with the existing semantic convention. Never include request timestamps in cross-job vector equality.
- **Controls**: exactly `original_run, original_jobs, retaining_run, retaining_jobs, retained_metadata, observed_at`; retained_metadata is the ordered payload/custody pair. All are fresh responses from strict 200 endpoints using the same credential. Preserve raw complete inventories separately; validate the original 62 and retaining 68 jobs with existing canonical rules.
- **OriginV2 input**: exactly `schema, operation, policy_sha256, observations, controls_before, controls_after, retaining_tag`, schema `exochain-retained-origin-027/v2`. The existing historical ZIP and retaining workflow remain explicit verifier inputs. OriginV2 output schema is `exochain-retained-origin-result-027/v2`; it keeps authenticated `historical_original_origin` separate from current `observations` and `original_vector`, includes `retained_record_sha256` and `metadata_policy_sha256`, and retains the existing origin/file-count and false crypto/signature/mutation result facts. This function always reports `current_crypto_verified=false`; actual subsequent crypto results belong in acceptance evidence, not a relabeled origin result. It does not fabricate v1 `current_original_origin` metadata.
- **Receipt v2 binding**: preserve all applicable v1 source/run/attempt/ref/tag/runtime/checker/transports/publication bindings, select exact operation and checker_version `retained-027/v2`, add `metadata_policy_sha256` and `original_vector`, and replace `original_origin`/`original_expiry` with `historical_original_origin` containing the unchanged historical verifier result. Binding fields remain **flat top-level fields**, not a new nested bindings object. New custody/acceptance member schemas are `exochain-retained-custody-receipt-027/v2` and `exochain-retained-acceptance-receipt-027/v2`; result schema is `exochain-retained-receipts-result-027/v2`. Include full producer Observations as top-level `original_observations` in **both** receipt members; validate it separately from stable cross-job bindings. Raw writer observations remain separate private run evidence.
- **ReceiptInputV2**: preliminary keys are exactly `schema, operation, policy_sha256, observed_at, context, current_run, current_jobs, upload_outputs, metadata_before, members`; schema `exochain-retained-receipts-input-027/v2`. Keep existing context/upload_outputs/member shapes; actual operation/policy are additionally checked against the executing dispatcher, not trusted merely because JSON says so. observed_at is captured after the authoritative preliminary reads and supplies the no-origin chronology/nonexpiry check. Full input additionally requires authenticated `origin` and fresh `metadata_after`. Preserve producer context.checked_at across jobs; use writer observation times only for separate validation and comparison of Vector.

Existing public function parameters stay valid for v1; add keyword-only `policy=None` to v2-capable functions. None selects only existing behavior; a validated policy selects only the explicit new operation. Do not infer selection from HTTP failures.

Explicitly set the v2 receipt's top-level `mode="recover-0.2.7-retained-404"`; do not derive it from `record["mode"]`. That immutable historical value remains `recover-0.2.7-retained`, and v1 continues using it. For full ReceiptInputV2, refresh observed_at after the actual ZIP and metadata_after reads and require it >= preliminary observed_at; recheck receipt nonexpiry at that final time, not the older preliminary time.

## Task 1: Canonical policy, observations and v2 receipt primitives

**Files:** Unit 1 above; relevant anchors: retained record validation near line 69, origin validation near 341, receipt binding/profile/full verification near 427–568. Extend `RetainedTests` in the existing test file.

**Interfaces:**

- Consume existing `validate_manifest`, `validate_retained_record`, `read_historical_custody`, `verify_retained_zip`, `complete_jobs`, `validate_run_identity`, `successful_steps`, `semantic_digest` and `timestamp`; preserve old public behavior.
- Produce `validate_retained_metadata_policy(manifest: dict, record: dict, policy: dict) -> dict` and `load_retained_metadata_policy(manifest: dict, record: dict, path: Path) -> dict`.
- Produce `validate_original_observation(manifest: dict, record: dict, policy: dict, historical: dict, observation: dict, *, now: str) -> dict`: validate one fixed-ID response's actual-status shape, historical identity/hash, UTC interval/eligibility and return one Vector item. This pure primitive performs no hosted-job authentication and cannot authorize acceptance; use it within the full validator and explicitly labeled local read-only diagnostics.
- Produce `validate_original_observations(manifest: dict, record: dict, policy: dict, historical: dict, observations: dict, *, now: str) -> list[dict]`; return the validated after Vector and require equal before Vector.
- Extend `verify_retained_origin(manifest, record, input_record, evidence_path, workflow_path, *, policy=None) -> dict` to validate OriginV2 without constructing substitute current metadata.
- Produce `retained_receipt_provenance(manifest: dict, record: dict, policy: dict, input_record: dict) -> dict`, with **no historical origin parameter**. Consume preliminary ReceiptInputV2 above and return exactly `profile, context, upload_outputs, observed_at` as a provenance-only result; no acceptance_verified flag. Validate producer/import/upload start/end ordering and current receipt nonexpiry against actual observed_at without an origin input.
- Extend existing `retained_receipt_bindings`, `retained_receipt_profile`, and `verify_retained_receipts` with keyword-only `policy=None`. Full v2 verification requires OriginV2 and actual ZIP bytes, reuses the preliminary validator, and separately validates producer raw observations against authoritative successful producer/import/upload chronology.

- [x] **Step 1: Add policy fixtures and negative tests before production edits.** Add `metadata_policy_fixture()` to RetainedTests, returning the exact policy shape/values above from a literal test fixture; extend the existing origin fixture with exact four recorded expiries and all nine authenticated historical objects. Existing synthetic fixtures remain clearly test-only; do not change an actual-evidence test to accept substituted hashes.

  Tests use the existing `self.v` canonical module as test-local `validator`, not a second imported implementation. Test `test_metadata_policy_rejects_nested_tampering_and_operation_confusion` pins these assertions:

  ~~~python
  self.assertEqual(validator.validate_retained_metadata_policy(manifest, record, policy), policy)
  self.assertEqual([x["id"] for x in policy["unavailable_originals"]],
                   [10518086890, 10518128532, 10517978596, 10517854663])
  self.assertEqual(policy["retained_artifact_ids"], [10779404529, 10780480598])
  with self.assertRaises(validator.RecoveryError):
      validator.validate_retained_metadata_policy(manifest, record,
          dict(policy, operation="recover-0.2.7-retained"))
  ~~~

  Add subtests mutating each nested field, adding/removing keys, changing each pin/hash/expiry, using bool-as-ID, duplicate/reordered IDs, wrong repository/attempt, wrong semantic digest, and duplicate JSON keys. Every mutation rejects; all three old record bytes/pins remain unchanged.

- [x] **Step 2: Run the policy test RED.** `python3 -B tools/test_release_recovery_027.py RetainedTests.test_metadata_policy_rejects_nested_tampering_and_operation_confusion -v`. Expected failure identifies the missing new validator, not fixture setup or network failure.
- [x] **Step 3: Implement the exact owned policy, independent literal semantic pin, loader and validator interfaces above.** Keep the retained record's historical mode unchanged. Independently compare actual bytes/hash values with the approved design and strict custody member inventory.
- [x] **Step 4: Run the policy test GREEN.** Same command, exit 0, with every negative subtest actually executed.
- [x] **Step 5: Add observation and origin tests.** Define `observation_fixture(missing_ids=(), *, offset_seconds=0)` returning valid Observations from the existing test historical fixture and a deterministic hosted-job fixture after all four expiries; only the specified eligible IDs become 404. Define `origin_v2_fixture()` supplying canonical Controls and the same historical/retaining proof used by existing origin tests. Add:

  ~~~python
  # test_observations_accept_all_200_and_each_eligible_404
  for missing in ((), (10518086890,), (10518128532,), (10517978596,),
                  (10517854663,), (10518086890,10518128532,10517978596,10517854663)):
      vector = validator.validate_original_observations(
          manifest, record, policy, historical, self.observation_fixture(missing), now=now)
      self.assertEqual(len(vector), 9)
      self.assertEqual([x["id"] for x in vector if x["status"] == 404], sorted(missing))
  # test_normalized_vector_ignores_times_but_detects_transition
  first = self.observation_fixture((10518086890,))
  later = self.observation_fixture((10518086890,), offset_seconds=60)
  self.assertEqual(validate(first), validate(later))
  ~~~

  Here `validate` is a test-local closure over the five fixed validator arguments and deterministic now, not a production helper. Add `test_observations_reject_fifth_early_conflicting_or_fabricated_metadata`: reject each other ID missing, early404, 200 conflict/invalid expired type, 404 carrying metadata/expired, any omission/duplicate/reordering, wrong member/hash, and 200-to-404 or 404-to-200 between passes. Add `test_observation_chronology_binds_actual_job_and_checked_at`: reject inverted/future/pre-job/copied-prior-run observations; allow legitimate in-progress capture without invented completed_at. Origin tests reject incomplete/duplicate original or retaining jobs, wrong attempts/SHA/ref/tag/workflow/producer steps, invalid historical import chronology and either retained metadata conflict/expiry.
- [x] **Step 6: Run observation/origin tests RED.** `python3 -B tools/test_release_recovery_027.py RetainedTests -v`; identify failures in newly added tests while preserving prior passing expectations.
- [x] **Step 7: Implement the observation and OriginV2 interfaces.** Reuse unchanged historical verification on all nine authenticated historical records, independently validate both fresh Controls, and validate four-ID absence only in the new branch. Preserve all old origin return structures and failures. Keep exact chronology and normalized-vector code in the canonical validator, not duplicated in importer/writer.
- [x] **Step 8: Run observation/origin tests GREEN.** Same command, exit 0; separate any existing actual-evidence skips from fixture results and do not count skipped checks as proof.
- [x] **Step 9: Add v2 preliminary/full receipt tests using existing `receipt_fixture()` and strict streaming ZIP fixture builder.** Test `test_preliminary_receipt_profile_rejects_replay_without_historical_origin` asserts valid provenance has the expected direct artifact digest/profile but no acceptance flag or origin requirement; reject wrong run/attempt/controller/ref/policy/operation, name-only fallback, bad metadata/size/expiry, incomplete jobs, failed producer/import/upload and chronological conflicts.

  ~~~python
  # test_v2_receipts_bind_policy_operation_vector_and_raw_observations
  self.assertEqual(custody_receipt["checker_version"], "retained-027/v2")
  self.assertEqual(custody_receipt["mode"], "recover-0.2.7-retained-404")
  self.assertEqual(custody_receipt["original_observations"],
                   acceptance_receipt["original_observations"])
  self.assertEqual(custody_receipt["original_vector"], writer_vector)
  self.assertLessEqual(last_observation_finish, context["checked_at"])
  self.assertLessEqual(context["checked_at"], upload_start)
  ~~~

  Supply those variables from fixture records, not hardcoded success. Test valid different writer timestamps; reject raw producer time tampering even when Vector is unchanged, wrong/checker runtime/policy/member hash/digest, metadata before/after drift, v1-for-new and v2-for-old, missing observation, forged crypto result fields, and malformed strict ZIP. Assert preliminary success cannot make full verification pass without authenticated origin or actual receipt bytes.
- [x] **Step 10: Run receipt tests RED.** `python3 -B tools/test_release_recovery_027.py RetainedTests -v`, expected newly added receipt assertions fail against unimplemented v2.
- [x] **Step 11: Implement staged receipt primitives and v2 profile in the existing verifier.** Factor shared context/direct-upload/job/profile logic from current `retained_receipt_profile`; stage 1 validates no arbitrary caller origin. At full verification require authoritative producer-start <= import-step-start <= every observation start <= its finish <= checked_at <= import-step-end <= upload-start <= upload-end <= producer-end <= receipt observed_at. Validate each interval separately, not by silently sorting input. Preserve exact receipt bounds: ZIP <=1048576 bytes, each of two members <=524288 bytes; strict profile/member order/digests/metadata equality. Keep the consumer's distinction between validating bound crypto evidence and independently performing crypto.
- [x] **Step 12: Run all canonical verifier tests GREEN.** `python3 -B tools/test_release_recovery_027.py -v`. Confirm old original/v1 valid cases still pass and both old modes reject unavailable originals.
- [x] **Step 13: Independently review this unit against design sections 4–6 and tests; resolve findings with RED/GREEN evidence.** Review exact policy semantic pin and all historical member hashes independently; reviewer verdict does not constitute human approval.
- [x] **Step 14: After implementation authority and completed review, main signs only this unit.** `git add -- governance/releases/v0.2.7/RETAINED-METADATA-POLICY.json tools/verify_release_recovery_027.py tools/test_release_recovery_027.py`, then `git -c user.signingkey=96B889DAE73CD7C511CCDE28897119B7198789EC commit -S -m "feat: define bounded retained metadata policy"`. Verify actual signature and record commit/tree/tests; do not push yet.

## Task 2: Scoped acquisition and acceptance-only producer

**Files:** Unit 2 above. Review existing Transport near lines 144–264, `fetch_origin_records`, `acquire_retained`, `current_receipt_context`, `accept_publications`, `create_retained_receipts`, source capture and final main ordering before editing.

**Interfaces:**

- Consume Task 1 canonical policy/origin/observation/receipt APIs; no second validator/importer.
- Extend `Transport.__init__(scratch, token, manifest, retained=None, *, policy=None)`; produce `Transport.original_metadata(artifact_id: int, destination: Path) -> dict`, returning a typed Observation using internally constructed fixed URL, actual wire status and captured UTC times. Generic `get`, `archive`, `receipt_archive` stay strict.
- Produce `capture_observer(custody, transport, capture: Path, evidence: Path, role: str) -> dict`, binding Observer to the authoritative current run and unique in-progress retained producer/writer job.
- Produce `fetch_retained_controls(manifest, record, custody, transport, evidence: Path, *, phase: str) -> dict` and `fetch_original_observation_pass(manifest, record, policy, custody, transport, evidence: Path, observer: dict, *, phase: str) -> dict`; phase is an internally generated safe filename label, never caller authority.
- Extend `acquire_retained(manifest, record, custody, transport, evidence, archives, candidate, workflow, *, policy=None, observer=None) -> tuple[dict, dict]`, preserving its existing origin-result/transport-result return and v1 behavior. V2 MUST complete start Controls -> before observations -> both archive downloads/historical verification -> acquisition-after observations -> end Controls -> canonical OriginV2 validation before returning. Write the complete immutable `acquisition-origin-input.json` plus raw controls/observations. This is validated acquisition-stage custody, not completed public/crypto acceptance, and supplies the writer's full-receipt stage BEFORE public checks.
- Produce `finalize_retained_observations(manifest, record, policy, custody, transport, evidence: Path, historical: Path, workflow: Path, *, observer: dict, initial_input: dict, phase: str) -> dict`; consume the already complete acquisition input, perform another fresh nine-original pass then end Controls, compare the original accepted Vector, and validate a new complete OriginV2 with original before/start Controls and the fresh after/end Controls. Return input while writing a new exclusive phase-specific file, preserving acquisition-after evidence separately. Producer invokes this after expensive acceptance; writer invokes it after fresh public checks and again after final readbacks. This later finalizer is NOT a prerequisite for obtaining the complete acquisition-stage input used by earlier full receipt verification.
- Extend `current_receipt_context` with keyword-only `observer=None, checked_at=None` for v2: actual captured Observer binds identity; actual checked_at is assigned only after final observations/source/file/crypto checks. Extend `create_retained_receipts` with keyword-only `policy=None` and use Task 1 v2 binding plus full producer observations.

- [x] **Step 1: Add executable transport regressions before edits.** Reuse the existing importer-module extraction and fake curl subprocess harness, which exercises the actual Transport. Test `test_scoped_original_metadata_status_uses_actual_http_code_only` with exact allowed200, allowed post-expiry404, and a 200 JSON body claiming404 that must fail metadata verification. A returned 404 must have no metadata:

  ~~~python
  observation = transport.original_metadata(10518086890, output)
  self.assertEqual((observation["status"], observation["variant"]), (404, "unavailable_404"))
  self.assertNotIn("metadata", observation)
  self.assertNotIn("expired", observation)
  ~~~

  Test `test_scoped_status_rejects_failures_and_secret_leaks` for 301/302/307, 401/403/410/429/500, malformed/multiple/contradictory final status, timeout, truncated body/header/status and oversize response. Put unique token/body/header/Location/signed-URL sentinels into test responses and assert none appear in stdout/stderr/exceptions. Test 404 on each run/jobs/retained/receipt/archive/registry path remains failure and an arbitrary ID cannot form a request.
- [x] **Step 2: Run transport tests RED.** `python3 -B tools/test_import_release_recovery_027.py ImportTests -v`; newly named cases must fail on missing scope/behavior, not due to harness setup.
- [x] **Step 3: Implement scoped actual-status transport.** Factor a private bounded wire-request primitive if necessary; keep `_get`/generic callers' existing accepted statuses unchanged and permit 404 only inside `original_metadata` after validated new-policy/fixed-ID selection. Cross-check actual curl final status against bounded final header status, reject ambiguity/redirects, discard 404 body within private temporary lifecycle. Preserve connect10s/max240s/process250s, header<=65536, existing body bounds, credential-free redirect archive requests, and no retry. Errors expose role/fixed ID/status or fixed failure class only, never arbitrary exception strings.
- [x] **Step 4: Run transport tests GREEN.** Same command exit 0, including old generic GET/archive/redirect credential regressions.
- [x] **Step 5: Add acquisition/control/producer tests using deterministic operational clock and canonical Controls fixtures.** Tests `test_controls_before_and_after_expensive_checks_are_exact`, `test_final_observation_and_checked_at_follow_acceptance`, and `test_original_vector_transition_prevents_receipt_output` record actual helper invocation order:

  ~~~python
  self.assertLess(events.index("controls-before"), events.index("observations-before"))
  self.assertLess(events.index("observations-before"), events.index("crypto-public-checks"))
  self.assertLess(events.index("crypto-public-checks"), events.index("observations-final"))
  self.assertLess(events.index("observations-final"), events.index("controls-final"))
  self.assertLess(events.index("controls-final"), events.index("checked-at"))
  self.assertLess(events.index("checked-at"), events.index("receipt-output"))
  self.assertEqual(success_receipts, [])  # each injected failure/transition case
  ~~~

  Define event recording by wrapping the actual acquisition/finalization functions, mocking only provider/crypto process boundaries. Test every positive-control failure, pagination omission/duplicate, wrong historical proof, both retained expiry boundaries (including exact equality), final 200/404 transition, actual job mismatch, source/file change, and genuine crypto rejection. No successful destination or GITHUB_OUTPUT acceptance handoff may be exposed on failure.
- [x] **Step 6: Run new acquisition/producer tests RED.** `python3 -B tools/test_import_release_recovery_027.py -v`; preserve full logs and failed assertion.
- [x] **Step 7: Implement canonical acquisition/finalization/receipt ordering.** Start Controls precede the initial nine originals. Validate fresh download ZIPs, historical proof, original and retaining attempt1 evidence with Task 1; an immediate acquisition-end nine-original pass plus complete end Controls and OriginV2 validation is mandatory. Native/package/Rust/GitHub preflight checks then run between the initial observations and a separate final pass. Finalizer reads nine originals and complete end Controls after expensive checks, then source/files are rechecked and checked_at finalized. Use exclusive private files for every phase; bind original/retaining/current signatures and workflow bytes. Emit v2 receipts only on complete success, no fresh-success claim from historical reports.
- [x] **Step 8: Add and run RED child-mode tests.** Extend `test_full_dispatcher_retained_child_environment_is_allowlisted`, `test_python_retained_bootstrap_has_explicit_accept_and_no_credentials`, and npm `test_retained_dry_and_live_all_profiles_never_enter_upload` for the new exact operation. Assert:

  ~~~python
  self.assertEqual(result["operation"], "recover-0.2.7-retained-404")
  self.assertIs(result["mutation_attempted"], False)
  self.assertIsNone(result["upload_exit_code"])
  self.assertEqual(package_upload_calls, [])
  self.assertEqual(python_stage_calls, [])
  self.assertEqual(leaked_credential_names, [])
  ~~~

  Derive variables from existing executable fixtures. Negative cases: new operation with import/npm-publish/Python-preflight, wrong version/ref/job/dry flag, any publisher credential/OIDC, missing/mismatched policy capture, writer without live direct handoff. Old normal publication fixtures must remain supported.
- [x] **Step 9: Implement the enumerated operation/source boundaries.** Dispatcher mode pairs permit new operation only with retained-acceptance/retained-github. Identity wrapper loads new policy only for new operation. Capture the policy from actual GITHUB_SHA and recheck exact bytes in importer, wrapper, dispatcher and writer capture contracts. Add new operation only to acceptance/readback paths in npm validation/receipt/upload-denial guards and Python accept/retained-readback; propagate actual validated operation instead of hardcoded old operation in both aggregate results and importer comparisons. Never broaden Python staging or npm publish eligibility. Producer GitHub preflight must pass the same explicit operation/policy to Task 3's stable metadata function; until that integration lands, its regression must fail closed, not emit an old v1 body for new mode.
- [x] **Step 10: Run Unit 2 GREEN suite.** `python3 -B tools/test_import_release_recovery_027.py -v`; `python3 -B tools/test_release_recovery_027.py -v`; `bash tools/test_release_recovery_npm.sh`; `bash tools/test_recover_release_python_027.sh`; `python3 -B tools/test_release_recovery_python_stage.py`. Require exit 0 for complete unit behavior; finish the shared stable-metadata interface in this unit as specified under Task 3 before claiming this producer preflight test passes. Unit 3 then owns writer integration and its review.
- [x] **Step 11: Independently review transport, control chronology, operation inventory and credential boundaries; resolve findings with actual RED/GREEN evidence.** Enumerate every exact operation comparison with `rg -n 'recover-0[.]2[.]7-retained|RELEASE_OPERATION|retained-accept|retained-readback' tools .github/workflows/release.yml`; adjudicate each site, including upload-denial and aggregate result assertions.
- [x] **Step 12: After authority and review, main signs explicit Unit 2 paths plus the shared stable-metadata function/tests from Task 3.** Use configured `git commit -S`, verify signature, record source/tree/logs, and leave pushing to the final reviewed handoff. No worker index writes; no wildcard staging.

## Task 3: Staged writer, fresh mutation rebind, and workflow contract

**Files:** Unit 3 above; source anchors: `retained_release_metadata` near266, `receipt_handoff`302, `receive_current_receipts`330, `complete_retained`372, `retained_main`378; release input option32/validation132/retained jobs5429 and5574/direct outputs5675.

**Interfaces:**

- Consume Task 1 provenance/full-receipt APIs and Task 2 acquisition/finalization/observation/control APIs.
- Extend `retained_release_metadata(manifest, publications, record, sha, ref, *, policy=None) -> tuple[dict, dict]`, preserving existing return types and v1 output; `release_assets` performs existing canonical public JSON-to-bytes serialization. **Implement and test this small shared prerequisite in Unit 2** so producer preflight is fully testable. New policy produces stable public schema `exochain-release-retained-custody/v2`, adds `metadata_policy_sha256` and the ordered policy `unavailable_originals` inventory, and exact disclosure: “Selected original artifact metadata may be unavailable after its recorded expiry. Historical identity is authenticated from retained custody; it is not a claim of current metadata visibility or proof of deletion.” Put policy digest and the same disclosure in the release body. No per-run request status/timestamp/observations in stable asset/body; fixed historical policy expiries remain present.
- Produce `prepare_current_receipt(custody, importer, manifest, record, policy, transport, evidence, handoff) -> dict`: fetch current authoritative run/jobs/direct receipt metadata and call provenance-only validation before acquisition; return its validated input, not acceptance.
- Extend `receive_current_receipts(custody, importer, manifest, record, publications, transport, evidence, historical, workflow, origin, handoff, *, policy=None, prepared=None) -> dict` with unchanged positional v1 arguments: v2 requires prepared input, fresh metadata before/after download, actual strict ZIP and full verification against authenticated historical origin/current writer vector. Recheck authoritative producer data if changed; no name lookup.
- Extend writer `rebind()` closure and existing `complete_retained(...)` integration without a second writer. Each invocation verifies source/files, both retained metadata and nine fresh originals against accepted Vector. On any mismatch re-read original/retaining run/jobs for bounded diagnostic evidence, then stop without pending write; diagnostic failure also stops.

- [x] **Step 1: Add shared stable-public-metadata tests (execute in Unit 2).** Test `test_v2_public_custody_is_stable_and_discloses_loss`: exact35 assets, v2 schema/new policy inventory/digest/disclosure, no operational status/timestamp fields, byte-identical stable asset across distinct legitimate request times, unchanged old-v1 bytes. Test producer preflight and writer use identical expected bytes/body. Test conflicting v1/v2 public body/asset is a conflict, never overwrite. Run `python3 -B tools/test_recover_github_release_027.py -v` RED, implement only the shared interface above, then run GREEN before Unit 2 review.
- [x] **Step 2: Add three-stage writer regressions.** Test `test_preliminary_handoff_precedes_acquisition_and_full_receipt` records:

  ~~~python
  self.assertEqual(events[:3], ["authoritative-provenance", "canonical-acquisition", "full-receipt"])
  self.assertLess(events.index("full-receipt"), events.index("public-readback"))
  self.assertLess(events.index("public-readback"), events.index("first-mutation"))
  self.assertEqual(public_calls, [])  # invalid provenance, ZIP, chronology or vector
  self.assertEqual(writer_calls, [])  # same failure cases
  ~~~

  At the full-receipt call, assert acquisition-origin-input already contains validated before/after observations and start/end Controls. Assert a later post-public finalizer runs separately and preserves the earlier input. Inject a failure in either checkpoint and require no pending write. Also expire the receipt between preliminary read and completed download: fresh final observed_at must reject it.

  Use existing FakeProvider and actual `complete_retained`/receipt helpers with injected bounded transport. Reject run/attempt/ref/controller/policy replay, uncompleted producer/upload, bad receipt artifact IDs/digests/member hashes, v1/v2 confusion and raw observation clock conflicts. Assert stage1 needs no origin object and cannot authorize later stages; equal producer/writer vectors with different valid timestamps pass full validation.
- [x] **Step 3: Run staged writer tests RED.** `python3 -B tools/test_recover_github_release_027.py -v`, preserving newly failing assertions.
- [x] **Step 4: Implement preliminary-before-acquisition then full-after-acquisition ordering.** Shape-check direct outputs, authenticate them with current API evidence, capture actual in-progress writer Observer, acquire and validate canonical history, then download/verify actual current receipt bytes and producer raw chronology. Compare Vector before fresh public checks; preserve separate writer observations and finalize them after public checks. No fabricated origin or receipt acceptance flag at stage1.
- [x] **Step 5: Add per-mutation and final-readback tests.** Test `test_rebind_stops_transition_before_each_mutation_and_final_readback` injects each eligible200-to404/404-to200 and noneligible404 immediately before create, each of35 uploads, publish, and final readback. Assert:

  ~~~python
  self.assertEqual(pending_write_calls, [])
  self.assertEqual(events[-1], "stop")
  self.assertIn("diagnostic-run-jobs-recheck", events)
  self.assertEqual(success_completion_receipts, [])
  self.assertEqual(recorded_prior_write_ids, actual_prior_write_ids)
  ~~~

  Test source/file change, both retained expiry equality/absence/change, fifth missing original, failed final full controls, unknown write followed by zero further writes, body/asset conflicts and no rollback. Preserve actual successful earlier writes in the journal; unknown responses remain uncertain, not failed-with-no-mutation.
- [x] **Step 6: Run mutation tests RED.** Same writer suite; observe failures from missing original-status rebind/final controls.
- [x] **Step 7: Extend every existing rebind boundary and final acceptance.** Before draft creation, each asset upload and publish, read both retained objects plus all nine observations and compare accepted Vector; validate request chronology against actual writer job and bounded UTC now. Full original/retaining controls run at acquisition and after final byte readback before emitting final success. Preserve complete run evidence and mutation journal on any failure. Keep read counts bounded by existing35-asset recovery, no polling/retry loop.
- [x] **Step 8: Add workflow/input/credential negative mutations and run them RED.** Test `test_new_operation_reuses_retained_dag_and_dry_skips_writer` and `test_new_mode_preserves_permissions_direct_outputs_and_source_capture`: new exact option/version/ref accepted, wrong variants rejected; no extra DAG jobs; producer needs CI/both gates/signedtag/input validation; writer additionally needs producer and is live-only. Preserve producer permissions contents/actions/attestations=read, writer contents=write/actions=read, no OIDC/package credentials. Assert actual `needs.retained-acceptance.outputs` supplies direct artifact_id/digest/producer_job_id/context/members. Reject any substitution by artifact name, previous attempt, source override or dry writer path.
- [x] **Step 9: Update existing workflow jobs and guards.** Add new operation to option and strict input case. Producer predicate uses explicit OR of the two exact retained operations; writer uses that parenthesized OR AND `!inputs.dry_run`. All other package-build/preparation/publisher/GitHub-writer routes must remain excluded. Preserve environment protections, runtime pins, token transport contract, signed-source capture and direct outputs. Update parsed DAG/ref/version guards without weakening normal/original coverage or changing hosted token permissions.
- [x] **Step 10: Run full Unit 3 GREEN suite.** `python3 -B tools/test_recover_github_release_027.py -v`; `python3 -B tools/test_release_recovery_workflow.py -v`; both Task1/2 Python suites; npm/Python guards; `bash tools/test_release_workflow_ref_binding.sh`; `bash tools/test_release_version_input_boundary.sh`. All Cargo-capable guards must have the five resource overrides, including any nested env-i fixtures.
- [x] **Step 11: Independent unit review covers exact source diff, all operation/schema comparisons, receipt chronology and every write ingress.** Reconcile review findings in the existing ignored ledger; a genuine negative result requires correction and focused/full affected tests, not a waiver.
- [x] **Step 12: After authority and review, main signs explicit remaining Unit 3 paths.** Verify configured signature and preserve immutable diff/commit/tree/test report. Do not duplicate the shared metadata prerequisite already signed with Unit2.

## Task 4: Documentation, complete validation and reviewed integration

**Files:** Unit4 above; ignored evidence remains in `.superpowers/sdd/RETAINED-RECOVERY-PLAN/` or a fresh private temporary evidence directory outside source.

**Interfaces:** Consume the completed exact policy digest and actual Task1–3 interfaces/tests. Produce a self-contained human PR handoff binding final head/tree, source scope, complete local/hosted evidence, known limitations, historical failures and remaining execution authority. No release execution helper or additional payload transport.

- [x] **Step 1: Reconcile the four existing operating documents with the approved explicit exception and actual new policy digest.** Preserve old-mode instructions/history; describe typed absence, information loss, staged receipts, fresh controls, all current crypto,35 assets, no overwrite, chronology and expiry. Distinguish design approval, subsequent plan approval/method, technical reviews, human exact-head reviews, protected approvals and dry/live authority. Keep the approved amendment unchanged and make its later approval explicit in the new records.
- [ ] **Step 2: Build a fresh final-source command inventory and runner in private evidence, not a build copy.** Use `mktemp -d`; write the runner with apply_patch. Read current `.github/workflows/ci.yml`: collect unique `tools/test_*.py` invocations including quoted PYTHON commands, and every `bash tools/test_*.sh`. Handle the actual npm runtime contract separately, not omit it. Record all commands before starting, actual source head/tree/start/end/exit status and unique raw log paths; never overwrite old runner/status/logs. Do not copy an old fixed command count or old original-observation directory/time as current evidence.
- [ ] **Step 3: Execute the nine complete local core gates on final source, with all resource overrides and disk checks before each command.**

  ~~~bash
  cargo build --workspace --release --locked
  cargo test --workspace --locked
  cargo test --workspace --release --locked
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo +nightly-2026-09-21 fmt --all -- --check
  cargo doc --workspace --no-deps --locked
  cargo audit --deny unsound --deny unmaintained
  cargo deny check
  bash tools/cross-impl-test/compare.sh
  ~~~

  Use `RUSTDOCFLAGS=-Dwarnings` for doc. Require exit0 per command; preserve warning/ignored-test inventory. Cross-implementation evidence describes the actual vector/repeatability scope, not unexecuted external TypeScript conformance. No source edits while final validation is active.
- [ ] **Step 4: Execute every final CI-derived Python suite and shell guard plus current/legacy real npm contracts.** Derive runtime paths by verifying actual executables, exact versions and official checksums; use explicit absolute `RELEASE_TEST_NODE`/`RELEASE_TEST_NPM`. Run `bash tools/test_release_npm_runtime_contract.sh` for Node24.15.0/npm11.12.1 and `bash tools/test_release_npm_runtime_contract.sh --expect-legacy-rejection` for Node22.14.0/npm10.9.2. The latter requires real successful old audit output rejected for missing verified bundles, not a fabricated failure. Never extract protected tokens to run `--token-contract`; that existing token contract is exercised with its genuinely scoped hosted credential in CI.
- [ ] **Step 5: Execute actual retained-byte and fresh read-only verification with the new code.** Require original/retaining explicit attempt1 controls and fresh9 HTTP observations from the normally configured read credential, exact newly downloaded nonexpired fixed2 archives/strict40+60 profiles, historical member proof, both native genuine attestations, all5 exact public crypto files/owners/publisher identities and all32 Rust checksums/nonyanked. Reuse the canonical verifier and acceptance helpers with actual pinned runtimes; preserve raw commands, results and UTC intervals. Write a private evidence-only `verify-local-metadata-evidence.py` harness with apply_patch; run `python3 -B <fresh-evidence-root>/verify-local-metadata-evidence.py`. It loads the exact final-source canonical modules, calls strict transport/ZIP/historical helpers and `validate_original_observation` for each actual response, and records source hashes, all nine Vector items and positive-control results; exit0 requires all actual checks pass. It must not call the full hosted Observer validator with a fabricated job, emit hosted acceptance receipts, or invoke hosted-only producer/writer mains with forged GitHub variables. Actual hosted-job chronology is tested with clearly labeled deterministic fixtures locally and verified against genuine hosted evidence only after separate execution authority. Keep old actual-evidence regression replay separate from fresh observations. Any live read/crypto failure is reported and stops PR-ready claims; no publisher credential or payload mutation.
- [ ] **Step 6: Preserve generated reports intact before unchanged SBOM guard and finish evidence audit.** Validate the exact generated/untracked targets for DAGDB reports and cross-impl results/vectors; move them without overwrite to the fresh evidence directory outside checkout, not delete them or weaken SBOM. Inspect every command's result, genuine failures, skips and known warnings. Record the final command count from actual executed inventory. Linux coverage and production-DB hosted tests are not local pass claims.
- [ ] **Step 7: Fresh independent whole-change review reads final source diff, design, plan, policy pin, operation inventory and actual validation logs.** Main adjudicates every finding and verifies its resolution. Any source correction reruns affected focused gates and the final complete validation on the corrected head. Retain prior failure logs; no reviewer opinion substitutes for tests or human consent.
- [ ] **Step 8: After approved implementation scope, serialize final signed documentation/evidence-summary commits and verify source cleanliness/signatures.** Stage explicit owned files only; no imported evidence, credentials or generated payloads. Preserve final local commit/tree and three immutable raw-file hashes from the planning baseline.
- [ ] **Step 9: Prepare and normally push the reviewed implementation to one verified-unused `bob-stewart/` remote branch without switching the local branch or force-pushing.** Inspect integrated main read-only and reconcile a changed base through an explicitly reviewed, clean and source-equivalent operation only after workers stop; do not blindly pull the ahead/behind local branch. If the base changes the reviewed source, redo validation/review. Create one self-contained PR with accurate scope/results and request Max/Robert once; attach the actual PR to the task. Plan approval for implementation/reviewed PR preparation is a prerequisite, not supplied by this document.
- [ ] **Step 10: Verify both exact-final-head non-author human approvals and complete exact-head hosted CI before normal integration.** Do not count agent review or aggregate reviewDecision as two people. Verify genuine repository authority and actual approval timestamps before merge, full job inventory, CODEOWNERS errors and normal protection state. Never impersonate, bypass, or rerun green CI. Then normally integrate only within applicable authority, preserving existing remote branches/tags and verified reviewed content.
- [ ] **Step 11: Verify integrated tree/signature and integrated CI, then hand off for separately applicable release execution authority.** Integrated tree must equal the reviewed candidate tree. GitHub-verified signature is distinct from local verification if its key is absent. Do not create a maintenance tag or dispatch as part of this implementation plan.

## Operational acceptance after separate authority

These are acceptance requirements, **not authorized operations or automatic continuation steps**. After reviewed integration and separately applicable tag/protected-DRY authority, verify current prerequisites and use one new unused signed maintenance tag on the actual integrated controller. Run the exact new operation with version0.2.7/dry_run=true; never rerun unchanged recover.3. New genuine release(Max) and release-second(Robert or tazmon95) gates retain prevent_self_review=true/can_admins_bypass=false.

Independent dry acceptance must inspect complete same-attempt jobs, actual source/tag/signatures, typed before/after observations/controls and job chronology, native/public genuine crypto,32 Rust checks, direct hosted receipt artifact ID/digest/actual ZIP/member bytes, successful producer/import/upload ordering, `dry_run=true`, `mutation_attempted=false`, and all writer jobs skipped. A green run alone is insufficient. Only then request applicable live authority. Live requires fresh producer and writer checks, the three receipt stages, all per-write rebinds, final authoritative completed writer chronology and full provider/35-asset byte readback. Separately authorized retirement follows complete release acceptance; no runtime deployment target is inferred.

## Planning review and execution handoff

This plan was prepared from the actual canonical source at the stated HEAD, the approved design, and two independent read-only transport/writer interface audits. No implementation tests, new crypto run, download, or release acceptance is claimed by plan preparation.

Main completed the required self-review: design sections4–6 map to Tasks1–3, section7 to ownership/authority, section8 to named tests/full validation, and section9 to historical-versus-current evidence labeling. Corrected the shared metadata return type to the actual pair of dictionaries, preserved flat receipt fields and existing direct-output key names, moved the producer's stable-public-metadata prerequisite into Unit2, and separated local primitive diagnostics from genuine hosted-job acceptance. All five Review Focus conditions have named tests. The plan consists predominantly of decisions/test boundaries, not production function bodies.

An additional independent plan review identified an Important ambiguity about complete acquisition-stage OriginV2 versus post-public finalization and a nonblocking v2 mode-selection ambiguity. Both are explicitly corrected above, with regression assertions for the two custody checkpoints and distinct historical/current modes. Main also added a fresh final receipt-time check so preliminary provenance cannot conceal expiry during acquisition/download. The original review and correction disposition remain in the ignored ledger; review is not implementation or human consent.

Human review and execution-method selection are next. Recommended: **Subagent-driven**, one fresh implementer and fresh independent reviewer per sequential unit, followed by whole-branch review; this is justified by the four connected custody/transport/receipt/publication boundaries. Alternative: **Native**, main implements all units with one fresh whole-branch reviewer at the end. Neither method changes authority, tests, exact-head human reviews, protected approvals or release acceptance requirements.
