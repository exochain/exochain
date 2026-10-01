# Preserved Payload Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete 0.2.7 using the exact preserved original ZIP through separately reviewed hosted transport and the existing protected release chain.

**Architecture:** Add explicit preserved operation to the canonical retained verifier/importer/writer. A dedicated custody-only prerelease supplies unchanged payload bytes, while original custody and failed-writer evidence remain strict current Actions dependencies. Distinct v3 origin/receipts disclose the new transport without relabeling history.

**Tech Stack:** Existing Python stdlib, Bash, configured Git/GPG/gh, pinned GitHub Actions and existing Rust/Node/Python gates; no new dependencies.

**Spec:** `governance/releases/v0.2.7/PRESERVED-PAYLOAD-RECOVERY-DESIGN.md`

## Global Constraints

- Explicit user implementation/execution authority is resolved; no further broad design/plan/method question. Genuine human repository/environment gates still apply.
- Operation `recover-0.2.7-preserved`; no automatic fallback in any old mode.
- Exact payload ZIP147126946 bytes/SHA256`eb4138638b9305b406fb50f5e49e205982611af6bcba9aedf92bb34dd7d06b5a`, unchanged strict40 members; no request to old10779404529 endpoint.
- Preserve all four historical JSON records/pins, original product/tags/publications, fixed-four404 policy, strict custody10780480598 and failed evidence11124850978.
- Dedicated public custody prerelease, not product400420101; one unchangedZIP; no product rebuild/repack/package republication/asset overwrite/deletion/protection bypass.
- Same sole worktree/local branch; main alone Git/index/sign/provider actions. Sequential implementation owners, independent task/final reviews. Imported evidence remains outsideGit.
- All Cargo commands main-owned with CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_RELEASE_DEBUG=0; keep4GiB free.
- Preserve every raw failure/unknown journal and evidence workspace; never manufacture unavailable evidence or claim skipped tests ran.

## Review Focus

- Provider-ID bootstrap must pin actual observations, never fabricated IDs or caller authority: Task1.
- Published transport metadata may change between independent reads; counters may legitimately change: Tasks1–3.
- HTTP binary response selection/redirect credentials differ from JSON metadata: Task2.
- Legacy v2 receipts must not pass preserved v3 or drift in shared refactoring: Tasks1–3.
- Workflow conditions and shell allowlists must not route preserved mode into package publishing: Task3.

---

### Task 1: Provision exact custody transport and implement pinned v3 verification

**Files:** Create `governance/releases/v0.2.7/PRESERVED-PAYLOAD-TRANSPORT.json`; modify `tools/verify_release_recovery_027.py`, `tools/test_release_recovery_027.py`. Main owns design/plan and private provisioning records.

**Interfaces:** Consumes unchanged manifest/record/metadata-policy and actual provisioned transport observations. Produces `PRESERVED_OPERATION`, `PRESERVED_PAYLOAD_POLICY_SHA256`, `load_preserved_payload_policy(manifest, record, policy, path)`, `validate_preserved_payload_policy(manifest, record, policy, preserved)`, `verify_preserved_payload_observation(preserved, observation)`. Add keyword-only `preserved=None` to canonical origin/receipt functions that need it; preserve old call/results. Canonical descriptor schema and observed identity projection follow the design. OriginV3 uses `exochain-retained-origin-027/v3`; result/binding/receipt v3 discriminators must agree throughout.

- [x] Main independently reviews bounded provisioning procedure, verifies local wholeZIP/strict40, current configured identity, reviewed anchor b587 signatures/tree/human reviews/CI and unused custodytag. Journal one intent per mutation, sign/push new custodytag, create dedicated draft, upload once, exact hosted metadata/byte readback, publish custody-only prerelease/latestfalse, independent final readback. Record real repository/tag/release/asset identities; no execution dispatch/product write.
- [x] Fresh implementer reads actual provisioning snapshot; writes strict descriptor from real fields and semantic pin, without changing four old records.
- [x] Add failing tests `test_preserved_policy_exact_pin_and_types`, `test_preserved_transport_identity_and_inventory`, `test_preserved_origin_has_no_current_old_payload`, `test_preserved_receipts_reject_v2_and_cross_transport`. Assert correct actual-shape fixture passes and each wrong ID/type/digest/schema/body/tag/extraasset/custodyexpiry/vector/chronology mutation fails; changing download_count alone passes. Run focused unittest selectors and retain RED.
- [x] Implement named policy/observation functions, shared v2/v3 origin checks and canonical receipt binding/provenance/full-verification extensions. V3 controls carry custody metadata and new transport observation, not fake oldpayloadcurrentmetadata. Require separate current writer acquisition identity and ownproducer receipts.
- [x] Run complete custody suite with actual two saved ZIPs via its existing supported evidence inputs; report exact tests/skips. Run focused receipt regressions and oldmode tests. Independent scoped spec/quality review; main adjudicates every finding, resolves blocking findings and signs explicit paths after worker stops.

### Task 2: Acquire the pinned hosted payload through canonical read-only transport

**Files:** Modify `tools/import_release_recovery_027.sh`, `tools/test_import_release_recovery_027.py`, `tools/verify_release_recovery_027.sh`, `tools/run_release_recovery_027.sh`, `tools/publish_release_npm_package.sh`, `tools/recover_release_python_027.sh`, their focused npm/Python/signature guards; narrowly extend verifier interfaces only if reviewed with caller compatibility.

**Interfaces:** Consume Task1 functions/descriptor. Extend `Transport(..., *, policy=None, preserved=None)`, `fetch_retained_controls(..., *, phase, preserved=None)`, `acquire_retained(..., *, policy=None, observer=None, preserved=None)`, `finalize_retained_observations(..., *, preserved=None)` and existing source/receipt helpers consistently. Add descriptor-derived `preserved_observation` and `preserved_archive` methods to Transport, reuse canonical strictZIP staging. Source-captured descriptor/signatures govern all callers; no environment/path/ID override.

- [x] Add failing tests for actual canonical transport direct200/one302 octet-stream, allowed official storagehost, hostile redirect/noauthforwarding/no diagnostic leakage, exact bounds/hash, changed beforeafteridentity, oldpayloadendpoint nevercalled, original404/custody checks stillcalled, and sourcecapture/atomicoutput. Keep RED outputs.
- [x] Extend fixed endpoint inventory with exact repository/anchor/release/asset/inventory requests from descriptor only; preserve GET-only/noauth storage and strict metadata parsing. Reuse payload profile to stage unchanged archive under historicalbasename honestly. Build actual V3 controls/origin across beforeafter/final passes; no synthetic oldmetadata.
- [x] Extend source capture/signature checks and producer v3 receipts; reverify native2/public5/Rust32 and actual observer chronology. Add preserved to accept/readback-only npm/Python predicates without enabling publisher credentials, OIDC or staging exemptions.
- [x] Run importer suite, custody regressions and nonCargo wrapper/npm/Python tests, saving RED/GREEN and exact scope. Main runs Cargo-capable guards with resourcebounds. Independent scoped review; resolve findings then main explicit-path signed commit.

### Task 3: Connect protected writer/workflow and truthful operating records

**Files:** Modify `tools/recover_github_release_027.py`, `tools/test_recover_github_release_027.py`, `.github/workflows/release.yml`, `tools/test_release_recovery_workflow.py`, `tools/test_release_workflow_ref_binding.sh`, `tools/test_release_version_input_boundary.sh`, other source-routing guards identified by exact search; update existing `RECOVERY-DESIGN.md`, `RECOVERY-PLAN.md`, `RECOVERY-VALIDATION.md`, `RETAINED-RECOVERY-PLAN.md`, `RETAINED-METADATA-IMPLEMENTATION-PLAN.md` where old restrictions need explicit mode-qualified clarification. Never alter historical JSON records.

**Interfaces:** Consume Task1/2 preserved keyword and receipts. Extend existing `retained_main`, `retained_release_metadata`, source/rebind/currentreceipt/public/final gates and already approved emptydraft transition. Preserve canonical job names and five direct producer outputs. No second publisher or new workflow DAG.

- [x] Add failing writer tests covering v3 receipt order/identity, independent transport reacquisition/final byte check, source/transport/localfile drift before eachmutation, exact sameempty400420101 bodytransition after predecessor authentication, conflicting/nonempty/published rejection, uncertainwrite stop/no retry, exact35 final acceptance; retain RED.
- [x] Implement preserved mode in canonical writer, stable v3 public custody/body with history/rehost disclosure, newtransport rebind and final freshbytecheck. Preserve old four-rowunknownjournal and originalHTTPcauselimit, sameID and nooverwrites.
- [x] Add failing parsed-workflow/source-boundary tests for new operation/input constraints, existing fullCI/twohumangates/signedtag dependencies, producer readonly/noOIDC/no registrycredentials, direct sameattempt handoff, LIVE-onlyprotectedwriter and packagebuild/publish exclusion; then implement exact operation predicates/captured policy path across canonicalworkflow/guards.
- [x] Update operatingdocs truthfully with actual descriptor/commands, newversusoldtransport/custody limitations and acceptance sequence; no unrunpassclaims. Focusedwriter/workflow/import/receipt suites and nonCargo guards GREEN; mainresourceboundedCargo guards. Independent scoped review, fixes and main signedcommit.

### Task 4: Validate final candidate, integrate normally, execute and verify release

**Files:** Main-owned new private validation runner/logs and plan-specific evidence ledger; truthful final doc corrections only before sourcefreeze. Existing PR846 and provider release state through legitimate configured operations.

**Interfaces:** Complete canonical preserved path from Tasks1–3. Reuse inventory discovery and resource/sourceguards from prior full92 validation, but create new independently reviewed run root; never restart historical runs or overwrite evidence.

- [ ] Main self-audits finaldiff/unchangedproduct-lock-historicalrecords/signatures; signs complete docs then freezes exactsource. Prepare new full CI-derived local command inventory and testplan, actual archives, current/legacy npm contracts, fullcore gates/allPython/allrequiredshellguards; classify exact generatedoutputs and preserve outsidecheckout. Independent runner readiness review before one run.
- [ ] Execute every command under resourcefloor on exact finalcandidate, retain all stdout/stderr/status/sourcehashes and audit everyresult. Fresh independent native/public/package/transport verification uses actualprovider evidence and separate local-versus-hosted labels. Diagnose/fix actualfailures with preserved oldruns and new exactcandidate validation when needed.
- [ ] Independent wholebranch source/evidence review plus main adjudication of everyfinding. Normallypush signed finalhead to existing PR846 branch, update body scope/evidence and attach; noforce, duplicate reviewerrequests or oldgreen reruns. Follow actualfreshfinalheadCI and two distinct eligible nonauthorhuman approvals.
- [ ] Normalintegration after fullgates; verify exact integratedtree/signature and integratedCI. Freshsource/protection/custody/transport/publicpreflight, new unused configuredsignedrecover.N tag and protectedpreservedDRY once. Follow genuineactualgates; verify actualread-onlytoken transport/currentdirectreceipt/cryptoproof and allwritersskipped before LIVE.
- [ ] SeparateprotectedLIVE once after acceptedDRY/currentpreflight; genuinegates/currentownreceipt/freshwritertransport/bodytransition/exact35publication. Independently verify allproviders and every35assetbyte plus freshtransport. Only then declare0.2.7released and close844; proceed separatelyapproved822retirement with itsownDRY/LIVE/31exactyankacceptance.

## Main self-review

Spec requirements map to Tasks1(policy/history/bootstrap),2(acquisition/credentials/producer),3(writer/workflow/docs),4(actualvalidation/consent/publication). Interfaces use the same `preserved` keyword and preserve old defaults. Each Review Focus item has an explicit negative/positive test. Provisioning identity is deliberately obtained before the pinned descriptor, not filled with invented future IDs. Human gates are externally required consent, never agent-generated substitutes.
