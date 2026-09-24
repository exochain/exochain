# Preserved original 0.2.7 payload recovery — approved design and implementation plan

> **Status: design approved by Bob on September 24, 2026; implementation underway.**
> Bob's explicit "plan approved" authorizes implementing this bounded extension
> and preparing its reviewed PR. It does not approve an unreviewed implementation,
> new transport upload, protection bypass, tag/dispatch or live release mutation.
> Package rebuild/repack/republication remain prohibited. Release execution stays
> stopped until the stated implementation review and protected prerequisites pass.
>
> **For agentic workers:** After explicit implementation approval, use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans`
> task by task. Unchecked items below are implementation acceptance steps, not
> claims that those steps have run.

**Goal:** Complete acceptance of the already published 0.2.7 packages and the
original GitHub Release using preserved original payload bytes, without
rebuilding, repacking, or republishing packages.

**Architecture:** Add one separately reviewed, fixed retained-custody operation
to the canonical recovery tooling. It consumes one existing GitHub transport
and its separately pinned historical custody evidence. Original artifact expiry
remains an honest historical/current observation; the retained transport must
itself still be available and unexpired. Existing normal release and original
recovery modes retain their current behavior and restrictions.

**Tech stack:** Existing GitHub Actions, Bash, strict Python parsers, Node/npm,
GitHub attestation verification, and hashlocked PyPI/Sigstore verification.
No new package dependency is proposed. Sections 1–6 are the approved design;
sections 7–9 specify implementation and test acceptance.

## 1. Evidence and the decision being reviewed

The old recovery cannot proceed unchanged: original WASM artifact
`10518086890` became `expired:true` at `2026-09-24T20:09:34Z`.
`verify_release_recovery_027.py` deliberately requires fresh `expired:false`
for all nine original metadata records. This is a prerequisite failure, not a
failure of a newly dispatched run; none was dispatched.

A bounded read-only local inventory found no original artifact ZIPs among 321
files in the six known evidence roots. The previously recorded inventory root
has seven empty lane directories. Two matching Python distributions are public
PyPI readback copies, not retained original Actions ZIPs. This does not assert
that no other copy exists anywhere; it rules out assuming the recorded paths
still contain a complete recovery input.

The existing hosted recovery transport is the viable candidate. It was created
after the original import succeeded and before the original artifacts expired.
It contains the **extracted original payload tree**, not the seven original ZIP
envelopes and not the two Rust preparation archives. The prospective controller
must say exactly what it verifies: the retained transport, all 40 original
payload files, historical import evidence, and fresh public/cryptographic
acceptance. It cannot claim a fresh verification of nine original ZIPs.

| Fixed identity | Value |
| --- | --- |
| Product | `v0.2.7`, source `666c578f719d1e54fce95d6831a3af92ea80df93` |
| Product tag object | `be47589ec7dbefe821ada35ed0a89dedc9751953` |
| Original production | run `35257955565`, attempt `1` |
| Retained transport | artifact `10779404529`, `exochain-027-recovery-original-files` |
| Transport bytes / SHA256 | `147126946` / `eb4138638b9305b406fb50f5e49e205982611af6bcba9aedf92bb34dd7d06b5a` |
| Retaining run | `35754493083`, attempt `1`, `workflow_dispatch` |
| Retaining controller / ref | `2198e4ef610e9ef6d04adf726f7f4b3e156a3bc1` / `refs/tags/v0.2.7-recover.2` |
| Retaining tag object | `cab642330dfc34099cddbe3721b376e26a67c722` |
| Retaining producer | job `107409656991`, `Verify Original 0.2.7 Artifact Custody` |
| Producer steps | import success ended `2026-09-23T22:33:27Z`; payload transport upload success `22:33:27–22:33:30Z`; custody evidence upload success `22:33:30–22:33:32Z` |
| Transport created / expiry | `2026-09-23T22:33:30Z` / `2026-09-30T22:33:27Z` |
| Historical custody evidence | artifact `10780480598`, `81581` bytes, SHA256 `1eb8514f9ead70a13e6e1c620d69c359cdb77a332772f400f9ca104ac30a2bb3` |
| Custody evidence created / expiry | `2026-09-23T22:33:32Z` / `2026-10-23T22:33:31Z` |
| Repository / owner / workflow IDs | `1116455646` / `129763194` / `248228578` |
| Original manifest semantic SHA256 | `17c77eafa0ea34fa7437cbc0d6988f561d686e330bee8c17cfe0e6a354e1bec4` |
| Publication identities semantic SHA256 | `4596c339d2af34ce3aeff5f2dd4a6be95fbb044250e934a27221170b97902ca7` |

Semantic pins are the existing strict-parser digests, not raw file SHA256s.
Both owned manifests and both semantic pins remain unchanged. Source inspection
is against `63aafee921edf91048484f5e33f2fb344164f181`; the implementation must
reconcile any newer integrated source without discarding reviewed changes.

The planning audit downloaded those two exact retained ZIPs read-only, with
metadata unchanged before/after. All **40/40 original payload members** match
the unchanged manifest, including exact sizes and SHA256s. The payload ZIP has
40 regular entries, mode `0100400`, STORED compression, no directory entries
and `147119630` expanded bytes. The custody ZIP has 60 regular entries, mode
`0100600`, DEFLATE compression, no directory entries and `459000` expanded bytes.
All 60 custody files also match the previously retained local evidence. Inspection
did not extract or execute payloads and did not rerun native/package crypto.

**Recommended choice:** explicitly approve the one pinned pre-expiry hosted
transport plus pinned historical custody evidence as an additional input mode.
This is a narrow custody-policy extension, not a claim that the current policy
already permits cross-run reuse or that original retention was extended.

Alternatives not selected:

- New transport containing original ZIPs: would permit current ZIP-envelope
  verification, but the bounded inventory found no such bytes. Creating and
  uploading another transport would need separate authority and review of its
  actual immutable identity. No fallback to that option is included.
- Blanket removal of expiry checks, caller-selected local files, arbitrary
  artifact IDs, registry downloads as custody replacements, rebuilding,
  repacking, new versions, or rerunning the unchanged failing controller: rejected.
- Reusing old success receipts as current package acceptance: rejected. Historical
  evidence establishes prior import; current acceptance is performed anew.

## 2. Global constraints and authority

- All proposed source/test/workflow/plan paths are **EXOCHAIN core release
  tooling or governance**. Downloaded archives, logs and provider responses are
  **imported evidence**, kept read-only outside the repository, never committed.
- No Rust product, package payload, dependency lock, version, original manifest,
  publication map, existing tag, environment protection, or repository permission
  changes. No new runtime deployment target or trust claim is introduced.
- Bob is accountable; Bob, Max and Robert are the actual maintainers. Use
  applicable existing security audit evidence, including Daybreak and other
  systems. No fictitious Legal department or exclusive audit-provider gate.
- Two distinct independent non-author maintainers must approve the final
  implementation head before merge; agent review is supporting evidence only.
  Retain full exact-head CI, verified integration tree/signature, signed new
  maintenance ref, both protected release approvals, dry then separate live.
- PR841's reviews occurred after its merge. Preserve that chronology. A newly
  reviewed prospective controller is the forward path; no fabricated retrospective
  waiver or additional nonexistent panel vote is required.
- Use only the current approved worktree/cache; no branch switch or new worktree.
  Preserve the dirty original checkout. Keep at least 4 GiB free. Every future
  Cargo invocation uses two jobs, incremental off, and dev/test/release debug=0.
  CI compilation/tests validate controller source; their outputs must never
  replace any original release payload. No product packaging/build lane runs
  for the retained operation.
- Bob has approved implementation and preparation of its reviewed PR. Actual
  final-head human reviews, protected approvals and execution authorization
  still govern release writes; plan approval does not replace those gates.

## 3. Fixed custody contract

### Separate mode, not a fallback

Proposed operation: `recover-0.2.7-retained`. Version remains exactly `0.2.7`;
controller ref remains `refs/tags/v0.2.7-recover.N`, positive unused N. Capture
all helpers and records from actual `GITHUB_SHA`. Never substitute the product
SHA or the retaining controller for the actual executing SHA/ref.

Add owned `RETAINED-CUSTODY.json` with its own strict schema and semantic pin.
  It records the exact identities in section 1, selected transport layout and
member inventory, historical evidence inventory and per-file hashes, original
manifest/publication pins, producer/upload mapping, and retention timestamps.
Derive the 40 expected payload paths/sizes/hashes from the unchanged original
manifest rather than maintaining a competing payload inventory. Require exact
schema, types, counts and cross-bindings; reject duplicate keys and extra fields.

The artifact API does not attest a producing attempt/job. Bind the fixed mapping
using the explicit attempt-1 run and fully paginated job records, successful
named producer and upload steps, original controller source, exact artifact
metadata, and the pinned evidence archive. Do not infer success from run-level
status: the retaining run later failed in unrelated publication acceptance.

### Historical original import versus current retained custody

1. Download only the two pinned retained artifacts from fixed GitHub API paths.
   Freshly require each to be unexpired and match every pinned identity, size,
   digest and retention timestamp. Recheck metadata after download. No deletion,
   reupload, retention extension or transport reconstruction is part of this mode.
2. Authenticate the retaining controller/tag and original product tag/signatures;
   verify exact attempt/run/source/workflow/event/repository and producer mapping.
3. Strictly parse the historical custody archive. Validate its exact file
   inventory and hashes before parsing its contents. Cross-bind original run,
   jobs, nine metadata records, original manifest and import/identity results.
   Re-run the unchanged original-origin checker on these explicitly labeled
   historical records, never pass them off as fresh API responses.
   Four pinned members are intentionally empty command-output records:
   `npm-{llm,sdk,wasm}-tarball-check.txt` and `python-artifact-check.json`.
   Accept only those exact zero-byte entries and hashes, do not parse the empty
   JSON filename or treat an empty output as standalone success. Producer/step
   success, structured import results and fresh validation supply that evidence.
4. Separately fetch all nine current original metadata records and original
   attempt-1 run/jobs. Require immutable identity/digest/size/source/producer
   agreement. Record actual `expired` values and elapsed expiry honestly. Only
   the new retained contract admits original expiry after the proved pre-expiry
   import; existing `origin` continues requiring fresh non-expiry. A changed
   immutable field, missing metadata, incomplete pagination, unavailable pinned
   evidence or unprovable import chronology fails closed. No metadata-loss
   fallback is included in this proposal.
5. Verify the retained ZIP's exact outer bytes and every original member before
   exposing a destination. Its 147,126,946-byte bound is separate from the
   unchanged 96 MiB original-ZIP bound. Do not globally increase parser limits.
6. Reuse canonical `verify_files`, npm/Python package structure, SBOM, native
   archive and actual native cryptographic verification. Native archives contain
   29 legacy rlibs each, not executables. Only those native archives have original
   GitHub build attestations. Rust preparation remains two historical metadata
   checks, not a claim to have recovered two preparation archives.

Historical receipt prose is not independent cryptographic proof. Fresh native
verification must use the genuine verifier and exact original subjects,
repository, source/ref, signer workflow/digest and original invocation. Fresh
package cryptographic acceptance follows section 4.

### Safe transport and extraction

Use fixed GET-only endpoints, bounded responses/timeouts and terminal pagination.
Only the validated GitHub artifact storage redirect is permitted; do not forward
GitHub authorization to storage, npm, PyPI or crates.io. Never log credentials
or signed storage URLs. No caller URL, path, digest, source or provenance override.

Validate the observed outer ZIP profile explicitly: unique exact member names,
the separate payload/custody compression and modes listed above, general-purpose
flags `8` (data descriptors), Unix creator `3`, creator version `45`, required
extractor version `20`, no central extra fields or member/archive comments,
internal attributes `0`, and exact DOS archive bits `0x20` in external
attributes (payload `0x81000020`, custody evidence `0x81800020`),
no directory entries, fixed sizes,
bounded aggregate expansion, local/central header agreement, nonoverlapping
records and complete archive boundaries. Reject traversal, absolute/backslash
paths, encrypted members, duplicate/extra entries, links, devices, FIFOs,
unsupported formats, prefix/trailing data and ambiguous metadata. Do not call
unvalidated `extractall` or use a download action that extracts before checks.
If the real archived profile differs from expectations, inspect it and review
the exact profile; do not silently broaden validation.

For these two pinned streaming ZIPs, local headers have version20, flags8,
zero CRC/compressed-size/uncompressed-size placeholders and no extra fields.
Each payload is followed by a **16-byte signed 32-bit data descriptor**:
signature `0x08074b50`, CRC32, compressed size, uncompressed size. Validate the
descriptor's actual CRC/sizes against streamed bytes and the central directory;
allow only those observed local placeholders, not literal equality to final
central values. Require exact member/descriptor boundaries and reject missing,
truncated, forged, overlapping, unsigned, ZIP64 or inconsistent descriptors.
Main inspected this structure for every entry in both actual archives.
During implementation, main independently confirmed the DOS archive bit and
zero internal attributes on all 100 entries; this refines the exact observed
profile without permitting additional file types or arbitrary attribute bits.

Hash and extract from the same stable open descriptors; use private fresh
directories, `O_NOFOLLOW`, regular/non-hardlinked files, exclusive creation and
bounded reads. Validate all members before exposing output; rehash while writing
and run `verify_files` afterward. No merge into a previous import tree and no
local planning-audit copy accepted as an execution input.

## 4. Acceptance-only workflow and receipts

Keep existing modes separate. Introduce retained-only jobs so job permissions
are structural, not conditional promises inside credentialed publisher jobs:

`full CI + both approvals + signed identities -> retained-acceptance -> retained-github (live only)`

`retained-acceptance` has only contents/actions/attestations read permissions and
no job-level `id-token:write`, publishing secrets, Python publisher action or
package upload path. It imports the pinned source, then serially accepts:

- All 32 Rust 0.2.7 versions: exact original checksums and nonyanked public state.
- WASM, LYNK and SDK: exact public tarball bytes/SRI, current expected owner,
  canonical package validation, genuine successful npm signature/provenance
  audit and exact reviewed source/ref/subject using Node24.15.0/npm11.12.1.
- Both Python distributions: complete two-file inventory, exact public bytes,
  nonyanked state, genuine PEP740/Sigstore crypto plus exact reviewed publisher
  identity using Python3.13.7 and the existing hashlocked verifier dependencies.

Use the unchanged five-record publication map: WASM binds original666c/v0.2.7;
LYNK/SDK/wheel/sdist bind2198/recover.2. These are historical publishers, not
the current acceptance controller. No arbitrary either-source override. Missing,
yanked, conflicting or unverifiable publication fails; it never triggers upload,
Python staging, registry fallback, or a different version.

All these checks run for **dry and live**, unlike current recovery dry-run, which
skips LYNK/SDK/Python. Both perform a read-only GitHub inventory/preflight. Dry-run
has no GitHub Release writer and makes no package/release/tag mutation; normal
Actions evidence uploads are permitted after execution is separately approved.
Do not upload another payload transport: each required runner reads the same
fixed retained source. Evidence uploads contain bounded receipts, not packages.

Each current receipt binds schema/mode, actual controller SHA/ref/tag object,
current run ID/attempt/job, retained-record and manifest/publication pins, exact
transport IDs/digests, checked original identities, checker/runtime versions,
byte/crypto results and `mutation_attempted:false`. Store actual current original
expiry separately from historical observations. Preserve original failed SDK and
Python receipts without relabeling them.

The final live job consumes only exact-ID/digest receipts produced by the same
current run/attempt and expected successful producer jobs, never an arbitrary
artifact name or previous run's success. Validate receipt transport before
parsing. Obtain receipt artifact ID/digest from the acceptance job's **direct
upload outputs**, then cross-check current-attempt successful producer/upload
steps, artifact creation chronology and authoritative metadata. Embedded receipt
JSON cannot establish its own producer: reject name-based lookup fallback and
an earlier-attempt artifact even if its JSON asserts the current attempt.
A rerun with inherited earlier-attempt receipts is not silently accepted;
fresh read-only acceptance jobs must run for the current attempt or execution
stops. Unknown mutation outcomes never authorize an automatic rerun.

## 5. GitHub Release completion, not package republication

Only `retained-github` receives narrowly scoped GitHub contents-write authority,
plus actions-read for exact retained/current receipt downloads,
with required release environment approval and no package token or OIDC. Before
writing, freshly verify source/tags, current receipt provenance, retained artifact
availability and all 40 files, then current Rust and five public package inventory,
byte/identity readbacks. Cryptographic acceptance must already be complete in
that same current run/attempt; stale or conflicting public evidence stops writes.

Reuse the existing GitHub helper, exact draft search/terminal pagination,
no-overwrite policy and append-only mutation journal. Expected public inventory
remains **35 assets**: two original native archives, 32 original SBOMs and
`RECOVERY-CUSTODY.json`. Neither npm tarballs nor Python distributions are
reuploaded to GitHub or package registries.

Add a versioned retained-custody receipt/description distinguishing original
production, historical import/retention, prior package publication and current
acceptance. Generate stable release asset bytes from reviewed static identity
plus the actual controller/ref; keep changing execution timestamps, run/attempt
IDs and current observations in separate run evidence. This lets same-controller
recovery compare an existing custody asset exactly without overwriting it.

Absent release may become a draft, only missing exact allowed assets may be
uploaded, and only complete verified drafts may be published. Reject conflicting
assets/metadata or incomplete already-public releases; never replace/delete.
Rebind identities immediately before writes and fresh-download all 35 assets
after publication; require the same release ID, exact names/bytes, `draft:false`
and signed original product tag. `target_commitish` is bookkeeping, not source
proof. The final public custody asset must not claim all 40 payload files are
GitHub release assets: only the stated 34 original assets plus the receipt belong.

Any uncertain create/upload/publish result records intent/outcome and stops
further writes. Preserve the journal and independently read authoritative state
before proposing a same-controller resume. No blind retry, rollback by deletion,
tag move or switch to a different controller's custody asset. Retirement of 31
old 0.2.3 versions remains a separate approved workflow **after** full 0.2.7
acceptance; this proposal does not execute or change it.

## 6. Review focus

Human review should decide the actual policy change: whether the specifically
pinned successful pre-expiry import and retained 40-file transport provide an
acceptable custody chain after the original download envelopes expire. The
tradeoff is explicit: no fresh original-ZIP verification, but fresh payload
hashes, native crypto, public package crypto, signed source identities and pinned
historical producer evidence. Hash equality alone is not uninterrupted custody.

Technical review must challenge archive ambiguity, expired-vs-retained evidence
substitution, current receipt replay, credential reachability, dry/live DAGs and
GitHub partial-write/resume behavior. Preserve full independent maintainer review
and protection gates without reopening resolved ownership assignments.

## 7. Implementation tasks — only after design approval

### Task 1 — Freeze the observed retained evidence contract

Files: new `governance/releases/v0.2.7/RETAINED-CUSTODY.json`,
`tools/verify_release_recovery_027.py`, `tools/test_release_recovery_027.py`.

- [ ] Curate exact two-artifact metadata, actual ZIP profile/member hashes,
  historical original evidence hashes and producer mapping into the owned record.
  Raw archives/logs stay outside source control. Review the record and semantic
  pin together; original manifest/publication records remain byte-for-byte intact.
- [ ] First add failing tests for proposed `retained-record`,
  `retained-origin`, `retained-transport` and `retained-receipts` CLI interfaces.
  They consume fixed-schema data and return bounded JSON/nonzero failure, never
  shell assignments. Original `origin`, `artifacts`, `files`, `publication` and
  `rust-registry` retain their existing contracts.
- [ ] Implement the strict distinct historical/current checks and bounded outer
  ZIP validator, reusing canonical parsing/file validators. Do not normalize
  expired metadata or reuse an arbitrary synthetic manifest to bypass a pin.
- [ ] Run positive actual-byte and complete negative matrix tests in section 8,
  then independently review this input boundary before workflow wiring.

### Task 2 — Reuse canonical read-only import and package acceptance

Files: `tools/import_release_recovery_027.sh`,
`tools/run_release_recovery_027.sh`, `tools/publish_release_npm_package.sh`,
`tools/recover_release_python_027.sh`, `tools/verify_release_recovery_027.sh`,
and their existing import/npm/Python/stage regression suites.

- [ ] First write failing no-upload/no-credential and explicit-mode tests. Root
  dispatcher validates the new exact operation; ordinary callers cannot turn on
  retained behavior through an untrusted environment switch.
- [ ] Add fixed retained GET orchestration inside the canonical importer,
  factoring shared structure/native/SBOM checks rather than copying a second
  implementation. Keep original importer and its 96 MiB limits unchanged.
- [ ] Establish verified acceptance-only context before npm credential checks
  for all three profiles; reject package tokens and OIDC variables in this mode.
  Reuse complete public acceptance; never execute npm publish/package lifecycles.
- [ ] Add Python acceptance-only dispatch using existing complete public
  verification, no stage creation and no publisher action. Isolate public checker
  environments from even the read-only GitHub credential.
- [ ] Produce current-context receipts and recheck actual source/ref/signatures
  and fixed files before exposing any accepted result. Verify failures expose
  no accepted output and preserve bounded diagnostics without credentials.

### Task 3 — Wire retained-only dry/live jobs and exact GitHub completion

Files: `.github/workflows/release.yml`, `.github/workflows/ci.yml`,
`tools/test_release_recovery_workflow.py`, `tools/recover_github_release_027.py`,
`tools/test_recover_github_release_027.py`, existing workflow/source/dry-run guards.

- [ ] Add failing parsed-YAML DAG/permission/input mutation tests. Normal
  packaging jobs and original recovery jobs must exclude the new operation.
  Keep all full CI, signed-source and protected approval dependencies.
- [ ] Add the two retained-only jobs described above, pinned existing actions
  and runtimes. Dry and live perform identical full read-only acceptance;
  only separately authorized live may reach GitHub contents-write.
- [ ] Add read-only GitHub preflight plus fixed same-run receipt validation and
  stable retained release metadata. Reuse existing 35-asset journal/recovery code.
- [ ] Test draft conflicts, current receipt replay, concurrent changes and
  unknown writes. A same-controller approved resume can accept identical existing
  assets only after fresh state/acceptance; no asset replacement is introduced.

### Task 4 — Complete validation and separately reviewed implementation

Files: this plan, `RECOVERY-DESIGN.md`, `RECOVERY-PLAN.md`,
`RECOVERY-VALIDATION.md`, `TEST-PLAN.md` under this release directory.

- [ ] Record the approved bounded extension in existing governance docs without
  rewriting historical failure/approval chronology or asserting implementation
  acceptance early. Original-mode restrictions remain explicit.
- [ ] Run every focused suite listed below, all CI-derived shell guards and full
  low-disk core gates; retain failed and passing logs separately. No new payload
  packaging command is permitted. Move generated test evidence intact outside
  the checkout before unchanged source-hygiene checks.
- [ ] Independently review the complete immutable implementation diff, correct
  findings with regression tests, then obtain both actual final-head maintainer
  approvals and full hosted CI before normal integration. Verify integrated
  tree equals reviewed tree and signature is valid.
- [ ] Only with release execution authority, create a new unused signed
  maintenance tag, perform protected complete dry acceptance, inspect genuine
  receipts, then separately authorize/protect live GitHub completion. Do not
  dispatch an expired/missing-source candidate merely to discover expected failure.
- [ ] Freshly verify all providers and 35 GitHub assets, preserve receipts, and
  report release acceptance separately from the issue 822 retirement outcome.

## 8. Test plan and acceptance evidence

| Boundary | Required positive / negative evidence |
| --- | --- |
| Source and records | Exact captured controller/product/retaining identities pass; swapped SHA/ref/tag, changed semantic pins, duplicate JSON keys, unknown fields, bool-as-integer and arbitrary override fail. |
| Original chronology | Pinned successful pre-expiry import plus matching current metadata pass in retained mode only; missing/failed producer, wrong attempt, late import, forged earlier timestamp, changed digest, incomplete pages or missing records fail. Original mode still rejects expired originals. |
| Retained availability | Exact two fresh nonexpired retained artifacts pass; expired, deleted, size/hash/name/run/source mismatch or metadata change during download fails. No local or alternate-artifact fallback. |
| Actual retained bytes | Independently hash real downloaded transport and all 40 manifest members; inspect actual historical evidence. Fixtures validate rejection behavior, not real custody or crypto. |
| ZIP/filesystem | Reject all malformed/ambiguous/link/path/type/size/CRC/header/overlap/prefix/trailing/duplicate cases, disk-floor violation and changed descriptors; no exposed destination on rejection. Explicitly test missing/truncated/forged/overlapping/inconsistent data descriptors against the real positive ZIP profile. Validate payload and receipt transports separately. |
| Network/secrets | Only fixed GETs and validated storage redirect; no auth on public/storage requests; bounded error paths do not print tokens/SAS. Credential/OIDC sentinels must be absent from all package verifier children. |
| Package acceptance | All 32 Rust versions and 5 mapped files pass only with actual correct public bytes/provenance; any missing/yanked/conflicting/wrong owner/wrong source/invalid crypto/extra Python file fails. Assertions prove zero upload calls, stage files, or publisher-action reachability. |
| Dry/live permissions | Dry exercises all 5 crypto checks and GitHub preflight with no writer. Normal/default mode and original recovery remain unchanged. Missing CI/approvals, enabled build/publish lane, job OIDC or secret exposure fails guard. |
| Receipts/replay | Bind direct upload outputs, same current run/attempt, controller/ref, producer/upload success and chronology, pins and transport; previous-run/attempt, forged success, missing crypto or altered receipt fails before any write. Include an older artifact whose JSON falsely asserts the current attempt. |
| GitHub | Exact 35-asset completion and same-controller identical-asset resume pass; extra/conflicting asset, partial public release, pagination ambiguity, concurrent change and unknown write stop. Final new downloads prove every asset. |

Focused commands for implementation (not a claim these have run for new code):

```sh
python3 -B tools/test_release_recovery_027.py
python3 -B tools/test_import_release_recovery_027.py
python3 -B tools/test_release_recovery_workflow.py
python3 -B tools/test_release_recovery_python_stage.py
python3 -B tools/test_recover_github_release_027.py
bash tools/test_release_recovery_npm.sh
bash tools/test_recover_release_python_027.sh
bash tools/test_verify_python_release_package.sh
```

Also run actual credential-free npm runtime contracts and genuine native/npm/
Python crypto verification. Enumerate all existing shell guards from current CI,
not a stale hardcoded count; run relevant retirement regressions too. Full core
commands remain build-release, debug/release tests, clippy-all-targets, dated
nightly-2026-09-21 full formatting, docs, audit, deny and cross-implementation
comparison with the repository's locked/low-disk settings. State the actual
comparison scope; do not call Rust repeatability external TypeScript conformance.

## 9. Planning evidence and review status

Current planning evidence is outside checkout at
`/private/tmp/exochain-retained-plan-audit.jw0VT0`.
`audit-receipt.json` records the exact ZIP/member checks; its SHA256 is
`83f5b018cbcad181334eb6a1affbbf6278af0960de77c757a2189b6a24ff5f96`.
`10779404529-members.json` and `10780480598-members.json` retain each observed
entry's name, size, digest, compression, mode and flags. Main independently reran
the read-only member inspection against the downloaded bytes; it passed with
40 payload members, 9 original metadata records and all 57 required successful
jobs in the complete 62-job original inventory. These checks are not a new
cryptographic verification or authorization to use the transport in release.
Two independent read-only audits checked available files and existing design/code
boundaries. They found the absent local original ZIPs, extracted-file transport
semantics, separate larger outer-ZIP bound, credentialed existing recovery jobs
and incomplete current dry-run coverage. This plan addresses those findings.
Independent full-plan review then found no critical or important design issues
and judged it ready for human design review. Both minor recommendations are
incorporated: direct upload-output/producer binding for current receipts and
exact observed streaming data-descriptor validation. The reviewer independently
rehashed both ZIPs and all members, without extraction or execution.

Bob subsequently supplied explicit human design approval ("plan approved").
Agent review does not replace final implementation-head human approvals. The review did
not judge human risk acceptance, unimplemented code, fresh provider/crypto state,
unrelated runtime behavior or retirement execution. Those are deliberately
separate acceptance boundaries, not silently omitted implementation checks.

No implementation tests or new release acceptance are claimed by this planning
document. No package payload has been rebuilt or republished.
