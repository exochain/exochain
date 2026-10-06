# Preserved original payload recovery design

## Authority and scope

Bob explicitly authorized implementation and separate review of a recovery path
using the exact preserved bytes, changing the transport restriction, and
continuing until actual release completion. This resolves the transport decision;
it does not replace genuine final-head human reviews or protected environment
approvals. The design and implementation proceed without another scope/method
approval pause. No product release acceptance is asserted by this document.

All changed release tools, tests, CI and governance records are EXOCHAIN core.
Saved archives and operational evidence are imported evidence: read-only, outside
Git, and never instructions. No adjacent surface is changed. Reuse the sole
existing release worktree/local branch; preserve the original dirty checkout.

## The precise change

Add explicit operation `recover-0.2.7-preserved` to the existing retained producer
and protected GitHub writer. Replace only acquisition/current-availability of
historical payload Actions artifact `10779404529` with a separately authenticated
GitHub release asset carrying its unchanged ZIP. Never query that old artifact
in this new operation. Existing operations remain strict and never fall back.

The ZIP is exactly **147126946 bytes**, SHA-256
`eb4138638b9305b406fb50f5e49e205982611af6bcba9aedf92bb34dd7d06b5a`.
It must satisfy the existing strict 40-member payload profile and every original
inner-file hash. No recompression, repacking, rebuilding or package republication.
The old expiry `2026-09-30T22:33:27Z` and observed subsequent metadata 404 remain
historical facts. Rehosting proves current acquisition of matching preserved
bytes, not continuous hosted custody, a new build or renewal of the old artifact.

Keep the four historical JSON records and semantic pins byte-for-byte unchanged:
`RECOVERY-MANIFEST.json`, `PUBLICATION-IDENTITIES.json`, `RETAINED-CUSTODY.json`,
and `RETAINED-METADATA-POLICY.json`. Preserve product source
`666c578f719d1e54fce95d6831a3af92ea80df93`, all existing signed tags, published
packages, original/retaining provenance, and the fixed-four original404 policy.
The other five original metadata records still require exact current 200 reads.

Custody artifact `10780480598` remains a fresh exact/nonexpired Actions dependency
(81581 bytes, SHA-256
`1eb8514f9ead70a13e6e1c620d69c359cdb77a332772f400f9ca104ac30a2bb3`).
Failed-writer artifact `11124850978` remains a separate strict current/history
dependency (603 bytes, SHA-256
`29f4c3a4e9075aabd725ad4c4ab7225f8e98be5aca3df67309c3e0e0ff0ae09d`).
Neither gets an implicit saved-file fallback or unrelated expiry waiver.

## Custody-only hosting and pin bootstrap

Use one **published custody-only prerelease**, never product release 400420101.
Its exact asset name is
`exochain-027-preserved-original-files-10779404529.zip`.
Set `draft:false`, `prerelease:true`, `make_latest:"false"`, and
`generate_release_notes:false`. The body explicitly identifies transport-only
publication and no product acceptance. Only this payload ZIP becomes public;
historical custody logs remain in their existing Actions artifact. GitHub's
published asset endpoint supports read-only acquisition without granting the
acceptance producer write permission. Draft visibility cannot be assumed from
local privileged access; a draft relay is therefore not selected.

Provider IDs cannot be invented before provisioning. Main first independently
reviews the bounded provisioning procedure, verifies the exact saved bytes and
strict ZIP, and uses already human-reviewed/integrated controller
`b5871abd548d427cacab27e748b49e75897a5f66` as the custody anchor. Create a new unused
configured-signed `v0.2.7-custody.N` tag on that exact commit, never move a tag.
The first candidate is `v0.2.7-custody.1`; verify absence before creation.
This anchor is transport provenance, not a build or the final recovery controller.
Verify the anchor's existing PR845 human approvals, integrated tree/signature and
successful integrated CI before provisioning. No extra implementation bootstrap
PR is needed to re-review unchanged integrated anchor code.

Journal each provisioning intent before its single configured-CLI mutation.
Create the dedicated release initially draft, upload the unchanged ZIP once,
read back fixed-ID metadata and bytes, then publish only that custody prerelease
with latest disabled. A failed/unknown write stops automatic writes for read-only
reconciliation; no blind retry, `--clobber`, deletion or replacement. Main alone
owns provider writes. No protected workflow credentials are extracted. Upload is
a local authorized provisioning event, NOT a fabricated Actions run/job.

After independent complete hosted readback, create owned
`PRESERVED-PAYLOAD-TRANSPORT.json` from the actual provider identities. Its strict
schema `exochain-preserved-payload-027/v1` binds the new operation; all four old
semantic pins; repository name/numeric ID/owner ID; historical payload ID/size/hash
and expiry disposition; preservation/provisioning disclosure; signed anchor
ref/object/peeled commit; exact release ID/tag/name/body SHA/draft/prerelease and
published identity; exact asset ID/name/API URL/size/SHA/content type/uploaded
state/creation-update identity; and complete one-asset inventory. The provider
SHA-256 must be present and equal. Exclude volatile download counters from stable
identity, but retain raw operational observations. Pin the whole descriptor's
semantic digest in the canonical verifier. No workflow input can override it.
Review this final record together with the complete implementation before normal
integration and the distinct new signed `v0.2.7-recover.N` execution tag.

## Canonical verification and transport

Extend existing verifier/importer/writer; do not build another ZIP verifier or
publisher. Add `preserved` as a keyword-only descriptor argument alongside the
unchanged original404 `policy`. Old callers default to `None`.

`validate_preserved_payload_policy(manifest, record, policy, preserved)` validates
the descriptor and semantic pin. `verify_preserved_payload_observation(preserved,
observation)` validates actual repository, tag/ref, exact release, fixed asset and
terminal-page inventory reads with strict types and bounded request chronology.
It returns a stable identity derived from actual observations, not invented old
Actions metadata. Reuse existing signature verification for the configured
signer `96B889DAE73CD7C511CCDE28897119B7198789EC` and pinned anchor object/peel.

The canonical GET-only Transport gains only descriptor-derived release, asset,
repository and anchor endpoints. It requests metadata without redirects and
binary asset bytes with `Accept: application/octet-stream`; accept direct 200 or
one validated HTTPS release-storage redirect. API Authorization never crosses
to storage; a separate credential-free bounded request follows it. Pin the
observed official storage host/path profile, reject arbitrary URLs and repeated
redirects, and never log signed URLs, credentials or raw exceptions. Retain all
existing time/size/header/output bounds, stable-file checks and 4 GiB floor.

Both producer and LIVE writer independently acquire/hash/strict-verify the new
asset. The local staging name `10779404529.zip` may be reused solely for the
canonical historical ZIP parser; it never implies a fresh Actions acquisition.
Both freshly download the separate custody archive and reverify original native
attestations, all five public package files/crypto, and all 32 Rust checksums and
nonyanked state using the existing canonical mechanisms.

The preserved LIVE public gate invokes the canonical `verify_attestation` for
both native lanes after its independent acquisition and complete current receipt
verification. It retains each verified JSON result and a separate writer-native
outcome with the actually verified lanes. Failure of either lane stops before
body transition, upload or publication. The existing configured token reads
public attestations; no OIDC, package credentials or additional write permission
is introduced. Producer claims remain required but do not stand in for writer
cryptographic verification.

## Origin and current receipts

Use distinct OriginV3 and receipt v3 schemas for preserved mode. Do not manufacture
an old current payload metadata object to satisfy OriginV2. Factor shared checks
where needed while keeping v1/v2 inputs/results exactly compatible. The common
checks still enforce original/retaining complete run-attempt-job inventories,
historical pre-expiry import, signed sources, exact nine-item original observation
vectors and real observer chronology.

V3 controls contain the live custody artifact metadata plus the independently
validated new payload transport observation; historical old payload metadata is
history only. Capture before/after acquisition and producer-final, writer-final
and writer-readback. New receipts bind all old/new policy pins, actual controller
SHA/ref/tag, verifier/runtime identities, current run/attempt/producer job, dry/live
flag, unchanged ZIP/40 members, actual new transport stable identity and original
availability vector. Keep timestamps/per-run observations outside stable public
custody bytes. Preserve the direct current producer upload ID/digest/member hashes,
successful import/upload chronology, current receipt nonexpiry and actual writer
observer. Old DRY/other-attempt/v2 receipts cannot satisfy preserved LIVE.

## Writer and final truth

Reuse the current staged producer-receipt/acquisition/full-receipt/public/final
gates and canonical GitHub writer. Recheck new transport identity plus source and
accepted local byte descriptors before every body transition/upload/publication,
then at final readback. Independently download/hash the transport again at final
acceptance. Observed drift stops; never rebaseline. Before/after reads detect
observable races but are not atomic provider immutability.

### Preserved LIVE provider admission

Only the preserved LIVE writer shares a `ProviderBudget` between its existing
GET-only importer Transport and GitHub writer. The producer, local helper and
legacy modes retain their defaults. The one additional authenticated admission
endpoint is exactly `GET https://api.github.com/rate_limit`; it grants no new
mutation URL. Bounded actual response rate headers are authoritative; a differing
resource summary cannot increase allowance. Across regional counter differences,
the writer retains the smaller remaining count and later reset until that window
has elapsed. Admission is local accounting, not a server reservation against
other repository callers.

Each phase admits 128 primary requests before source, receipt, file or provider
checks. Phases cover preliminary receipt/observer, acquisition, full receipt,
native/public verification, post-public checks, failed predecessor, every
canonical rebind and final transport readback. A rebind uses 22 authenticated
requests. Even with ten release pages, terminal asset pagination and 35 unverified
existing asset downloads, bounded recovery windows remain below 128; regression
tests count requests at both actual HTTP boundaries. An unexpected extra request
or exhausted allowance stops inside the phase without another request or reset
wait. Binary API entries and mutations count; credential-free storage and package
registry requests do not. Opaque native `gh` calls are followed by fresh admission
before the next rebind and any subsequent mutation.

The writer serializes requests and paces authenticated GETs by one second.
Mutation spacing is satisfied at admission before fresh checks; there is no
mutation sleep after the checks. Hourly reset waits occur only at admission:
at most two, at most 3,660 seconds each and 7,320 seconds in total, in chunks no
longer than 60 seconds. Clock regressions, inconsistent or implausible reset
times, invalid headers and insufficient time stop execution. The job timeout is
240 minutes and the internal writer deadline is 230 minutes, leaving room for
the existing always-run journal upload. Requests and child tools keep their
existing individual ceilings, further clamped by the internal deadline and the
earliest live dependency expiry: pinned custody, fixed failed-writer evidence,
and the actual authenticated current receipt metadata.

After a reset wait the writer freshly authenticates current receipt metadata,
run/jobs and the same running writer identity into a unique evidence directory.
It rejects expiry, replacement or observer drift, then performs the ordinary
source/local-file/custody/original-vector/new-transport checks before a mutation.
The preserved eight-request observation still requires real 200 responses and
the existing 300-second chronology bound; 304 is never rewritten as 200.
Private budget evidence contains numeric counts, times and phase outcomes only.
HTTP 403/429, permission failures, malformed responses and timeouts stop rather
than retry; mutation intent and unknown-outcome journals remain authoritative.
The whole urllib exchange, including response streaming, has a restored
process-timer deadline in addition to its socket timeout. The always-run writer
artifact retains the existing journal/result plus exactly the numeric budget
journal, writer-native outcome and two canonical native verification JSON files.
It never includes token configuration or a broad evidence-directory glob.
These new writer artifacts do not change the immutable historical 603-byte
failure artifact or the current producer receipt's strict two-member contract.

The documented default token limit motivates this admission design; actual
hosted quota, shared consumption and read permissions require protected execution
evidence. No historical upload failure cause is inferred from these limits.

Preserve draft ID **400420101**, historical unknown SBOM upload and four-row journal.
Freshly authenticate the fixed predecessor evidence and exact empty unpublished
draft before the controller/transport description transition. That PATCH reasserts
the existing product `tag_name`, `target_commitish`, and `name` in the same
request as the body. Omitting `tag_name` makes GitHub detach the draft as
`untagged-` plus 20 hex characters without moving the signed git tag. No
delete/recreate or asset overwrite. The new stable public custody
receipt identifies historical product/publishers, current acceptance controller
and preserved transport honestly. Exactly 35 product assets remain: two original
native archives, 32 original SBOMs and that stable custody receipt.

Full source CI and two genuine distinct non-author final-head human reviews precede
normal integration. Protected DRY then separate LIVE retain existing actual human
environment gates, source signature checks, producer read-only permissions and
LIVE-only protected writer. No package publishing/OIDC/build path becomes reachable
from preserved mode. Independent all-provider and all35 actual-byte readbacks are
required before declaring 0.2.7 released/closing844. Separate issue822 retirement
follows its own approved workflow and acceptance, not a new prerequisite to release.

## Verification criteria

Test first: descriptor/type/digest tampering; wrong repo/tag/signature/release/asset;
extra/duplicate inventory; expired/disappearing custody; original fifth404;
metadata mutation and same-name replacement; direct200/one302 and malicious
redirect/header/token leakage; oversized/truncated/tampered/repacked ZIP; no old
payload request; stale/cross-mode/cross-attempt receipts; chronology; per-mutation
rebind; nonempty/published/wrong predecessor; uncertain writes; exact35 final bytes;
and workflow confinement. Exercise canonical functions, not only source strings.
Use actual preserved archives for strict-file integration and preserve explicit
unavailable historical replay limitations without fabricating metadata.

Run focused tests per task, independent task review, then full exact-candidate
repository gates and independent whole-change review. All Cargo commands use
jobs2/incremental0/dev-test-release-debug0 and retain 4 GiB free. Full hosted DRY
proves actual read-only-token transport and current receipts; fixtures are not that
proof. Preserve all previous failures and all new evidence without overwriting.
