# EXOCHAIN 0.2.7 publication recovery

## Scope and authority

The maintainer has repeatedly authorized fixes and release operations and has
rejected another release-version decision loop. Prepare this correction through
normal review while retaining product version **0.2.7**. This document does not
approve its own implementation, replace required independent reviews, or grant
permission to bypass protected environments. No existing product approval is
being reopened.

All changes are EXOCHAIN core release tooling, CI, tests and governance records.
No runtime crate, adjacent surface, package payload or dependency lockfile is
changed. Imported logs and reports remain outside source control. The recovery
manifest records selected independently verified facts, not executable input.

## Observed failure

Original run `35257955565`, attempt 1, published all 32 Rust crates and uploaded
`@exochain/exochain-wasm@0.2.7`. Its registry visibility wait expired after about
50 seconds. Subsequent readback proved the public WASM tarball byte-identical to
the prepared artifact: 782077 bytes, SHA-256
`a9660cbf0241e8adde6be92cd7a13beea00c0fe258ea6c79ea527750f182d023`.

A second defect prevents unchanged retries: bundled npm 10.9.2 emits only
`invalid` and `missing` in successful signature-audit JSON. The acceptance
verifier requires `verified[].attestationBundles`. Earlier unit tests constructed
that shape without testing the pinned CLI. A narrow retry was canceled before
publication after this incompatibility was established. It must not be retried
unchanged.

The correction retains the exact provenance verifier. A credential-free test
using real npm 11.12.1 output against the published WASM artifact has passed it.
The publisher runtime will use a single exact Node distribution with that
bundled npm, verified before changing any runtime pin. Build-time pins and all
already prepared artifacts remain unchanged.

## Separate immutable identities

| Item | Required identity |
| --- | --- |
| Product | `0.2.7` |
| Product tag | `v0.2.7` |
| Product tag object | `be47589ec7dbefe821ada35ed0a89dedc9751953` |
| Product source | `666c578f719d1e54fce95d6831a3af92ea80df93` |
| Original preparation | `exochain/exochain`, `release.yml`, run `35257955565`, attempt `1` |
| Controller | Real `github.sha` of reviewed signed `v0.2.7-recover.N`, positive integer N |
| Existing WASM publication | Original product commit and `refs/tags/v0.2.7` |
| New npm/Python publication | Actual controller commit and maintenance ref |

Never assign the product commit to `GITHUB_SHA` in a controller run. Keep
`verify_release_source.sh` and `verify_release_tag.sh` unchanged: their existing
dispatch equality applies to the controller and maintenance tag. Separately
verify the original product tag object, peel, signature and remote identity.
Preserve signed v0.2.6 and all historical publication records.

The new npm/Python publication attestations attest the recovery publisher, not
the original build. Original source-to-artifact custody is established by the
reviewed fixed manifest, original Actions producer evidence and exact bytes.
Only the original native archives have original GitHub build attestations; do
not claim that every npm, Python or SBOM artifact was separately attested.

## Execution design

Keep recovery directly in `.github/workflows/release.yml` to retain the configured
PyPI Trusted Publisher identity (repository, workflow filename and environment).
Add `operation`, default `release`, with one alternative `recover-0.2.7`.
Recovery permits no caller-selected source, artifact run, artifact ID, package,
registry or digest. Reject any version other than 0.2.7 and any ref other than
the maintenance tag. Explicitly exclude the normal build/publication DAG during
recovery; run the existing full reusable CI on the actual controller commit.

The recovery DAG is:

1. Validate controller input/source and fixed product identity; run full CI.
2. Pass both existing independent protected environments; verify the maintenance
   signature and remote identity using the configured signer.
3. Import original artifacts without npm/Cargo publishing credentials or OIDC.
   Require fixed original workflow/repository/event/ref/source/run/attempt,
   successful named producing and CI jobs, exact artifact IDs/archive digests,
   strict extracted file inventory and file hashes. Verify native attestations.
   The overall original run is allowed to have failed at publication acceptance.
4. Fresh protected publication runners revalidate controller source, maintenance
   tag, original product tag, manifest and local bytes immediately before
   mutation. Verify all 32 already-published Rust records without republishing.
   WASM is acceptance-only: absence or mismatch fails with no upload. LYNK and
   SDK use the existing publisher, accepting an existing version only after
   exact owner, integrity, signature and expected provenance validation.
5. Publish only absent exact Python distributions through the existing pinned
   PyPI action and retain complete digest and PEP 740 readback. Partial preflight
   rejects extra/conflicting files, verifies every existing file and provenance,
   then stages only missing manifest-listed distributions. Do not weaken the
   existing full-inventory verifier: final acceptance still requires both files.
   Its expected certificate ref/commit is the real controller identity.
6. Only after every required acceptance succeeds, create or complete the GitHub
   Release at original v0.2.7 with original native archives, SBOMs and an explicit
   recovery-custody record. Existing conflicting releases/assets fail closed;
   never replace asset bytes silently. Recovery receipts identify both sources.

No package lifecycle or build execution receives a publishing credential. Use
fresh private tool/config directories, exact bundled runtime versions, the
existing trusted-tool closure checks and immutable helper capture. Public
registry reads and signature audits are unauthenticated. The mutation step alone
gets its required credential. Never print credential values.

## Failure and resumption

The visibility check is bounded to at most 25 attempts with 15-second intervals
(at most 360 seconds of sleeps). Only 404 is retryable for visibility. Malformed,
conflicting, unauthorized or unexpected responses fail immediately. Signature
verification failures remain failures; do not turn an empty array into evidence
that a particular package was verified.

A failed upload is not automatically repeated. A subsequent independently
approved execution first observes actual registry state and resumes only from
positively verified exact existing bytes. Already-published WASM/Rust packages
are never uploaded by this controller. Missing evidence, expired artifacts or
an unknown mutation result stops further writes with a retained receipt.
Ordinary resumption uses the same maintenance ref and commit. A new controller
may not silently accept earlier-controller publication provenance; doing so
requires an explicitly reviewed per-package identity record. No arbitrary
override or either-identity fallback is allowed.

Recovery dry-run import/validation jobs receive no publishing secret or OIDC
permission. A conditional publish step in an OIDC-enabled job is not a
token-free dry run. Same-run transport ZIPs may differ from the original ZIPs;
fresh publishers must verify the original inner-file manifest again.

### September 24 Python acceptance repair and successor identity records

Run `35754493083`, attempt 2, Python job `107717206104` uploaded both original
distributions successfully, then rejected PyPI's publisher object because it
omitted `claims` rather than containing `claims: null`. The four actual identity
fields match. Independent public downloads match the original manifest, and
the real pinned `pypi-attestations==0.0.30` CLI cryptographically verifies both
original attestations. Its `GitHubPublisher` model does not declare `claims`;
the repository's additional check remains stricter than that model: accept only
the exact four-field identity or that identity with null claims. Non-null claims,
unknown fields and mismatched identities still fail. No raw provenance is edited.

A reviewed successor uses `PUBLICATION-IDENTITIES.json`, separately semantically
pinned by the existing custody verifier and captured from the actual controller
commit. The original `RECOVERY-MANIFEST.json` and its semantic pin are unchanged.
The five fixed records bind WASM, LYNK, SDK, wheel and sdist to their original
manifest file hashes/sizes and one exact publication source/ref each. WASM binds
the original product; the other four records bind `2198e4ef610e9ef6d04adf726f7f4b3e156a3bc1`
at `refs/tags/v0.2.7-recover.2`. Observed publishing run/attempt fields are reviewed
evidence metadata, not an additional invocation check claimed by the certificate
verifiers. No alternate controller, caller override or either-identity fallback
is admitted. The real executing SHA/ref still governs source, tags and staging.

All five mapped publications must exist and pass complete public crypto and
identity verification. Absence fails; npm performs no upload and Python stages
no distributions. Normal release-mode publishing remains unchanged. The final
GitHub custody receipt distinguishes original product source, prior package
publishers and the current acceptance/release controller; it must not attribute
earlier package signatures to the successor.

The original import and its fresh non-expiry checks remain unchanged. No
cross-run transport reuse, expiry waiver or retention workaround is authorized
by these records. An expiry failure stops further writes. Normal exact-head
review, full CI, signed successor tag, two independent protected environments,
dry run and separate live execution remain prerequisites.

### Formatter reproducibility during successor review

PR841's initial exact-head CI selected a newer floating nightly formatter and
rejected macro wrapping in unchanged Rust source. Gate 5 now uses the exact
nightly-2026-09-21 distribution that passed hosted PR840 on the same product
tree. Both installation and invocation are pinned; repo_truth and documented
local commands use that same formatter. The build/test compiler remains stable.
The full workspace check and constitutional dependency are unchanged. Parsed
YAML and behavioral mutation regressions reject floating/mismatched toolchains,
removed coverage/check flags, conditional skips and suppressed failures. This
repairs reproducibility without modifying product Rust files or weakening gates.

## Acceptance

Tests must execute the actual selected npm CLI, not only manufactured JSON.
Exercise wrong source/ref/digest/owner, missing/invalid bundles, actual old-CLI
schema rejection, and zero upload calls for existing WASM. Test malicious
manifest values, duplicate or extra records, wrong original producer identity,
failed producers, malformed or unsafe archives, changed bytes, moved tags,
controller/product identity substitution and normal-mode recovery override.

Workflow tests must establish mutual exclusion, full CI and both protected
approvals, credential/OIDC isolation, original artifact IDs and acceptance
dependencies before final GitHub publication. Run all existing release guards,
normal core gates and a whole-branch security review before requesting normal
maintainer reviews. Hosted dry run and then genuinely approved live execution
remain distinct from local validation.

Issue #822's separately reviewed retirement controller is unchanged. Complete
its actual approvals/execution/readbacks separately. No deployment/runtime
claim is made without an identified target and independent runtime evidence.

## September 24 retained-custody extension

Bob approved the bounded design in `RETAINED-RECOVERY-PLAN.md` after original
WASM artifact `10518086890` became `expired:true`. The original
`recover-0.2.7` importer still requires all nine original metadata records to
be fresh and nonexpired. Its failure on expiry is correct; the new
`recover-0.2.7-retained` operation is separate, never an automatic fallback.

The retained operation pins `RETAINED-CUSTODY.json` to the existing
`RECOVERY-MANIFEST.json` and `PUBLICATION-IDENTITIES.json`. It authenticates
the original product and retaining controller, proves the successful original
attempt-1 import preceded original expiry using the pinned historical evidence
and current matching metadata for this strict older mode. It then freshly
downloads both nonexpired retained artifacts from fixed GitHub endpoints. The
147126946-byte payload transport
contains 40 extracted original files, not the seven original ZIP envelopes or
two Rust preparation archives. Its separate custody archive has 60 historical
evidence members. Strict ZIP headers, signed data descriptors, file types,
boundaries, sizes, CRCs and SHA256s are checked before exposing files; the
unchanged original 96 MiB ZIP bound is not widened. Missing or changed evidence,
expired retained artifacts or ambiguous ZIPs stop the operation.

`retained-acceptance` has read-only contents/actions/attestations permissions,
no publisher secret or job OIDC, and runs in both dry and live requests after
full CI, both approval jobs and signed-tag verification. It reuses canonical
checks for all 32 public Rust versions and five mapped npm/Python files, including
genuine public-byte and cryptographic identity checks, without upload, staging
or package publication. Its direct upload outputs bind the current run/attempt,
producer and receipt artifact ID/digest. Only live `retained-github` receives
contents write with the release environment. It verifies current receipts and
fresh public state before using the existing journaled, no-overwrite 35-asset
GitHub Release writer. An earlier attempt's artifact is rejected even if its
JSON claims the current attempt; unknown writes stop until authoritative state
is read independently. The public custody asset distinguishes original
production, retaining transport, prior package publishers and current
acceptance controller.

The retained source through signed `e2c138a6c5d9d947240ecd363aa1ab87adcb5e41`
has three approved task-specific independent reviews. Final-candidate
validation, whole-branch review, exact-head CI, two actual non-author maintainer
approvals, signed unused maintenance tag, protected dry acceptance, separately
approved live completion and provider/35-asset readback remain distinct gates.
PR841's approvals occurred after merge; PR842's two approvals and 74 checks
preceded its normal integration at 21:03:20 UTC. No retrospective approval is
implied by this extension. No release, retirement or runtime deployment is
claimed here.

## September 25 retained-metadata amendment

Bob approved `RETAINED-METADATA-AMENDMENT.md` on September 25 and the detailed
implementation plan with subagents on September 26 for implementation and a
reviewed PR. The amendment adds only `recover-0.2.7-retained-404` for version
`0.2.7`; neither `recover-0.2.7` nor `recover-0.2.7-retained` falls back to it.
The new operation requires the separately pinned
`RETAINED-METADATA-POLICY.json` (semantic SHA-256
`bf9968454e1fb95fde2b2c435f61940a39cc25e6fb45a28ff9523a82f755c244`).
It does not change the three earlier manifest, publication or retained-custody
records or their pins.

The exact four original artifact IDs `10518086890`, `10518128532`,
`10517978596` and `10517854663` may each have an actual HTTP 404 only when its
request starts at or after its pinned historical expiry. Each of the other five
IDs `10517981432`, `10518080916`, `10517457207`, `10517966616` and
`10517459550` requires an exact HTTP 200. A selected ID may still return 200;
all nine returning 200 is valid. Every 200 must match authenticated historical
metadata except the strictly checked Boolean `expired` value. A 404 is a typed
`unavailable_404` observation, not a fabricated metadata object, current
`expired` value or proof of deletion. Its member hash is authenticated against
the 60-member historical custody archive. Current immutable fields cannot be
compared for an absent object, and the seven original ZIP envelopes are not
recovered. Other statuses, early or unselected 404s, and changing availability
or identity across checks stop acceptance.

The existing read-only retained producer and protected live writer use the same
signed source, original run `35257955565` attempt 1 and retaining run
`35754493083` attempt 1. They require complete 62/68-job controls, nine typed
observations before and after acquisition, and both exact retained metadata
records: payload `10779404529` and custody `10780480598`, each nonexpired at
every required check. Original pre-expiry import and actual retaining
import/upload chronology remain provable from authenticated history. The strict
40-file payload and 60-member custody ZIP profiles, source/signer checks, two
genuine native attestations, five genuine public-package byte/crypto checks and
32 exact nonyanked Rust checksum checks remain required. No payload rebuild,
repack, stage, upload, republication, alternate ID, local fallback or retention
extension is introduced.

Before acquiring the fixed transports, the writer authenticates direct receipt
outputs and the actual in-progress writer job in the same run/attempt. That
preliminary provenance is not receipt or publication acceptance. After canonical
acquisition, it verifies receipt metadata before download, the strict current
receipt ZIP and both members, and metadata after download; its final receipt
time is captured after those reads and checked before expiry. Both v2 members
contain raw producer observations. The verifier preserves the producer's
`checked_at`, validates producer/import/upload chronology, and compares the
producer and writer's normalized nine-item Vectors without requiring equal
request times. The acquisition input remains intact while separate post-public
and per-write finalization checks run. Source/files, nine original observations,
both retained records and fresh run/job controls are rebound before each
mutation and final readback. A mismatch stops the pending operation even if a
bounded diagnostic read fails; prior and uncertain journal entries remain.

Public output remains exactly 35 assets with no overwrite. Version 2 stable
custody and body disclose the fixed policy and the loss of current visibility;
operational timestamps and raw observations stay in separate run evidence.
Unit source reviews and historical approvals are distinct from final-source
validation, fresh cryptographic evidence, exact-head CI and two new non-author
human approvals. No new protected run, release execution or 35-asset readback
is claimed by this documentation snapshot.
