# Guarded transition of the empty 0.2.7 draft

## Authority and scope

Bob approved this bounded transition on September 30, 2026. It applies only to
`recover-0.2.7-retained-404` and existing GitHub draft **400420101**. It does not
authorize arbitrary adoption of another controller's release, asset replacement,
package republication, tag movement, expiry relaxation or changes to human
protections. The earlier same-controller-only rule remains the default; this is
its sole explicitly approved empty-draft exception.

The changed paths are EXOCHAIN core release tooling, tests and governance
documentation. No Rust governance/runtime behavior or adjacent surface changes.
Imported incident logs and archives remain read-only evidence, not source files.

## Exact predecessor and preserved history

The predecessor is the canonical retained-404 description generated for
controller `b5871abd548d427cacab27e748b49e75897a5f66` at
`refs/tags/v0.2.7-recover.4`. Its UTF-8 body SHA-256 is
`27ec3297363af0b6d50246237d9eb1bde7084893953505f674058bebeb27da1d`.
The draft must still be unpublished, non-prerelease and empty, with its exact
pinned identity and old metadata. A release-list result alone is insufficient:
independently enumerate assets to the terminal page and reject duplicates.

Failed run `36653810772`, attempt 1, final writer `109921191171` produced
artifact `11124850978`, `exochain-027-retained-github-receipts`. Its exact ZIP
is 603 bytes with SHA-256
`29f4c3a4e9075aabd725ad4c4ab7225f8e98be5aca3df67309c3e0e0ff0ae09d`.
Its sole member is
`exochain-retained-github.5gehyybi/mutation-journal.jsonl`, 1473 bytes,
SHA-256 `0c248f93130119592d029253f6f7e370651713054228dae551338690b2157d01`.
Authenticate the exact artifact metadata before and after acquisition, its
nonexpiry, controller/run binding, whole ZIP and member bytes. No alternate ID
or local-file fallback is allowed. This is authenticated historical evidence,
not a replacement for the current producer receipt.

The four historical rows record draft-create intent/response followed by first
SBOM-upload intent/unknown. The historical HTTP status and cause were discarded
and remain unknown. The repaired request headers are a demonstrated correction,
not proof of that old failure's cause. Neither fresh empty inventory nor a later
success erases the uncertain request or its journal.

## Canonical operation and fail-closed ordering

The existing read-only producer preflight may recognize only the exact approved
predecessor after authenticating its history. It does not update the release.
The old `recover-0.2.7` and `recover-0.2.7-retained` modes remain strict.

The protected final writer must first complete the unchanged actual same-attempt
producer receipt checks, actual writer Observer, canonical retained acquisition,
current source/custody/expiry controls and public acceptance. Only after the
final gate may it freshly recheck the sole exact empty predecessor, append an
intent record, and PATCH **only the body** to the actual corrected controller's
canonical description. It must validate the response and fresh authoritative
readback before the first asset upload. The new journal records the predecessor,
intended description and observed outcome without modifying old evidence.

Wrong ID, old controller/body, metadata drift, a published/nonempty release,
duplicate release/asset inventory, stale receipt, changed historical artifact,
expiry, failed rebind, unexpected HTTP result or ambiguous transition response
stops further writes. There is no automatic retry. Fresh pre-write and post-write
reads detect observable races; they are not an atomic provider compare-and-swap
and must not be represented as one.

## Unchanged delivery requirements

Preserve draft ID/history, original product source and all existing tags,
original payload bytes, existing package publications, exact 35 GitHub assets
(two native archives, 32 SBOMs and stable custody receipt), all immutable custody
pins and every existing expiry check. No asset exists to overwrite in an eligible
predecessor. New stable custody bytes truthfully identify the actual corrected
controller; original product and prior publisher identities remain unchanged.

Final-source validation, independent technical review, two genuine non-author
exact-head maintainer reviews, normal integration, a signed reviewed controller,
protected DRY then LIVE, fresh own-attempt receipts and independent all-provider
and 35-asset actual-byte acceptance remain mandatory. Technical agents cannot
approve protected deployments. Completed old approvals are historical and must
not be requested again as though incomplete. Release completion and subsequent
issue 822 retirement are separate acceptance outcomes.

## Test and evidence plan

Exercise the actual canonical producer/writer call paths and HTTP adapter:

- Exact eligible predecessor: preflight makes no writes; writer transitions
  after all current gates, preserves ID and performs only the body PATCH.
- Wrong ID/controller/body, published/nonempty release, duplicate inventory,
  historical metadata/archive/member mismatch or expiry: no transition.
- Stale same-attempt receipt or failed current controls: no transition.
- Observable pre-write/post-write drift and ambiguous response: stop without
  retry or subsequent upload/publish.
- Existing strict modes and normal same-controller completion: unchanged.
- Existing header separation and bounded safe HTTP diagnostics: preserved.

Run focused writer/import/workflow/custody/stage tests, npm boundaries and the
new full final-candidate local gate inventory, then required hosted platform
and coverage gates. Save actual command output, exit status, source hashes,
failures and review dispositions. Fixture results are not cryptographic or
hosted release acceptance. This document specifies requirements and does not
assert that any test, transition or release execution has completed.
