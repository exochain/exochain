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
