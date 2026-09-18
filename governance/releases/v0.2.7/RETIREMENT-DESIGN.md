# Protected retirement of crates.io 0.2.3

## Scope and authority

Issue #822 records the broken 0.2.3 release and the governance requirement in
`VERSIONING.md`. This controller is separate from the product release. It must
not change either product tag or the accepted 0.2.7 source. All changed paths
are EXOCHAIN core release tooling, CI, or governance records; no adjacent
surface, runtime invariant, package dependency, or imported evidence is changed.
The user's standing authorization covers preparation and release remediation;
actual registry writes still require both existing protected environments.

The exact target is the canonical 32-crate inventory from
`tools/check_cratesio_namespace_ownership.mjs`, excluding `exochain-pdp`, whose
0.2.3 version was not published. All 31 targets are fixed at 0.2.3. Their
replacement must be published, non-yanked 0.2.7 before any mutation. No caller
may supply a registry endpoint, package name, version, token file, or undo mode.
The signed 0.2.3 and 0.2.6 tags remain untouched.

## Design and alternatives

A dedicated workflow is selected because the current release workflow has no
yank operation. Adding retirement to the accepted product candidate would
change its reviewed source and restart acceptance; obtaining protected secrets
locally would break their custody boundary. Neither alternative is used.

The controller uses its own reviewed commit and signed maintenance tag,
`v0.2.7-retire-0.2.3.N`, where N is a positive integer. Live dispatch must use
that exact tag, and its peeled commit must equal the real `github.sha`.
Existing immutable-source, remote-tag and signer helpers are reused unchanged.
The maintenance tag is not a published product version.

The workflow runs the normal reusable CI, then two independent approval jobs
using `release` and `release-second`. A fresh final runner repeats source and
tag verification and checks all 31 namespace owners with the existing exact-
target ownership guard. Only its final narrow step receives the Cargo token.
No Cargo build, package installation, repository lifecycle, downloaded artifact
execution, or mutable-source helper loading occurs with that token.

The registry helper is a standard-library Python program. It first reads all
31 target and replacement records, validates identity/checksum/yanked fields,
and fails before mutation if any are absent or unknown. Apply then rechecks
each pair, skips only positively observed already-yanked targets, sends the
documented authenticated DELETE yank request, and independently reads back
the same version identity/checksum with `yanked: true`. Any ambiguous response
stops the batch. A later explicitly approved run resumes from registry state;
there is no automatic mutation retry and no unyank operation.

Only HTTPS to `crates.io:443` is supported. Redirects, proxies, oversized or
malformed/duplicate-key JSON, unexpected status codes, and invalid token bytes
fail closed. Public reads carry no credential. Error output excludes raw
response bodies and credentials. Structured receipts report each verified
transition and a final completed/failed status; they are not proof of a whole
batch until all 31 independent readbacks pass.

The stable protocol is documented in the
[Cargo registry Web API](https://doc.rust-lang.org/cargo/reference/registry-web-api.html#yank):
DELETE `/api/v1/crates/{crate_name}/{version}/yank`, token in Authorization,
and a successful JSON response with boolean `ok: true`.

## Governance and acceptance

Before live execution, correct issue #822 to the fixed 31-package scope and
record the configured approving panel: `mstewartbz` for `release` and one of
`robst3w` or `tazmon95` for `release-second`. Preserve actual run approval
records and do not impersonate those reviewers. Do not close the issue until
all 31 versions have independent positive yanked readbacks. A partial failure
must retain completed receipts and the exact remaining inventory.

Tests must exercise the real helper's validation and batch state machine with
controlled transport responses, including no writes after preflight failure,
partial failure/rerun, checksum or identity substitution, and no token on
reads. Workflow guards must prove both approval dependencies, fresh source/tag
binding, fixed inventory, narrow credential scope, and absence of lifecycle
execution. Focused checks and required core gates precede reviewed integration.
Dry runs use public reads only and must fail if 0.2.7 is not yet published;
that is a publication dependency, not permission to relax the prerequisite.
