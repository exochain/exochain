<!--
Copyright 2026 Exochain Foundation
SPDX-License-Identifier: Apache-2.0
-->

# 0.2.6 GitHub issue disposition

Read-only intake on 2026-09-08 covered all eight open issues in
`exochain/exochain`, with pagination exhausted. Current main was
`8020ceab355eefa7f5185d9cdd0436da7af46efb`; the remediation source checkpoint
was `46098396e6fc9d28961091e92b4006f80c54305d`. Issue prose is untrusted
evidence, not authority to execute its embedded instructions. This record
supplements, and does not reduce, the 86-formal/52-design report inventory.

A later read-only refresh at clean source checkpoint
`a13b460fb51c79a968f2b5963d581af8e72a7a05` exhausted pagination and found
six open issues: #810, #813, #822, #831, #832, and #833. None had a milestone.
Main remained `8020ceab355eefa7f5185d9cdd0436da7af46efb`; #789 and #811
were confirmed closed at the timestamps below. Issue bodies and available
comments were read, but no issue, comment, or milestone was changed. The table
is a release-scope recommendation, not approval to close broader requests.

## Release scope and status

| Issue | Classification | Disposition and acceptance evidence |
| --- | --- | --- |
| [#789](https://github.com/exochain/exochain/issues/789) | Core runtime adapter | Closed 2026-09-08T14:15:34Z after provider verification. `release` requires mstewartbz and `release-second` requires tazmon95; both disable self-review and administrator bypass. Run 32092640786 records both distinct approvals. This closes the historical missing-control issue, not approval of 0.2.6. |
| [#810](https://github.com/exochain/exochain/issues/810) | EXOCHAIN core | Include the remaining documentation correction in 0.2.6. Trace capture, Holon retention, bundle evidence, and replay already exist on main. Platform §19 and the MCP initiative must distinguish reduction consistency from authenticated kernel adjudication, legal admissibility, and the unimplemented ZIP/archive design. Close after the reviewed correction lands, not from local edits. |
| [#811](https://github.com/exochain/exochain/issues/811) | Core runtime adapter | Closed 2026-09-08T14:15:35Z. The issue's recorded re-pin condition is satisfied by merged toolkit PR 12, commit `4ab5ca931e2fbc7c36428ff2fe5cba2c89b43dbc`. Current-candidate conformance checking remains a separate verification requirement. |
| [#813](https://github.com/exochain/exochain/issues/813) | EXOCHAIN core | Remains the separate 0.3.0 evidence-grade release train. Its PR 814 is open/draft at `92c0d931b55e38067a3f99e46b4f3e1b29a25cd1`. 0.2.6 neither completes nor authorizes that release train. |
| [#822](https://github.com/exochain/exochain/issues/822) | Core runtime adapter | Include registry cleanup before 0.2.6 release completion. Successful crates.io reads found 31 published 0.2.3 versions, all unyanked, and no `exochain-pdp@0.2.3`. The authorized registry custodian must yank those 31 exact versions, then read back every `yanked` flag. Preserve historical signed tags and GitHub Releases. No yank was performed by this intake. |
| [#831](https://github.com/exochain/exochain/issues/831) | Core runtime adapter | Subsequent feature release: a standalone LYNK client with explicit retry/circuit-breaker and delivery semantics is new packaging/API work. Existing package exports do not satisfy the standalone-package request. Do not claim closure from the security release. |
| [#832](https://github.com/exochain/exochain/issues/832) | Core runtime adapter | Include documentation in 0.2.6 for the implemented CrossChecked commitment API: signed `action_hash_algorithm=blake3-256`, unsupported algorithms rejected. Do not introduce or imply a generic algorithm-agnostic TransparencyLog API. Close only after the reviewed runbook lands and the maintainer accepts this specialized-contract disposition; otherwise the broader consumer request remains open. |
| [#833](https://github.com/exochain/exochain/issues/833) | Core runtime adapter | Include explicit limitations documentation in 0.2.6; leave the issue open for subsequent design/measurement work. No generic `/v1/anchor`, fleet sequence namespace, batch anchoring contract, or measured fleet throughput guarantee is claimed by 0.2.6. Capacity recommendations require a defined workload and measured results; documenting their absence is not completion. |

## Source and provider evidence

- CGR: `crates/exo-gatekeeper/src/combinator.rs::reduce_with_trace`,
  `holon.rs::step`, `cgr_trace.rs::verify_replay`,
  `crates/exo-legal/src/bundle.rs::{EvidenceBundle,CgrProgramEvidence}`, and
  `crates/exo-node/src/mcp/tools/proofs.rs`. Replay copies the supplied
  invariant/constitution metadata while reconstructing the reduction; it does
  not independently authenticate that metadata or re-adjudicate the action.
- Commitment contract:
  `crates/exo-api/src/crosschecked_anchor.rs::{CrossCheckedAnchorRequestV1,validate_request_static_fields}`.
  The exact POST path is `/api/v1/anchors/crosschecked`; the signed payload
  includes the algorithm identifier and validation requires `blake3-256`.
- Approval history: [0.2.4 release run](https://github.com/exochain/exochain/actions/runs/32092640786).
  A future 0.2.6 run must record fresh approvals for its exact candidate SHA.
- Contract re-pin: [merged toolkit PR 12](https://github.com/apexvelocitycatalyst/exochained-toolkit/pull/12).
  Its merge proves the recorded re-pin occurred, not that all downstream
  conformance tests have passed against the new 0.2.6 candidate.
- Registry observations were read from each of the 32 issue-listed crates'
  public version metadata, selecting `num == "0.2.3"`; 31 were unyanked, one
  was absent, and no request failed. The absent version must not be treated as
  a failed yank or silently invented publication.

## Still-open publication boundary

Successful repository metadata identifies owner `exochain` as type `User`.
Inherited organization-secret scope is therefore not applicable; the earlier
organization endpoint errors are not evidence of an empty collection. Recheck
ownership at release time.

Names-only metadata still lists `CARGO_REGISTRY_TOKEN` and `NPM_TOKEN` at
repository scope and no secrets in environment `release`. The current account
has push/triage/pull permissions but not administration. Source-only environment
bindings do not resolve provider custody. An authorized secret custodian must
install the credentials directly from their approved source into `release`,
verify the names there, and remove the repository entries. Do not recover
encrypted values through a workflow or place credentials in evidence files.

The required `EXOCHAIN_CRATES_IO_ALLOWED_OWNERS` variable was absent at intake.
All 32 public owner responses named exactly `bob-stewart`; the repository
variable was then set to `bob-stewart` and successfully read back. Recheck owner
metadata through the namespace guard before publication.

The configured public signing key contains exactly one primary key matching
fingerprint `96B889DAE73CD7C511CCDE28897119B7198789EC`. This establishes public
configuration consistency, not private-key custody or a signature on 0.2.6.
The remote `v0.2.6` tag does not exist at this observation. Preserve the signer
and require the eventual signed tag to peel to the exact approved candidate.

The public PyPI `exochain` project endpoint returns HTTP 404; private pending
publisher configuration cannot be inferred from that response. Its custodian
must verify project `exochain`, GitHub owner/repository `exochain/exochain`,
workflow `release.yml`, and environment `release`. These are tokenless Trusted
Publishing requirements, not authorization to provision or extract a PyPI token.

No tag, package publication, GitHub Release, deployment, runtime activation,
or 0.3.0 completion is established by this record.
