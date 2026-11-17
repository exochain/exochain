<!-- Copyright 2026 Exochain Foundation -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 0.4.0 publication-readiness record

This file is the publication-readiness record for package publication of ExoChain v0.4.0.
The last verified published release remains v0.2.7 in
`governance/releases/published-release-snapshot.json`.
This record does not claim that 0.4.0 is published.

## Scope

The pre-1.0 minor increment covers mandatory production MCP authorization and
unknown-field rejection at the generic AVC endpoint.
PR #891 is that API change.
The increment does not change a constitutional invariant, a permission grant, or a cryptographic primitive.
First-party package versions move together.
Third-party dependency pins stay fixed.
Version alignment and regenerated SDK distributions still have to pass in the release workflow.

## Package publication

The package-publication commit is the merge commit of this pull request.
That merge commit is created when this pull request merges.
Bob Stewart signs the sign-off below before that merge.
The signed tag `v0.4.0` lands on that merge commit.
Commit `2be2549262f3aafa351afeab4a907b3db594cc19` is the tested candidate for PR #892.
Constitutional CI must pass on that merge commit.
An approved signer then creates the annotated signed tag `v0.4.0` on that commit.
A person then dispatches `EXOCHAIN Release` with `operation=release`,
`version=0.4.0`, and `dry_run=false` on the commit that tag peels to.

The dispatch uses the existing environments `release` and `release-second`.
`VERSIONING.md` names `release`, then `release-second`.
This file does not create the tag, dispatch the workflow, or publish a registry.
Pushing the tag does not start `EXOCHAIN Release`.
A signed tag identifies source.
A signed tag does not by itself establish publication.
`.github/workflows/release.yml` does not read this file.
`tools/write_ci_candidate.py` always sets `publication_authorized` to false.
This record cannot change that field.

The job `approve` binds `release`.
The job `approve-second` binds `release-second`.
Those two jobs run at the same time.
Both jobs must succeed before `verify-signed-tag`.
Live publisher jobs bind `release` again.
Live publisher jobs do not bind `release-second`.
GitHub does not reuse one environment approval across jobs.
One environment is one-of.
Two environments are two-of.
Two reviewers on one environment are not two-person control.
Both environments already exist.
Workflow source does not prove the live reviewer lists.
This record does not include that inspection.
A live dispatch still needs current repository-setting evidence that two distinct approvals are enforced.

A dry run still traverses `release`.
Every dispatch traverses `release` and `release-second`.
A dry run skips the signed-tag requirement, the SBOM and SLSA jobs, registry publication, and GitHub Release creation.
A dry run does not skip `release`.
A dry run does not create a draft GitHub Release.

## Signature

Bob Stewart signs governance records himself.
The sign-off below is reserved for him.
This file does not write his name.
An earlier pull-request approval is not this sign-off.

## Sign-off

## CI evidence

Constitutional CI run
[41359466850](https://github.com/exochain/exochain/actions/runs/41359466850)
succeeded on `2be2549262f3aafa351afeab4a907b3db594cc19`, the merge of PR #892.
All 40 jobs passed, including All Constitutional Gates and Release Candidate Readiness.
That run does not cover the merge commit of this change.
Do not transfer that run forward.
Constitutional CI must pass again on the merge commit before the signed tag is created.

## SBOM

The 0.4.0 canonical digest is
`b1e79bc4aef94740a946263dac6a6f26270c90ada59c2420c98b80efa8f7791f`.
`tools/test_verify_release_sbom.sh` pins that digest for cargo-cyclonedx 0.5.9.
The corpus is the committed source.
No `*.cdx.json` corpus is checked in.
On `2be2549262f3aafa351afeab4a907b3db594cc19`, `bash tools/test_verify_release_sbom.sh` with cargo-cyclonedx 0.5.9 printed `release SBOM validator test passed`.
Both canonical runs matched the digest.

## Deployment

Items 1 through 6 gate deployment of 0.4.0.
They do not gate package publication.
They stay unchecked.
The deployment target is not chosen.
The operational owner is not chosen.
This file does not deploy a node.

1. Select and record the deployment target and operational owner. Neither is
   established by this candidate; do not infer a commitment from review requests.
2. Deploy an attestation-capable node first. Validate the versioned AVC request
   shape and rejection of unknown fields before migrating MCP clients.
3. Configure the independently pinned validator, host action signer, synchronized
   trusted HLC and origin-scoped transport credentials. Authorize provider access,
   data egress and budgets before model calls.
4. Share one durable atomic execution journal across workers in the same
   tenant/actor/idempotency scope. FileExecutionJournal needs POSIX storage and
   directory fsync through its ancestors. Independent disks do not ensure
   distributed exactly-once execution.
5. Verify exact-action success and rejection of denied, stale or tampered
   authorization before tool dispatch; concurrent/restarted duplicate suppression;
   withheld output on receipt outage; cancellation and uncertain-effect escalation
   without automatic action retry; and host-verified completion.
6. Disable dispatch for rollback, preserve journal claims, and reconcile uncertain
   effects before issuing new attempt identities. Never restore an authorization
   bypass as a rollback path.

The authoritative API contract and examples remain in
`packages/exochain-llm-proxy/README.md`.
No live runtime evidence is claimed here.

## Path classification

Rust manifests, lockfiles, protocol literals, SDK versions and tests, changelog,
version documentation and this record are EXOCHAIN core release metadata.
`tools/test_verify_release_sbom.sh` is EXOCHAIN core CI/release tooling.
LYNK package manifests and locks are core runtime adapter metadata. They are
coordinated because the release alignment gate requires one first-party version.
No adjacent products or historical release records are changed.
