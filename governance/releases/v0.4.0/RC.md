<!-- Copyright 2026 Exochain Foundation -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 0.4.0 governed-agent release preparation

Status: draft, not publication-ready. Direct follow-up to PR #891.

The pre-1.0 minor increment covers mandatory production MCP authorization and
unknown-field rejection at the generic AVC endpoint. No constitutional invariant,
permission grant or cryptographic primitive changes in this version alignment.
First-party package versions move together; third-party dependency pins stay fixed.

## Acceptance gates

- Version alignment and regenerated SDK distributions must pass.
- Regenerate the reviewed cargo-cyclonedx 0.5.9 corpus for 0.4.0 and verify its
  canonical digest twice before updating tools/test_verify_release_sbom.sh.
  The 0.4.0 canonical digest is
  `b1e79bc4aef94740a946263dac6a6f26270c90ada59c2420c98b80efa8f7791f`.
- Full constitutional CI must pass for the exact version commit. Prior PR #891
  and merged-main readiness do not validate this candidate.
- An approved signer must create the signed tag for the final release commit.
  Verify both independently protected release environments before live dispatch.
  No tag, release dispatch, publication or deployment is authorized by this record.

## Node-first migration acceptance

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
packages/exochain-llm-proxy/README.md. No live runtime evidence is claimed here.

## Path classification

Rust manifests, lockfiles, protocol literals, SDK versions and tests, changelog,
version documentation and this record are EXOCHAIN core release metadata.
`tools/test_verify_release_sbom.sh` is EXOCHAIN core CI/release tooling.
LYNK package manifests and locks are core runtime adapter metadata. They are
coordinated because the release alignment gate requires one first-party version.
No adjacent products or historical release records are changed.
