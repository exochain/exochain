// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { test } from 'node:test';

async function loadRootTrustRegistry() {
  try {
    return await import('../src/root-trust-registry.mjs');
  } catch (error) {
    assert.fail(`CyberMedica root trust registry module must exist and load: ${error.message}`);
  }
}

async function loadTrustAdapter() {
  try {
    return await import('../src/trust-adapter.mjs');
  } catch (error) {
    assert.fail(`CyberMedica trust adapter module must exist and load: ${error.message}`);
  }
}

const digestA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const digestB = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const digestC = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const digestD = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const digestE = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const digestF = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const digest1 = '1111111111111111111111111111111111111111111111111111111111111111';
const digest2 = '2222222222222222222222222222222222222222222222222222222222222222';
const digest3 = '3333333333333333333333333333333333333333333333333333333333333333';
const digest4 = '4444444444444444444444444444444444444444444444444444444444444444';
const digest5 = '5555555555555555555555555555555555555555555555555555555555555555';
const digest6 = '6666666666666666666666666666666666666666666666666666666666666666';
const digest7 = '7777777777777777777777777777777777777777777777777777777777777777';
const digest8 = '8888888888888888888888888888888888888888888888888888888888888888';
const digest9 = '9999999999999999999999999999999999999999999999999999999999999999';

function certifier(index, overrides = {}) {
  const padded = String(index).padStart(2, '0');
  return {
    certifierDid: `did:exo:root-certifier-${padded}`,
    rosterPosition: index,
    organizationRef: `independent-org-${padded}`,
    independenceBasis: `independent-clinical-research-safety-seat-${padded}`,
    signingKeyHash: index % 2 === 0 ? digestA : digestB,
    active: true,
    ...overrides,
  };
}

function validRosterInput(overrides = {}) {
  return {
    rosterId: 'root-roster-alpha',
    rosterVersion: '2026-05-23-root-roster-v1',
    hlcTimestamp: { physicalMs: 1790001000000, logical: 4 },
    certifiers: Array.from({ length: 13 }, (_, index) => certifier(index + 1)),
    ...overrides,
  };
}

const validArtifacts = Object.freeze([
  {
    artifactKind: 'root_certifier_roster',
    artifactVersion: '2026-05-23-root-roster-v1',
    artifactHash: digestA,
    custodyDigest: digest1,
    storageRef: 'cm-root-artifacts/root-roster-alpha.cbor',
  },
  {
    artifactKind: 'dkg_transcript',
    artifactVersion: '2026-05-23-root-dkg-v1',
    artifactHash: digestB,
    custodyDigest: digest2,
    storageRef: 'cm-root-artifacts/root-dkg-transcript-alpha.cbor',
  },
  {
    artifactKind: 'root_signed_envelopes',
    artifactVersion: '2026-05-23-root-envelopes-v1',
    artifactHash: digestC,
    custodyDigest: digest3,
    storageRef: 'cm-root-artifacts/root-signed-envelopes-alpha.cbor',
  },
  {
    artifactKind: 'root_trust_bundle',
    artifactVersion: '2026-05-23-root-bundle-v1',
    artifactHash: digestD,
    custodyDigest: digest4,
    storageRef: 'cm-root-artifacts/root-trust-bundle-alpha.cbor',
  },
  {
    artifactKind: 'root_verifier_evidence',
    artifactVersion: '2026-05-23-root-verifier-v1',
    artifactHash: digestE,
    custodyDigest: digest5,
    storageRef: 'cm-root-artifacts/root-verifier-evidence-alpha.cbor',
  },
  {
    artifactKind: 'immutable_audit_hash',
    artifactVersion: '2026-05-23-root-audit-v1',
    artifactHash: digestF,
    custodyDigest: digest6,
    storageRef: 'cm-root-artifacts/root-immutable-audit-alpha.cbor',
  },
]);

function validRegistryInput(overrides = {}) {
  return {
    registryId: 'root-artifact-registry-alpha',
    registryVersion: '2026-05-23-root-artifacts-v1',
    hlcTimestamp: { physicalMs: 1790001000000, logical: 5 },
    artifacts: validArtifacts.map((artifact) => ({ ...artifact })),
    ...overrides,
  };
}

function validOperationsRunbookInput(overrides = {}) {
  return {
    runbookId: 'root-operations-runbook-alpha',
    runbookVersion: '2026-05-23-root-ops-v1',
    hlcTimestamp: { physicalMs: 1790001000000, logical: 6 },
    ceremonyOwnerDid: 'did:exo:root-ceremony-owner-alpha',
    backupOwnerDid: 'did:exo:root-ceremony-backup-alpha',
    incidentResponsePathRef: 'cm-root-runbooks/root-incident-response-alpha',
    incidentResponsePathHash: digestA,
    escalationPathRef: 'cm-root-runbooks/root-escalation-alpha',
    escalationPathHash: digestB,
    rollbackDisablementRef: 'cm-root-runbooks/root-rollback-disablement-alpha',
    rollbackDisablementHash: digestC,
    ownerAttestationHash: digestD,
    backupOwnerAttestationHash: digestE,
    reviewedBy: ['did:exo:quality-governance-alpha', 'did:exo:security-operations-alpha'],
    metadataOnly: true,
    protectedContentExcluded: true,
    bobEscalationId: 'ESC-ROOT-OWNER',
    ...overrides,
  };
}

test('root certifier roster requires 13 unique independent active certifiers and deterministic evidence', async () => {
  const { evaluateRootCertifierRoster } = await loadRootTrustRegistry();

  const rosterA = evaluateRootCertifierRoster(validRosterInput());
  const rosterB = evaluateRootCertifierRoster(
    validRosterInput({ certifiers: [...validRosterInput().certifiers].reverse() }),
  );

  assert.equal(rosterA.valid, true);
  assert.equal(rosterA.state, 'verified');
  assert.equal(rosterA.failClosed, false);
  assert.equal(rosterA.certifierCount, 13);
  assert.equal(rosterA.dkgParticipantCount, 13);
  assert.equal(rosterA.thresholdSignature, '7-of-13');
  assert.equal(rosterA.exochainProductionClaim, false);
  assert.equal(rosterA.rosterHash, rosterB.rosterHash);
  assert.deepEqual(rosterA.blockedBy, []);

  const duplicate = evaluateRootCertifierRoster(
    validRosterInput({
      certifiers: [
        certifier(1),
        certifier(1, { rosterPosition: 2 }),
        ...Array.from({ length: 11 }, (_, index) => certifier(index + 3)),
      ],
    }),
  );

  assert.equal(duplicate.valid, false);
  assert.equal(duplicate.state, 'denied');
  assert.equal(duplicate.failClosed, true);
  assert.ok(duplicate.blockedBy.includes('root_certifier_roster_duplicate'));

  const missingBasis = evaluateRootCertifierRoster(
    validRosterInput({
      certifiers: [certifier(1, { independenceBasis: '' }), ...Array.from({ length: 12 }, (_, index) => certifier(index + 2))],
    }),
  );

  assert.equal(missingBasis.valid, false);
  assert.ok(missingBasis.blockedBy.includes('root_certifier_independence_basis_absent'));
});

test('root artifact registry requires every activation artifact and rejects protected content', async () => {
  const { evaluateRootArtifactRegistry } = await loadRootTrustRegistry();

  const registryA = evaluateRootArtifactRegistry(validRegistryInput());
  const registryB = evaluateRootArtifactRegistry(
    validRegistryInput({ artifacts: [...validRegistryInput().artifacts].reverse() }),
  );

  assert.equal(registryA.valid, true);
  assert.equal(registryA.state, 'verified');
  assert.equal(registryA.failClosed, false);
  assert.equal(registryA.artifactCount, 6);
  assert.equal(registryA.exochainProductionClaim, false);
  assert.equal(registryA.registryHash, registryB.registryHash);
  assert.deepEqual(registryA.blockedBy, []);

  const missingVerifier = evaluateRootArtifactRegistry(
    validRegistryInput({
      artifacts: validArtifacts.filter((artifact) => artifact.artifactKind !== 'root_verifier_evidence'),
    }),
  );

  assert.equal(missingVerifier.valid, false);
  assert.equal(missingVerifier.state, 'denied');
  assert.ok(missingVerifier.blockedBy.includes('root_verifier_evidence_absent'));

  assert.throws(
    () =>
      evaluateRootArtifactRegistry(
        validRegistryInput({
          artifacts: [
            ...validArtifacts,
            {
              artifactKind: 'root_operator_note',
              artifactVersion: '2026-05-23-note-v1',
              artifactHash: digest7,
              custodyDigest: digest8,
              storageRef: 'cm-root-artifacts/operator-note-alpha.cbor',
              rawContent: 'patient Alice Example private escalation note',
            },
          ],
        }),
      ),
    /protected content/i,
  );
});

test('root operations runbook requires owner backup incident and rollback authority evidence', async () => {
  const { evaluateRootOperationsRunbook } = await loadRootTrustRegistry();

  const runbookA = evaluateRootOperationsRunbook(validOperationsRunbookInput());
  const runbookB = evaluateRootOperationsRunbook(
    validOperationsRunbookInput({
      reviewedBy: [...validOperationsRunbookInput().reviewedBy].reverse(),
    }),
  );

  assert.equal(runbookA.valid, true);
  assert.equal(runbookA.state, 'verified');
  assert.equal(runbookA.failClosed, false);
  assert.equal(runbookA.exochainProductionClaim, false);
  assert.equal(runbookA.bobEscalationId, 'ESC-ROOT-OWNER');
  assert.equal(runbookA.ceremonyOwnerDid, 'did:exo:root-ceremony-owner-alpha');
  assert.equal(runbookA.backupOwnerDid, 'did:exo:root-ceremony-backup-alpha');
  assert.equal(runbookA.incidentResponsePathRef, 'cm-root-runbooks/root-incident-response-alpha');
  assert.equal(runbookA.rollbackDisablementRef, 'cm-root-runbooks/root-rollback-disablement-alpha');
  assert.equal(runbookA.runbookHash, runbookB.runbookHash);
  assert.deepEqual(runbookA.reviewedBy, [
    'did:exo:quality-governance-alpha',
    'did:exo:security-operations-alpha',
  ]);

  const missingOwner = evaluateRootOperationsRunbook(
    validOperationsRunbookInput({
      ceremonyOwnerDid: '',
      backupOwnerDid: 'did:exo:root-ceremony-owner-alpha',
      metadataOnly: false,
      rollbackDisablementHash: 'not-a-digest',
    }),
  );

  assert.equal(missingOwner.valid, false);
  assert.equal(missingOwner.state, 'denied');
  assert.equal(missingOwner.failClosed, true);
  assert.ok(missingOwner.blockedBy.includes('root_ceremony_owner_absent'));
  assert.ok(missingOwner.blockedBy.includes('root_runbook_metadata_boundary_invalid'));
  assert.ok(missingOwner.blockedBy.includes('root_rollback_disablement_hash_invalid'));

  const sameOwner = evaluateRootOperationsRunbook(
    validOperationsRunbookInput({
      backupOwnerDid: 'did:exo:root-ceremony-owner-alpha',
    }),
  );

  assert.equal(sameOwner.valid, false);
  assert.ok(sameOwner.blockedBy.includes('root_backup_owner_not_independent'));

  assert.throws(
    () =>
      evaluateRootOperationsRunbook(
        validOperationsRunbookInput({
          rawContent: 'Participant Alice Example root incident note must not be stored.',
        }),
      ),
    /protected content/i,
  );
});

test('root trust bundle provider stays inactive until roster registry config and verifier evidence are verified', async () => {
  const {
    evaluateRootArtifactRegistry,
    evaluateRootCertifierRoster,
    evaluateRootOperationsRunbook,
    evaluateRootTrustBundleProvider,
  } = await loadRootTrustRegistry();
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const inactive = evaluateRootTrustBundleProvider({});

  assert.equal(inactive.allowed, false);
  assert.equal(inactive.state, 'inactive');
  assert.equal(inactive.failClosed, true);
  assert.ok(inactive.blockedBy.includes('root_bundle_provider_endpoint_absent'));
  assert.ok(inactive.blockedBy.includes('root_certifier_roster_unverified'));
  assert.ok(inactive.blockedBy.includes('root_artifact_registry_unverified'));
  assert.ok(inactive.blockedBy.includes('root_operations_runbook_unverified'));
  assert.equal(inactive.rootBundle, null);

  const roster = evaluateRootCertifierRoster(validRosterInput());
  const registry = evaluateRootArtifactRegistry(validRegistryInput());
  const operationsRunbook = evaluateRootOperationsRunbook(validOperationsRunbookInput());

  const missingRunbook = evaluateRootTrustBundleProvider({
    providerConfig: {
      endpointRef: 'cybermedica-root-provider-prod-ref',
      credentialScope: 'cybermedica-root-provider-only',
      health: 'ready',
    },
    roster,
    artifactRegistry: registry,
    verifierResult: {
      status: 'verified',
      verified: true,
      verifierReceiptId: 'root-verifier-receipt-alpha',
      thresholdSignature: '7-of-13',
      dkgParticipantCount: 13,
      rootTrustBundleHash: digest9,
    },
  });

  assert.equal(missingRunbook.allowed, false);
  assert.equal(missingRunbook.state, 'denied');
  assert.ok(missingRunbook.blockedBy.includes('root_operations_runbook_unverified'));

  const pending = evaluateRootTrustBundleProvider({
    providerConfig: {
      endpointRef: 'cybermedica-root-provider-prod-ref',
      credentialScope: 'cybermedica-root-provider-only',
      health: 'ready',
    },
    roster,
    artifactRegistry: registry,
    operationsRunbook,
    verifierResult: {
      status: 'pending',
      verified: false,
      verifierReceiptId: 'root-verifier-pending-alpha',
      thresholdSignature: '7-of-13',
      dkgParticipantCount: 13,
      rootTrustBundleHash: digest9,
    },
  });

  assert.equal(pending.allowed, false);
  assert.equal(pending.state, 'pending');
  assert.deepEqual(pending.blockedBy, ['root_verifier_pending']);
  assert.equal(pending.rootBundle.status, 'pending');
  assert.equal(pending.rootBundle.certifierCount, 13);
  assert.equal(pending.rootBundle.ceremonyOwnerDid, 'did:exo:root-ceremony-owner-alpha');

  const secretBearing = evaluateRootTrustBundleProvider({
    providerConfig: {
      endpointRef: 'cybermedica-root-provider-prod-ref',
      rotationEvidence: [{ credentialSecret: 'operator-secret-material' }],
      health: 'ready',
    },
    roster,
    artifactRegistry: registry,
    operationsRunbook,
    verifierResult: {
      status: 'verified',
      verified: true,
      verifierReceiptId: 'root-verifier-receipt-alpha',
      thresholdSignature: '7-of-13',
      dkgParticipantCount: 13,
      rootTrustBundleHash: digest9,
    },
  });

  assert.equal(secretBearing.allowed, false);
  assert.equal(secretBearing.failClosed, true);
  assert.ok(secretBearing.blockedBy.includes('root_bundle_provider_secret_material_prohibited'));

  const sharedExochainScope = evaluateRootTrustBundleProvider({
    providerConfig: {
      endpointRef: 'cybermedica-root-provider-prod-ref',
      credentialScope: 'exochain-root-bootstrap-signing',
      health: 'ready',
    },
    roster,
    artifactRegistry: registry,
    operationsRunbook,
    verifierResult: {
      status: 'verified',
      verified: true,
      verifierReceiptId: 'root-verifier-receipt-alpha',
      thresholdSignature: '7-of-13',
      dkgParticipantCount: 13,
      rootTrustBundleHash: digest9,
    },
  });

  assert.equal(sharedExochainScope.allowed, false);
  assert.equal(sharedExochainScope.failClosed, true);
  assert.ok(sharedExochainScope.blockedBy.includes('root_bundle_provider_credential_scope_not_cybermedica_only'));

  const verified = evaluateRootTrustBundleProvider({
    providerConfig: {
      endpointRef: 'cybermedica-root-provider-prod-ref',
      credentialScope: 'cybermedica-root-provider-only',
      health: 'ready',
    },
    roster,
    artifactRegistry: registry,
    operationsRunbook,
    verifierResult: {
      status: 'verified',
      verified: true,
      verifierReceiptId: 'root-verifier-receipt-alpha',
      thresholdSignature: '7-of-13',
      dkgParticipantCount: 13,
      rootTrustBundleHash: digest9,
    },
  });

  assert.equal(verified.allowed, true);
  assert.equal(verified.state, 'verified');
  assert.equal(verified.exochainProductionClaim, false);
  assert.equal(verified.rootBundle.verified, true);
  assert.equal(verified.rootBundle.operationsRunbookHash, operationsRunbook.runbookHash);

  const activation = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: verified.rootBundle,
    gatewayAdapter: { verified: true },
    receiptPath: { verified: true },
    privacyBoundary: { verified: true },
    decisionForum: { verified: true },
  });

  assert.equal(activation.allowed, true);
  assert.equal(activation.state, 'verified');
  assert.equal(activation.exochainProductionClaim, true);
});
