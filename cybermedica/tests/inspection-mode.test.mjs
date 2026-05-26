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

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_4 = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

const REQUIRED_EVIDENCE_FAMILIES = [
  'access_logs',
  'chain_of_custody',
  'decision_rationale',
  'evidence_index',
  'issue_history',
  'staff_training',
  'version_history',
];

async function loadInspectionMode() {
  try {
    return await import('../src/inspection-mode.mjs');
  } catch (error) {
    assert.fail(`CyberMedica inspection mode module must exist and load: ${error.message}`);
  }
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function evidenceFamily(family, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    family,
    manifestHash: hashes[index],
    receiptHash: hashes[index + 1],
    custodyDigest: hashes[index + 2],
    accessPolicyRef: `inspection-access-policy-${family}`,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function inspectionModeInput(overrides = {}) {
  return mergeDeep(
    {
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-alpha',
      actor: {
        did: 'did:exo:regulatory-inspector-alpha',
        kind: 'human',
        roleRefs: ['regulatory_inspector', 'auditor_inspector'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['inspection_mode', 'read'],
        authorityChainHash: DIGEST_A,
      },
      inspectionPolicy: {
        policyRef: 'inspection-mode-policy-alpha',
        policyHash: DIGEST_B,
        status: 'active',
        allowedPurposes: ['regulatory_inspection', 'sponsor_audit'],
        allowedViewerRoles: ['auditor_inspector', 'regulatory_inspector'],
        requiredEvidenceFamilies: REQUIRED_EVIDENCE_FAMILIES,
        maxSessionDurationMs: 7_200_000,
        exportDisabledByDefault: true,
        disclosureLogRequired: true,
        metadataOnly: true,
        protectedContentExcluded: true,
        evaluatedAtHlc: { physicalMs: 1801010000000, logical: 0 },
      },
      sessionRequest: {
        requestRef: 'inspection-session-request-alpha',
        purpose: 'regulatory_inspection',
        requestedViewerRole: 'regulatory_inspector',
        requestedScopes: ['training_delegation', 'evidence_index', 'decision_rationale', 'access_logs'],
        siteRef: 'site-alpha',
        protocolRef: 'protocol-cm-001',
        requestedAtHlc: { physicalMs: 1801010100000, logical: 0 },
        startsAtHlc: { physicalMs: 1801010200000, logical: 0 },
        expiresAtHlc: { physicalMs: 1801013800000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
        productionTrustClaim: false,
      },
      evidencePackage: {
        auditPackageReceiptHash: DIGEST_C,
        legalPackReceiptHash: DIGEST_D,
        qmsPassportReceiptHash: DIGEST_E,
        manualGuideReceiptHash: DIGEST_F,
        dashboardSnapshotHash: DIGEST_1,
        evidenceFamilies: REQUIRED_EVIDENCE_FAMILIES.map((family, index) => evidenceFamily(family, index)),
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      boundaryAttestation: {
        accessPolicyHash: DIGEST_2,
        exportPolicyHash: DIGEST_3,
        disclosureLogHash: DIGEST_4,
        suppressionLogHash: DIGEST_5,
        filteredViewHash: DIGEST_6,
        protectedContentSuppressed: true,
        directIdentifiersSuppressed: true,
        sponsorConfidentialSuppressed: true,
        rawSourceDocumentsExcluded: true,
        disclosureLogRequired: true,
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      humanAuthorization: {
        status: 'approved',
        reviewerDid: 'did:exo:quality-manager-alpha',
        reviewHash: DIGEST_7,
        approvedAtHlc: { physicalMs: 1801010150000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      receiptEvidence: {
        custodyDigest: DIGEST_8,
        artifactHash: DIGEST_9,
      },
    },
    overrides,
  );
}

test('inspection mode creates deterministic read-only metadata sessions for authorized auditors and regulators', async () => {
  const { evaluateInspectionModeSession } = await loadInspectionMode();
  const inputA = inspectionModeInput({
    sessionRequest: {
      requestedScopes: ['access_logs', 'decision_rationale', 'evidence_index', 'training_delegation'],
    },
    evidencePackage: {
      evidenceFamilies: [...inspectionModeInput().evidencePackage.evidenceFamilies].reverse(),
    },
  });
  const inputB = inspectionModeInput({
    sessionRequest: {
      requestedScopes: ['training_delegation', 'evidence_index', 'decision_rationale', 'access_logs'],
    },
  });

  const first = evaluateInspectionModeSession(inputA);
  const second = evaluateInspectionModeSession(inputB);

  assert.equal(first.status, 'ready');
  assert.deepEqual(first.reasons, []);
  assert.equal(first.inspectionModeSession.accessMode, 'read_only_inspection');
  assert.equal(first.inspectionModeSession.purpose, 'regulatory_inspection');
  assert.deepEqual(first.inspectionModeSession.evidenceFamilies, REQUIRED_EVIDENCE_FAMILIES);
  assert.deepEqual(first.inspectionModeSession.requestedScopes, [
    'access_logs',
    'decision_rationale',
    'evidence_index',
    'training_delegation',
  ]);
  assert.equal(first.inspectionModeSession.metadataOnly, true);
  assert.equal(first.inspectionModeSession.protectedContentSuppressed, true);
  assert.equal(first.inspectionModeSession.disclosureLogRequired, true);
  assert.equal(first.inspectionModeSession.productionTrustClaim, false);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'inspection_mode_session');
  assert.equal(first.inspectionModeSession.sessionId, second.inspectionModeSession.sessionId);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.actionHash, second.receipt.actionHash);
  assert.doesNotMatch(JSON.stringify(first), /participant alice|source document|medical record|patient/iu);
});

test('inspection mode fails closed for unsafe roles missing evidence broad claims and unbounded sessions', async () => {
  const { evaluateInspectionModeSession } = await loadInspectionMode();
  const denied = evaluateInspectionModeSession(
    inspectionModeInput({
      actor: {
        did: 'did:exo:sponsor-viewer-alpha',
        kind: 'ai_agent',
        roleRefs: ['sponsor_viewer'],
      },
      authority: {
        permissions: ['read'],
        authorityChainHash: 'not-a-digest',
      },
      inspectionPolicy: {
        allowedPurposes: ['sponsor_audit'],
        allowedViewerRoles: ['auditor_inspector'],
        requiredEvidenceFamilies: REQUIRED_EVIDENCE_FAMILIES,
        maxSessionDurationMs: 10,
      },
      sessionRequest: {
        purpose: 'regulatory_inspection',
        requestedViewerRole: 'regulatory_inspector',
        startsAtHlc: { physicalMs: 1801010200000, logical: 0 },
        expiresAtHlc: { physicalMs: 1801010200001, logical: 0 },
        productionTrustClaim: true,
      },
      evidencePackage: {
        evidenceFamilies: REQUIRED_EVIDENCE_FAMILIES.filter((family) => family !== 'access_logs').map((family, index) =>
          evidenceFamily(family, index),
        ),
      },
      boundaryAttestation: {
        protectedContentSuppressed: false,
        directIdentifiersSuppressed: false,
        sponsorConfidentialSuppressed: false,
        rawSourceDocumentsExcluded: false,
        disclosureLogRequired: false,
        suppressionLogHash: '',
      },
      humanAuthorization: {
        status: 'pending',
        reviewerDid: '',
        reviewHash: '',
      },
    }),
  );

  assert.equal(denied.status, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('inspection_actor_role_unauthorized'));
  assert.ok(denied.reasons.includes('inspection_authority_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('inspection_purpose_not_allowed:regulatory_inspection'));
  assert.ok(denied.reasons.includes('inspection_viewer_role_not_allowed:regulatory_inspector'));
  assert.ok(denied.reasons.includes('inspection_evidence_family_missing:access_logs'));
  assert.ok(denied.reasons.includes('protected_content_suppression_missing'));
  assert.ok(denied.reasons.includes('direct_identifier_suppression_missing'));
  assert.ok(denied.reasons.includes('sponsor_confidential_suppression_missing'));
  assert.ok(denied.reasons.includes('raw_source_document_exclusion_missing'));
  assert.ok(denied.reasons.includes('disclosure_log_not_required'));
  assert.ok(denied.reasons.includes('human_authorization_not_approved'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.equal(denied.inspectionModeSession, null);
  assert.equal(denied.receipt, null);
});

test('inspection mode denies malformed empty objects without issuing receipts', async () => {
  const { evaluateInspectionModeSession } = await loadInspectionMode();
  const denied = evaluateInspectionModeSession({
    tenantId: '',
    targetTenantId: 'tenant-site-alpha',
    actor: null,
    authority: null,
    inspectionPolicy: null,
    sessionRequest: null,
    evidencePackage: null,
    boundaryAttestation: null,
    humanAuthorization: null,
    receiptEvidence: null,
  });

  assert.equal(denied.status, 'denied');
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('actor_did_absent'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('inspection_policy_ref_absent'));
  assert.ok(denied.reasons.includes('inspection_request_ref_absent'));
  assert.ok(denied.reasons.includes('inspection_evidence_package_absent'));
  assert.ok(denied.reasons.includes('boundary_attestation_absent'));
  assert.ok(denied.reasons.includes('human_authorization_absent'));
  assert.ok(denied.reasons.includes('receipt_artifact_hash_invalid'));
  assert.ok(denied.reasons.includes('receipt_custody_digest_invalid'));
  assert.equal(denied.inspectionModeSession, null);
  assert.equal(denied.receipt, null);
});

test('inspection mode rejects raw inspection content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateInspectionModeSession } = await loadInspectionMode();

  assert.throws(
    () =>
      evaluateInspectionModeSession(
        inspectionModeInput({
          evidencePackage: {
            rawInspectionNotes: 'full source document packet for participant Alice',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateInspectionModeSession(
        inspectionModeInput({
          boundaryAttestation: {
            privateKey: 'root-secret-key-material',
          },
        }),
      ),
    ProtectedContentError,
  );
});
