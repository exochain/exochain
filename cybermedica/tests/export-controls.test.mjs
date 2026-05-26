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

const REQUIRED_CONTROL_DOMAINS = ['access', 'confidentiality', 'disclosure', 'privacy'];

async function loadExportControls() {
  try {
    return await import('../src/export-controls.mjs');
  } catch (error) {
    assert.fail(`CyberMedica export controls module must exist and load: ${error.message}`);
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

function exportRecord(overrides = {}) {
  return {
    recordRef: 'export-control-record',
    exportFamily: 'site_readiness',
    exportType: 'sponsor_diligence_packet',
    siteRef: 'site-alpha',
    artifactHash: DIGEST_A,
    metadataHash: DIGEST_B,
    custodyDigest: DIGEST_C,
    accessLogHash: DIGEST_D,
    classification: 'confidential_metadata_only',
    sensitivityTags: ['metadata_only', 'quality_evidence'],
    allowedRoleRefs: ['quality_manager', 'sponsor_viewer'],
    recipientClasses: ['sponsor_viewer'],
    privacyCategory: 'metadata_minimized',
    confidentialityCategory: 'sponsor_confidential_metadata',
    participantLinked: false,
    consentRef: null,
    updatedAtHlc: { physicalMs: 1799000000000, logical: 0 },
    boundary: {
      metadataOnly: true,
      rawContentExcluded: true,
      sourcePayloadExcluded: true,
      directIdentifiersExcluded: true,
      sponsorConfidentialContentExcluded: true,
      privilegedContentExcluded: true,
    },
    ...overrides,
  };
}

function exportRecords() {
  return [
    exportRecord({
      recordRef: 'readiness-passport-alpha',
      exportFamily: 'site_readiness',
      artifactHash: DIGEST_A,
      metadataHash: DIGEST_B,
      custodyDigest: DIGEST_C,
    }),
    exportRecord({
      recordRef: 'audit-index-alpha',
      exportFamily: 'audit_evidence',
      artifactHash: DIGEST_D,
      metadataHash: DIGEST_E,
      custodyDigest: DIGEST_F,
      sensitivityTags: ['metadata_only', 'audit_metadata'],
      recipientClasses: ['auditor', 'sponsor_viewer'],
    }),
    exportRecord({
      recordRef: 'participant-consent-readiness-alpha',
      exportFamily: 'participant_consent',
      artifactHash: DIGEST_1,
      metadataHash: DIGEST_2,
      custodyDigest: DIGEST_3,
      sensitivityTags: ['metadata_only', 'participant_linked_metadata'],
      participantLinked: true,
      consentRef: 'consent-bailment-alpha',
    }),
    exportRecord({
      recordRef: 'finance-suppressed-alpha',
      exportFamily: 'site_readiness',
      artifactHash: DIGEST_4,
      metadataHash: DIGEST_5,
      custodyDigest: DIGEST_6,
      sensitivityTags: ['metadata_only', 'finance_confidential_metadata'],
      allowedRoleRefs: ['finance_owner'],
      recipientClasses: ['finance_owner'],
      confidentialityCategory: 'finance_confidential_metadata',
    }),
  ];
}

function exportControlInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'sponsor_viewer'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['export_control', 'read'],
      authorityChainHash: DIGEST_A,
    },
    exportRequest: {
      exportRef: 'fr041-export-control-alpha',
      exportType: 'sponsor_diligence_packet',
      purpose: 'sponsor_diligence',
      recipientTenantId: 'tenant-sponsor-alpha',
      recipientClass: 'sponsor_viewer',
      requestedAtHlc: { physicalMs: 1799000000000, logical: 1 },
      generatedAtHlc: { physicalMs: 1799000000000, logical: 4 },
      metadataOnly: true,
      productionTrustClaim: false,
    },
    exportControlPolicy: {
      policyRef: 'fr041-export-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredControlDomains: REQUIRED_CONTROL_DOMAINS,
      allowedExportTypes: ['sponsor_diligence_packet', 'structured_data_export'],
      allowedPurposes: ['sponsor_diligence', 'audit_inspection'],
      allowedRecipientClasses: ['sponsor_viewer', 'auditor'],
      allowedRoleRefs: ['quality_manager', 'sponsor_viewer', 'auditor'],
      allowedSensitivityTags: ['metadata_only', 'quality_evidence', 'audit_metadata', 'participant_linked_metadata'],
      allowedPrivacyCategories: ['metadata_minimized'],
      allowedConfidentialityCategories: ['sponsor_confidential_metadata'],
      metadataOnly: true,
      sourcePayloadAccessible: false,
      directIdentifiersAllowed: false,
      disclosureLogRequired: true,
      suppressionMode: 'suppress_without_identifiers',
      evaluatedAtHlc: { physicalMs: 1799000000000, logical: 2 },
      validUntilHlc: { physicalMs: 1799100000000, logical: 0 },
      productionTrustClaim: false,
    },
    records: exportRecords(),
    participantConsentMatrix: [
      {
        consentRef: 'consent-bailment-alpha',
        status: 'active',
        scope: 'export_metadata',
        participantCodeHash: DIGEST_7,
        consentReceiptHash: DIGEST_8,
        revoked: false,
        expiresAtHlc: { physicalMs: 1799100000000, logical: 0 },
      },
    ],
    disclosureLog: {
      logRef: 'fr041-disclosure-alpha',
      disclosureLogHash: DIGEST_C,
      purpose: 'sponsor_diligence',
      recipientClass: 'sponsor_viewer',
      loggedAtHlc: { physicalMs: 1799000000000, logical: 3 },
      includesRawContent: false,
      includesSuppressedRecordRefs: false,
      includesDirectIdentifiers: false,
    },
    humanAuthorization: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      status: 'approved',
      authorizationHash: DIGEST_D,
      authorizedAtHlc: { physicalMs: 1799000000000, logical: 3 },
      aiFinalAuthorityRejected: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      reviewedByHuman: true,
      scopeHash: DIGEST_E,
    },
    custodyDigest: DIGEST_9,
  };
  return mergeDeep(base, overrides);
}

test('export controls permit deterministic FR-041 metadata exports with suppressed records hidden', async () => {
  const { evaluateExportControl } = await loadExportControls();

  const resultA = evaluateExportControl(exportControlInput());
  const resultB = evaluateExportControl(
    exportControlInput({
      aiAssistance: null,
      records: [...exportRecords()]
        .reverse()
        .map((record, index) => (index === 0 ? { ...record, rawExportPayload: false } : record)),
      exportControlPolicy: {
        allowedSensitivityTags: [
          'participant_linked_metadata',
          'audit_metadata',
          'quality_evidence',
          'metadata_only',
        ],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.controlPackage.packageId, resultB.controlPackage.packageId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.controlPackage.exportControlsApplied, true);
  assert.equal(resultA.controlPackage.privacyBoundarySatisfied, true);
  assert.equal(resultA.controlPackage.confidentialityBoundarySatisfied, true);
  assert.equal(resultA.controlPackage.accessBoundarySatisfied, true);
  assert.equal(resultA.controlPackage.disclosureLogged, true);
  assert.equal(resultA.controlPackage.suppressedRecordCount, 1);
  assert.equal(Object.hasOwn(resultA.controlPackage, 'suppressedRecordRefs'), false);
  assert.equal(resultA.controlPackage.trustState, 'inactive');
  assert.equal(resultA.controlPackage.exochainProductionClaim, false);
  assert.deepEqual(resultA.controlPackage.controlDomains, REQUIRED_CONTROL_DOMAINS);
  assert.deepEqual(
    resultA.controlPackage.records.map((record) => record.recordRef),
    ['audit-index-alpha', 'participant-consent-readiness-alpha', 'readiness-passport-alpha'],
  );
  assert.deepEqual(Object.keys(resultA.controlPackage.records[0]), [
    'accessLogHash',
    'artifactHash',
    'classification',
    'confidentialityCategory',
    'custodyDigest',
    'exportFamily',
    'metadataHash',
    'participantLinked',
    'privacyCategory',
    'recordRef',
    'sensitivityTags',
    'siteRef',
    'updatedAtHlc',
  ]);
});

test('export controls fail closed for unsafe policy and production trust claims', async () => {
  const { evaluateExportControl } = await loadExportControls();

  const result = evaluateExportControl(
    exportControlInput({
      exportRequest: {
        exportType: 'unsupported_export',
        productionTrustClaim: true,
      },
      exportControlPolicy: {
        status: 'suspended',
        requiredControlDomains: ['access', 'privacy'],
        sourcePayloadAccessible: true,
        directIdentifiersAllowed: true,
        productionTrustClaim: true,
      },
      disclosureLog: {
        includesRawContent: true,
        includesSuppressedRecordRefs: true,
        includesDirectIdentifiers: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('export_type_not_allowed'));
  assert.ok(result.reasons.includes('export_request_production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('export_policy_not_active'));
  assert.ok(result.reasons.includes('control_domain_missing:confidentiality'));
  assert.ok(result.reasons.includes('source_payload_access_forbidden'));
  assert.ok(result.reasons.includes('direct_identifier_export_forbidden'));
  assert.ok(result.reasons.includes('disclosure_log_raw_content_forbidden'));
  assert.ok(result.reasons.includes('disclosure_log_suppressed_refs_forbidden'));
});

test('export controls require active participant consent and human authorization', async () => {
  const { evaluateExportControl } = await loadExportControls();

  const result = evaluateExportControl(
    exportControlInput({
      actor: {
        kind: 'ai_agent',
      },
      participantConsentMatrix: [
        {
          consentRef: 'consent-bailment-alpha',
          status: 'revoked',
          scope: 'export_metadata',
          participantCodeHash: DIGEST_7,
          consentReceiptHash: DIGEST_8,
          revoked: true,
          expiresAtHlc: { physicalMs: 1799100000000, logical: 0 },
        },
      ],
      humanAuthorization: {
        status: 'draft',
        aiFinalAuthorityRejected: false,
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('participant_consent_not_active:participant-consent-readiness-alpha'));
  assert.ok(result.reasons.includes('participant_consent_revoked:participant-consent-readiness-alpha'));
  assert.ok(result.reasons.includes('human_authorization_not_approved'));
  assert.ok(result.reasons.includes('ai_final_authority_not_rejected'));
  assert.ok(result.reasons.includes('ai_review_human_review_absent'));
});

test('export controls validate HLC ordering and policy expiry', async () => {
  const { evaluateExportControl } = await loadExportControls();

  const result = evaluateExportControl(
    exportControlInput({
      exportRequest: {
        requestedAtHlc: { physicalMs: 1799000000000, logical: 5 },
        generatedAtHlc: { physicalMs: 1799000000000, logical: 4 },
      },
      exportControlPolicy: {
        evaluatedAtHlc: { physicalMs: 1799000000000, logical: 2 },
        validUntilHlc: { physicalMs: 1799000000000, logical: 4 },
      },
      disclosureLog: {
        loggedAtHlc: { physicalMs: 1799000000000, logical: 1 },
      },
      humanAuthorization: {
        authorizedAtHlc: { physicalMs: 1799000000000, logical: 6 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('export_generated_before_request'));
  assert.ok(result.reasons.includes('export_policy_before_request'));
  assert.ok(result.reasons.includes('export_policy_expired'));
  assert.ok(result.reasons.includes('disclosure_log_before_policy'));
  assert.ok(result.reasons.includes('human_authorization_after_export_generation'));

  const malformed = evaluateExportControl(
    exportControlInput({
      exportRequest: {
        requestedAtHlc: { physicalMs: 1799000000000, logical: -1 },
      },
    }),
  );
  assert.ok(malformed.reasons.includes('export_requested_time_invalid'));
});

test('export controls reject raw export payloads protected content and secret material', async () => {
  const { evaluateExportControl } = await loadExportControls();

  assert.throws(
    () =>
      evaluateExportControl(
        exportControlInput({
          records: [
            {
              ...exportRecords()[0],
              rawExportPayload: [{ artifactHash: DIGEST_A }],
            },
          ],
        }),
      ),
    /raw export content field/i,
  );

  assert.throws(
    () =>
      evaluateExportControl(
        exportControlInput({
          records: [
            {
              ...exportRecords()[0],
              sourceDocumentBody: 'Participant Alice Example source worksheet.',
            },
          ],
        }),
      ),
    /raw export content field|protected content/i,
  );

  assert.throws(
    () =>
      evaluateExportControl(
        exportControlInput({
          records: [
            {
              ...exportRecords()[0],
              rawExportPayload: 1,
            },
          ],
        }),
      ),
    /raw export content field/i,
  );

  assert.throws(
    () =>
      evaluateExportControl(
        exportControlInput({
          exportControlPolicy: {
            clientSecret: 'secret-value',
          },
        }),
      ),
    /export secret field/i,
  );
});
