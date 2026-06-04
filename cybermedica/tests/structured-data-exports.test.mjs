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
const RESPONSE_PACKAGE_HASH = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
const REQUEST_HASH = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';

const REQUIRED_EXPORT_FAMILIES = ['audit_record', 'diligence_packet', 'evidence_index', 'site_data'];

async function loadStructuredDataExports() {
  try {
    return await import('../src/structured-data-exports.mjs');
  } catch (error) {
    assert.fail(`CyberMedica structured data exports module must exist and load: ${error.message}`);
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

function exportRecord(overrides) {
  return {
    recordRef: 'structured-export-record',
    family: 'site_data',
    siteRef: 'site-alpha',
    artifactHash: DIGEST_A,
    metadataHash: DIGEST_B,
    provenanceHash: DIGEST_C,
    custodyDigest: DIGEST_D,
    accessLogHash: DIGEST_E,
    decisionRationaleHash: DIGEST_F,
    versionHistoryHash: DIGEST_1,
    retentionRuleRef: 'retention-site-alpha-qms',
    classification: 'qms_metadata_only',
    sensitivityTags: ['metadata_only', 'quality_evidence'],
    allowedRoleRefs: ['quality_manager', 'sponsor_viewer'],
    recipientClasses: ['sponsor_viewer'],
    updatedAtHlc: { physicalMs: 1797000100000, logical: 0 },
    exportable: true,
    participantLinked: false,
    boundary: {
      metadataOnly: true,
      rawContentExcluded: true,
      sourcePayloadExcluded: true,
      directIdentifiersExcluded: true,
    },
    ...overrides,
  };
}

function structuredRecords() {
  return [
    exportRecord({
      recordRef: 'site-data-passport-alpha',
      family: 'site_data',
      artifactHash: DIGEST_A,
      metadataHash: DIGEST_B,
      provenanceHash: DIGEST_C,
    }),
    exportRecord({
      recordRef: 'evidence-index-consent-alpha',
      family: 'evidence_index',
      artifactHash: DIGEST_D,
      metadataHash: DIGEST_E,
      provenanceHash: DIGEST_F,
      sensitivityTags: ['metadata_only', 'quality_evidence', 'sponsor_confidential_metadata'],
    }),
    exportRecord({
      recordRef: 'audit-record-internal-alpha',
      family: 'audit_record',
      artifactHash: DIGEST_1,
      metadataHash: DIGEST_2,
      provenanceHash: DIGEST_3,
      sensitivityTags: ['metadata_only', 'audit_metadata'],
      allowedRoleRefs: ['quality_manager', 'auditor'],
      recipientClasses: ['auditor', 'sponsor_viewer'],
    }),
    exportRecord({
      recordRef: 'diligence-packet-sponsor-alpha',
      family: 'diligence_packet',
      artifactHash: DIGEST_4,
      metadataHash: DIGEST_5,
      provenanceHash: DIGEST_6,
      sensitivityTags: ['metadata_only', 'sponsor_confidential_metadata'],
    }),
    exportRecord({
      recordRef: 'site-data-finance-suppressed',
      family: 'site_data',
      artifactHash: DIGEST_7,
      metadataHash: DIGEST_8,
      provenanceHash: DIGEST_9,
      sensitivityTags: ['metadata_only', 'finance_confidential_metadata'],
      allowedRoleRefs: ['finance_owner'],
      recipientClasses: ['finance_owner'],
    }),
  ];
}

function structuredExportInput(overrides = {}) {
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
      permissions: ['data_export', 'read'],
      authorityChainHash: DIGEST_A,
    },
    exportGrant: {
      grantRef: 'structured-export-grant-alpha',
      grantHash: DIGEST_B,
      status: 'active',
      scope: 'structured_data_export',
      recipientTenantId: 'tenant-sponsor-alpha',
      expiresAtHlc: { physicalMs: 1798000000000, logical: 0 },
    },
    exportRequest: {
      exportRef: 'nfr013-portable-export-alpha',
      purpose: 'sponsor_diligence',
      requestedFamilies: REQUIRED_EXPORT_FAMILIES,
      requestedFormat: 'json',
      recipientTenantId: 'tenant-sponsor-alpha',
      recipientClass: 'sponsor_viewer',
      requestedAtHlc: { physicalMs: 1797000200000, logical: 0 },
      generatedAtHlc: { physicalMs: 1797000200000, logical: 3 },
      metadataOnly: true,
    },
    accessPolicy: {
      policyRef: 'portable-export-access-policy-alpha',
      policyHash: DIGEST_C,
      status: 'active',
      evaluatedAtHlc: { physicalMs: 1797000200000, logical: 1 },
      allowedFamilies: REQUIRED_EXPORT_FAMILIES,
      allowedSiteRefs: ['site-alpha'],
      allowedRoleRefs: ['quality_manager', 'sponsor_viewer', 'auditor'],
      allowedRecipientClasses: ['sponsor_viewer', 'auditor'],
      allowedSensitivityTags: ['metadata_only', 'quality_evidence', 'audit_metadata', 'sponsor_confidential_metadata'],
      sourcePayloadAccessible: false,
      metadataOnly: true,
      disclosureLogRequired: true,
      productionTrustClaim: false,
    },
    records: structuredRecords(),
    disclosureLog: {
      logRef: 'portable-export-disclosure-alpha',
      disclosureLogHash: DIGEST_D,
      purpose: 'sponsor_diligence',
      recipientClass: 'sponsor_viewer',
      loggedAtHlc: { physicalMs: 1797000200000, logical: 2 },
      includesRawContent: false,
    },
    responsePackage: {
      packageRef: 'structured-diligence-response-package-alpha',
      packageHash: RESPONSE_PACKAGE_HASH,
      requestRef: 'sponsor-cro-request-alpha',
      workItemRef: 'sponsor-cro-work-item-alpha',
      recipientTenantId: 'tenant-sponsor-alpha',
      packageRecordRefs: [
        'audit-record-internal-alpha',
        'diligence-packet-sponsor-alpha',
        'evidence-index-consent-alpha',
        'site-data-passport-alpha',
      ],
      generatedAtHlc: { physicalMs: 1797000200000, logical: 2 },
      metadataOnly: true,
      rawContentExcluded: true,
      protectedContentExcluded: true,
    },
    sponsorCroRequestEvidence: {
      requestRef: 'sponsor-cro-request-alpha',
      requestHash: REQUEST_HASH,
      requesterClass: 'sponsor',
      workItemRef: 'sponsor-cro-work-item-alpha',
      workItemStatus: 'approved_for_response',
      disclosureEventRef: 'portable-export-disclosure-alpha',
      disclosureLogHash: DIGEST_D,
      decisionForumMatterRef: 'df-sponsor-cro-request-alpha',
      humanReviewHash: DIGEST_E,
      responsePackageHash: RESPONSE_PACKAGE_HASH,
      linkedRecipientTenantId: 'tenant-sponsor-alpha',
      linkedExportRef: 'nfr013-portable-export-alpha',
      metadataOnly: true,
      sourcePayloadExcluded: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
      linkedAtHlc: { physicalMs: 1797000200000, logical: 2 },
    },
    humanAuthorization: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      status: 'approved',
      authorizedAtHlc: { physicalMs: 1797000200000, logical: 2 },
      authorizationHash: DIGEST_E,
      aiFinalAuthorityRejected: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      scopeHash: DIGEST_F,
      evidenceRefs: ['evidence-index-consent-alpha', 'audit-record-internal-alpha'],
      limitationHashes: [DIGEST_1],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_2,
  };
  return mergeDeep(base, overrides);
}

test('structured data export creates deterministic NFR-013 portable package under access policy', async () => {
  const { evaluateStructuredDataExport } = await loadStructuredDataExports();

  const resultA = evaluateStructuredDataExport(structuredExportInput());
  const resultB = evaluateStructuredDataExport(
    structuredExportInput({
      exportRequest: {
        requestedFamilies: [...REQUIRED_EXPORT_FAMILIES].reverse(),
      },
      records: [...structuredRecords()].reverse(),
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.exportPackage.packageId, resultB.exportPackage.packageId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.exportPackage.trustState, 'inactive');
  assert.equal(resultA.exportPackage.exochainProductionClaim, false);
  assert.equal(resultA.exportPackage.structuredExportSubjectToAccessPolicy, true);
  assert.equal(resultA.exportPackage.provenancePreserved, true);
  assert.equal(resultA.exportPackage.custodyPreserved, true);
  assert.equal(resultA.exportPackage.timestampsPreserved, true);
  assert.equal(resultA.exportPackage.accessLogsPreserved, true);
  assert.equal(resultA.exportPackage.decisionRationalePreserved, true);
  assert.equal(resultA.exportPackage.versionHistoryPreserved, true);
  assert.equal(resultA.exportPackage.suppressedRecordCount, 1);
  assert.equal(Object.hasOwn(resultA.exportPackage, 'suppressedRecordRefs'), false);
  assert.equal(resultA.exportPackage.responsePackageHash, RESPONSE_PACKAGE_HASH);
  assert.deepEqual(resultA.exportPackage.sponsorCroRequestRefs, ['sponsor-cro-request-alpha']);
  assert.deepEqual(resultA.exportPackage.sponsorCroWorkItemRefs, ['sponsor-cro-work-item-alpha']);
  assert.deepEqual(resultA.exportPackage.exportFamilies, REQUIRED_EXPORT_FAMILIES);
  assert.deepEqual(
    resultA.exportPackage.records.map((record) => record.recordRef),
    [
      'audit-record-internal-alpha',
      'diligence-packet-sponsor-alpha',
      'evidence-index-consent-alpha',
      'site-data-passport-alpha',
    ],
  );
  assert.deepEqual(Object.keys(resultA.exportPackage.records[0]), [
    'accessLogHash',
    'artifactHash',
    'classification',
    'custodyDigest',
    'decisionRationaleHash',
    'family',
    'metadataHash',
    'provenanceHash',
    'recordRef',
    'retentionRuleRef',
    'sensitivityTags',
    'siteRef',
    'updatedAtHlc',
    'versionHistoryHash',
  ]);
});

test('structured data export requires controlled Sponsor/CRO request linkage for diligence packets', async () => {
  const { evaluateStructuredDataExport } = await loadStructuredDataExports();

  const absent = evaluateStructuredDataExport(
    structuredExportInput({
      sponsorCroRequestEvidence: null,
    }),
  );

  assert.equal(absent.decision, 'denied');
  assert.equal(absent.failClosed, true);
  assert.equal(absent.receipt, null);
  assert.ok(absent.reasons.includes('sponsor_cro_request_evidence_absent'));

  const malformed = evaluateStructuredDataExport(
    structuredExportInput({
      sponsorCroRequestEvidence: {
        requestRef: '',
        requestHash: 'not-a-digest',
        requesterClass: 'public_observer',
        workItemRef: '',
        workItemStatus: 'draft',
        disclosureEventRef: '',
        disclosureLogHash: 'bad',
        decisionForumMatterRef: '',
        humanReviewHash: 'bad',
        responsePackageHash: 'bad',
        linkedRecipientTenantId: 'tenant-other',
        linkedExportRef: 'other-export',
        metadataOnly: false,
        sourcePayloadExcluded: false,
        protectedContentExcluded: false,
        productionTrustClaim: true,
        linkedAtHlc: { physicalMs: 1797000200000, logical: -1 },
      },
      responsePackage: {
        packageRef: '',
        packageHash: 'not-a-digest',
        requestRef: 'other-request',
        workItemRef: 'other-work-item',
        recipientTenantId: 'tenant-other',
        packageRecordRefs: ['site-data-passport-alpha'],
        generatedAtHlc: { physicalMs: 1797000200000, logical: 4 },
        metadataOnly: false,
        rawContentExcluded: false,
        protectedContentExcluded: false,
      },
    }),
  );

  assert.equal(malformed.decision, 'denied');
  assert.equal(malformed.receipt, null);
  assert.ok(malformed.reasons.includes('sponsor_cro_request_ref_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_hash_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_requester_class_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_work_item_ref_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_work_item_status_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_disclosure_event_ref_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_disclosure_log_hash_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_disclosure_log_hash_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_decision_forum_matter_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_human_review_hash_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_human_review_hash_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_hash_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_ref_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_hash_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_request_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_work_item_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_recipient_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_record_scope_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_after_export_generation'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_metadata_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_raw_content_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_protected_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_recipient_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_linked_export_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_metadata_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_source_payload_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_protected_boundary_invalid'));
  assert.ok(malformed.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_link_time_invalid'));
});

test('structured data export fails closed for missing families unsafe policy and inactive grant', async () => {
  const { evaluateStructuredDataExport } = await loadStructuredDataExports();

  const result = evaluateStructuredDataExport(
    structuredExportInput({
      exportGrant: {
        status: 'revoked',
      },
      accessPolicy: {
        status: 'suspended',
        sourcePayloadAccessible: true,
        productionTrustClaim: true,
      },
      records: structuredRecords().filter((record) => record.family !== 'evidence_index'),
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('export_grant_not_active'));
  assert.ok(result.reasons.includes('access_policy_not_active'));
  assert.ok(result.reasons.includes('access_policy_payload_access_forbidden'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('required_family_missing:evidence_index'));
});

test('structured data export requires human authorization and safe AI assistance', async () => {
  const { evaluateStructuredDataExport } = await loadStructuredDataExports();

  const result = evaluateStructuredDataExport(
    structuredExportInput({
      actor: {
        kind: 'ai_agent',
      },
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
  assert.ok(result.reasons.includes('human_authorization_not_approved'));
  assert.ok(result.reasons.includes('ai_final_authority_not_rejected'));
  assert.ok(result.reasons.includes('ai_review_human_review_absent'));
});

test('structured data export validates HLC ordering and export grant expiry', async () => {
  const { evaluateStructuredDataExport } = await loadStructuredDataExports();

  const result = evaluateStructuredDataExport(
    structuredExportInput({
      exportGrant: {
        expiresAtHlc: { physicalMs: 1797000199000, logical: 0 },
      },
      exportRequest: {
        requestedAtHlc: { physicalMs: 1797000200000, logical: -1 },
        generatedAtHlc: { physicalMs: 1797000199000, logical: 0 },
      },
      disclosureLog: {
        loggedAtHlc: { physicalMs: 1797000200000, logical: 0 },
      },
      humanAuthorization: {
        authorizedAtHlc: { physicalMs: 1797000200000, logical: 2 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('export_requested_time_invalid'));
  assert.ok(result.reasons.includes('disclosure_log_before_access_policy'));
  assert.ok(result.reasons.includes('export_generated_before_disclosure_log'));
  assert.ok(result.reasons.includes('export_grant_expired'));
  assert.ok(result.reasons.includes('human_authorization_after_export_generation'));
});

test('structured data export handles absent AI assistance and inert raw markers', async () => {
  const { evaluateStructuredDataExport } = await loadStructuredDataExports();

  const result = evaluateStructuredDataExport(
    structuredExportInput({
      aiAssistance: null,
      records: structuredRecords().map((record, index) => ({
        ...record,
        ...(index === 0 ? { rawExport: false } : {}),
      })),
    }),
  );

  assert.equal(result.decision, 'permitted');
  assert.equal(result.exportPackage.recordCount, 4);
  assert.equal(result.exportPackage.suppressedRecordCount, 1);
});

test('structured data export rejects raw export source content and secret material', async () => {
  const { evaluateStructuredDataExport } = await loadStructuredDataExports();

  assert.throws(
    () =>
      evaluateStructuredDataExport(
        structuredExportInput({
          records: [
            {
              ...structuredRecords()[0],
              sourceDocumentBody: 'Participant Alice Example source document text.',
            },
          ],
        }),
      ),
    /raw structured export content|protected content/i,
  );

  assert.throws(
    () =>
      evaluateStructuredDataExport(
        structuredExportInput({
          records: [
            {
              ...structuredRecords()[0],
              rawExport: [{ metadataHash: DIGEST_A }],
            },
          ],
        }),
      ),
    /raw structured export content/i,
  );

  assert.throws(
    () =>
      evaluateStructuredDataExport(
        structuredExportInput({
          records: [
            {
              ...structuredRecords()[0],
              rawExport: 1,
            },
          ],
        }),
      ),
    /raw structured export content/i,
  );

  assert.throws(
    () =>
      evaluateStructuredDataExport(
        structuredExportInput({
          sponsorCroRequestEvidence: {
            rawRequestNarrative: 'Participant Alice Example request narrative.',
          },
        }),
      ),
    /raw structured export content/i,
  );

  assert.throws(
    () =>
      evaluateStructuredDataExport(
        structuredExportInput({
          responsePackage: {
            rawResponsePackage: { participantListing: ['Participant Alice Example'] },
          },
        }),
      ),
    /raw structured export content/i,
  );

  assert.throws(
    () =>
      evaluateStructuredDataExport(
        structuredExportInput({
          exportRequest: {
            accessToken: 'secret-token-value',
          },
        }),
      ),
    /secret field/i,
  );
});
