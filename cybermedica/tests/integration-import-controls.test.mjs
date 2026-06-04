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

const REQUIRED_CHECKS = Object.freeze([
  'authority',
  'consent',
  'hash',
  'idempotency',
  'privacy',
  'schema',
  'tenant',
]);

async function loadIntegrationImportControls() {
  try {
    return await import('../src/integration-import-controls.mjs');
  } catch (error) {
    assert.fail(`CyberMedica integration import controls module must exist and load: ${error.message}`);
  }
}

function importControlInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:integration-service-alpha',
      kind: 'service_account',
      humanOwnerDid: 'did:exo:system-administrator-alpha',
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['integration_import', 'read'],
      authorityChainHash: DIGEST_A,
    },
    importRequest: {
      importRef: 'clinical-integration-import-edc-alpha',
      connectorRef: 'connector-edc-alpha',
      connectorType: 'edc',
      systemRef: 'system-edc-alpha',
      purpose: 'trial_data_index_refresh',
      objectFamilies: ['audit_record', 'consent_metadata', 'source_data_index', 'visit_metadata'],
      format: 'json',
      requestedAtHlc: { physicalMs: 1799000000000, logical: 0 },
      receivedAtHlc: { physicalMs: 1799000000000, logical: 2 },
      metadataOnly: true,
      payloadStoredExternally: true,
      productionTrustClaim: false,
    },
    connectorEvidence: {
      connectorRef: 'connector-edc-alpha',
      type: 'edc',
      systemRef: 'system-edc-alpha',
      status: 'verified',
      mode: 'inbound',
      configurationHash: DIGEST_B,
      mappingHash: DIGEST_C,
      accessPolicyHash: DIGEST_D,
      importProfileHash: DIGEST_E,
      lastVerifiedAtHlc: { physicalMs: 1799000000000, logical: 1 },
      healthCheck: {
        status: 'passing',
        checkedAtHlc: { physicalMs: 1799000000000, logical: 3 },
        statusHash: DIGEST_F,
        rawResponseExcluded: true,
      },
      metadataOnly: true,
      payloadStoredOutsideReceipt: true,
      protectedPayloadExcluded: true,
      secretsManagedExternally: true,
      failClosedOnError: true,
    },
    schemaMapping: {
      mappingRef: 'edc-import-map-alpha',
      schemaVersion: 'v1',
      profileHash: DIGEST_1,
      fieldMapHash: DIGEST_2,
      validationRulesHash: DIGEST_3,
      supportedObjectFamilies: ['audit_record', 'consent_metadata', 'source_data_index', 'visit_metadata'],
      tenantPartitioningEnforced: true,
      defaultDenyUnknownFields: true,
      directIdentifiersRejected: true,
      sourcePayloadExcluded: true,
      validatedAtHlc: { physicalMs: 1799000000000, logical: 4 },
    },
    importBatch: {
      batchRef: 'edc-import-batch-alpha',
      sourceSystemBatchRef: 'edc-feed-2026-05-31-alpha',
      sourceHash: DIGEST_4,
      manifestHash: DIGEST_5,
      recordCount: 42,
      acceptedRecordCount: 40,
      rejectedRecordCount: 2,
      duplicateRecordCount: 1,
      idempotencyKeyHash: DIGEST_6,
      replayProtectionHash: DIGEST_7,
      receivedAtHlc: { physicalMs: 1799000000000, logical: 2 },
      validatedAtHlc: { physicalMs: 1799000000000, logical: 5 },
      metadataOnly: true,
      rawPayloadExcluded: true,
      directIdentifiersExcluded: true,
    },
    validationEvidence: {
      status: 'passed',
      validationHash: DIGEST_8,
      requiredChecks: REQUIRED_CHECKS,
      failedRecordManifestHash: DIGEST_9,
      rejectedRecordsQuarantined: true,
      acceptedRecordsMetadataOnly: true,
      checkedAtHlc: { physicalMs: 1799000000000, logical: 6 },
    },
    privacyBoundary: {
      boundaryRef: 'integration-import-privacy-alpha',
      boundaryHash: DIGEST_A,
      phiPiiExcludedFromReceipts: true,
      sponsorConfidentialMinimized: true,
      sourcePayloadRetainedExternally: true,
      participantConsentChecked: true,
      disclosureLogRequired: true,
      receiptMetadataMinimized: true,
    },
    consentBoundary: {
      participantLinkedDataPresent: true,
      requiredForParticipantLinkedData: true,
      participantConsentChecked: true,
      consentPolicyHash: DIGEST_B,
      activeConsentReceiptRefs: ['cmr_consent_process_alpha'],
      revokedConsentCheckHash: DIGEST_C,
      revokedConsentDetected: false,
      deniesRevokedConsent: true,
    },
    disclosureLog: {
      logRef: 'integration-import-disclosure-alpha',
      disclosureLogHash: DIGEST_D,
      purpose: 'trial_data_index_refresh',
      loggedAtHlc: { physicalMs: 1799000000000, logical: 7 },
      includesRawContent: false,
    },
    humanReview: {
      reviewerDid: 'did:exo:system-administrator-alpha',
      status: 'approved',
      reviewHash: DIGEST_E,
      reviewedAtHlc: { physicalMs: 1799000000000, logical: 8 },
      aiFinalAuthorityRejected: true,
    },
    custodyDigest: DIGEST_F,
    ...overrides,
  };
  return base;
}

test('integration import controls create deterministic inactive metadata manifests for inbound clinical connectors', async () => {
  const { evaluateIntegrationImportControls } = await loadIntegrationImportControls();

  const resultA = evaluateIntegrationImportControls(importControlInput());
  const resultB = evaluateIntegrationImportControls({
    ...importControlInput(),
    importRequest: {
      ...importControlInput().importRequest,
      objectFamilies: [...importControlInput().importRequest.objectFamilies].reverse(),
    },
    schemaMapping: {
      ...importControlInput().schemaMapping,
      supportedObjectFamilies: [...importControlInput().schemaMapping.supportedObjectFamilies].reverse(),
    },
    validationEvidence: {
      ...importControlInput().validationEvidence,
      requiredChecks: [...REQUIRED_CHECKS].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.importManifest.status, 'accepted_metadata_only');
  assert.equal(resultA.importManifest.trustState, 'inactive');
  assert.equal(resultA.importManifest.exochainProductionClaim, false);
  assert.equal(resultA.importManifest.sourcePayloadExternal, true);
  assert.equal(resultA.importManifest.receiptMetadataOnly, true);
  assert.equal(resultA.importManifest.participantConsentChecked, true);
  assert.equal(resultA.importManifest.rejectedRecordCount, 2);
  assert.deepEqual(resultA.importManifest.objectFamilies, [
    'audit_record',
    'consent_metadata',
    'source_data_index',
    'visit_metadata',
  ]);
  assert.equal(resultA.importManifest.manifestHash, resultB.importManifest.manifestHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'integration_import_control_manifest');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|raw payload|client_secret|source document/iu);
});

test('integration import controls accept eISF metadata imports without raw source payloads', async () => {
  const { evaluateIntegrationImportControls } = await loadIntegrationImportControls();

  const result = evaluateIntegrationImportControls({
    ...importControlInput(),
    importRequest: {
      ...importControlInput().importRequest,
      importRef: 'clinical-integration-import-eisf-alpha',
      connectorRef: 'connector-eisf-alpha',
      connectorType: 'eisf',
      systemRef: 'system-eisf-alpha',
      purpose: 'site_file_metadata_refresh',
      objectFamilies: ['document_metadata', 'evidence_index'],
    },
    connectorEvidence: {
      ...importControlInput().connectorEvidence,
      connectorRef: 'connector-eisf-alpha',
      type: 'eisf',
      systemRef: 'system-eisf-alpha',
    },
    schemaMapping: {
      ...importControlInput().schemaMapping,
      mappingRef: 'eisf-import-map-alpha',
      supportedObjectFamilies: ['document_metadata', 'evidence_index'],
    },
    consentBoundary: {
      participantLinkedDataPresent: false,
    },
    disclosureLog: {
      ...importControlInput().disclosureLog,
      purpose: 'site_file_metadata_refresh',
    },
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.failClosed, false);
  assert.equal(result.importManifest.connectorType, 'eisf');
  assert.deepEqual(result.importManifest.objectFamilies, ['document_metadata', 'evidence_index']);
  assert.equal(result.importManifest.sourcePayloadExternal, true);
  assert.equal(result.importManifest.receiptMetadataOnly, true);
  assert.equal(result.receipt.anchorPayload.artifactType, 'integration_import_control_manifest');
  assert.doesNotMatch(JSON.stringify(result), /Participant Alice|raw payload|source document|client_secret/iu);
});

test('integration import controls fail closed for unsafe connector schema and import request defects', async () => {
  const { evaluateIntegrationImportControls } = await loadIntegrationImportControls();

  const denied = evaluateIntegrationImportControls({
    ...importControlInput(),
    importRequest: {
      ...importControlInput().importRequest,
      connectorRef: 'connector-edc-other',
      format: 'binary_dump',
      objectFamilies: ['source_data_index', 'unapproved_payload_family'],
      metadataOnly: false,
      payloadStoredExternally: false,
      productionTrustClaim: true,
    },
    connectorEvidence: {
      ...importControlInput().connectorEvidence,
      status: 'failing',
      mode: 'outbound',
      failClosedOnError: false,
      payloadStoredOutsideReceipt: false,
      protectedPayloadExcluded: false,
      healthCheck: {
        ...importControlInput().connectorEvidence.healthCheck,
        status: 'failing',
        statusHash: 'bad',
        rawResponseExcluded: false,
      },
    },
    schemaMapping: {
      ...importControlInput().schemaMapping,
      supportedObjectFamilies: ['source_data_index'],
      tenantPartitioningEnforced: false,
      defaultDenyUnknownFields: false,
      directIdentifiersRejected: false,
      sourcePayloadExcluded: false,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.receipt, null);
  assert.equal(denied.importManifest.status, 'blocked');
  assert.ok(denied.reasons.includes('import_connector_ref_mismatch'));
  assert.ok(denied.reasons.includes('import_format_unsupported'));
  assert.ok(denied.reasons.includes('import_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('import_payload_storage_boundary_invalid'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('import_object_family_unsupported:unapproved_payload_family'));
  assert.ok(denied.reasons.includes('connector_not_verified:connector-edc-alpha'));
  assert.ok(denied.reasons.includes('connector_mode_not_inbound:connector-edc-alpha'));
  assert.ok(denied.reasons.includes('connector_fail_closed_absent:connector-edc-alpha'));
  assert.ok(denied.reasons.includes('connector_payload_storage_boundary_invalid:connector-edc-alpha'));
  assert.ok(denied.reasons.includes('connector_protected_payload_boundary_invalid:connector-edc-alpha'));
  assert.ok(denied.reasons.includes('connector_health_not_passing:connector-edc-alpha'));
  assert.ok(denied.reasons.includes('connector_health_check_hash_invalid:connector-edc-alpha'));
  assert.ok(denied.reasons.includes('connector_health_raw_response_forbidden:connector-edc-alpha'));
  assert.ok(denied.reasons.includes('schema_family_not_supported:unapproved_payload_family'));
  assert.ok(denied.reasons.includes('schema_tenant_partitioning_absent'));
  assert.ok(denied.reasons.includes('schema_default_deny_unknown_fields_absent'));
  assert.ok(denied.reasons.includes('schema_direct_identifier_rejection_absent'));
  assert.ok(denied.reasons.includes('schema_source_payload_boundary_invalid'));
});

test('integration import controls enforce participant consent privacy HLC and human review boundaries', async () => {
  const { evaluateIntegrationImportControls } = await loadIntegrationImportControls();

  const denied = evaluateIntegrationImportControls({
    ...importControlInput(),
    importBatch: {
      ...importControlInput().importBatch,
      recordCount: 6,
      acceptedRecordCount: 5,
      rejectedRecordCount: -1,
      duplicateRecordCount: -1,
      validatedAtHlc: { physicalMs: 1799000000000, logical: 1 },
      rawPayloadExcluded: false,
      directIdentifiersExcluded: false,
    },
    validationEvidence: {
      ...importControlInput().validationEvidence,
      status: 'failed',
      requiredChecks: ['schema', 'tenant'],
      checkedAtHlc: { physicalMs: 1799000000000, logical: 4 },
      rejectedRecordsQuarantined: false,
      acceptedRecordsMetadataOnly: false,
    },
    privacyBoundary: {
      ...importControlInput().privacyBoundary,
      phiPiiExcludedFromReceipts: false,
      sourcePayloadRetainedExternally: false,
      participantConsentChecked: false,
      receiptMetadataMinimized: false,
    },
    consentBoundary: {
      ...importControlInput().consentBoundary,
      participantConsentChecked: false,
      activeConsentReceiptRefs: [],
      revokedConsentDetected: true,
      deniesRevokedConsent: false,
    },
    disclosureLog: {
      ...importControlInput().disclosureLog,
      loggedAtHlc: { physicalMs: 1799000000000, logical: 0 },
      includesRawContent: true,
    },
    humanReview: {
      ...importControlInput().humanReview,
      status: 'pending',
      reviewedAtHlc: { physicalMs: 1799000000000, logical: 3 },
      aiFinalAuthorityRejected: false,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('batch_accepted_rejected_count_mismatch'));
  assert.ok(denied.reasons.includes('batch_rejected_count_invalid'));
  assert.ok(denied.reasons.includes('batch_duplicate_count_invalid'));
  assert.ok(denied.reasons.includes('batch_validated_before_received'));
  assert.ok(denied.reasons.includes('batch_raw_payload_boundary_invalid'));
  assert.ok(denied.reasons.includes('batch_direct_identifier_boundary_invalid'));
  assert.ok(denied.reasons.includes('validation_status_not_passed'));
  assert.ok(denied.reasons.includes('validation_required_check_missing:authority'));
  assert.ok(denied.reasons.includes('validation_required_check_missing:consent'));
  assert.ok(denied.reasons.includes('validation_required_check_missing:hash'));
  assert.ok(denied.reasons.includes('validation_rejected_records_not_quarantined'));
  assert.ok(denied.reasons.includes('validation_accepted_records_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('privacy_phi_pii_receipt_boundary_invalid'));
  assert.ok(denied.reasons.includes('privacy_source_payload_boundary_invalid'));
  assert.ok(denied.reasons.includes('privacy_participant_consent_boundary_invalid'));
  assert.ok(denied.reasons.includes('privacy_receipt_metadata_minimization_absent'));
  assert.ok(denied.reasons.includes('participant_consent_check_absent'));
  assert.ok(denied.reasons.includes('active_consent_receipt_absent'));
  assert.ok(denied.reasons.includes('revoked_consent_detected'));
  assert.ok(denied.reasons.includes('revoked_consent_denial_absent'));
  assert.ok(denied.reasons.includes('disclosure_log_before_import_validation'));
  assert.ok(denied.reasons.includes('disclosure_log_raw_content_forbidden'));
  assert.ok(denied.reasons.includes('human_review_not_approved'));
  assert.ok(denied.reasons.includes('ai_final_authority_not_rejected'));
  assert.ok(denied.reasons.includes('human_review_before_validation'));
});

test('integration import controls deny tenant actor authority and custody defects', async () => {
  const { evaluateIntegrationImportControls } = await loadIntegrationImportControls();

  const denied = evaluateIntegrationImportControls({
    ...importControlInput(),
    targetTenantId: 'tenant-other',
    actor: {
      did: 'did:exo:ai-import-agent',
      kind: 'ai_agent',
    },
    authority: {
      valid: true,
      revoked: true,
      expired: false,
      permissions: ['read'],
      authorityChainHash: 'bad',
    },
    custodyDigest: 'bad',
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('import_actor_kind_invalid'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('integration_import_authority_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));

  const missingOwner = evaluateIntegrationImportControls({
    ...importControlInput(),
    actor: {
      did: 'did:exo:integration-service-alpha',
      kind: 'service_account',
    },
  });

  assert.equal(missingOwner.decision, 'denied');
  assert.ok(missingOwner.reasons.includes('service_account_human_owner_absent'));
});

test('integration import controls reject raw payloads and secret material before receipts', async () => {
  const { ProtectedContentError, evaluateIntegrationImportControls } = await loadIntegrationImportControls();

  assert.throws(
    () =>
      evaluateIntegrationImportControls({
        ...importControlInput(),
        rawImportPayload: 'Participant Alice source document payload',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateIntegrationImportControls({
        ...importControlInput(),
        connectorEvidence: {
          ...importControlInput().connectorEvidence,
          clientSecret: 'must-not-be-stored',
        },
      }),
    ProtectedContentError,
  );
});

test('integration import controls handle absent objects and inert raw markers as fail-closed metadata states', async () => {
  const { ProtectedContentError, evaluateIntegrationImportControls } = await loadIntegrationImportControls();

  const absent = evaluateIntegrationImportControls({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:system-administrator-alpha', kind: 'human' },
    authority: { valid: true, permissions: ['integration_import'], authorityChainHash: DIGEST_A },
    rawPayload: [null, false],
    connectorSecret: {},
  });

  assert.equal(absent.decision, 'denied');
  assert.equal(absent.failClosed, true);
  assert.equal(absent.receipt, null);
  assert.ok(absent.reasons.includes('import_ref_absent'));
  assert.ok(absent.reasons.includes('connector_evidence_ref_absent'));
  assert.ok(absent.reasons.includes('schema_mapping_ref_absent'));
  assert.ok(absent.reasons.includes('batch_ref_absent'));

  assert.throws(
    () =>
      evaluateIntegrationImportControls({
        ...importControlInput(),
        rawPayload: 1,
      }),
    ProtectedContentError,
  );
});
