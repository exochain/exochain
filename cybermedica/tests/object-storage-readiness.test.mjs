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

const REQUIRED_STORAGE_DOMAINS = [
  'access_policy',
  'audit_disclosure_logging',
  'backup_replication',
  'encryption_at_rest',
  'malware_quarantine',
  'object_lock_legal_hold',
  'provider_binding',
  'receipt_separation',
  'retention_disposition',
  'tenant_partitioning',
  'versioning_integrity',
];

const REQUIRED_ARTIFACT_CLASSES = [
  'controlled_documents',
  'diligence_exports',
  'evidence_payloads',
  'generated_reports',
  'sensitive_artifacts',
];

async function loadObjectStorageReadiness() {
  try {
    return await import('../src/object-storage-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica object storage readiness module must exist and load: ${error.message}`);
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

function storageDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5];
  return {
    domain,
    status: 'ready',
    evidenceRef: `object-storage-evidence-${domain}`,
    evidenceHash: hashes[index],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner`,
    reviewerDid: `did:exo:${domain.replaceAll('_', '-')}-reviewer`,
    reviewedAtHlc: { physicalMs: 1800010100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function storageDomains() {
  return REQUIRED_STORAGE_DOMAINS.map((domain, index) => storageDomain(domain, index));
}

function artifactClass(artifactClassRef, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E];
  return {
    artifactClassRef,
    bucketRef: `cm-${artifactClassRef.replaceAll('_', '-')}-bucket`,
    bucketPolicyHash: hashes[index],
    tenantPrefixHash: [DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4][index],
    retentionPolicyRef: `retention-${artifactClassRef}`,
    retentionPolicyHash: [DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8, DIGEST_A][index],
    defaultSensitivityTags: ['metadata_only', artifactClassRef],
    rawPayloadStoredInOperationalDb: false,
    receiptPayloadContainsRawContent: false,
    directPublicUrlAllowed: false,
    objectVersioningEnabled: true,
    objectLockEnabled: true,
    legalHoldSupported: true,
    malwareScanRequired: true,
    quarantineOnDetection: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function artifactClasses() {
  return REQUIRED_ARTIFACT_CLASSES.map((artifactClassRef, index) => artifactClass(artifactClassRef, index));
}

function readinessInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:object-storage-owner-alpha',
      kind: 'human',
      roleRefs: ['deployment_owner', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['object_storage_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    storagePolicy: {
      policyRef: 'object-storage-readiness-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredStorageDomains: REQUIRED_STORAGE_DOMAINS,
      requiredArtifactClasses: REQUIRED_ARTIFACT_CLASSES,
      encryptionAtRestRequired: true,
      tenantPartitioningRequired: true,
      directPublicAccessForbidden: true,
      objectLockRequiredForRegulatedArtifacts: true,
      legalHoldRequired: true,
      malwareScanningRequired: true,
      receiptPayloadBoundaryRequired: true,
      externalExochainReceiptStoreRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800009900000, logical: 0 },
    },
    readinessCycle: {
      cycleRef: 'object-storage-readiness-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800009950000, logical: 0 },
      providerValidatedAtHlc: { physicalMs: 1800010100000, logical: 11 },
      validationRecordedAtHlc: { physicalMs: 1800010200000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800010300000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800010400000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    storageDomains: storageDomains(),
    artifactClasses: artifactClasses(),
    providerBinding: {
      providerRef: 'encrypted-object-storage-provider-alpha',
      providerHash: DIGEST_C,
      regionRef: 'regulated-us-region-alpha',
      environmentRef: 'customer-zero-internal',
      bucketNamespaceHash: DIGEST_D,
      kmsKeyPolicyHash: DIGEST_E,
      encryptionMode: 'customer_managed_key',
      encryptionAtRestEnabled: true,
      encryptionInTransitRequired: true,
      tenantPrefixIsolationEnabled: true,
      crossTenantListDenied: true,
      directPublicUrlAllowed: false,
      signedUrlTtlSeconds: 900,
      metadataOnly: true,
      validatedAtHlc: { physicalMs: 1800010100000, logical: 11 },
    },
    accessBoundary: {
      rbacPolicyHash: DIGEST_F,
      abacPolicyHash: DIGEST_1,
      serviceAccountPolicyHash: DIGEST_2,
      leastPrivilegeAttested: true,
      directIdentifierAccessSeparated: true,
      participantCodeBoundaryHash: DIGEST_3,
      disclosureLogHash: DIGEST_4,
      healthDebugTelemetryPayloadSuppressed: true,
      rawPayloadDownloadRequiresHumanAuthority: true,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800010100000, logical: 12 },
    },
    retentionBoundary: {
      retentionMatrixHash: DIGEST_5,
      legalHoldPolicyHash: DIGEST_6,
      dispositionApprovalPolicyHash: DIGEST_7,
      versionHistoryPreserved: true,
      deletionRequiresGovernance: true,
      holdOverridesDeletion: true,
      auditLogHash: DIGEST_8,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800010100000, logical: 13 },
    },
    validationEvidence: {
      commandRefs: ['node --test tests/object-storage-readiness.test.mjs', 'npm run quality'],
      commandsPassed: true,
      providerPolicyScanPassed: true,
      tenantIsolationTestsPassed: true,
      protectedContentScanPassed: true,
      secretScanPassed: true,
      backupRestoreDrillPassed: true,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      coverageLineBasisPoints: 9970,
      validationEvidenceHash: DIGEST_A,
      recordedAtHlc: { physicalMs: 1800010200000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:site-quality-leader-alpha',
      reviewerRoleRefs: ['quality_manager', 'deployment_owner'],
      decision: 'object_storage_ready_inactive_trust',
      decisionHash: DIGEST_B,
      noProductionTrustClaim: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800010300000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordHash: DIGEST_C,
      previousAuditRecordHash: DIGEST_D,
      operationalLogHash: DIGEST_E,
      immutableReceiptRequested: false,
      externalReceiptStoreRef: 'external-exochain-receipt-store-alpha',
      receiptRecordedAtHlc: { physicalMs: 1800010400000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    custodyDigest: DIGEST_F,
  };

  return mergeDeep(base, overrides);
}

test('object storage readiness module loads', async () => {
  const module = await loadObjectStorageReadiness();

  assert.equal(typeof module.evaluateObjectStorageReadiness, 'function');
});

test('permits deterministic inactive metadata-only encrypted object storage readiness', async () => {
  const { evaluateObjectStorageReadiness } = await loadObjectStorageReadiness();

  const resultA = evaluateObjectStorageReadiness(readinessInput());
  const resultB = evaluateObjectStorageReadiness(
    readinessInput({
      storageDomains: [...storageDomains()].reverse(),
      artifactClasses: [...artifactClasses()].reverse(),
      humanReview: {
        reviewerRoleRefs: ['deployment_owner', 'quality_manager'],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.objectStorageReadiness.status, 'object_storage_ready_inactive_trust');
  assert.equal(resultA.objectStorageReadiness.domainCoverageBasisPoints, 10000);
  assert.deepEqual(resultA.objectStorageReadiness.requiredArtifactClasses, REQUIRED_ARTIFACT_CLASSES);
  assert.equal(resultA.objectStorageReadiness.providerRef, 'encrypted-object-storage-provider-alpha');
  assert.equal(resultA.objectStorageReadiness.encryptionAtRestVerified, true);
  assert.equal(resultA.objectStorageReadiness.tenantPartitioningVerified, true);
  assert.equal(resultA.objectStorageReadiness.externalReceiptStoreRequired, true);
  assert.equal(resultA.objectStorageReadiness.rawPayloadsExcludedFromOperationalDb, true);
  assert.equal(resultA.objectStorageReadiness.rawPayloadsExcludedFromReceipts, true);
  assert.equal(resultA.objectStorageReadiness.directPublicAccessAllowed, false);
  assert.equal(resultA.objectStorageReadiness.productionTrustClaim, false);
  assert.equal(resultA.objectStorageReadiness.objectStorageHash, resultB.objectStorageReadiness.objectStorageHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'object_storage_readiness');
  assert.equal(resultA.receipt.anchorPayload.custodyDigest, DIGEST_F);
  assert.doesNotMatch(JSON.stringify(resultA), /source document body|patient alice|raw payload|secret value/iu);
});

test('object storage readiness fails closed for missing storage domains and unsafe storage boundaries', async () => {
  const { evaluateObjectStorageReadiness } = await loadObjectStorageReadiness();

  const denied = evaluateObjectStorageReadiness(
    readinessInput({
      targetTenantId: 'tenant-site-beta',
      authority: {
        valid: true,
        revoked: true,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      storageDomains: storageDomains().filter((domain) => domain.domain !== 'object_lock_legal_hold'),
      artifactClasses: artifactClasses().map((item) =>
        item.artifactClassRef === 'evidence_payloads'
          ? {
              ...item,
              rawPayloadStoredInOperationalDb: true,
              receiptPayloadContainsRawContent: true,
              directPublicUrlAllowed: true,
              objectLockEnabled: false,
              legalHoldSupported: false,
              malwareScanRequired: false,
            }
          : item,
      ),
      providerBinding: {
        encryptionAtRestEnabled: false,
        tenantPrefixIsolationEnabled: false,
        crossTenantListDenied: false,
        directPublicUrlAllowed: true,
        signedUrlTtlSeconds: 7200,
      },
      accessBoundary: {
        leastPrivilegeAttested: false,
        healthDebugTelemetryPayloadSuppressed: false,
        rawPayloadDownloadRequiresHumanAuthority: false,
      },
      auditRecord: {
        externalReceiptStoreRef: '',
        immutableReceiptRequested: true,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('object_storage_authority_missing'));
  assert.ok(denied.reasons.includes('storage_domain_missing:object_lock_legal_hold'));
  assert.ok(denied.reasons.includes('provider_encryption_at_rest_absent'));
  assert.ok(denied.reasons.includes('provider_tenant_partitioning_absent'));
  assert.ok(denied.reasons.includes('provider_cross_tenant_list_not_denied'));
  assert.ok(denied.reasons.includes('provider_direct_public_url_allowed'));
  assert.ok(denied.reasons.includes('signed_url_ttl_exceeds_policy'));
  assert.ok(denied.reasons.includes('artifact_class_raw_payload_in_operational_db:evidence_payloads'));
  assert.ok(denied.reasons.includes('artifact_class_raw_payload_in_receipt:evidence_payloads'));
  assert.ok(denied.reasons.includes('artifact_class_direct_public_url_allowed:evidence_payloads'));
  assert.ok(denied.reasons.includes('artifact_class_object_lock_absent:evidence_payloads'));
  assert.ok(denied.reasons.includes('artifact_class_legal_hold_absent:evidence_payloads'));
  assert.ok(denied.reasons.includes('artifact_class_malware_scan_absent:evidence_payloads'));
  assert.ok(denied.reasons.includes('least_privilege_attestation_absent'));
  assert.ok(denied.reasons.includes('health_debug_telemetry_payload_suppression_absent'));
  assert.ok(denied.reasons.includes('raw_payload_human_authority_gate_absent'));
  assert.ok(denied.reasons.includes('external_receipt_store_ref_absent'));
  assert.ok(denied.reasons.includes('immutable_receipt_requested_before_external_exochain_activation'));
  assert.equal(denied.objectStorageReadiness, null);
  assert.equal(denied.receipt, null);
});

test('object storage readiness validates HLC ordering and human final authority', async () => {
  const { evaluateObjectStorageReadiness } = await loadObjectStorageReadiness();

  const denied = evaluateObjectStorageReadiness(
    readinessInput({
      actor: {
        did: 'did:exo:object-storage-ai-reviewer',
        kind: 'ai_agent',
        roleRefs: ['quality_assistant'],
      },
      storagePolicy: {
        evaluatedAtHlc: { physicalMs: 1800010500000, logical: 0 },
      },
      readinessCycle: {
        openedAtHlc: { physicalMs: 1800010000000, logical: 0 },
        providerValidatedAtHlc: { physicalMs: 1800009900000, logical: 0 },
        validationRecordedAtHlc: { physicalMs: 1800009890000, logical: 0 },
        humanReviewedAtHlc: { physicalMs: 1800009960000, logical: 0 },
        auditRecordedAtHlc: { physicalMs: 1800009970000, logical: 0 },
      },
      storageDomains: storageDomains().map((domain) => ({
        ...domain,
        reviewedAtHlc: { physicalMs: 1800009900000, logical: 0 },
      })),
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        reviewedAtHlc: { physicalMs: 1800009960000, logical: 0 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1800009950000, logical: 0 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_object_storage_reviewer_required'));
  assert.ok(denied.reasons.includes('policy_evaluated_after_cycle_opened'));
  assert.ok(denied.reasons.includes('provider_validation_before_cycle_opened'));
  assert.ok(denied.reasons.includes('validation_before_provider_validation'));
  assert.ok(denied.reasons.includes('storage_domain_review_before_cycle_opened:access_policy'));
  assert.ok(denied.reasons.includes('human_review_ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('audit_record_before_human_review'));
});

test('object storage readiness rejects raw artifacts and secret-bearing storage records', async () => {
  const { ProtectedContentError, evaluateObjectStorageReadiness } = await loadObjectStorageReadiness();

  assert.throws(
    () =>
      evaluateObjectStorageReadiness(
        readinessInput({
          artifactClasses: [
            ...artifactClasses(),
            {
              artifactClassRef: 'unsafe_artifact',
              rawObjectBody: 'participant Alice source document body',
            },
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateObjectStorageReadiness(
        readinessInput({
          providerBinding: {
            accessToken: 'secret value',
          },
        }),
      ),
    ProtectedContentError,
  );
});
