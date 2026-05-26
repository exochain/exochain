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

import { ProtectedContentError, canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const STORAGE_SCHEMA = 'cybermedica.object_storage_readiness.v1';
const DECISION_SCHEMA = 'cybermedica.object_storage_readiness_decision.v1';
const REQUIRED_PERMISSION = 'object_storage_review';
const MAX_SIGNED_URL_TTL_SECONDS = 900;

const REQUIRED_STORAGE_DOMAINS = Object.freeze([
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
]);

const REQUIRED_ARTIFACT_CLASSES = Object.freeze([
  'controlled_documents',
  'diligence_exports',
  'evidence_payloads',
  'generated_reports',
  'sensitive_artifacts',
]);

const POLICY_STATUSES = new Set(['active']);
const DOMAIN_STATUSES = new Set(['ready']);
const HUMAN_REVIEW_DECISIONS = new Set(['hold_for_object_storage_gap', 'object_storage_ready_inactive_trust']);

const RAW_STORAGE_FIELDS = new Set([
  'body',
  'content',
  'freetext',
  'objectbody',
  'payloadbody',
  'rawartifact',
  'rawartifactbody',
  'rawbucketcontent',
  'rawobject',
  'rawobjectbody',
  'rawpayload',
  'rawpayloadbody',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_STORAGE_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'apitoken',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'kmskeysecret',
  'password',
  'privatekey',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'sessionsecret',
  'signaturesecret',
  'signingkey',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function sensitiveValuePresent(value) {
  if (value === null || value === undefined || value === false) {
    return false;
  }
  if (typeof value === 'string') {
    return value.trim().length > 0;
  }
  if (Array.isArray(value)) {
    return value.some((item) => sensitiveValuePresent(item));
  }
  if (typeof value === 'object') {
    return Object.keys(value).length > 0;
  }
  return true;
}

function assertNoStoragePayloadOrSecrets(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoStoragePayloadOrSecrets(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_STORAGE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`object storage source content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_STORAGE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`object storage secret field is not allowed at ${path}.${key}`);
    }
    assertNoStoragePayloadOrSecrets(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoStoragePayloadOrSecrets(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [BigInt(hlc.physicalMs), BigInt(hlc.logical)];
}

function compareHlc(left, right) {
  if (left[0] < right[0]) {
    return -1;
  }
  if (left[0] > right[0]) {
    return 1;
  }
  if (left[1] < right[1]) {
    return -1;
  }
  if (left[1] > right[1]) {
    return 1;
  }
  return 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function storageDomainSort(left, right) {
  return String(left.domain).localeCompare(String(right.domain));
}

function artifactClassSort(left, right) {
  return String(left.artifactClassRef).localeCompare(String(right.artifactClassRef));
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_object_storage_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'object_storage_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateStoragePolicy(policy, reasons) {
  const requiredStorageDomains = sortedTextList(policy?.requiredStorageDomains);
  const requiredArtifactClasses = sortedTextList(policy?.requiredArtifactClasses);

  addReason(reasons, !hasText(policy?.policyRef), 'object_storage_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'object_storage_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'object_storage_policy_not_active');
  addReason(reasons, policy?.encryptionAtRestRequired !== true, 'encryption_at_rest_policy_absent');
  addReason(reasons, policy?.tenantPartitioningRequired !== true, 'tenant_partitioning_policy_absent');
  addReason(reasons, policy?.directPublicAccessForbidden !== true, 'direct_public_access_policy_absent');
  addReason(reasons, policy?.objectLockRequiredForRegulatedArtifacts !== true, 'object_lock_policy_absent');
  addReason(reasons, policy?.legalHoldRequired !== true, 'legal_hold_policy_absent');
  addReason(reasons, policy?.malwareScanningRequired !== true, 'malware_scanning_policy_absent');
  addReason(reasons, policy?.receiptPayloadBoundaryRequired !== true, 'receipt_payload_boundary_policy_absent');
  addReason(reasons, policy?.externalExochainReceiptStoreRequired !== true, 'external_receipt_store_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'object_storage_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'object_storage_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'object_storage_policy_time_invalid');
  evaluateRequiredSet(
    requiredStorageDomains,
    REQUIRED_STORAGE_DOMAINS,
    'policy_storage_domain_missing',
    'policy_storage_domain_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredArtifactClasses,
    REQUIRED_ARTIFACT_CLASSES,
    'policy_artifact_class_missing',
    'policy_artifact_class_unsupported',
    reasons,
  );

  return {
    requiredArtifactClasses: requiredArtifactClasses.length > 0 ? requiredArtifactClasses : [...REQUIRED_ARTIFACT_CLASSES],
    requiredStorageDomains: requiredStorageDomains.length > 0 ? requiredStorageDomains : [...REQUIRED_STORAGE_DOMAINS],
  };
}

function evaluateReadinessCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'readiness_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'object_storage_production_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'readiness_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'readiness_cycle_protected_boundary_invalid');

  for (const [field, value] of [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['providerValidatedAtHlc', cycle?.providerValidatedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ]) {
    addReason(reasons, hlcTuple(value) === null, `readiness_cycle_time_invalid:${field}`);
  }

  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'policy_evaluated_after_cycle_opened');
  addReason(
    reasons,
    hlcBefore(cycle?.providerValidatedAtHlc, cycle?.openedAtHlc),
    'provider_validation_before_cycle_opened',
  );
  addReason(
    reasons,
    hlcBefore(cycle?.validationRecordedAtHlc, cycle?.providerValidatedAtHlc),
    'validation_before_provider_validation',
  );
  addReason(reasons, hlcBefore(cycle?.humanReviewedAtHlc, cycle?.validationRecordedAtHlc), 'human_review_before_validation');
  addReason(reasons, hlcBefore(cycle?.auditRecordedAtHlc, cycle?.humanReviewedAtHlc), 'cycle_audit_before_human_review');
}

function normalizeStorageDomains(input, requiredStorageDomains, cycle, reasons) {
  const domains = Array.isArray(input?.storageDomains) ? [...input.storageDomains].sort(storageDomainSort) : [];
  addReason(reasons, domains.length === 0, 'storage_domains_absent');
  const seen = new Set();
  const normalized = domains.map((domainRecord) => {
    const domain = hasText(domainRecord?.domain) ? domainRecord.domain : 'unknown';
    addReason(reasons, seen.has(domain), `storage_domain_duplicate:${domain}`);
    seen.add(domain);
    addReason(reasons, !REQUIRED_STORAGE_DOMAINS.includes(domain), `storage_domain_unsupported:${domain}`);
    addReason(reasons, !DOMAIN_STATUSES.has(domainRecord?.status), `storage_domain_not_ready:${domain}`);
    addReason(reasons, !hasText(domainRecord?.evidenceRef), `storage_domain_evidence_ref_absent:${domain}`);
    addReason(reasons, !isDigest(domainRecord?.evidenceHash), `storage_domain_evidence_hash_invalid:${domain}`);
    addReason(reasons, !hasText(domainRecord?.ownerDid), `storage_domain_owner_absent:${domain}`);
    addReason(reasons, !hasText(domainRecord?.reviewerDid), `storage_domain_reviewer_absent:${domain}`);
    addReason(reasons, hlcTuple(domainRecord?.reviewedAtHlc) === null, `storage_domain_review_time_invalid:${domain}`);
    addReason(
      reasons,
      hlcBefore(domainRecord?.reviewedAtHlc, cycle?.openedAtHlc),
      `storage_domain_review_before_cycle_opened:${domain}`,
    );
    addReason(reasons, domainRecord?.metadataOnly !== true, `storage_domain_metadata_boundary_invalid:${domain}`);
    addReason(reasons, domainRecord?.protectedContentExcluded !== true, `storage_domain_protected_boundary_invalid:${domain}`);
    addReason(reasons, domainRecord?.productionTrustClaim === true, `storage_domain_production_claim_forbidden:${domain}`);
    return {
      domain,
      evidenceHash: domainRecord?.evidenceHash ?? null,
      evidenceRef: domainRecord?.evidenceRef ?? null,
      status: domainRecord?.status ?? null,
    };
  });

  for (const domain of requiredStorageDomains) {
    addReason(reasons, !seen.has(domain), `storage_domain_missing:${domain}`);
  }

  return normalized;
}

function normalizeArtifactClasses(input, requiredArtifactClasses, reasons) {
  const artifactClasses = Array.isArray(input?.artifactClasses) ? [...input.artifactClasses].sort(artifactClassSort) : [];
  addReason(reasons, artifactClasses.length === 0, 'artifact_classes_absent');
  const seen = new Set();
  const normalized = artifactClasses.map((item) => {
    const artifactClassRef = hasText(item?.artifactClassRef) ? item.artifactClassRef : 'unknown';
    addReason(reasons, seen.has(artifactClassRef), `artifact_class_duplicate:${artifactClassRef}`);
    seen.add(artifactClassRef);
    addReason(reasons, !REQUIRED_ARTIFACT_CLASSES.includes(artifactClassRef), `artifact_class_unsupported:${artifactClassRef}`);
    addReason(reasons, !hasText(item?.bucketRef), `artifact_class_bucket_ref_absent:${artifactClassRef}`);
    addReason(reasons, !isDigest(item?.bucketPolicyHash), `artifact_class_bucket_policy_hash_invalid:${artifactClassRef}`);
    addReason(reasons, !isDigest(item?.tenantPrefixHash), `artifact_class_tenant_prefix_hash_invalid:${artifactClassRef}`);
    addReason(reasons, !hasText(item?.retentionPolicyRef), `artifact_class_retention_policy_ref_absent:${artifactClassRef}`);
    addReason(reasons, !isDigest(item?.retentionPolicyHash), `artifact_class_retention_policy_hash_invalid:${artifactClassRef}`);
    addReason(reasons, sortedTextList(item?.defaultSensitivityTags).length === 0, `artifact_class_sensitivity_tags_absent:${artifactClassRef}`);
    addReason(
      reasons,
      item?.rawPayloadStoredInOperationalDb === true,
      `artifact_class_raw_payload_in_operational_db:${artifactClassRef}`,
    );
    addReason(reasons, item?.receiptPayloadContainsRawContent === true, `artifact_class_raw_payload_in_receipt:${artifactClassRef}`);
    addReason(reasons, item?.directPublicUrlAllowed === true, `artifact_class_direct_public_url_allowed:${artifactClassRef}`);
    addReason(reasons, item?.objectVersioningEnabled !== true, `artifact_class_versioning_absent:${artifactClassRef}`);
    addReason(reasons, item?.objectLockEnabled !== true, `artifact_class_object_lock_absent:${artifactClassRef}`);
    addReason(reasons, item?.legalHoldSupported !== true, `artifact_class_legal_hold_absent:${artifactClassRef}`);
    addReason(reasons, item?.malwareScanRequired !== true, `artifact_class_malware_scan_absent:${artifactClassRef}`);
    addReason(reasons, item?.quarantineOnDetection !== true, `artifact_class_quarantine_absent:${artifactClassRef}`);
    addReason(reasons, item?.metadataOnly !== true, `artifact_class_metadata_boundary_invalid:${artifactClassRef}`);
    addReason(reasons, item?.protectedContentExcluded !== true, `artifact_class_protected_boundary_invalid:${artifactClassRef}`);
    return {
      artifactClassRef,
      bucketPolicyHash: item?.bucketPolicyHash ?? null,
      bucketRef: item?.bucketRef ?? null,
      directPublicUrlAllowed: item?.directPublicUrlAllowed === true,
      objectLockEnabled: item?.objectLockEnabled === true,
      rawPayloadStoredInOperationalDb: item?.rawPayloadStoredInOperationalDb === true,
      receiptPayloadContainsRawContent: item?.receiptPayloadContainsRawContent === true,
      tenantPrefixHash: item?.tenantPrefixHash ?? null,
    };
  });

  for (const artifactClassRef of requiredArtifactClasses) {
    addReason(reasons, !seen.has(artifactClassRef), `artifact_class_missing:${artifactClassRef}`);
  }

  return normalized;
}

function evaluateProviderBinding(provider, reasons) {
  addReason(reasons, !hasText(provider?.providerRef), 'provider_ref_absent');
  addReason(reasons, !isDigest(provider?.providerHash), 'provider_hash_invalid');
  addReason(reasons, !hasText(provider?.regionRef), 'provider_region_ref_absent');
  addReason(reasons, !hasText(provider?.environmentRef), 'provider_environment_ref_absent');
  addReason(reasons, !isDigest(provider?.bucketNamespaceHash), 'bucket_namespace_hash_invalid');
  addReason(reasons, !isDigest(provider?.kmsKeyPolicyHash), 'kms_key_policy_hash_invalid');
  addReason(reasons, !hasText(provider?.encryptionMode), 'provider_encryption_mode_absent');
  addReason(reasons, provider?.encryptionAtRestEnabled !== true, 'provider_encryption_at_rest_absent');
  addReason(reasons, provider?.encryptionInTransitRequired !== true, 'provider_encryption_in_transit_absent');
  addReason(reasons, provider?.tenantPrefixIsolationEnabled !== true, 'provider_tenant_partitioning_absent');
  addReason(reasons, provider?.crossTenantListDenied !== true, 'provider_cross_tenant_list_not_denied');
  addReason(reasons, provider?.directPublicUrlAllowed === true, 'provider_direct_public_url_allowed');
  addReason(
    reasons,
    !Number.isSafeInteger(provider?.signedUrlTtlSeconds) ||
      provider.signedUrlTtlSeconds <= 0 ||
      provider.signedUrlTtlSeconds > MAX_SIGNED_URL_TTL_SECONDS,
    'signed_url_ttl_exceeds_policy',
  );
  addReason(reasons, provider?.metadataOnly !== true, 'provider_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(provider?.validatedAtHlc) === null, 'provider_validated_time_invalid');
}

function evaluateAccessBoundary(boundary, reasons) {
  addReason(reasons, !isDigest(boundary?.rbacPolicyHash), 'rbac_policy_hash_invalid');
  addReason(reasons, !isDigest(boundary?.abacPolicyHash), 'abac_policy_hash_invalid');
  addReason(reasons, !isDigest(boundary?.serviceAccountPolicyHash), 'service_account_policy_hash_invalid');
  addReason(reasons, boundary?.leastPrivilegeAttested !== true, 'least_privilege_attestation_absent');
  addReason(reasons, boundary?.directIdentifierAccessSeparated !== true, 'direct_identifier_access_boundary_absent');
  addReason(reasons, !isDigest(boundary?.participantCodeBoundaryHash), 'participant_code_boundary_hash_invalid');
  addReason(reasons, !isDigest(boundary?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(
    reasons,
    boundary?.healthDebugTelemetryPayloadSuppressed !== true,
    'health_debug_telemetry_payload_suppression_absent',
  );
  addReason(reasons, boundary?.rawPayloadDownloadRequiresHumanAuthority !== true, 'raw_payload_human_authority_gate_absent');
  addReason(reasons, boundary?.metadataOnly !== true, 'access_boundary_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(boundary?.reviewedAtHlc) === null, 'access_boundary_review_time_invalid');
}

function evaluateRetentionBoundary(boundary, reasons) {
  addReason(reasons, !isDigest(boundary?.retentionMatrixHash), 'retention_matrix_hash_invalid');
  addReason(reasons, !isDigest(boundary?.legalHoldPolicyHash), 'legal_hold_policy_hash_invalid');
  addReason(reasons, !isDigest(boundary?.dispositionApprovalPolicyHash), 'disposition_approval_policy_hash_invalid');
  addReason(reasons, boundary?.versionHistoryPreserved !== true, 'version_history_preservation_absent');
  addReason(reasons, boundary?.deletionRequiresGovernance !== true, 'deletion_governance_absent');
  addReason(reasons, boundary?.holdOverridesDeletion !== true, 'legal_hold_override_absent');
  addReason(reasons, !isDigest(boundary?.auditLogHash), 'retention_audit_log_hash_invalid');
  addReason(reasons, boundary?.metadataOnly !== true, 'retention_boundary_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(boundary?.reviewedAtHlc) === null, 'retention_boundary_review_time_invalid');
}

function evaluateValidationEvidence(evidence, reasons) {
  addReason(reasons, sortedTextList(evidence?.commandRefs).length === 0, 'validation_command_refs_absent');
  addReason(reasons, evidence?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, evidence?.providerPolicyScanPassed !== true, 'provider_policy_scan_not_passed');
  addReason(reasons, evidence?.tenantIsolationTestsPassed !== true, 'tenant_isolation_tests_not_passed');
  addReason(reasons, evidence?.protectedContentScanPassed !== true, 'protected_content_scan_not_passed');
  addReason(reasons, evidence?.secretScanPassed !== true, 'secret_scan_not_passed');
  addReason(reasons, evidence?.backupRestoreDrillPassed !== true, 'backup_restore_drill_not_passed');
  addReason(reasons, evidence?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, evidence?.noExochainSourceModified !== true, 'exochain_source_modified');
  addReason(reasons, !isBasisPoints(evidence?.coverageLineBasisPoints), 'coverage_line_basis_points_invalid');
  addReason(reasons, !isDigest(evidence?.validationEvidenceHash), 'validation_evidence_hash_invalid');
  addReason(reasons, hlcTuple(evidence?.recordedAtHlc) === null, 'validation_recorded_time_invalid');
  addReason(reasons, evidence?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
}

function evaluateHumanReview(review, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, review?.decision === 'hold_for_object_storage_gap', 'object_storage_review_held');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_claim_forbidden');
  addReason(reasons, review?.finalAuthority !== 'human' || review?.aiFinalAuthority === true, 'human_review_ai_final_authority_forbidden');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
}

function evaluateAuditRecord(record, humanReview, reasons) {
  addReason(reasons, !isDigest(record?.auditRecordHash), 'audit_record_hash_invalid');
  addReason(reasons, !isDigest(record?.previousAuditRecordHash), 'previous_audit_record_hash_invalid');
  addReason(reasons, !isDigest(record?.operationalLogHash), 'operational_log_hash_invalid');
  addReason(reasons, record?.immutableReceiptRequested === true, 'immutable_receipt_requested_before_external_exochain_activation');
  addReason(reasons, !hasText(record?.externalReceiptStoreRef), 'external_receipt_store_ref_absent');
  addReason(reasons, hlcTuple(record?.receiptRecordedAtHlc) === null, 'receipt_recorded_time_invalid');
  addReason(reasons, hlcBefore(record?.receiptRecordedAtHlc, humanReview?.reviewedAtHlc), 'audit_record_before_human_review');
  addReason(reasons, record?.metadataOnly !== true, 'audit_record_metadata_boundary_invalid');
  addReason(reasons, record?.protectedContentExcluded !== true, 'audit_record_protected_boundary_invalid');
}

function buildReadiness(input, policyShape, storageDomains, artifactClasses) {
  const readiness = {
    schema: STORAGE_SCHEMA,
    artifactClasses,
    directPublicAccessAllowed:
      input?.providerBinding?.directPublicUrlAllowed === true ||
      artifactClasses.some((item) => item.directPublicUrlAllowed === true),
    domainCoverageBasisPoints: basisPoints(
      storageDomains.filter((domain) => domain.status === 'ready' && REQUIRED_STORAGE_DOMAINS.includes(domain.domain)).length,
      REQUIRED_STORAGE_DOMAINS.length,
    ),
    encryptionAtRestVerified: input?.providerBinding?.encryptionAtRestEnabled === true,
    externalReceiptStoreRequired:
      input?.storagePolicy?.externalExochainReceiptStoreRequired === true && hasText(input?.auditRecord?.externalReceiptStoreRef),
    objectStorageHash: null,
    productionTrustClaim: false,
    providerRef: input?.providerBinding?.providerRef ?? null,
    rawPayloadsExcludedFromOperationalDb: artifactClasses.every((item) => item.rawPayloadStoredInOperationalDb === false),
    rawPayloadsExcludedFromReceipts: artifactClasses.every((item) => item.receiptPayloadContainsRawContent === false),
    requiredArtifactClasses: policyShape.requiredArtifactClasses,
    requiredStorageDomains: policyShape.requiredStorageDomains,
    status: input?.humanReview?.decision ?? 'object_storage_ready_inactive_trust',
    storageDomains,
    tenantPartitioningVerified:
      input?.providerBinding?.tenantPrefixIsolationEnabled === true && input?.providerBinding?.crossTenantListDenied === true,
    trustState: 'inactive',
  };
  readiness.objectStorageHash = sha256Hex({
    artifactClasses: readiness.artifactClasses,
    providerRef: readiness.providerRef,
    requiredArtifactClasses: readiness.requiredArtifactClasses,
    schema: STORAGE_SCHEMA,
    storageDomains: readiness.storageDomains,
    tenantId: input?.tenantId ?? null,
  });
  return readiness;
}

function buildReceipt(input, objectStorageReadiness) {
  return createEvidenceReceipt({
    actorDid: input?.actor?.did ?? 'unknown',
    artifactHash: objectStorageReadiness.objectStorageHash,
    artifactType: 'object_storage_readiness',
    artifactVersion: input?.readinessCycle?.cycleRef ?? 'unknown',
    classification: 'qms_metadata_only',
    custodyDigest: input?.custodyDigest,
    hlcTimestamp: input?.auditRecord?.receiptRecordedAtHlc ?? input?.readinessCycle?.auditRecordedAtHlc ?? {
      logical: 0,
      physicalMs: 0,
    },
    sensitivityTags: ['metadata_only', 'object_storage_boundary', 'no_payload_content'],
    sourceSystem: input?.providerBinding?.providerRef ?? 'cybermedica-object-storage-readiness',
    tenantId: input?.tenantId ?? 'unknown',
  });
}

export function evaluateObjectStorageReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policyShape = evaluateStoragePolicy(input?.storagePolicy, reasons);
  evaluateReadinessCycle(input?.readinessCycle, input?.storagePolicy, reasons);
  const storageDomains = normalizeStorageDomains(input, policyShape.requiredStorageDomains, input?.readinessCycle, reasons);
  const artifactClasses = normalizeArtifactClasses(input, policyShape.requiredArtifactClasses, reasons);
  evaluateProviderBinding(input?.providerBinding, reasons);
  evaluateAccessBoundary(input?.accessBoundary, reasons);
  evaluateRetentionBoundary(input?.retentionBoundary, reasons);
  evaluateValidationEvidence(input?.validationEvidence, reasons);
  evaluateHumanReview(input?.humanReview, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.humanReview, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const finalReasons = uniqueReasons(reasons);
  if (finalReasons.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      objectStorageReadiness: null,
      reasons: finalReasons,
      receipt: null,
    };
  }

  const objectStorageReadiness = buildReadiness(input, policyShape, storageDomains, artifactClasses);
  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    objectStorageReadiness,
    reasons: [],
    receipt: buildReceipt(input, objectStorageReadiness),
  };
}
