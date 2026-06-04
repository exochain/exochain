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
const MIGRATION_SCHEMA = 'cybermedica.database_migration_readiness.v1';
const DECISION_SCHEMA = 'cybermedica.database_migration_readiness_decision.v1';
const REQUIRED_PERMISSION = 'database_migration_review';

const REQUIRED_MIGRATION_DOMAINS = Object.freeze([
  'access_policy',
  'backup_restore',
  'change_control',
  'data_classification',
  'migration_ordering',
  'operational_receipt_separation',
  'schema_plan',
  'tenant_isolation',
  'validation',
]);

const REQUIRED_OBJECT_STORAGE_ARTIFACT_CLASSES = Object.freeze([
  'controlled_documents',
  'diligence_exports',
  'evidence_payloads',
  'generated_reports',
  'sensitive_artifacts',
]);

const POLICY_STATUSES = new Set(['active']);
const DOMAIN_STATUSES = new Set(['ready']);
const HUMAN_REVIEW_DECISIONS = new Set(['hold_for_migration_gap', 'migration_ready_inactive_trust']);
const MIGRATION_DIRECTIONS = new Set(['down', 'up']);

const RAW_MIGRATION_FIELDS = new Set([
  'body',
  'content',
  'freetext',
  'migrationbody',
  'migrationnotes',
  'rawdatabasecontent',
  'rawmigrationcontent',
  'rawmigrationlog',
  'rawmigrationnotes',
  'rawschema',
  'rawschemadiff',
  'rawsql',
  'rawvalidationoutput',
  'reviewnotes',
  'sql',
  'sqlbody',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_MIGRATION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'connectionstring',
  'credential',
  'credentialsecret',
  'databasepassword',
  'dbpassword',
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

function assertNoRawMigrationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawMigrationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_MIGRATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw database migration content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_MIGRATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`database migration secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawMigrationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawMigrationContent(input ?? {});
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

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlc(left, right) {
  if (left[0] !== right[0]) {
    return left[0] < right[0] ? -1 : 1;
  }
  if (left[1] !== right[1]) {
    return left[1] < right[1] ? -1 : 1;
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

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_database_migration_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'database_migration_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateMigrationPolicy(policy, reasons) {
  const requiredMigrationDomains = sortedTextList(policy?.requiredMigrationDomains);

  addReason(reasons, !hasText(policy?.policyRef), 'migration_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'migration_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'migration_policy_not_active');
  addReason(reasons, policy?.mutableOperationalStateRequired !== true, 'mutable_operational_state_policy_absent');
  addReason(reasons, policy?.exochainReceiptMutationForbidden !== true, 'receipt_mutation_policy_absent');
  addReason(reasons, policy?.objectStorageForRawArtifactsRequired !== true, 'object_storage_boundary_policy_absent');
  addReason(reasons, policy?.tenantIsolationRequired !== true, 'tenant_isolation_policy_absent');
  addReason(reasons, policy?.rootVerificationRequiredForTrustClaims !== true, 'root_verification_gate_absent');
  addReason(reasons, policy?.noCredentialDisclosure !== true, 'credential_disclosure_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'migration_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'migration_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'migration_policy_time_invalid');
  evaluateRequiredSet(
    requiredMigrationDomains,
    REQUIRED_MIGRATION_DOMAINS,
    'policy_migration_domain_missing',
    'policy_migration_domain_unsupported',
    reasons,
  );

  return {
    requiredMigrationDomains:
      requiredMigrationDomains.length > 0 ? requiredMigrationDomains : [...REQUIRED_MIGRATION_DOMAINS],
  };
}

function evaluateMigrationCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.migrationRef), 'migration_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'migration_cycle_production_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'migration_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'migration_cycle_protected_boundary_invalid');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['planLockedAtHlc', cycle?.planLockedAtHlc],
    ['backupVerifiedAtHlc', cycle?.backupVerifiedAtHlc],
    ['dryRunCompletedAtHlc', cycle?.dryRunCompletedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `migration_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'migration_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(
      reasons,
      hlcBefore(currentValue, previousValue),
      `migration_cycle_${currentLabel}_before_${previousLabel}`,
    );
  }
}

function evaluateMigrationDomains(domains, policySummary, cycle, reasons) {
  addReason(reasons, !Array.isArray(domains) || domains.length === 0, 'migration_domains_absent');
  if (!Array.isArray(domains)) {
    return [];
  }

  const domainNames = sortedTextList(domains.map((domain) => domain?.domain));
  const seenDomains = new Set();

  evaluateRequiredSet(
    domainNames,
    policySummary.requiredMigrationDomains,
    'migration_domain_missing',
    'migration_domain_unsupported',
    reasons,
  );

  domains.forEach((domain, index) => {
    const label = hasText(domain?.domain) ? domain.domain : `index_${index}`;
    addReason(reasons, !hasText(domain?.domain), `migration_domain_absent:${label}`);
    addReason(reasons, seenDomains.has(domain?.domain), `migration_domain_duplicate:${label}`);
    if (hasText(domain?.domain)) {
      seenDomains.add(domain.domain);
    }
    addReason(reasons, !policySummary.requiredMigrationDomains.includes(domain?.domain), `migration_domain_invalid:${label}`);
    addReason(reasons, !DOMAIN_STATUSES.has(domain?.status), `migration_domain_status_invalid:${label}`);
    addReason(reasons, !hasText(domain?.evidenceRef), `migration_domain_evidence_ref_absent:${label}`);
    addReason(reasons, !isDigest(domain?.evidenceHash), `migration_domain_evidence_hash_invalid:${label}`);
    addReason(reasons, !hasText(domain?.ownerDid), `migration_domain_owner_absent:${label}`);
    addReason(reasons, !hasText(domain?.reviewerDid), `migration_domain_reviewer_absent:${label}`);
    addReason(reasons, domain?.metadataOnly !== true, `migration_domain_metadata_boundary_invalid:${label}`);
    addReason(reasons, domain?.protectedContentExcluded !== true, `migration_domain_protected_boundary_invalid:${label}`);
    addReason(reasons, domain?.productionTrustClaim === true, `migration_domain_production_claim_forbidden:${label}`);
    addReason(reasons, hlcTuple(domain?.reviewedAtHlc) === null, `migration_domain_review_time_invalid:${label}`);
    addReason(reasons, hlcBefore(domain?.reviewedAtHlc, cycle?.planLockedAtHlc), `migration_domain_review_before_plan:${label}`);
  });

  return domainNames;
}

function migrationLabel(migration, index) {
  return hasText(migration?.migrationId) ? migration.migrationId : `index_${index}`;
}

function evaluateSchemaMigrations(migrations, cycle, reasons) {
  addReason(reasons, !Array.isArray(migrations) || migrations.length === 0, 'schema_migrations_absent');
  if (!Array.isArray(migrations)) {
    return { migrationSequences: [], migrationSummaries: [], schemaVersionFrom: null, schemaVersionTo: null };
  }

  const sortedMigrations = [...migrations].sort((left, right) => {
    if (left?.sequence !== right?.sequence) {
      return (left?.sequence ?? 0) - (right?.sequence ?? 0);
    }
    return String(left?.migrationId ?? '').localeCompare(String(right?.migrationId ?? ''));
  });
  const seenIds = new Set();
  const seenSequences = new Set();
  let previousVersionTo = null;

  sortedMigrations.forEach((migration, index) => {
    const label = migrationLabel(migration, index);
    addReason(reasons, !hasText(migration?.migrationId), `migration_id_absent:${label}`);
    addReason(reasons, seenIds.has(migration?.migrationId), `migration_id_duplicate:${label}`);
    if (hasText(migration?.migrationId)) {
      seenIds.add(migration.migrationId);
    }
    addReason(
      reasons,
      !Number.isSafeInteger(migration?.sequence) || migration.sequence <= 0,
      `migration_sequence_invalid:${label}`,
    );
    addReason(reasons, seenSequences.has(migration?.sequence), `migration_sequence_duplicate:${label}`);
    if (Number.isSafeInteger(migration?.sequence)) {
      seenSequences.add(migration.sequence);
    }
    addReason(reasons, migration?.sequence !== index + 1, 'migration_sequence_gap_or_order_invalid');
    addReason(reasons, !isDigest(migration?.migrationHash), `migration_hash_invalid:${label}`);
    addReason(reasons, !isDigest(migration?.checksumHash), `migration_checksum_hash_invalid:${label}`);
    addReason(
      reasons,
      !Number.isSafeInteger(migration?.schemaVersionFrom) || migration.schemaVersionFrom < 0,
      `migration_schema_from_invalid:${label}`,
    );
    addReason(
      reasons,
      !Number.isSafeInteger(migration?.schemaVersionTo) || migration.schemaVersionTo <= migration?.schemaVersionFrom,
      `migration_schema_to_invalid:${label}`,
    );
    addReason(
      reasons,
      previousVersionTo !== null && migration?.schemaVersionFrom !== previousVersionTo,
      `migration_schema_chain_broken:${label}`,
    );
    if (Number.isSafeInteger(migration?.schemaVersionTo)) {
      previousVersionTo = migration.schemaVersionTo;
    }
    addReason(reasons, !MIGRATION_DIRECTIONS.has(migration?.direction), `migration_direction_invalid:${label}`);
    addReason(reasons, migration?.reversible !== true, `migration_reversibility_absent:${label}`);
    addReason(
      reasons,
      migration?.destructiveChange === true && !isDigest(migration?.destructiveChangeApprovalHash),
      `destructive_change_without_approval:${label}`,
    );
    addReason(reasons, migration?.tenantScoped !== true, `migration_tenant_scope_absent:${label}`);
    addReason(reasons, !hasText(migration?.tenantPartitionKey), `migration_tenant_partition_key_absent:${label}`);
    addReason(
      reasons,
      migration?.touchesSensitiveTables === true && !isDigest(migration?.dataClassificationMappingHash),
      `sensitive_migration_classification_hash_invalid:${label}`,
    );
    addReason(
      reasons,
      migration?.touchesSensitiveTables === true && migration?.directIdentifierColumnsEncrypted !== true,
      `sensitive_migration_identifier_encryption_absent:${label}`,
    );
    addReason(
      reasons,
      migration?.touchesSensitiveTables === true && migration?.participantIdentitySeparated !== true,
      `sensitive_migration_identity_separation_absent:${label}`,
    );
    addReason(
      reasons,
      migration?.evidencePayloadStoredOutsideDb !== true,
      `migration_evidence_payload_boundary_invalid:${label}`,
    );
    addReason(reasons, migration?.operationalStateMutable !== true, `migration_mutable_state_boundary_invalid:${label}`);
    addReason(
      reasons,
      migration?.exochainReceiptMutation === true,
      `migration_exochain_receipt_mutation_forbidden:${label}`,
    );
    addReason(reasons, migration?.usesSystemTime === true, `migration_system_time_forbidden:${label}`);
    addReason(reasons, migration?.usesRandomness === true, `migration_randomness_forbidden:${label}`);
    addReason(reasons, migration?.usesFloatingPoint === true, `migration_floating_point_forbidden:${label}`);
    addReason(reasons, migration?.metadataOnly !== true, `migration_metadata_boundary_invalid:${label}`);
    addReason(reasons, migration?.protectedContentExcluded !== true, `migration_protected_boundary_invalid:${label}`);
    addReason(reasons, hlcTuple(migration?.reviewedAtHlc) === null, `migration_review_time_invalid:${label}`);
    addReason(reasons, hlcBefore(migration?.reviewedAtHlc, cycle?.planLockedAtHlc), `migration_review_before_plan:${label}`);
  });

  return {
    migrationSequences: sortedMigrations.map((migration) => migration.sequence).filter(Number.isSafeInteger),
    migrationSummaries: sortedMigrations.map((migration, index) => ({
      checksumHash: migration?.checksumHash ?? null,
      migrationHash: migration?.migrationHash ?? null,
      migrationId: migrationLabel(migration, index),
      schemaVersionFrom: migration?.schemaVersionFrom ?? null,
      schemaVersionTo: migration?.schemaVersionTo ?? null,
      sequence: migration?.sequence ?? null,
      tenantScoped: migration?.tenantScoped === true,
      touchesSensitiveTables: migration?.touchesSensitiveTables === true,
    })),
    schemaVersionFrom: sortedMigrations[0]?.schemaVersionFrom ?? null,
    schemaVersionTo: sortedMigrations.at(-1)?.schemaVersionTo ?? null,
  };
}

function evaluateDataBoundary(boundary, cycle, reasons) {
  addReason(reasons, boundary === null || boundary === undefined, 'data_boundary_absent');
  addReason(reasons, !hasText(boundary?.operationalDatabaseRef), 'operational_database_ref_absent');
  addReason(reasons, !isDigest(boundary?.operationalDatabaseHash), 'operational_database_hash_invalid');
  addReason(reasons, !hasText(boundary?.migrationToolRef), 'migration_tool_ref_absent');
  addReason(
    reasons,
    sortedTextList(boundary?.mutableStateTableRefs).length === 0,
    'mutable_state_table_refs_absent',
  );
  addReason(reasons, !isDigest(boundary?.tenantPartitionPolicyHash), 'tenant_partition_policy_hash_invalid');
  addReason(reasons, !isDigest(boundary?.rowLevelSecurityPolicyHash), 'row_level_security_policy_hash_invalid');
  addReason(
    reasons,
    !isDigest(boundary?.directIdentifierEncryptionPolicyHash),
    'direct_identifier_encryption_policy_hash_invalid',
  );
  addReason(reasons, !isDigest(boundary?.objectStorageBoundaryHash), 'object_storage_boundary_hash_invalid');
  addReason(reasons, boundary?.exochainReceiptStoreExternal !== true, 'exochain_receipt_store_must_be_external');
  addReason(reasons, boundary?.evidencePayloadStoredOutsideDb !== true, 'evidence_payload_db_storage_forbidden');
  addReason(reasons, !hasText(boundary?.rawArtifactStorageRef), 'raw_artifact_storage_ref_absent');
  addReason(reasons, boundary?.directIdentifierColumnsEncrypted !== true, 'direct_identifier_encryption_absent');
  addReason(reasons, boundary?.participantIdentitySeparated !== true, 'participant_identity_separation_absent');
  addReason(reasons, boundary?.operationalStateMutable !== true, 'operational_state_mutability_absent');
  addReason(reasons, boundary?.productionTrustClaim === true, 'data_boundary_production_claim_forbidden');
  addReason(reasons, boundary?.metadataOnly !== true, 'data_boundary_metadata_boundary_invalid');
  addReason(reasons, boundary?.protectedContentExcluded !== true, 'data_boundary_protected_boundary_invalid');
  addReason(reasons, hlcTuple(boundary?.reviewedAtHlc) === null, 'data_boundary_review_time_invalid');
  addReason(reasons, hlcBefore(boundary?.reviewedAtHlc, cycle?.planLockedAtHlc), 'data_boundary_review_before_plan');

  return {
    directIdentifierColumnsEncrypted: boundary?.directIdentifierColumnsEncrypted === true,
    evidencePayloadStoredOutsideDb: boundary?.evidencePayloadStoredOutsideDb === true,
    exochainReceiptStoreExternal: boundary?.exochainReceiptStoreExternal === true,
    mutableStateTableRefs: sortedTextList(boundary?.mutableStateTableRefs),
    operationalDatabaseHash: boundary?.operationalDatabaseHash ?? null,
    operationalDatabaseRef: boundary?.operationalDatabaseRef ?? null,
    participantIdentitySeparated: boundary?.participantIdentitySeparated === true,
    rawArtifactStorageRef: boundary?.rawArtifactStorageRef ?? null,
  };
}

function evaluateObjectStorageReadinessEvidence(evidence, dataBoundary, cycle, reasons) {
  addReason(reasons, evidence === null || evidence === undefined, 'object_storage_readiness_evidence_absent');
  addReason(
    reasons,
    evidence?.schema !== 'cybermedica.object_storage_readiness.v1',
    'object_storage_readiness_schema_invalid',
  );
  addReason(
    reasons,
    !isDigest(evidence?.objectStorageReadinessReceiptHash),
    'object_storage_readiness_receipt_hash_invalid',
  );
  addReason(reasons, !isDigest(evidence?.objectStorageReadinessHash), 'object_storage_readiness_hash_invalid');
  addReason(reasons, !isDigest(evidence?.objectStorageBoundaryHash), 'object_storage_boundary_lineage_hash_invalid');
  addReason(
    reasons,
    isDigest(evidence?.objectStorageBoundaryHash) &&
      isDigest(dataBoundary?.objectStorageBoundaryHash) &&
      evidence.objectStorageBoundaryHash !== dataBoundary.objectStorageBoundaryHash,
    'object_storage_boundary_lineage_mismatch',
  );
  addReason(reasons, !hasText(evidence?.providerRef), 'object_storage_provider_ref_absent');
  addReason(
    reasons,
    evidence?.status !== 'object_storage_ready_inactive_trust',
    'object_storage_readiness_status_invalid',
  );
  addReason(reasons, evidence?.trustState !== 'inactive', 'object_storage_trust_state_not_inactive');
  addReason(reasons, evidence?.externalReceiptStoreRequired !== true, 'object_storage_external_receipt_store_absent');
  addReason(
    reasons,
    evidence?.rawPayloadsExcludedFromOperationalDb !== true,
    'object_storage_raw_payload_db_boundary_absent',
  );
  addReason(
    reasons,
    evidence?.rawPayloadsExcludedFromReceipts !== true,
    'object_storage_raw_payload_receipt_boundary_absent',
  );
  addReason(reasons, evidence?.directPublicAccessAllowed === true, 'object_storage_direct_public_access_allowed');
  addReason(reasons, evidence?.metadataOnly !== true, 'object_storage_readiness_metadata_boundary_invalid');
  addReason(reasons, evidence?.protectedContentExcluded !== true, 'object_storage_readiness_protected_boundary_invalid');
  addReason(reasons, evidence?.productionTrustClaim === true, 'object_storage_production_claim_forbidden');
  addReason(reasons, hlcTuple(evidence?.reviewedAtHlc) === null, 'object_storage_readiness_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(evidence?.reviewedAtHlc, cycle?.planLockedAtHlc),
    'object_storage_readiness_review_before_migration_plan',
  );
  addReason(
    reasons,
    hlcAfter(evidence?.reviewedAtHlc, cycle?.validationRecordedAtHlc),
    'object_storage_readiness_review_after_migration_validation',
  );

  const artifactClassesCovered = sortedTextList(evidence?.artifactClassesCovered);
  evaluateRequiredSet(
    artifactClassesCovered,
    REQUIRED_OBJECT_STORAGE_ARTIFACT_CLASSES,
    'object_storage_artifact_class_missing',
    'object_storage_artifact_class_unsupported',
    reasons,
  );

  return {
    artifactClassesCovered,
    directPublicAccessAllowed: evidence?.directPublicAccessAllowed === true,
    externalReceiptStoreRequired: evidence?.externalReceiptStoreRequired === true,
    objectStorageBoundaryHash: evidence?.objectStorageBoundaryHash ?? null,
    objectStorageReadinessHash: evidence?.objectStorageReadinessHash ?? null,
    objectStorageReadinessReceiptHash: evidence?.objectStorageReadinessReceiptHash ?? null,
    providerRef: evidence?.providerRef ?? null,
    rawPayloadsExcludedFromOperationalDb: evidence?.rawPayloadsExcludedFromOperationalDb === true,
    rawPayloadsExcludedFromReceipts: evidence?.rawPayloadsExcludedFromReceipts === true,
    status: evidence?.status ?? null,
    trustState: evidence?.trustState ?? null,
  };
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  addReason(reasons, validation === null || validation === undefined, 'validation_evidence_absent');
  addReason(reasons, sortedTextList(validation?.commandRefs).length === 0, 'validation_commands_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_failed');
  addReason(reasons, validation?.dryRunPassed !== true, 'migration_dry_run_failed');
  addReason(reasons, validation?.rollbackDrillPassed !== true, 'rollback_drill_failed');
  addReason(reasons, validation?.backupRestoreVerified !== true, 'backup_restore_not_verified');
  addReason(reasons, validation?.tenantIsolationTestsPassed !== true, 'tenant_isolation_validation_failed');
  addReason(reasons, validation?.receiptSeparationTestsPassed !== true, 'receipt_separation_validation_failed');
  addReason(reasons, validation?.protectedContentScanPassed !== true, 'protected_content_scan_failed');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'source_guard_validation_failed');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'exochain_read_only_validation_absent');
  addReason(reasons, !isBasisPoints(validation?.coverageLineBasisPoints), 'coverage_line_basis_points_invalid');
  addReason(reasons, !isDigest(validation?.migrationManifestHash), 'migration_manifest_hash_invalid');
  addReason(reasons, !isDigest(validation?.rollbackEvidenceHash), 'rollback_evidence_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_record_time_invalid');
  addReason(reasons, hlcBefore(validation?.recordedAtHlc, cycle?.dryRunCompletedAtHlc), 'validation_before_dry_run');

  return {
    commandRefs: sortedTextList(validation?.commandRefs),
    coverageLineBasisPoints: validation?.coverageLineBasisPoints ?? null,
    migrationManifestHash: validation?.migrationManifestHash ?? null,
    rollbackEvidenceHash: validation?.rollbackEvidenceHash ?? null,
  };
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_claim_forbidden');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.validationRecordedAtHlc), 'human_review_before_validation');
  addReason(reasons, review?.decision === 'hold_for_migration_gap', 'human_review_hold_for_migration_gap');
}

function evaluateAuditRecord(audit, cycle, review, reasons) {
  addReason(reasons, audit === null || audit === undefined, 'audit_record_absent');
  addReason(reasons, !isDigest(audit?.auditRecordHash), 'audit_record_hash_invalid');
  addReason(reasons, !isDigest(audit?.previousAuditRecordHash), 'previous_audit_record_hash_invalid');
  addReason(reasons, !isDigest(audit?.operationalLogHash), 'operational_log_hash_invalid');
  addReason(reasons, audit?.immutableReceiptRequested === true, 'immutable_receipt_request_before_activation_forbidden');
  addReason(reasons, audit?.metadataOnly !== true, 'audit_record_metadata_boundary_invalid');
  addReason(reasons, audit?.protectedContentExcluded !== true, 'audit_record_protected_boundary_invalid');
  addReason(reasons, hlcTuple(audit?.receiptRecordedAtHlc) === null, 'audit_record_time_invalid');
  addReason(reasons, hlcBefore(audit?.receiptRecordedAtHlc, review?.reviewedAtHlc), 'audit_record_before_human_review');
  addReason(reasons, hlcBefore(cycle?.auditRecordedAtHlc, audit?.receiptRecordedAtHlc), 'audit_receipt_after_cycle_audit');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined) {
    return;
  }
  addReason(reasons, aiAssistance?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance?.humanReviewed !== true, 'ai_assistance_human_review_absent');
  addReason(reasons, !isDigest(aiAssistance?.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, aiAssistance?.metadataOnly !== true, 'ai_assistance_metadata_boundary_invalid');
}

function buildMigrationReadiness(
  input,
  policySummary,
  domainCoverage,
  migrationSummary,
  dataBoundarySummary,
  objectStorageSummary,
  validationSummary,
) {
  const migrationReadinessHash = sha256Hex({
    auditRecordHash: input.auditRecord.auditRecordHash,
    dataBoundaryHash: input.dataBoundary.operationalDatabaseHash,
    domainCoverage,
    humanDecisionHash: input.humanReview.decisionHash,
    migrationRef: input.migrationCycle.migrationRef,
    migrationSequences: migrationSummary.migrationSequences,
    objectStorageBoundaryHash: objectStorageSummary.objectStorageBoundaryHash,
    objectStorageReadinessHash: objectStorageSummary.objectStorageReadinessHash,
    objectStorageReadinessReceiptHash: objectStorageSummary.objectStorageReadinessReceiptHash,
    policyHash: input.migrationPolicy.policyHash,
    releaseCandidateRef: input.migrationCycle.releaseCandidateRef,
    schemaVersionFrom: migrationSummary.schemaVersionFrom,
    schemaVersionTo: migrationSummary.schemaVersionTo,
    tenantId: input.tenantId,
    validationEvidenceHash: input.validationEvidence.migrationManifestHash,
  });

  return {
    schema: MIGRATION_SCHEMA,
    migrationReadinessId: `cmdm_${sha256Hex({
      migrationReadinessHash,
      migrationRef: input.migrationCycle.migrationRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    releaseCandidateRef: input.migrationCycle.releaseCandidateRef,
    trustState: 'inactive',
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    baselineMigrationReady: true,
    productionActivationReady: false,
    mutableOperationalStateSeparated: dataBoundarySummary.exochainReceiptStoreExternal === true,
    exochainReceiptStoreExternal: dataBoundarySummary.exochainReceiptStoreExternal,
    evidencePayloadStoredOutsideDb: dataBoundarySummary.evidencePayloadStoredOutsideDb,
    directIdentifierColumnsEncrypted: dataBoundarySummary.directIdentifierColumnsEncrypted,
    participantIdentitySeparated: dataBoundarySummary.participantIdentitySeparated,
    requiredMigrationDomains: policySummary.requiredMigrationDomains,
    migrationDomainsCovered: domainCoverage,
    migrationSequences: migrationSummary.migrationSequences,
    schemaVersionFrom: migrationSummary.schemaVersionFrom,
    schemaVersionTo: migrationSummary.schemaVersionTo,
    schemaMigrations: migrationSummary.migrationSummaries,
    dataBoundarySummary,
    objectStorageReadinessSummary: objectStorageSummary,
    validationSummary,
    migrationReadinessHash,
    objectStorageBoundaryHash: objectStorageSummary.objectStorageBoundaryHash,
    objectStorageReadinessHash: objectStorageSummary.objectStorageReadinessHash,
    objectStorageReadinessReceiptHash: objectStorageSummary.objectStorageReadinessReceiptHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, migrationReadiness) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: migrationReadiness.migrationReadinessHash,
    artifactType: 'database_migration_readiness',
    artifactVersion: input.migrationCycle.releaseCandidateRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: [
      'database_migration',
      'inactive_trust_state',
      'metadata_only',
      'object_storage_readiness_lineage',
    ],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateDatabaseMigrationReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateMigrationPolicy(input?.migrationPolicy, reasons);
  evaluateMigrationCycle(input?.migrationCycle, input?.migrationPolicy, reasons);
  const domainCoverage = evaluateMigrationDomains(input?.migrationDomains, policySummary, input?.migrationCycle, reasons);
  const migrationSummary = evaluateSchemaMigrations(input?.schemaMigrations, input?.migrationCycle, reasons);
  const dataBoundarySummary = evaluateDataBoundary(input?.dataBoundary, input?.migrationCycle, reasons);
  const objectStorageSummary = evaluateObjectStorageReadinessEvidence(
    input?.objectStorageReadinessEvidence,
    input?.dataBoundary,
    input?.migrationCycle,
    reasons,
  );
  const validationSummary = evaluateValidationEvidence(input?.validationEvidence, input?.migrationCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.migrationCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.migrationCycle, input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      migrationReadiness: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const migrationReadiness = buildMigrationReadiness(
    input,
    policySummary,
    domainCoverage,
    migrationSummary,
    dataBoundarySummary,
    objectStorageSummary,
    validationSummary,
  );

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    migrationReadiness,
    receipt: buildReceipt(input, migrationReadiness),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
