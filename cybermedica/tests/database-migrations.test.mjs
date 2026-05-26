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

const REQUIRED_MIGRATION_DOMAINS = [
  'access_policy',
  'backup_restore',
  'change_control',
  'data_classification',
  'migration_ordering',
  'operational_receipt_separation',
  'schema_plan',
  'tenant_isolation',
  'validation',
];

async function loadDatabaseMigrations() {
  try {
    return await import('../src/database-migrations.mjs');
  } catch (error) {
    assert.fail(`CyberMedica database migrations module must exist and load: ${error.message}`);
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

function migrationDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    domain,
    status: 'ready',
    evidenceRef: `database-migration-evidence-${domain}`,
    evidenceHash: hashes[index],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner`,
    reviewerDid: `did:exo:${domain.replaceAll('_', '-')}-reviewer`,
    reviewedAtHlc: { physicalMs: 1800005100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function migrationDomains() {
  return REQUIRED_MIGRATION_DOMAINS.map((domain, index) => migrationDomain(domain, index));
}

function schemaMigration(overrides = {}) {
  return {
    migrationId: '202605250001_create_qms_operational_tables',
    sequence: 1,
    migrationHash: DIGEST_4,
    checksumHash: DIGEST_5,
    schemaVersionFrom: 0,
    schemaVersionTo: 1,
    direction: 'up',
    reversible: true,
    destructiveChange: false,
    destructiveChangeApprovalHash: null,
    tenantScoped: true,
    tenantPartitionKey: 'tenant_id',
    touchesSensitiveTables: true,
    dataClassificationMappingHash: DIGEST_6,
    directIdentifierColumnsEncrypted: true,
    participantIdentitySeparated: true,
    evidencePayloadStoredOutsideDb: true,
    operationalStateMutable: true,
    exochainReceiptMutation: false,
    usesSystemTime: false,
    usesRandomness: false,
    usesFloatingPoint: false,
    metadataOnly: true,
    protectedContentExcluded: true,
    reviewedAtHlc: { physicalMs: 1800005100000, logical: 10 },
    ...overrides,
  };
}

function migrationInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:database-migration-owner-alpha',
      kind: 'human',
      roleRefs: ['deployment_owner', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['database_migration_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    migrationPolicy: {
      policyRef: 'database-migration-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredMigrationDomains: REQUIRED_MIGRATION_DOMAINS,
      mutableOperationalStateRequired: true,
      exochainReceiptMutationForbidden: true,
      objectStorageForRawArtifactsRequired: true,
      tenantIsolationRequired: true,
      rootVerificationRequiredForTrustClaims: true,
      noCredentialDisclosure: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800004900000, logical: 0 },
    },
    migrationCycle: {
      migrationRef: 'database-migration-readiness-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800004950000, logical: 0 },
      planLockedAtHlc: { physicalMs: 1800005000000, logical: 0 },
      backupVerifiedAtHlc: { physicalMs: 1800005050000, logical: 0 },
      dryRunCompletedAtHlc: { physicalMs: 1800005150000, logical: 0 },
      validationRecordedAtHlc: { physicalMs: 1800005200000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800005300000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800005400000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    migrationDomains: migrationDomains(),
    schemaMigrations: [
      schemaMigration(),
      schemaMigration({
        migrationId: '202605250002_add_quality_state_indexes',
        sequence: 2,
        migrationHash: DIGEST_7,
        checksumHash: DIGEST_8,
        schemaVersionFrom: 1,
        schemaVersionTo: 2,
        touchesSensitiveTables: false,
        dataClassificationMappingHash: null,
        reviewedAtHlc: { physicalMs: 1800005100000, logical: 11 },
      }),
    ],
    dataBoundary: {
      operationalDatabaseRef: 'postgres-operational-cybermedica-alpha',
      operationalDatabaseHash: DIGEST_C,
      migrationToolRef: 'node-pg-migrations-baseline',
      mutableStateTableRefs: ['qms_controls', 'evidence_indexes', 'workflow_states'],
      tenantPartitionPolicyHash: DIGEST_D,
      rowLevelSecurityPolicyHash: DIGEST_E,
      directIdentifierEncryptionPolicyHash: DIGEST_F,
      objectStorageBoundaryHash: DIGEST_1,
      exochainReceiptStoreExternal: true,
      evidencePayloadStoredOutsideDb: true,
      rawArtifactStorageRef: 'encrypted-object-storage-boundary',
      directIdentifierColumnsEncrypted: true,
      participantIdentitySeparated: true,
      operationalStateMutable: true,
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800005100000, logical: 12 },
    },
    validationEvidence: {
      commandRefs: ['node --test tests/database-migrations.test.mjs', 'npm run quality'],
      commandsPassed: true,
      dryRunPassed: true,
      rollbackDrillPassed: true,
      backupRestoreVerified: true,
      tenantIsolationTestsPassed: true,
      receiptSeparationTestsPassed: true,
      protectedContentScanPassed: true,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      coverageLineBasisPoints: 9970,
      migrationManifestHash: DIGEST_2,
      rollbackEvidenceHash: DIGEST_3,
      recordedAtHlc: { physicalMs: 1800005200000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:site-quality-leader-alpha',
      reviewerRoleRefs: ['quality_manager', 'deployment_owner'],
      decision: 'migration_ready_inactive_trust',
      decisionHash: DIGEST_4,
      noProductionTrustClaim: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800005300000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordHash: DIGEST_5,
      previousAuditRecordHash: DIGEST_6,
      operationalLogHash: DIGEST_7,
      immutableReceiptRequested: false,
      receiptRecordedAtHlc: { physicalMs: 1800005400000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_8,
      humanReviewed: true,
      metadataOnly: true,
    },
    custodyDigest: DIGEST_6,
  };

  return mergeDeep(base, overrides);
}

test('database migration readiness module loads', async () => {
  const module = await loadDatabaseMigrations();

  assert.equal(typeof module.evaluateDatabaseMigrationReadiness, 'function');
});

test('permits deterministic inactive metadata-only database migration readiness', async () => {
  const { evaluateDatabaseMigrationReadiness } = await loadDatabaseMigrations();
  const input = migrationInput();

  const first = evaluateDatabaseMigrationReadiness(input);
  const second = evaluateDatabaseMigrationReadiness(input);

  assert.deepEqual(first, second);
  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first.reasons, []);
  assert.equal(first.trustState, 'inactive');
  assert.equal(first.exochainProductionClaim, false);
  assert.equal(first.migrationReadiness.baselineMigrationReady, true);
  assert.equal(first.migrationReadiness.productionActivationReady, false);
  assert.equal(first.migrationReadiness.mutableOperationalStateSeparated, true);
  assert.equal(first.migrationReadiness.exochainReceiptStoreExternal, true);
  assert.deepEqual(first.migrationReadiness.migrationSequences, [1, 2]);
  assert.deepEqual(first.migrationReadiness.migrationDomainsCovered, REQUIRED_MIGRATION_DOMAINS);
  assert.match(first.migrationReadiness.migrationReadinessHash, /^[0-9a-f]{64}$/u);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'database_migration_readiness');
  assert.equal(first.receipt.anchorPayload.classification, 'restricted_metadata_only');
});

test('denies incomplete or unsupported migration-domain coverage', async () => {
  const { evaluateDatabaseMigrationReadiness } = await loadDatabaseMigrations();
  const input = migrationInput({
    migrationDomains: [
      ...migrationDomains().filter((domain) => domain.domain !== 'tenant_isolation'),
      migrationDomain('unreviewed_manual_patch', 1),
    ],
  });

  const decision = evaluateDatabaseMigrationReadiness(input);

  assert.equal(decision.decision, 'denied');
  assert.equal(decision.failClosed, true);
  assert.match(decision.reasons.join('|'), /migration_domain_missing:tenant_isolation/);
  assert.match(decision.reasons.join('|'), /migration_domain_unsupported:unreviewed_manual_patch/);
  assert.equal(decision.migrationReadiness, null);
  assert.equal(decision.receipt, null);
});

test('denies unsafe migration ordering and nondeterministic migration behavior', async () => {
  const { evaluateDatabaseMigrationReadiness } = await loadDatabaseMigrations();
  const input = migrationInput({
    schemaMigrations: [
      schemaMigration({
        migrationId: '202605250003_skip_sequence',
        sequence: 3,
        destructiveChange: true,
        destructiveChangeApprovalHash: null,
        exochainReceiptMutation: true,
        usesSystemTime: true,
        usesRandomness: true,
        usesFloatingPoint: true,
      }),
    ],
  });

  const decision = evaluateDatabaseMigrationReadiness(input);

  assert.equal(decision.decision, 'denied');
  assert.match(decision.reasons.join('|'), /migration_sequence_gap_or_order_invalid/);
  assert.match(decision.reasons.join('|'), /destructive_change_without_approval:202605250003_skip_sequence/);
  assert.match(decision.reasons.join('|'), /migration_exochain_receipt_mutation_forbidden:202605250003_skip_sequence/);
  assert.match(decision.reasons.join('|'), /migration_system_time_forbidden:202605250003_skip_sequence/);
  assert.match(decision.reasons.join('|'), /migration_randomness_forbidden:202605250003_skip_sequence/);
  assert.match(decision.reasons.join('|'), /migration_floating_point_forbidden:202605250003_skip_sequence/);
});

test('denies database boundaries that blur mutable state raw artifacts or receipts', async () => {
  const { evaluateDatabaseMigrationReadiness } = await loadDatabaseMigrations();
  const input = migrationInput({
    dataBoundary: {
      directIdentifierColumnsEncrypted: false,
      evidencePayloadStoredOutsideDb: false,
      exochainReceiptStoreExternal: false,
      participantIdentitySeparated: false,
      tenantPartitionPolicyHash: '0000000000000000000000000000000000000000000000000000000000000000',
    },
  });

  const decision = evaluateDatabaseMigrationReadiness(input);

  assert.equal(decision.decision, 'denied');
  assert.match(decision.reasons.join('|'), /direct_identifier_encryption_absent/);
  assert.match(decision.reasons.join('|'), /evidence_payload_db_storage_forbidden/);
  assert.match(decision.reasons.join('|'), /exochain_receipt_store_must_be_external/);
  assert.match(decision.reasons.join('|'), /participant_identity_separation_absent/);
  assert.match(decision.reasons.join('|'), /tenant_partition_policy_hash_invalid/);
});

test('denies failed dry-run rollback tenant isolation and receipt separation validation', async () => {
  const { evaluateDatabaseMigrationReadiness } = await loadDatabaseMigrations();
  const input = migrationInput({
    validationEvidence: {
      commandsPassed: false,
      dryRunPassed: false,
      rollbackDrillPassed: false,
      backupRestoreVerified: false,
      tenantIsolationTestsPassed: false,
      receiptSeparationTestsPassed: false,
      protectedContentScanPassed: false,
      noExochainSourceModified: false,
    },
  });

  const decision = evaluateDatabaseMigrationReadiness(input);

  assert.equal(decision.decision, 'denied');
  assert.match(decision.reasons.join('|'), /validation_commands_failed/);
  assert.match(decision.reasons.join('|'), /migration_dry_run_failed/);
  assert.match(decision.reasons.join('|'), /rollback_drill_failed/);
  assert.match(decision.reasons.join('|'), /backup_restore_not_verified/);
  assert.match(decision.reasons.join('|'), /tenant_isolation_validation_failed/);
  assert.match(decision.reasons.join('|'), /receipt_separation_validation_failed/);
  assert.match(decision.reasons.join('|'), /protected_content_scan_failed/);
  assert.match(decision.reasons.join('|'), /exochain_read_only_validation_absent/);
});

test('denies AI final authority production trust claims and cross-tenant migration review', async () => {
  const { evaluateDatabaseMigrationReadiness } = await loadDatabaseMigrations();
  const input = migrationInput({
    targetTenantId: 'tenant-site-bravo',
    actor: { kind: 'ai_agent' },
    migrationCycle: { productionTrustClaim: true },
    humanReview: {
      finalAuthority: 'ai',
      aiFinalAuthority: true,
      noProductionTrustClaim: false,
    },
  });

  const decision = evaluateDatabaseMigrationReadiness(input);

  assert.equal(decision.decision, 'denied');
  assert.match(decision.reasons.join('|'), /tenant_boundary_violation/);
  assert.match(decision.reasons.join('|'), /ai_final_authority_forbidden/);
  assert.match(decision.reasons.join('|'), /human_database_migration_reviewer_required/);
  assert.match(decision.reasons.join('|'), /migration_cycle_production_claim_forbidden/);
  assert.match(decision.reasons.join('|'), /human_review_production_claim_forbidden/);
});

test('rejects raw migration content protected content and deployment secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDatabaseMigrationReadiness } = await loadDatabaseMigrations();

  assert.throws(
    () =>
      evaluateDatabaseMigrationReadiness(
        migrationInput({
          schemaMigrations: [
            schemaMigration({
              rawSql: 'alter table participants add column participant_name text;',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );
  assert.throws(
    () =>
      evaluateDatabaseMigrationReadiness(
        migrationInput({
          dataBoundary: {
            password: 'database-password-must-not-enter-readiness-record',
          },
        }),
      ),
    ProtectedContentError,
  );
});
