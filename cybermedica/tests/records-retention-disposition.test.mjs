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

const REQUIRED_RECORD_FAMILIES = [
  'audit_trails',
  'clinical_trial_agreements',
  'controlled_documents',
  'data_corrections',
  'decision_forum_records',
  'diligence_exports',
  'evidence_payload_metadata',
  'final_reports',
  'participant_consent_records',
  'safety_reporting_records',
  'source_data_traceability',
  'training_delegation_records',
];

async function loadRecordsRetentionDisposition() {
  try {
    return await import('../src/records-retention-disposition.mjs');
  } catch (error) {
    assert.fail(`CyberMedica records retention disposition module must exist and load: ${error.message}`);
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

function ruleCandidate(ruleRef, periodMonths, ruleHash, overrides = {}) {
  return {
    ruleRef,
    jurisdictionOrSourceRef: `source-${ruleRef}`,
    periodMonths,
    ruleHash,
    legalBasisHash: DIGEST_7,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function recordSchedule(recordFamily, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6];
  const selectedMonths = 300 + index;
  return {
    recordFamily,
    recordSetRef: `record-set-${recordFamily}`,
    recordSetHash: hashes[index],
    retentionClass: 'regulated_quality_record',
    ruleCandidates: [
      ruleCandidate(`${recordFamily}-protocol`, 180 + index, hashes[(index + 1) % hashes.length]),
      ruleCandidate(`${recordFamily}-regulatory`, selectedMonths, hashes[(index + 2) % hashes.length]),
      ruleCandidate(`${recordFamily}-sponsor`, 240 + index, hashes[(index + 3) % hashes.length]),
    ],
    selectedRuleRef: `${recordFamily}-regulatory`,
    selectedRetentionMonths: selectedMonths,
    startAtHlc: { physicalMs: 1802040000000 + index, logical: 0 },
    eligibleDispositionAtHlc: { physicalMs: 1802049000000 + index, logical: 0 },
    custodianDid: 'did:exo:records-manager-alpha',
    storageBoundaryRef: 'object-storage-readiness-alpha',
    accessPolicyHash: DIGEST_8,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function archivePackage(recordFamily, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6];
  return {
    recordFamily,
    archiveRef: `archive-${recordFamily}`,
    archiveHash: hashes[(index + 4) % hashes.length],
    custodyDigest: hashes[(index + 5) % hashes.length],
    objectLockEnabled: true,
    legalHoldSupported: true,
    retrievalIndexHash: hashes[(index + 6) % hashes.length],
    accessLogHash: hashes[(index + 7) % hashes.length],
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function dispositionRequest(recordFamily, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6];
  return {
    recordFamily,
    dispositionType: 'archive',
    requestRef: `disp-${recordFamily}`,
    requestedAtHlc: { physicalMs: 1802050000000 + index, logical: 0 },
    approvedAtHlc: { physicalMs: 1802050000000 + index, logical: 1 },
    approvedByDid: 'did:exo:records-governance-alpha',
    dispositionEvidenceHash: hashes[index],
    legalHoldChecked: true,
    recordsPastEligibleDate: true,
    destructionCertificateHash: null,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function retentionInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:records-manager-alpha',
      kind: 'human',
      roleRefs: ['records_manager', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['records_retention_disposition', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    retentionPolicy: {
      policyRef: 'records-retention-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredRecordFamilies: REQUIRED_RECORD_FAMILIES,
      conflictPolicy: 'longest_applicable_retention',
      legalHoldOverridesDisposition: true,
      destructionRequiresHumanApproval: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1802039900000, logical: 0 },
    },
    retentionCycle: {
      cycleRef: 'records-retention-disposition-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1802039950000, logical: 0 },
      scheduleCompiledAtHlc: { physicalMs: 1802041000000, logical: 12 },
      archiveVerifiedAtHlc: { physicalMs: 1802042000000, logical: 0 },
      holdReviewedAtHlc: { physicalMs: 1802043000000, logical: 0 },
      dispositionReviewedAtHlc: { physicalMs: 1802050100000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1802050200000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    recordSchedules: REQUIRED_RECORD_FAMILIES.map((recordFamily, index) => recordSchedule(recordFamily, index)),
    archivePackages: REQUIRED_RECORD_FAMILIES.map((recordFamily, index) => archivePackage(recordFamily, index)),
    legalHolds: [
      {
        holdRef: 'legal-hold-source-data-alpha',
        status: 'active',
        appliesToRecordFamilies: ['source_data_traceability', 'participant_consent_records'],
        holdHash: DIGEST_C,
        reasonHash: DIGEST_D,
        imposedAtHlc: { physicalMs: 1802042500000, logical: 0 },
        reviewedAtHlc: { physicalMs: 1802043000000, logical: 0 },
        reviewedByDid: 'did:exo:legal-quality-alpha',
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      {
        holdRef: 'legal-hold-released-final-report-alpha',
        status: 'released',
        appliesToRecordFamilies: ['final_reports'],
        holdHash: DIGEST_E,
        reasonHash: DIGEST_F,
        imposedAtHlc: { physicalMs: 1802042000000, logical: 0 },
        releasedAtHlc: { physicalMs: 1802042600000, logical: 0 },
        reviewedAtHlc: { physicalMs: 1802043000000, logical: 0 },
        reviewedByDid: 'did:exo:legal-quality-alpha',
        metadataOnly: true,
        protectedContentExcluded: true,
      },
    ],
    dispositionRequests: REQUIRED_RECORD_FAMILIES.map((recordFamily, index) =>
      dispositionRequest(recordFamily, index, {
        dispositionType: ['participant_consent_records', 'source_data_traceability'].includes(recordFamily)
          ? 'retain_on_hold'
          : 'archive',
      }),
    ),
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      reviewerRoleRefs: ['quality_manager', 'records_manager'],
      decision: 'records_retention_ready_inactive_trust',
      decisionHash: DIGEST_1,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1802050100000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'records-retention-audit-alpha',
      auditRecordHash: DIGEST_2,
      previousAuditRecordHash: DIGEST_3,
      disclosureLogHash: DIGEST_4,
      receiptRecordedAtHlc: { physicalMs: 1802050200000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    custodyDigest: DIGEST_5,
  };
  return mergeDeep(base, overrides);
}

test('records retention disposition creates deterministic inactive metadata package', async () => {
  const { evaluateRecordsRetentionDisposition } = await loadRecordsRetentionDisposition();

  const first = evaluateRecordsRetentionDisposition(retentionInput());
  const second = evaluateRecordsRetentionDisposition({
    ...retentionInput(),
    retentionPolicy: {
      ...retentionInput().retentionPolicy,
      requiredRecordFamilies: [...REQUIRED_RECORD_FAMILIES].reverse(),
    },
    recordSchedules: [...retentionInput().recordSchedules].reverse(),
    archivePackages: [...retentionInput().archivePackages].reverse(),
    dispositionRequests: [...retentionInput().dispositionRequests].reverse(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.retentionPackage.packageId, second.retentionPackage.packageId);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.retentionPackage.schema, 'cybermedica.records_retention_disposition.v1');
  assert.equal(first.retentionPackage.trustState, 'inactive');
  assert.equal(first.retentionPackage.exochainProductionClaim, false);
  assert.equal(first.retentionPackage.metadataOnly, true);
  assert.equal(first.retentionPackage.conflictPolicy, 'longest_applicable_retention');
  assert.deepEqual(first.retentionPackage.requiredRecordFamilies, REQUIRED_RECORD_FAMILIES);
  assert.deepEqual(first.retentionPackage.activeLegalHoldFamilies, [
    'participant_consent_records',
    'source_data_traceability',
  ]);
  assert.equal(first.retentionPackage.dispositionOutcomes.length, REQUIRED_RECORD_FAMILIES.length);
  assert.deepEqual(first.retentionPackage.dispositionOutcomes[0], {
    archiveRef: 'archive-audit_trails',
    dispositionStatus: 'archive_approved',
    dispositionType: 'archive',
    eligibleDispositionAtHlc: { physicalMs: 1802049000000, logical: 0 },
    legalHoldActive: false,
    recordFamily: 'audit_trails',
    selectedRetentionMonths: 300,
  });
  assert.deepEqual(
    first.retentionPackage.dispositionOutcomes
      .filter((outcome) => outcome.legalHoldActive)
      .map((outcome) => outcome.dispositionStatus),
    ['retained_on_legal_hold', 'retained_on_legal_hold'],
  );
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.containsProtectedContent, false);
});

test('records retention disposition fails closed for incomplete schedules and unsafe conflict resolution', async () => {
  const { evaluateRecordsRetentionDisposition } = await loadRecordsRetentionDisposition();

  const input = retentionInput({
    retentionPolicy: {
      conflictPolicy: 'shortest_retention',
      requiredRecordFamilies: [...REQUIRED_RECORD_FAMILIES, 'unsupported_record_family'],
    },
    recordSchedules: retentionInput().recordSchedules
      .filter((schedule) => schedule.recordFamily !== 'source_data_traceability')
      .map((schedule) =>
        schedule.recordFamily === 'audit_trails'
          ? {
              ...schedule,
              selectedRuleRef: `${schedule.recordFamily}-protocol`,
              selectedRetentionMonths: 180,
            }
          : schedule,
      ),
    archivePackages: retentionInput().archivePackages.filter(
      (archive) => archive.recordFamily !== 'source_data_traceability',
    ),
    dispositionRequests: retentionInput().dispositionRequests.filter(
      (request) => request.recordFamily !== 'source_data_traceability',
    ),
  });

  const result = evaluateRecordsRetentionDisposition(input);

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('retention_conflict_policy_invalid'));
  assert.ok(result.reasons.includes('required_record_family_unsupported:unsupported_record_family'));
  assert.ok(result.reasons.includes('record_schedule_missing:source_data_traceability'));
  assert.ok(result.reasons.includes('archive_package_missing:source_data_traceability'));
  assert.ok(result.reasons.includes('disposition_request_missing:source_data_traceability'));
  assert.ok(result.reasons.includes('selected_retention_not_longest:audit_trails'));
  assert.equal(result.retentionPackage, null);
  assert.equal(result.receipt, null);
});

test('records retention disposition fails closed for duplicate family evidence rows', async () => {
  const { evaluateRecordsRetentionDisposition } = await loadRecordsRetentionDisposition();
  const base = retentionInput();

  const result = evaluateRecordsRetentionDisposition({
    ...base,
    recordSchedules: [...base.recordSchedules, recordSchedule('audit_trails', 0, { recordSetRef: 'duplicate-audit' })],
    archivePackages: [...base.archivePackages, archivePackage('audit_trails', 0, { archiveRef: 'duplicate-audit' })],
    dispositionRequests: [
      ...base.dispositionRequests,
      dispositionRequest('audit_trails', 0, { requestRef: 'duplicate-audit' }),
    ],
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('record_schedule_duplicate:audit_trails'));
  assert.ok(result.reasons.includes('archive_package_duplicate:audit_trails'));
  assert.ok(result.reasons.includes('disposition_request_duplicate:audit_trails'));
  assert.equal(result.retentionPackage, null);
  assert.equal(result.receipt, null);
});

test('records retention disposition blocks destruction under hold or before eligibility', async () => {
  const { evaluateRecordsRetentionDisposition } = await loadRecordsRetentionDisposition();

  const input = retentionInput({
    dispositionRequests: retentionInput().dispositionRequests.map((request) => {
      if (request.recordFamily === 'participant_consent_records') {
        return {
          ...request,
          dispositionType: 'destroy',
          destructionCertificateHash: DIGEST_6,
        };
      }
      if (request.recordFamily === 'audit_trails') {
        return {
          ...request,
          dispositionType: 'destroy',
          destructionCertificateHash: DIGEST_7,
          recordsPastEligibleDate: false,
        };
      }
      return request;
    }),
  });

  const result = evaluateRecordsRetentionDisposition(input);

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('disposition_blocked_by_legal_hold:participant_consent_records'));
  assert.ok(result.reasons.includes('disposition_before_eligible:audit_trails'));
});

test('records retention disposition verifies disposition timing against the eligible schedule HLC', async () => {
  const { evaluateRecordsRetentionDisposition } = await loadRecordsRetentionDisposition();

  const result = evaluateRecordsRetentionDisposition(
    retentionInput({
      dispositionRequests: retentionInput().dispositionRequests.map((request) =>
        request.recordFamily === 'audit_trails'
          ? {
              ...request,
              requestedAtHlc: { physicalMs: 1802048000000, logical: 0 },
              approvedAtHlc: { physicalMs: 1802048000000, logical: 1 },
              recordsPastEligibleDate: true,
            }
          : request,
      ),
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('disposition_request_before_eligible:audit_trails'));
  assert.ok(result.reasons.includes('disposition_approval_before_eligible:audit_trails'));
  assert.equal(result.retentionPackage, null);
  assert.equal(result.receipt, null);
});

test('records retention disposition denies disposition before released legal hold review', async () => {
  const { evaluateRecordsRetentionDisposition } = await loadRecordsRetentionDisposition();

  const result = evaluateRecordsRetentionDisposition(
    retentionInput({
      legalHolds: retentionInput().legalHolds.map((hold) =>
        hold.holdRef === 'legal-hold-released-final-report-alpha'
          ? {
              ...hold,
              releasedAtHlc: { physicalMs: 1802050050000, logical: 0 },
              reviewedAtHlc: { physicalMs: 1802043000000, logical: 0 },
            }
          : hold,
      ),
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('legal_hold_review_before_release:legal-hold-released-final-report-alpha'));
  assert.ok(result.reasons.includes('disposition_before_legal_hold_release:final_reports'));
  assert.equal(result.retentionPackage, null);
  assert.equal(result.receipt, null);
});

test('records retention disposition validates human review inactive trust and HLC ordering', async () => {
  const { evaluateRecordsRetentionDisposition } = await loadRecordsRetentionDisposition();

  const result = evaluateRecordsRetentionDisposition(
    retentionInput({
      actor: { did: 'did:exo:records-ai-alpha', kind: 'ai_agent' },
      authority: { valid: true, revoked: false, expired: false, permissions: ['read'], authorityChainHash: 'bad' },
      retentionCycle: {
        productionTrustClaim: true,
        dispositionReviewedAtHlc: { physicalMs: 1802040000000, logical: 0 },
      },
      humanReview: {
        decision: 'records_retention_ready_inactive_trust',
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
        reviewedAtHlc: { physicalMs: 1802040000000, logical: 0 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1802030000000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('records_retention_authority_missing'));
  assert.ok(result.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('human_review_final_authority_invalid'));
  assert.ok(result.reasons.includes('human_review_ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_review_production_claim_not_denied'));
  assert.ok(result.reasons.includes('retention_cycle_hlc_order_invalid'));
  assert.ok(result.reasons.includes('audit_record_time_before_human_review'));
});

test('records retention disposition rejects raw record content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateRecordsRetentionDisposition } = await loadRecordsRetentionDisposition();

  assert.throws(
    () =>
      evaluateRecordsRetentionDisposition(
        retentionInput({
          rawRecordBody: 'participant source documents must never be anchored in retention receipts',
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRecordsRetentionDisposition(
        retentionInput({
          archivePackages: [
            ...retentionInput().archivePackages,
            {
              recordFamily: 'secret-leak',
              archiveRef: 'archive-secret',
              accessToken: 'token-value',
            },
          ],
        }),
    ),
    ProtectedContentError,
  );
});
