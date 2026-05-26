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

const REQUIRED_REVIEW_DOMAINS = [
  'action_items',
  'consent_records',
  'data_integrity',
  'delegation_training',
  'evidence_custody',
  'protocol_adherence',
  'safety_reporting',
  'source_crf_consistency',
];

async function loadMonitoringVisits() {
  try {
    return await import('../src/monitoring-visits.mjs');
  } catch (error) {
    assert.fail(`CyberMedica monitoring visits module must exist and load: ${error.message}`);
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

function reviewDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    domain,
    status: 'verified',
    evidenceHash: hashes[index],
    custodyDigest: hashes[index + 1],
    reviewedAtHlc: { physicalMs: 1802010100000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function finding(findingRef, severity, overrides = {}) {
  return {
    findingRef,
    domain: severity === 'major' ? 'source_crf_consistency' : 'protocol_adherence',
    severity,
    status: severity === 'observation' ? 'closed' : 'action_required',
    findingHash: severity === 'critical' ? DIGEST_5 : DIGEST_6,
    evidenceHash: severity === 'critical' ? DIGEST_7 : DIGEST_8,
    ownerDid: 'did:exo:site-quality-owner-alpha',
    dueAtHlc: { physicalMs: 1802015000000, logical: 0 },
    capaRequired: severity === 'critical' || severity === 'major',
    capaRef: severity === 'observation' ? null : `CAPA-${findingRef}`,
    decisionForumRequired: severity === 'critical',
    decisionForumMatterRef: severity === 'critical' ? `DF-${findingRef}` : null,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function actionItem(actionItemRef, findingRef, overrides = {}) {
  return {
    actionItemRef,
    findingRef,
    ownerDid: 'did:exo:site-quality-owner-alpha',
    actionHash: DIGEST_1,
    dueAtHlc: { physicalMs: 1802016000000, logical: 0 },
    status: 'open',
    escalationRole: 'site_quality_lead',
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function monitoringVisitInput(overrides = {}) {
  return mergeDeep(
    {
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-alpha',
      actor: {
        did: 'did:exo:cro-monitor-alpha',
        kind: 'human',
        roleRefs: ['cro_monitor', 'monitor_cra'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['monitoring_visit', 'read'],
        authorityChainHash: DIGEST_A,
      },
      visitPlan: {
        visitRef: 'MON-VISIT-SITE-ALPHA-2026-0001',
        visitType: 'interim_monitoring',
        siteRef: 'site-alpha',
        studyRef: 'study-cm-001',
        protocolRef: 'protocol-cm-001',
        sponsorRef: 'sponsor-alpha',
        croRef: 'cro-alpha',
        objectiveHash: DIGEST_B,
        plannedAtHlc: { physicalMs: 1802010000000, logical: 0 },
        scheduledStartHlc: { physicalMs: 1802010050000, logical: 0 },
        scheduledEndHlc: { physicalMs: 1802013600000, logical: 0 },
        monitoringPlanHash: DIGEST_C,
        metadataOnly: true,
        protectedContentExcluded: true,
        productionTrustClaim: false,
      },
      accessPolicy: {
        policyRef: 'monitoring-access-policy-alpha',
        policyHash: DIGEST_D,
        status: 'active',
        allowedRoles: ['cro_monitor', 'monitor_cra', 'sponsor_monitor'],
        allowedReviewDomains: REQUIRED_REVIEW_DOMAINS,
        leastPrivilege: true,
        disclosureLogRequired: true,
        protectedContentSuppressed: true,
        directIdentifiersSuppressed: true,
        sourceDocumentsExcluded: true,
        metadataOnly: true,
        protectedContentExcluded: true,
        reviewedAtHlc: { physicalMs: 1802010005000, logical: 0 },
      },
      reviewEvidence: {
        domains: REQUIRED_REVIEW_DOMAINS.map((domain, index) => reviewDomain(domain, index)),
        sourceCrfConsistency: {
          status: 'verified',
          reviewedRecordCount: 72,
          discrepancyCount: 0,
          discrepancyRegisterHash: DIGEST_E,
          reviewerDid: 'did:exo:cro-monitor-alpha',
          reviewedAtHlc: { physicalMs: 1802010100010, logical: 0 },
          metadataOnly: true,
          protectedContentExcluded: true,
        },
        consentReview: {
          status: 'verified',
          activeConsentVersionRef: 'consent-form-v7',
          reviewedConsentRecordCount: 18,
          missingConsentCount: 0,
          supersededFormUseDetected: false,
          evidenceHash: DIGEST_F,
          reviewedAtHlc: { physicalMs: 1802010100020, logical: 0 },
          metadataOnly: true,
          protectedContentExcluded: true,
        },
        safetyReview: {
          status: 'verified',
          eventLogHash: DIGEST_2,
          saeReconciliationHash: DIGEST_3,
          unresolvedSafetySignalCount: 0,
          reviewedAtHlc: { physicalMs: 1802010100030, logical: 0 },
          metadataOnly: true,
          protectedContentExcluded: true,
        },
      },
      findings: [
        finding('FIND-MON-PROTOCOL-001', 'critical', {
          domain: 'protocol_adherence',
          evidenceHash: DIGEST_6,
          findingHash: DIGEST_7,
        }),
        finding('FIND-MON-SOURCE-001', 'major', {
          evidenceHash: DIGEST_8,
          findingHash: DIGEST_9,
        }),
        finding('FIND-MON-DOC-001', 'observation', {
          domain: 'evidence_custody',
          evidenceHash: DIGEST_A,
          findingHash: DIGEST_B,
        }),
      ],
      actionItems: [
        actionItem('ACT-MON-PROTOCOL-001', 'FIND-MON-PROTOCOL-001', {
          actionHash: DIGEST_C,
          escalationRole: 'decision_forum_chair',
        }),
        actionItem('ACT-MON-SOURCE-001', 'FIND-MON-SOURCE-001', {
          actionHash: DIGEST_D,
          escalationRole: 'site_quality_lead',
        }),
      ],
      visitReport: {
        reportHash: DIGEST_E,
        reportVersion: 'v1',
        draftedAtHlc: { physicalMs: 1802020000000, logical: 0 },
        reviewedBySiteDid: 'did:exo:quality-manager-alpha',
        reviewedBySponsorDid: 'did:exo:sponsor-quality-alpha',
        approvedAtHlc: { physicalMs: 1802020100000, logical: 0 },
        disclosureLogHash: DIGEST_F,
        oversightSummaryHash: DIGEST_4,
        locked: true,
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      humanReview: {
        status: 'approved',
        reviewerDid: 'did:exo:quality-manager-alpha',
        reviewHash: DIGEST_5,
        reviewedAtHlc: { physicalMs: 1802020200000, logical: 0 },
        aiAssisted: true,
        aiFinalAuthority: false,
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      receiptEvidence: {
        artifactHash: DIGEST_6,
        custodyDigest: DIGEST_7,
      },
    },
    overrides,
  );
}

test('monitoring visit creates deterministic inactive oversight record with findings and action items', async () => {
  const { evaluateMonitoringVisit } = await loadMonitoringVisits();
  const inputA = monitoringVisitInput({
    reviewEvidence: {
      domains: [...monitoringVisitInput().reviewEvidence.domains].reverse(),
    },
    findings: [...monitoringVisitInput().findings].reverse(),
    actionItems: [...monitoringVisitInput().actionItems].reverse(),
  });
  const inputB = monitoringVisitInput();

  const first = evaluateMonitoringVisit(inputA);
  const second = evaluateMonitoringVisit(inputB);

  assert.equal(first.status, 'ready');
  assert.deepEqual(first.reasons, []);
  assert.equal(first.monitoringVisit.visitType, 'interim_monitoring');
  assert.equal(first.monitoringVisit.accessMode, 'metadata_only_monitoring');
  assert.deepEqual(first.monitoringVisit.reviewDomains, REQUIRED_REVIEW_DOMAINS);
  assert.deepEqual(first.monitoringVisit.findingSummary, {
    critical: 1,
    major: 1,
    minor: 0,
    observation: 1,
  });
  assert.deepEqual(first.monitoringVisit.requiredEscalationRoles, [
    'decision_forum_chair',
    'site_quality_lead',
  ]);
  assert.deepEqual(first.monitoringVisit.capaRefs, ['CAPA-FIND-MON-PROTOCOL-001', 'CAPA-FIND-MON-SOURCE-001']);
  assert.deepEqual(first.monitoringVisit.actionItemRefs, ['ACT-MON-PROTOCOL-001', 'ACT-MON-SOURCE-001']);
  assert.equal(first.monitoringVisit.sourceCrfConsistencyStatus, 'verified');
  assert.equal(first.monitoringVisit.consentReviewStatus, 'verified');
  assert.equal(first.monitoringVisit.safetyReviewStatus, 'verified');
  assert.equal(first.monitoringVisit.metadataOnly, true);
  assert.equal(first.monitoringVisit.productionTrustClaim, false);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'monitoring_visit_record');
  assert.equal(first.monitoringVisit.monitoringVisitId, second.monitoringVisit.monitoringVisitId);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.actionHash, second.receipt.actionHash);
  assert.doesNotMatch(JSON.stringify(first), /participant alice|medical record|source document|case report form body/iu);
});

test('monitoring visit supports clean visits with no findings and documented no-action rationale', async () => {
  const { evaluateMonitoringVisit } = await loadMonitoringVisits();
  const result = evaluateMonitoringVisit(
    monitoringVisitInput({
      findings: [],
      actionItems: [],
      noFindingRationale: {
        rationaleHash: DIGEST_8,
        reviewerDid: 'did:exo:quality-manager-alpha',
        reviewedAtHlc: { physicalMs: 1802020300000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
    }),
  );

  assert.equal(result.status, 'ready');
  assert.equal(result.monitoringVisit.findingCount, 0);
  assert.deepEqual(result.monitoringVisit.requiredEscalationRoles, []);
  assert.deepEqual(result.monitoringVisit.actionItemRefs, []);
});

test('monitoring visit fails closed for authority review findings report and boundary defects', async () => {
  const { evaluateMonitoringVisit } = await loadMonitoringVisits();
  const denied = evaluateMonitoringVisit(
    monitoringVisitInput({
      targetTenantId: 'tenant-site-beta',
      actor: {
        did: 'did:exo:ai-monitor-alpha',
        kind: 'ai_agent',
        roleRefs: ['cro_monitor'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: 'not-a-digest',
      },
      visitPlan: {
        visitRef: '',
        visitType: 'unscheduled_visit',
        scheduledStartHlc: { physicalMs: 1802000000000, logical: 0 },
        scheduledEndHlc: { physicalMs: 1801990000000, logical: 0 },
        productionTrustClaim: true,
      },
      accessPolicy: {
        status: 'inactive',
        allowedRoles: ['sponsor_viewer'],
        allowedReviewDomains: REQUIRED_REVIEW_DOMAINS.filter((domain) => domain !== 'source_crf_consistency'),
        leastPrivilege: false,
        disclosureLogRequired: false,
        protectedContentSuppressed: false,
        directIdentifiersSuppressed: false,
        sourceDocumentsExcluded: false,
      },
      reviewEvidence: {
        domains: REQUIRED_REVIEW_DOMAINS.filter((domain) => domain !== 'safety_reporting').map((domain, index) =>
          reviewDomain(domain, index),
        ),
        sourceCrfConsistency: {
          status: 'unverified',
          reviewedRecordCount: 0,
          discrepancyCount: -1,
          discrepancyRegisterHash: '',
          reviewerDid: '',
          reviewedAtHlc: { physicalMs: 1802000000000, logical: 0 },
          metadataOnly: false,
          protectedContentExcluded: false,
        },
        consentReview: {
          status: 'blocked',
          activeConsentVersionRef: '',
          reviewedConsentRecordCount: 0,
          missingConsentCount: 1,
          supersededFormUseDetected: true,
          evidenceHash: '',
          reviewedAtHlc: { physicalMs: 1802000000000, logical: 0 },
        },
        safetyReview: {
          status: 'blocked',
          eventLogHash: '',
          saeReconciliationHash: '',
          unresolvedSafetySignalCount: 1,
          reviewedAtHlc: { physicalMs: 1802000000000, logical: 0 },
        },
      },
      findings: [
        finding('', 'critical', {
          status: 'closed',
          domain: 'unsupported_domain',
          findingHash: '',
          evidenceHash: '',
          ownerDid: '',
          dueAtHlc: { physicalMs: 1802010000000, logical: 0 },
          capaRequired: true,
          capaRef: '',
          decisionForumRequired: true,
          decisionForumMatterRef: '',
          metadataOnly: false,
          protectedContentExcluded: false,
        }),
      ],
      actionItems: [
        actionItem('', 'missing-finding', {
          actionHash: '',
          ownerDid: '',
          status: 'closed',
          escalationRole: 'unsupported_role',
          metadataOnly: false,
          protectedContentExcluded: false,
        }),
      ],
      noFindingRationale: null,
      visitReport: {
        reportHash: '',
        reportVersion: '',
        draftedAtHlc: { physicalMs: 1802010000000, logical: 0 },
        approvedAtHlc: { physicalMs: 1802000000000, logical: 0 },
        reviewedBySiteDid: '',
        reviewedBySponsorDid: '',
        disclosureLogHash: '',
        oversightSummaryHash: '',
        locked: false,
        metadataOnly: false,
        protectedContentExcluded: false,
      },
      humanReview: {
        status: 'pending',
        reviewerDid: '',
        reviewHash: '',
        reviewedAtHlc: { physicalMs: 1802010000000, logical: 0 },
        aiAssisted: true,
        aiFinalAuthority: true,
      },
      receiptEvidence: {
        artifactHash: '',
        custodyDigest: '',
      },
    }),
  );

  assert.equal(denied.status, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.monitoringVisit, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('monitoring_visit_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('visit_ref_absent'));
  assert.ok(denied.reasons.includes('visit_type_invalid'));
  assert.ok(denied.reasons.includes('visit_end_not_after_start'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('monitoring_policy_inactive'));
  assert.ok(denied.reasons.includes('monitoring_actor_role_not_allowed:cro_monitor'));
  assert.ok(denied.reasons.includes('monitoring_policy_least_privilege_absent'));
  assert.ok(denied.reasons.includes('monitoring_policy_disclosure_log_not_required'));
  assert.ok(denied.reasons.includes('monitoring_policy_protected_boundary_absent'));
  assert.ok(denied.reasons.includes('monitoring_policy_direct_identifier_boundary_absent'));
  assert.ok(denied.reasons.includes('monitoring_policy_source_document_boundary_absent'));
  assert.ok(denied.reasons.includes('review_domain_missing:safety_reporting'));
  assert.ok(denied.reasons.includes('review_domain_not_allowed:safety_reporting'));
  assert.ok(denied.reasons.includes('source_crf_consistency_unverified'));
  assert.ok(denied.reasons.includes('source_crf_discrepancy_count_invalid'));
  assert.ok(denied.reasons.includes('consent_review_not_verified'));
  assert.ok(denied.reasons.includes('consent_review_missing_consent_records'));
  assert.ok(denied.reasons.includes('consent_review_superseded_form_detected'));
  assert.ok(denied.reasons.includes('safety_review_not_verified'));
  assert.ok(denied.reasons.includes('safety_review_unresolved_signals'));
  assert.ok(denied.reasons.includes('finding_ref_absent'));
  assert.ok(denied.reasons.includes('finding_domain_unsupported:unknown_finding'));
  assert.ok(denied.reasons.includes('finding_capa_ref_absent:unknown_finding'));
  assert.ok(denied.reasons.includes('finding_decision_forum_ref_absent:unknown_finding'));
  assert.ok(denied.reasons.includes('action_item_ref_absent'));
  assert.ok(denied.reasons.includes('action_item_finding_missing:unknown_action_item'));
  assert.ok(denied.reasons.includes('report_not_locked'));
  assert.ok(denied.reasons.includes('human_monitoring_review_not_approved'));
  assert.ok(denied.reasons.includes('human_review_ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('receipt_artifact_hash_invalid'));
  assert.ok(denied.reasons.includes('receipt_custody_digest_invalid'));
});

test('monitoring visit denies absent objects without issuing receipts', async () => {
  const { evaluateMonitoringVisit } = await loadMonitoringVisits();
  const denied = evaluateMonitoringVisit({
    tenantId: '',
    targetTenantId: 'tenant-site-alpha',
    actor: null,
    authority: null,
    visitPlan: null,
    accessPolicy: null,
    reviewEvidence: null,
    findings: null,
    actionItems: null,
    visitReport: null,
    humanReview: null,
    receiptEvidence: null,
  });

  assert.equal(denied.status, 'denied');
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('actor_did_absent'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('visit_ref_absent'));
  assert.ok(denied.reasons.includes('monitoring_policy_ref_absent'));
  assert.ok(denied.reasons.includes('review_evidence_absent'));
  assert.ok(denied.reasons.includes('visit_report_absent'));
  assert.ok(denied.reasons.includes('human_review_absent'));
  assert.ok(denied.reasons.includes('receipt_artifact_hash_invalid'));
  assert.ok(denied.reasons.includes('receipt_custody_digest_invalid'));
  assert.equal(denied.monitoringVisit, null);
  assert.equal(denied.receipt, null);
});

test('monitoring visit rejects raw monitoring content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateMonitoringVisit } = await loadMonitoringVisits();

  assert.throws(
    () =>
      evaluateMonitoringVisit(
        monitoringVisitInput({
          reviewEvidence: {
            rawSourceDocument: 'complete case report form body for participant Alice',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateMonitoringVisit(
        monitoringVisitInput({
          visitReport: {
            rawMonitoringNotes: 'monitoring narrative with source document excerpts',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateMonitoringVisit(
        monitoringVisitInput({
          accessPolicy: {
            apiKey: 'secret-monitoring-provider-token',
          },
        }),
      ),
    ProtectedContentError,
  );
});
