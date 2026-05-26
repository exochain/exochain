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

const REQUIRED_PUBLICATION_DOMAINS = [
  'audit_trail',
  'change_control',
  'crosslink_refresh',
  'distribution_acknowledgement',
  'draft_review',
  'drift_feedback',
  'manual_versioning',
  'training_update',
];

const REQUIRED_CHANGE_TYPES = [
  'crosslink_refresh',
  'inspection_guide_update',
  'manual_revision',
  'runbook_update',
  'training_notice',
  'workflow_guide_update',
];

async function loadDocumentationPublication() {
  try {
    return await import('../src/documentation-publication.mjs');
  } catch (error) {
    assert.fail(`CyberMedica documentation publication module must exist and load: ${error.message}`);
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

function publicationEvidence(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    domain,
    evidenceRef: `publication-evidence-${domain}`,
    evidenceHash: hashes[index],
    ownerRoleRef: domain === 'training_update' ? 'training_owner' : 'quality_manager',
    approved: true,
    reviewedAtHlc: { physicalMs: 1800009000000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function publicationEvidenceItems() {
  return REQUIRED_PUBLICATION_DOMAINS.map((domain, index) => publicationEvidence(domain, index));
}

function changeRequest(changeType, index, overrides = {}) {
  const highRisk = changeType === 'manual_revision';
  return {
    changeRef: `doc-change-${changeType}`,
    sourceBacklogItemRef: `cqi-item-${changeType}`,
    sourceSignalRef: `inquiry-${changeType}`,
    changeType,
    draftHash: [DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1][index],
    rationaleHash: [DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_7][index],
    affectedManualRefs: [`manual-${changeType}`],
    affectedWorkflowRefs: [`workflow-${changeType}`],
    ownerRoleRef: highRisk ? 'quality_manager' : 'documentation_owner',
    requiresTrainingUpdate: changeType === 'training_notice',
    highRiskReviewRequired: highRisk,
    highRiskReviewHash: highRisk ? DIGEST_8 : null,
    draftedAtHlc: { physicalMs: 1800008900000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function changeRequests() {
  return REQUIRED_CHANGE_TYPES.map((changeType, index) => changeRequest(changeType, index));
}

function publicationInput(overrides = {}) {
  const changes = changeRequests();
  return mergeDeep(
    {
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-alpha',
      actor: {
        did: 'did:exo:documentation-publisher-alpha',
        kind: 'human',
        roleRefs: ['quality_manager', 'documentation_owner'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['documentation_publish', 'govern'],
        authorityChainHash: DIGEST_A,
      },
      publicationPolicy: {
        policyRef: 'documentation-publication-policy-alpha',
        policyHash: DIGEST_B,
        status: 'active',
        requiredPublicationDomains: REQUIRED_PUBLICATION_DOMAINS,
        requiredChangeTypes: REQUIRED_CHANGE_TYPES,
        humanApprovalRequired: true,
        versionGovernanceRequired: true,
        crosslinkValidationRequired: true,
        effectiveUseAcknowledgementRequired: true,
        driftFeedbackRequired: true,
        aiAssistanceAdvisoryOnly: true,
        metadataOnly: true,
        protectedContentExcluded: true,
        evaluatedAtHlc: { physicalMs: 1800008800000, logical: 0 },
      },
      publicationCycle: {
        cycleRef: 'documentation-publication-cycle-alpha',
        openedAtHlc: { physicalMs: 1800008850000, logical: 0 },
        draftReadyAtHlc: { physicalMs: 1800008900000, logical: 0 },
        crosslinksValidatedAtHlc: { physicalMs: 1800009000000, logical: 0 },
        humanApprovedAtHlc: { physicalMs: 1800009100000, logical: 0 },
        publishedAtHlc: { physicalMs: 1800009200000, logical: 0 },
        distributionRecordedAtHlc: { physicalMs: 1800009300000, logical: 0 },
        auditRecordedAtHlc: { physicalMs: 1800009400000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
        productionTrustClaim: false,
      },
      sourceBacklog: {
        inquiryCqiBacklogReceiptHash: DIGEST_C,
        documentationRunbookReceiptHash: DIGEST_D,
        currentManualSetHash: DIGEST_E,
        currentManualIndexHash: DIGEST_F,
        cqiActionPackageHash: DIGEST_1,
        driftImprovementRef: 'drift-documentation-friction-alpha',
        noRawInquiryContent: true,
        reviewedAtHlc: { physicalMs: 1800008860000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      publicationEvidence: publicationEvidenceItems(),
      changeRequests: changes,
      crosslinkRefresh: {
        matrixRef: 'manual-crosslink-matrix-alpha-v2',
        matrixHash: DIGEST_2,
        priorMatrixHash: DIGEST_3,
        linksControls: true,
        linksEvidence: true,
        linksProcedures: true,
        linksWorkflows: true,
        linksPolicies: true,
        brokenLinkCount: 0,
        affectedControlRefs: ['control-documentation-governance'],
        affectedEvidenceRefs: ['evidence-documentation-publication'],
        refreshedAtHlc: { physicalMs: 1800009000000, logical: 1 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      versionGovernance: {
        newManualSetHash: DIGEST_4,
        priorManualSetHash: DIGEST_E,
        versionRef: 'manual-set-alpha-v2',
        changeControlRef: 'manual-change-control-alpha-v2',
        supersededVersionsRetained: true,
        rollbackVersionRef: 'manual-set-alpha-v1',
        rollbackVersionHash: DIGEST_E,
        distributionPlanHash: DIGEST_5,
        effectiveUseAcknowledgementRequired: true,
        approvedByHuman: true,
        approvedAtHlc: { physicalMs: 1800009100000, logical: 1 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      publicationPackage: {
        packageRef: 'documentation-publication-package-alpha',
        linkedChangeRefs: changes.map((change) => change.changeRef),
        publicationArtifactHash: DIGEST_6,
        releaseNotesHash: DIGEST_7,
        manualIndexHash: DIGEST_8,
        accessPolicyHash: DIGEST_9,
        communicationEvidenceHash: DIGEST_A,
        staffNotificationHash: DIGEST_B,
        publishedAtHlc: { physicalMs: 1800009200000, logical: 1 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      acknowledgementPlan: {
        planRef: 'documentation-effective-use-ack-alpha',
        requiredRoleRefs: [
          'administrator',
          'clinical_research_coordinator',
          'principal_investigator',
          'quality_manager',
          'site_leader',
        ],
        acknowledgementPolicyHash: DIGEST_C,
        dueAtHlc: { physicalMs: 1800009500000, logical: 0 },
        blockedSupersededUse: true,
        staffCommunicationHash: DIGEST_D,
        recordedAtHlc: { physicalMs: 1800009300000, logical: 1 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      driftFeedback: {
        driftSignalRef: 'drift-documentation-publication-alpha',
        driftSignalHash: DIGEST_E,
        cqiBacklogUpdated: true,
        runbookIndexUpdated: true,
        effectivenessReviewScheduled: true,
        scheduledReviewAtHlc: { physicalMs: 1800010000000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      aiAssistant: {
        used: true,
        assistantRef: 'documentation-publication-ai-alpha',
        recommendationHash: DIGEST_F,
        limitationHashes: [DIGEST_1],
        advisoryOnly: true,
        finalAuthority: false,
        humanReviewed: true,
        reviewedAtHlc: { physicalMs: 1800009050000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      humanReview: {
        reviewerDid: 'did:exo:quality-owner-alpha',
        reviewerRoleRefs: ['quality_manager'],
        decision: 'documentation_publication_ready',
        decisionHash: DIGEST_2,
        finalAuthority: 'human',
        aiFinalAuthority: false,
        noProductionTrustClaim: true,
        reviewedAtHlc: { physicalMs: 1800009150000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      validationEvidence: {
        commandRefs: ['node --test tests/documentation-publication.test.mjs', 'npm run quality'],
        commandsPassed: true,
        sourceGuardPassed: true,
        noExochainSourceModified: true,
        recordedAtHlc: { physicalMs: 1800009400000, logical: 1 },
        metadataOnly: true,
      },
      custodyDigest: DIGEST_3,
    },
    overrides,
  );
}

test('documentation change publication produces deterministic inactive publication receipts', async () => {
  const { evaluateDocumentationChangePublication } = await loadDocumentationPublication();
  const input = publicationInput();

  const first = evaluateDocumentationChangePublication(input);
  const second = evaluateDocumentationChangePublication(input);

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first, second);
  assert.equal(first.documentationPublication.trustState, 'inactive');
  assert.equal(first.documentationPublication.exochainProductionClaim, false);
  assert.equal(first.documentationPublication.metadataOnly, true);
  assert.equal(first.documentationPublication.containsProtectedContent, false);
  assert.deepEqual(first.documentationPublication.publicationDomains, REQUIRED_PUBLICATION_DOMAINS);
  assert.deepEqual(first.documentationPublication.changeTypes, REQUIRED_CHANGE_TYPES);
  assert.equal(first.documentationPublication.changeCount, 6);
  assert.deepEqual(first.documentationPublication.highRiskChangeRefs, ['doc-change-manual_revision']);
  assert.equal(first.documentationPublication.crosslinkRefreshReady, true);
  assert.equal(first.documentationPublication.distributionReady, true);
  assert.equal(first.documentationPublication.driftFeedbackReady, true);
  assert.equal(first.documentationPublication.aiAssistanceUsed, true);
  assert.equal(first.receipt.anchorPayload.artifactType, 'documentation_change_publication');
  assert.equal(first.receipt.anchorPayload.classification, 'metadata_only_documentation_publication');
});

test('documentation publication fails closed for missing domain coverage and incomplete package links', async () => {
  const { evaluateDocumentationChangePublication } = await loadDocumentationPublication();
  const changes = changeRequests().filter((change) => change.changeType !== 'training_notice');
  const result = evaluateDocumentationChangePublication(
    publicationInput({
      publicationCycle: { productionTrustClaim: true },
      publicationEvidence: publicationEvidenceItems().filter((row) => row.domain !== 'distribution_acknowledgement'),
      changeRequests: changes,
      crosslinkRefresh: { brokenLinkCount: 1 },
      publicationPackage: { linkedChangeRefs: changes.slice(0, -1).map((change) => change.changeRef) },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.match(result.reasons.join('\n'), /publication_domain_missing:distribution_acknowledgement/u);
  assert.match(result.reasons.join('\n'), /change_type_missing:training_notice/u);
  assert.match(result.reasons.join('\n'), /publication_package_missing_change:doc-change-workflow_guide_update/u);
  assert.match(result.reasons.join('\n'), /crosslink_refresh_has_broken_links/u);
  assert.match(result.reasons.join('\n'), /production_trust_claim_forbidden/u);
});

test('documentation publication requires high-risk review and advisory-only AI assistance', async () => {
  const { evaluateDocumentationChangePublication } = await loadDocumentationPublication();
  const changes = changeRequests().map((change) =>
    change.changeType === 'manual_revision' ? { ...change, highRiskReviewHash: null } : change,
  );
  const result = evaluateDocumentationChangePublication(
    publicationInput({
      changeRequests: changes,
      aiAssistant: {
        advisoryOnly: false,
        finalAuthority: true,
        humanReviewed: false,
      },
      humanReview: {
        aiFinalAuthority: true,
        finalAuthority: 'ai',
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /change_request_invalid:doc-change-manual_revision:high_risk_review_hash_invalid/u);
  assert.match(result.reasons.join('\n'), /ai_assistant_not_advisory_only/u);
  assert.match(result.reasons.join('\n'), /ai_final_authority_forbidden/u);
  assert.match(result.reasons.join('\n'), /human_final_authority_missing/u);
});

test('documentation publication validates HLC ordering and supports no AI operation', async () => {
  const { evaluateDocumentationChangePublication } = await loadDocumentationPublication();

  const noAi = evaluateDocumentationChangePublication(publicationInput({ aiAssistant: { used: false } }));
  assert.equal(noAi.decision, 'permitted');
  assert.equal(noAi.documentationPublication.aiAssistanceUsed, false);

  const inertRawMarkers = evaluateDocumentationChangePublication(
    publicationInput({
      publicationPackage: {
        rawManualContent: [false, null],
        rawPublicationContent: {},
        releaseCopy: false,
      },
    }),
  );
  assert.equal(inertRawMarkers.decision, 'permitted');

  const result = evaluateDocumentationChangePublication(
    publicationInput({
      publicationCycle: {
        crosslinksValidatedAtHlc: { physicalMs: 1800008899999, logical: 0 },
        publishedAtHlc: { physicalMs: 1800009099999, logical: 0 },
      },
      crosslinkRefresh: { refreshedAtHlc: { physicalMs: 1800008899998, logical: 0 } },
      versionGovernance: { approvedAtHlc: { physicalMs: 1800009000000, logical: 0 } },
      acknowledgementPlan: { recordedAtHlc: { physicalMs: 1800009199999, logical: 0 } },
      validationEvidence: { recordedAtHlc: { physicalMs: 1800009300000, logical: -1 } },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /publication_cycle_crosslinksValidatedAtHlc_before_draftReadyAtHlc/u);
  assert.match(result.reasons.join('\n'), /crosslink_refresh_before_cycle_validation/u);
  assert.match(result.reasons.join('\n'), /publication_cycle_publishedAtHlc_before_humanApprovedAtHlc/u);
  assert.match(result.reasons.join('\n'), /acknowledgement_record_before_distribution/u);
  assert.match(result.reasons.join('\n'), /validation_record_time_invalid/u);

  const equalClockResult = evaluateDocumentationChangePublication(
    publicationInput({
      versionGovernance: { approvedAtHlc: { physicalMs: 1800009000000, logical: 0 } },
    }),
  );
  assert.equal(equalClockResult.decision, 'denied');
  assert.match(equalClockResult.reasons.join('\n'), /manual_version_approval_time_not_after_crosslinks/u);
});

test('documentation publication handles absent objects and malformed clocks as denial states', async () => {
  const { evaluateDocumentationChangePublication } = await loadDocumentationPublication();
  const result = evaluateDocumentationChangePublication({});

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /tenant_absent/u);
  assert.match(result.reasons.join('\n'), /publication_policy_ref_absent/u);
  assert.match(result.reasons.join('\n'), /publication_cycle_openedAtHlc_invalid/u);
  assert.match(result.reasons.join('\n'), /source_backlog_receipt_hash_invalid/u);
  assert.match(result.reasons.join('\n'), /publication_package_ref_absent/u);
});

test('documentation publication rejects raw manual content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDocumentationChangePublication } = await loadDocumentationPublication();

  assert.throws(
    () => evaluateDocumentationChangePublication(publicationInput({ publicationPackage: { rawManualContent: 'new manual body' } })),
    ProtectedContentError,
  );
  assert.throws(
    () =>
      evaluateDocumentationChangePublication(
        publicationInput({ changeRequests: [{ ...changeRequests()[0], reviewerEmail: 'qa@example.com' }] }),
      ),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateDocumentationChangePublication(publicationInput({ aiAssistant: { apiKey: DIGEST_A } })),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateDocumentationChangePublication(publicationInput({ aiAssistant: { apiKey: 7 } })),
    ProtectedContentError,
  );
});
