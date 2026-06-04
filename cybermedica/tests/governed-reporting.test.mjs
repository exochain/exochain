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

const REQUIRED_REPORT_DOMAINS = [
  'audit',
  'capa',
  'consent_readiness',
  'deviations',
  'equipment',
  'product_accountability',
  'qms_status',
  'risk',
  'site_readiness',
  'sponsor_diligence',
  'training',
];

async function loadGovernedReporting() {
  try {
    return await import('../src/governed-reporting.mjs');
  } catch (error) {
    assert.fail(`CyberMedica governed reporting module must exist and load: ${error.message}`);
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

function sourceManifestRows(domains = REQUIRED_REPORT_DOMAINS) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5];
  return domains.map((domain, index) => ({
    domain,
    sourceFamilyRef: `source-family-${domain}`,
    sourceManifestHash: hashes[index],
    evidenceIndexHash: hashes[(index + 1) % hashes.length],
    auditTrailHash: hashes[(index + 2) % hashes.length],
    custodyDigest: hashes[(index + 3) % hashes.length],
    freshnessHlc: { physicalMs: 1796000500000 + index, logical: 0 },
    accessDecision: 'permitted',
    accessPolicyRef: `access-policy-${domain}`,
    metadataOnly: true,
    phiPiiExcluded: true,
    sponsorConfidentialMinimized: true,
    sourcePayloadExcluded: true,
    containsRawContent: false,
  }));
}

function reportingInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'site_leader'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['report_generate', 'read'],
      authorityChainHash: DIGEST_A,
    },
    apiAccess: {
      accessId: 'cmapi_authorized_reporting_alpha',
      accessHash: DIGEST_B,
      status: 'authorized',
      family: 'reporting',
      endpointRef: 'governed-reporting-api',
      method: 'GET',
      purpose: 'reporting',
      scopes: ['api:read', 'report:generate'],
      participantLinked: false,
      metadataOnly: true,
      sourcePayloadsStayExternal: true,
      failClosedApiAccess: false,
      trustState: 'inactive',
      exochainProductionClaim: false,
    },
    reportTemplate: {
      templateRef: 'report-template-fr050-standard',
      templateVersion: 'v1',
      templateKind: 'standard',
      status: 'approved',
      schemaVersion: 'cybermedica.governed_report_template.v1',
      approvedByDid: 'did:exo:qms-governance-owner',
      approvedAtHlc: { physicalMs: 1796000000000, logical: 1 },
      templateHash: DIGEST_C,
      outputProfileHash: DIGEST_D,
      accessPolicyHash: DIGEST_E,
      retentionPolicyHash: DIGEST_F,
      supportedDomains: REQUIRED_REPORT_DOMAINS,
      supportedFormats: ['json', 'pdf'],
      metadataOnly: true,
      productionTrustClaim: false,
    },
    customDefinition: null,
    reportRequest: {
      requestRef: 'report-request-fr050-alpha',
      reportRef: 'qms-status-readiness-alpha',
      purpose: 'reporting',
      apiAccessHash: DIGEST_B,
      requestedDomains: REQUIRED_REPORT_DOMAINS,
      requestedFormat: 'json',
      audienceRefs: ['quality_manager', 'site_leader', 'sponsor_viewer'],
      requestedAtHlc: { physicalMs: 1796000600000, logical: 0 },
      generatedAtHlc: { physicalMs: 1796000600000, logical: 3 },
      periodStartHlc: { physicalMs: 1795000000000, logical: 0 },
      periodEndHlc: { physicalMs: 1796000501000, logical: 0 },
      metadataOnly: true,
    },
    dataManifest: {
      schema: 'cybermedica.report_data_manifest.v1',
      manifestHash: DIGEST_1,
      custodyDigest: DIGEST_2,
      metadataOnly: true,
      sourcePayloadsExcluded: true,
      directIdentifiersExcluded: true,
      domainRows: sourceManifestRows(),
    },
    privacyBoundary: {
      boundaryRef: 'report-privacy-boundary-alpha',
      boundaryHash: DIGEST_3,
      metadataOnly: true,
      phiPiiExcluded: true,
      participantDirectIdentifiersExcluded: true,
      sponsorConfidentialMinimized: true,
      sourcePayloadsStayExternal: true,
      disclosureLogRequired: true,
    },
    disclosureLog: {
      logRef: 'report-disclosure-log-alpha',
      disclosureLogHash: DIGEST_4,
      loggedAtHlc: { physicalMs: 1796000600000, logical: 4 },
      recipientClasses: ['quality_manager', 'site_leader', 'sponsor_viewer'],
      purpose: 'reporting',
      includesRawContent: false,
    },
    exportPlan: {
      exportRef: 'report-export-plan-alpha',
      format: 'json',
      artifactHash: DIGEST_5,
      evidenceIndexHash: DIGEST_6,
      auditTrailHash: DIGEST_A,
      versionHistoryHash: DIGEST_B,
      accessLogHash: DIGEST_C,
      retentionRuleRef: 'retention-qms-report-alpha',
      structuredExport: true,
      portableExportSubjectToAccessPolicy: true,
      metadataOnly: true,
      rawContentExcluded: true,
      productionTrustClaim: false,
    },
    sponsorExportGrant: {
      grantRef: 'sponsor-diligence-report-grant-alpha',
      grantHash: DIGEST_D,
      status: 'active',
      scope: 'sponsor_diligence_report',
    },
    sponsorCroRequestEvidence: {
      requestRef: 'sponsor-cro-request-alpha',
      requestHash: DIGEST_E,
      requesterClass: 'sponsor',
      workItemRef: 'sponsor-cro-work-item-alpha',
      workItemStatus: 'queued_for_site_review',
      disclosureEventRef: 'disclosure-event-sponsor-cro-alpha',
      disclosureLogHash: DIGEST_4,
      decisionForumMatterRef: 'df-sponsor-cro-request-alpha',
      humanReviewHash: DIGEST_2,
      responsePackageHash: DIGEST_5,
      linkedReportRef: 'qms-status-readiness-alpha',
      metadataOnly: true,
      sourcePayloadExcluded: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
      linkedAtHlc: { physicalMs: 1796000600000, logical: 2 },
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      evidenceRefs: ['evidence-index-alpha', 'audit-trail-alpha'],
      reasoningSummaryHash: DIGEST_E,
      confidenceBasisPoints: 8700,
      limitationHashes: [DIGEST_F],
      unresolvedAssumptionHashes: [DIGEST_1],
      recommendedHumanReviewerDids: ['did:exo:quality-manager-alpha'],
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      status: 'approved',
      reviewedAtHlc: { physicalMs: 1796000600000, logical: 5 },
      reviewEvidenceHash: DIGEST_2,
      aiFinalAuthorityRejected: true,
    },
    custodyDigest: DIGEST_3,
  };

  return mergeDeep(base, overrides);
}

test('governed reporting generates deterministic standard report receipts across all FR-050 domains', async () => {
  const { evaluateGovernedReport } = await loadGovernedReporting();

  const resultA = evaluateGovernedReport(reportingInput());
  const resultB = evaluateGovernedReport(
    reportingInput({
      reportRequest: {
        requestedDomains: [...REQUIRED_REPORT_DOMAINS].reverse(),
        audienceRefs: ['sponsor_viewer', 'site_leader', 'quality_manager'],
      },
      dataManifest: {
        domainRows: [...sourceManifestRows()].reverse(),
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.report.status, 'generated');
  assert.equal(resultA.report.templateKind, 'standard');
  assert.deepEqual(resultA.report.includedDomains, REQUIRED_REPORT_DOMAINS);
  assert.equal(resultA.report.metadataOnly, true);
  assert.equal(resultA.report.exochainProductionClaim, false);
  assert.deepEqual(resultA.report.sponsorCroRequestRefs, ['sponsor-cro-request-alpha']);
  assert.deepEqual(resultA.report.sponsorCroWorkItemRefs, ['sponsor-cro-work-item-alpha']);
  assert.deepEqual(resultA.report.sponsorCroResponsePackageHashes, [DIGEST_5]);
  assert.equal(resultA.report.reportHash, resultB.report.reportHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'governed_report');
  assert.doesNotMatch(JSON.stringify(resultA), /raw narrative|Participant Alice|source document|access token/iu);
});

test('governed reporting supports approved custom reports with explainable advisory AI metadata', async () => {
  const { evaluateGovernedReport } = await loadGovernedReporting();

  const domains = ['audit', 'capa', 'risk'];
  const result = evaluateGovernedReport(
    reportingInput({
      reportTemplate: {
        templateRef: 'report-template-fr050-custom',
        templateKind: 'custom',
        supportedDomains: domains,
        supportedFormats: ['pdf'],
      },
      customDefinition: {
        definitionRef: 'custom-report-risk-capa-audit',
        status: 'approved',
        ownerDid: 'did:exo:quality-manager-alpha',
        approvedByDid: 'did:exo:qms-governance-owner',
        approvedAtHlc: { physicalMs: 1796000000000, logical: 2 },
        sourceTemplateRef: 'report-template-fr050-custom',
        definitionHash: DIGEST_4,
        domains,
      },
      reportRequest: {
        reportRef: 'custom-risk-capa-audit-alpha',
        requestedDomains: domains,
        requestedFormat: 'pdf',
      },
      dataManifest: {
        domainRows: sourceManifestRows(domains),
      },
      exportPlan: {
        format: 'pdf',
      },
      sponsorExportGrant: null,
      sponsorCroRequestEvidence: null,
    }),
  );

  assert.equal(result.decision, 'permitted');
  assert.equal(result.report.templateKind, 'custom');
  assert.deepEqual(result.report.includedDomains, domains);
  assert.equal(result.report.customDefinitionRef, 'custom-report-risk-capa-audit');
  assert.equal(result.report.aiAssisted, true);
  assert.deepEqual(result.report.aiEvidenceRefs, ['audit-trail-alpha', 'evidence-index-alpha']);
  assert.equal(result.report.aiConfidenceBasisPoints, 8700);
  assert.deepEqual(result.report.aiRecommendedHumanReviewerDids, ['did:exo:quality-manager-alpha']);
});

test('governed reporting fails closed for unsafe API access template access policy and export defects', async () => {
  const { evaluateGovernedReport } = await loadGovernedReporting();

  const denied = evaluateGovernedReport(
    reportingInput({
      targetTenantId: 'tenant-other',
      actor: {
        did: 'did:exo:reporting-ai',
        kind: 'ai_agent',
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      apiAccess: {
        status: 'blocked',
        family: 'integration',
        metadataOnly: false,
        exochainProductionClaim: true,
      },
      reportTemplate: {
        status: 'draft',
        metadataOnly: false,
        productionTrustClaim: true,
        supportedDomains: REQUIRED_REPORT_DOMAINS.filter((domain) => domain !== 'product_accountability'),
      },
      dataManifest: {
        domainRows: sourceManifestRows().map((row) =>
          row.domain === 'sponsor_diligence'
            ? {
                ...row,
                accessDecision: 'denied',
                metadataOnly: false,
              }
            : row,
        ),
      },
      exportPlan: {
        metadataOnly: false,
        portableExportSubjectToAccessPolicy: false,
        productionTrustClaim: true,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.report.status, 'blocked');
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('report_authority_missing'));
  assert.ok(denied.reasons.includes('api_access_not_authorized'));
  assert.ok(denied.reasons.includes('api_access_family_not_reporting'));
  assert.ok(denied.reasons.includes('api_access_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('report_template_not_approved'));
  assert.ok(denied.reasons.includes('report_template_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('template_domain_missing:product_accountability'));
  assert.ok(denied.reasons.includes('domain_access_not_permitted:sponsor_diligence'));
  assert.ok(denied.reasons.includes('domain_metadata_boundary_invalid:sponsor_diligence'));
  assert.ok(denied.reasons.includes('export_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('export_access_policy_boundary_invalid'));
});

test('governed reporting fails closed when sponsor diligence reports are not linked to controlled Sponsor/CRO requests', async () => {
  const { evaluateGovernedReport } = await loadGovernedReporting();

  const absent = evaluateGovernedReport(
    reportingInput({
      sponsorCroRequestEvidence: null,
    }),
  );

  assert.equal(absent.decision, 'denied');
  assert.equal(absent.failClosed, true);
  assert.equal(absent.receipt, null);
  assert.ok(absent.reasons.includes('sponsor_cro_request_evidence_absent'));

  const malformed = evaluateGovernedReport(
    reportingInput({
      sponsorCroRequestEvidence: {
        requestRef: '',
        requestHash: 'not-a-digest',
        requesterClass: 'public_observer',
        workItemRef: '',
        workItemStatus: 'draft',
        disclosureLogHash: '',
        responsePackageHash: 'not-a-digest',
        linkedReportRef: 'other-report',
        metadataOnly: false,
        sourcePayloadExcluded: false,
        protectedContentExcluded: false,
        productionTrustClaim: true,
        linkedAtHlc: { physicalMs: 1796000600000, logical: -1 },
      },
    }),
  );

  assert.equal(malformed.decision, 'denied');
  assert.ok(malformed.reasons.includes('sponsor_cro_request_ref_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_hash_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_requester_class_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_work_item_ref_absent'));
  assert.ok(malformed.reasons.includes('sponsor_cro_work_item_status_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_disclosure_log_hash_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_response_package_hash_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_linked_report_mismatch'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_metadata_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_source_payload_boundary_invalid'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_protected_boundary_invalid'));
  assert.ok(malformed.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(malformed.reasons.includes('sponsor_cro_request_link_time_invalid'));

  const mismatched = evaluateGovernedReport(
    reportingInput({
      sponsorCroRequestEvidence: {
        disclosureLogHash: DIGEST_6,
        humanReviewHash: DIGEST_6,
        responsePackageHash: DIGEST_6,
        linkedAtHlc: { physicalMs: 1796000600000, logical: 7 },
      },
    }),
  );

  assert.equal(mismatched.decision, 'denied');
  assert.ok(mismatched.reasons.includes('sponsor_cro_disclosure_log_hash_mismatch'));
  assert.ok(mismatched.reasons.includes('sponsor_cro_human_review_hash_mismatch'));
  assert.ok(mismatched.reasons.includes('sponsor_cro_response_package_hash_mismatch'));
  assert.ok(mismatched.reasons.includes('sponsor_cro_request_link_after_report_generation'));
});

test('governed reporting requires human review and rejects AI final authority', async () => {
  const { evaluateGovernedReport } = await loadGovernedReporting();

  const denied = evaluateGovernedReport(
    reportingInput({
      aiAssistance: {
        used: true,
        finalAuthority: true,
        evidenceRefs: [],
        reasoningSummaryHash: 'not-a-digest',
        confidenceBasisPoints: 10001,
        limitationHashes: [],
        unresolvedAssumptionHashes: [DIGEST_1],
        recommendedHumanReviewerDids: [],
      },
      humanReview: {
        reviewerDid: '',
        status: 'pending',
        reviewedAtHlc: { physicalMs: 1796000600000, logical: 2 },
        reviewEvidenceHash: 'not-a-digest',
        aiFinalAuthorityRejected: false,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_evidence_refs_absent'));
  assert.ok(denied.reasons.includes('ai_reasoning_summary_hash_invalid'));
  assert.ok(denied.reasons.includes('ai_confidence_basis_points_invalid'));
  assert.ok(denied.reasons.includes('ai_limitations_absent'));
  assert.ok(denied.reasons.includes('ai_recommended_human_reviewers_absent'));
  assert.ok(denied.reasons.includes('human_report_reviewer_absent'));
  assert.ok(denied.reasons.includes('human_report_review_not_approved'));
  assert.ok(denied.reasons.includes('human_review_before_report_generation'));
  assert.ok(denied.reasons.includes('human_review_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('ai_final_authority_not_rejected'));
});

test('governed reporting validates HLC ordering including same tick logical clocks', async () => {
  const { evaluateGovernedReport } = await loadGovernedReporting();

  const sameTick = evaluateGovernedReport(
    reportingInput({
      disclosureLog: {
        loggedAtHlc: { physicalMs: 1796000600000, logical: 6 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1796000600000, logical: 5 },
      },
    }),
  );

  assert.equal(sameTick.decision, 'permitted');

  const denied = evaluateGovernedReport(
    reportingInput({
      reportRequest: {
        generatedAtHlc: { physicalMs: 1796000600000, logical: 0 },
      },
      disclosureLog: {
        loggedAtHlc: { physicalMs: 1796000600000, logical: 2 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1796000600000, logical: 1 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('report_generated_before_request'));

  const malformed = evaluateGovernedReport(
    reportingInput({
      reportRequest: {
        generatedAtHlc: { physicalMs: '1796000600000', logical: 3 },
      },
      disclosureLog: {
        loggedAtHlc: { physicalMs: 1796000600000, logical: 4 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1796000600000, logical: 5 },
      },
    }),
  );

  assert.equal(malformed.decision, 'denied');
  assert.ok(malformed.reasons.includes('report_generation_time_invalid'));
});

test('governed reporting rejects raw report exports source content and protected identifiers before receipts', async () => {
  const { ProtectedContentError, evaluateGovernedReport } = await loadGovernedReporting();

  const noAi = evaluateGovernedReport(
    reportingInput({
      aiAssistance: { used: false },
      exportPlan: {
        rawExport: false,
      },
      privacyBoundary: {
        rawReport: [],
      },
    }),
  );

  assert.equal(noAi.decision, 'permitted');
  assert.equal(noAi.report.aiAssisted, false);

  assert.throws(
    () =>
      evaluateGovernedReport(
        reportingInput({
          reportRequest: {
            rawReportText: 'raw narrative must not enter receipts',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateGovernedReport(
        reportingInput({
          exportPlan: {
            rawExport: 7,
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateGovernedReport(
        reportingInput({
          apiAccess: {
            apiKey: 'redacted-key',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateGovernedReport(
        reportingInput({
          dataManifest: {
            domainRows: [
              {
                ...sourceManifestRows(['audit'])[0],
                sourceDocumentBody: 'source document body',
              },
            ],
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateGovernedReport(
        reportingInput({
          exportPlan: {
            exportPayload: { participantName: 'Participant Alice' },
          },
        }),
      ),
    ProtectedContentError,
  );
});
