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

const REQUIRED_VENDOR_CATEGORIES = [
  'central_lab',
  'data_management_vendor',
  'imaging_provider',
  'logistics_provider',
  'pharmacy',
  'technology_vendor',
];

async function loadVendorReadiness() {
  try {
    return await import('../src/vendor-subcontractor-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica vendor-subcontractor readiness module must exist and load: ${error.message}`);
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

function vendor(category, index, overrides = {}) {
  const digestCycle = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  const handlesProtectedData = ['central_lab', 'data_management_vendor', 'technology_vendor'].includes(category);
  const base = {
    vendorRef: `vendor-${category}`,
    vendorCategory: category,
    vendorRole: category === 'central_lab' ? 'specimen_processing' : `${category}_service`,
    qualificationStatus: 'qualified',
    criticality: ['central_lab', 'pharmacy', 'data_management_vendor'].includes(category) ? 'critical' : 'major',
    delegatedDutyRefs: [`duty-${category}`],
    linkedProtocolRefs: ['protocol-cardiac-alpha'],
    ownerDid: `did:exo:vendor-owner-${index}`,
    qualificationEvidenceHash: digestCycle[index % digestCycle.length],
    dueDiligenceHash: digestCycle[(index + 1) % digestCycle.length],
    contractAgreementHash: digestCycle[(index + 2) % digestCycle.length],
    serviceLevelHash: digestCycle[(index + 3) % digestCycle.length],
    oversightReviewHash: digestCycle[(index + 4) % digestCycle.length],
    riskAssessmentRef: `risk-vendor-${category}`,
    contingencyPlanHash: digestCycle[(index + 5) % digestCycle.length],
    businessContinuityHash: digestCycle[index % digestCycle.length],
    issueEscalationPathHash: digestCycle[(index + 1) % digestCycle.length],
    renewalDueHlc: { physicalMs: 1810000000000 + index, logical: 0 },
    lastReviewedAtHlc: { physicalMs: 1795000000000 + index, logical: 0 },
    handlesProtectedData,
    dataProcessingAgreementHash: handlesProtectedData ? digestCycle[(index + 2) % digestCycle.length] : null,
    privacyBoundaryHash: handlesProtectedData ? digestCycle[(index + 3) % digestCycle.length] : null,
    accessPolicyHash: handlesProtectedData ? digestCycle[(index + 4) % digestCycle.length] : null,
    dataMinimizationHash: handlesProtectedData ? digestCycle[(index + 5) % digestCycle.length] : null,
    metadataOnly: true,
    protectedContentExcluded: true,
  };
  return { ...base, ...overrides };
}

function vendorRows() {
  return REQUIRED_VENDOR_CATEGORIES.map((category, index) => vendor(category, index));
}

function readinessInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'vendor_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_vendor_readiness', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    vendorPolicy: {
      policyRef: 'vendor-subcontractor-readiness-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredVendorCategories: REQUIRED_VENDOR_CATEGORIES,
      requiredReviewDomains: [
        'contractual_obligations',
        'decommissioning',
        'issue_escalation',
        'privacy_security',
        'qualification',
        'risk_management',
        'service_level_monitoring',
        'sponsor_cro_visibility',
      ],
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800000000000, logical: 0 },
      productionTrustClaim: false,
    },
    vendorProgram: {
      programRef: 'vendor-program-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      status: 'active',
      qualificationProcedureHash: DIGEST_C,
      subcontractorOversightProcedureHash: DIGEST_D,
      sponsorCroVisibilityPolicyHash: DIGEST_E,
      issueManagementProcedureHash: DIGEST_F,
      metadataOnly: true,
      protectedContentExcluded: true,
      openedAtHlc: { physicalMs: 1790000000000, logical: 0 },
      compiledAtHlc: { physicalMs: 1799000000000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1801000000000, logical: 0 },
    },
    vendors: vendorRows(),
    oversight: {
      reviewRef: 'vendor-oversight-review-alpha',
      reviewDomains: [
        'contractual_obligations',
        'decommissioning',
        'issue_escalation',
        'privacy_security',
        'qualification',
        'risk_management',
        'service_level_monitoring',
        'sponsor_cro_visibility',
      ],
      activeIssueRefs: [],
      openCriticalIssueRefs: [],
      sponsorCroDisclosureLogHash: DIGEST_A,
      escalationRegisterHash: DIGEST_B,
      decommissioningPlanHash: DIGEST_C,
      humanReviewed: true,
      reviewedByDid: 'did:exo:quality-manager-alpha',
      reviewedAtHlc: { physicalMs: 1801000000000, logical: 1 },
      metadataOnly: true,
    },
    dependencyEvidence: {
      protocolFeasibilityRef: 'protocol-feasibility-alpha',
      riskAssessmentRefs: ['risk-vendor-central_lab', 'risk-vendor-data_management_vendor'],
      governedIntegrationRefs: ['integration-edc-alpha', 'integration-lab-alpha'],
      diligencePacketRefs: ['diligence-vendor-alpha'],
      evidenceHashes: [DIGEST_A, DIGEST_B, DIGEST_C],
      metadataOnly: true,
    },
    review: {
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-vendor-readiness-alpha',
        workflowReceiptId: 'df-workflow-vendor-readiness-alpha',
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      finalAuthority: 'human',
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_D,
  };
  return mergeDeep(base, overrides);
}

test('vendor and subcontractor readiness creates deterministic inactive oversight receipts', async () => {
  const { evaluateVendorSubcontractorReadiness } = await loadVendorReadiness();

  const resultA = evaluateVendorSubcontractorReadiness(readinessInput());
  const resultB = evaluateVendorSubcontractorReadiness({
    ...readinessInput(),
    vendors: [...readinessInput().vendors].reverse(),
    vendorPolicy: {
      ...readinessInput().vendorPolicy,
      requiredVendorCategories: [...REQUIRED_VENDOR_CATEGORIES].reverse(),
      requiredReviewDomains: [...readinessInput().vendorPolicy.requiredReviewDomains].reverse(),
    },
    oversight: {
      ...readinessInput().oversight,
      reviewDomains: [...readinessInput().oversight.reviewDomains].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.vendorReadiness.readinessStatus, 'ready_for_protocol_use');
  assert.deepEqual(resultA.vendorReadiness.vendorCategoriesCovered, REQUIRED_VENDOR_CATEGORIES);
  assert.equal(resultA.vendorReadiness.criticalVendorCount, 3);
  assert.equal(resultA.vendorReadiness.protectedDataVendorCount, 3);
  assert.equal(resultA.vendorReadiness.exochainProductionClaim, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'vendor_subcontractor_readiness');
  assert.equal(resultA.vendorReadiness.readinessId, resultB.vendorReadiness.readinessId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.doesNotMatch(JSON.stringify(resultA), /central lab contact|vendor contract body|Participant Alice/iu);
});

test('vendor readiness fails closed for missing category unqualified vendor and expired renewal', async () => {
  const { evaluateVendorSubcontractorReadiness } = await loadVendorReadiness();

  const result = evaluateVendorSubcontractorReadiness({
    ...readinessInput(),
    vendors: readinessInput().vendors
      .filter((row) => row.vendorCategory !== 'logistics_provider')
      .map((row) =>
        row.vendorCategory === 'central_lab'
          ? {
              ...row,
              qualificationStatus: 'pending',
              renewalDueHlc: { physicalMs: 1790000000000, logical: 0 },
              contingencyPlanHash: '',
            }
          : row,
      ),
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.vendorReadiness.readinessStatus, 'not_ready');
  assert.ok(result.reasons.includes('required_vendor_category_missing:logistics_provider'));
  assert.ok(result.reasons.includes('vendor_not_qualified:vendor-central_lab'));
  assert.ok(result.reasons.includes('vendor_renewal_due_or_invalid:vendor-central_lab'));
  assert.ok(result.reasons.includes('critical_vendor_contingency_absent:vendor-central_lab'));
});

test('protected-data vendors require data-processing privacy access and minimization evidence', async () => {
  const { evaluateVendorSubcontractorReadiness } = await loadVendorReadiness();

  const result = evaluateVendorSubcontractorReadiness({
    ...readinessInput(),
    vendors: readinessInput().vendors.map((row) =>
      row.vendorCategory === 'data_management_vendor'
        ? {
            ...row,
            dataProcessingAgreementHash: '',
            privacyBoundaryHash: '',
            accessPolicyHash: '',
            dataMinimizationHash: '',
          }
        : row,
    ),
    dependencyEvidence: {
      ...readinessInput().dependencyEvidence,
      governedIntegrationRefs: [],
    },
  });

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('|'), /protected_data_vendor_dpa_absent:vendor-data_management_vendor/);
  assert.match(result.reasons.join('|'), /protected_data_vendor_privacy_boundary_absent:vendor-data_management_vendor/);
  assert.match(result.reasons.join('|'), /protected_data_vendor_access_policy_absent:vendor-data_management_vendor/);
  assert.match(result.reasons.join('|'), /protected_data_vendor_minimization_absent:vendor-data_management_vendor/);
  assert.match(result.reasons.join('|'), /governed_integration_ref_absent/);
});

test('vendor readiness requires human governance and denies AI final authority', async () => {
  const { evaluateVendorSubcontractorReadiness } = await loadVendorReadiness();

  const result = evaluateVendorSubcontractorReadiness(
    readinessInput({
      actor: { did: 'did:exo:ai-agent-alpha', kind: 'ai_agent', roleRefs: ['assistant'] },
      review: {
        decisionForum: {
          verified: true,
          state: 'approved',
          humanGate: { verified: false },
          quorum: { status: 'met' },
          openChallenge: false,
          decisionId: 'df-vendor-readiness-alpha',
          workflowReceiptId: 'df-workflow-vendor-readiness-alpha',
        },
        evidenceBundle: { complete: false, phiBoundaryAttested: false },
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
      oversight: {
        ...readinessInput().oversight,
        humanReviewed: false,
        reviewedByDid: '',
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_gate_unverified'));
  assert.ok(result.reasons.includes('evidence_bundle_incomplete'));
  assert.ok(result.reasons.includes('vendor_oversight_human_review_absent'));
});

test('vendor readiness handles absent objects as denial states', async () => {
  const { evaluateVendorSubcontractorReadiness } = await loadVendorReadiness();

  const result = evaluateVendorSubcontractorReadiness({});

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('tenant_absent'));
  assert.ok(result.reasons.includes('vendor_policy_ref_absent'));
  assert.ok(result.reasons.includes('vendor_program_ref_absent'));
  assert.ok(result.reasons.includes('vendor_collection_absent'));
});

test('vendor readiness rejects raw vendor content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateVendorSubcontractorReadiness } = await loadVendorReadiness();

  assert.throws(
    () =>
      evaluateVendorSubcontractorReadiness(
        readinessInput({
          vendors: [
            {
              ...vendorRows()[0],
              vendorContractBody: 'vendor contract body with central lab contact',
            },
            ...vendorRows().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateVendorSubcontractorReadiness(
        readinessInput({
          vendorPolicy: {
            ...readinessInput().vendorPolicy,
            apiKey: 'sk_live_vendor_secret',
          },
        }),
      ),
    ProtectedContentError,
  );
});
