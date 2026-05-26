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

const REQUIRED_WORKFLOWS = [
  'capa',
  'decision_forum',
  'deviation',
  'document_control',
  'enrollment_gate',
  'evidence_intake',
  'internal_audit',
  'launch_gate',
  'safety_event',
];

const REQUIRED_ROLES = [
  'auditor',
  'coordinator',
  'decision_forum',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
  'system_administrator',
];

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

async function loadTenantConfigurations() {
  try {
    return await import('../src/tenant-configurations.mjs');
  } catch (error) {
    assert.fail(`CyberMedica tenant configurations module must exist and load: ${error.message}`);
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

function workflow(workflowFamily, index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    workflowFamily,
    workflowRef: `workflow-${workflowFamily}`,
    workflowVersion: 'v1',
    status: 'active',
    definitionHash: hashes[index],
    requiredRoleRefs: ['quality_manager', workflowFamily === 'decision_forum' ? 'decision_forum' : 'site_leader'],
    decisionGateRef: workflowFamily === 'decision_forum' ? 'df-governance-v1' : `gate-${workflowFamily}`,
    failClosedOnMissingEvidence: true,
    metadataOnly: true,
  };
}

function role(roleRef, index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    roleRef,
    displayNameHash: hashes[index],
    permissionRefs: roleRef === 'system_administrator' ? ['tenant_configuration_manage'] : [`${roleRef}:read`],
    authorityPolicyHash: hashes[(index + 1) % hashes.length],
    delegationPolicyHash: hashes[(index + 2) % hashes.length],
    accessPolicyHash: hashes[(index + 3) % hashes.length],
    separationOfPowersGroup: roleRef === 'system_administrator' ? 'administration' : 'operations',
    humanOwnerRequired: roleRef !== 'sponsor_viewer',
    status: 'active',
    metadataOnly: true,
  };
}

function sopMapping(index) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D];
  return {
    mappingRef: `sop-map-${index}`,
    sopRef: `SOP-QMS-${index}`,
    sopVersion: 'v1',
    sopHash: hashes[index],
    controlRefs: [`CM-QMS-CTRL-${index + 1}`],
    workflowRefs: [REQUIRED_WORKFLOWS[index]],
    roleRefs: ['quality_manager'],
    effectiveAtHlc: { physicalMs: 1796600200000 + index, logical: 0 },
    metadataOnly: true,
  };
}

function evidenceRequirement(index) {
  const hashes = [DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    requirementRef: `evidence-req-${index}`,
    artifactType: ['training_record', 'delegation_log', 'consent_material', 'audit_report'][index],
    classification: 'confidential_metadata_only',
    requiredForControlRefs: [`CM-QMS-CTRL-${index + 1}`],
    reviewRoleRefs: ['quality_manager'],
    freshnessDays: [365, 180, 90, 30][index],
    retentionRuleHash: hashes[index],
    custodyRequired: true,
    metadataOnly: true,
  };
}

function reviewFrequency(objectFamily, index) {
  const hashes = [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5];
  return {
    objectFamily,
    frequencyDays: [365, 180, 90, 60, 30][index],
    ownerRoleRef: 'quality_manager',
    escalationRuleHash: hashes[index],
    reviewWindowDays: 14,
    metadataOnly: true,
  };
}

function reportingTemplate(index) {
  const domains = [REQUIRED_REPORT_DOMAINS, ['audit', 'capa', 'qms_status', 'risk']][index];
  return {
    templateRef: index === 0 ? 'standard-qms-status-template' : 'custom-sponsor-diligence-template',
    templateKind: index === 0 ? 'standard' : 'custom',
    status: 'approved',
    templateHash: [DIGEST_4, DIGEST_5][index],
    outputProfileHash: [DIGEST_5, DIGEST_6][index],
    accessPolicyHash: [DIGEST_6, DIGEST_A][index],
    supportedDomains: domains,
    metadataOnly: true,
  };
}

function tenantConfigurationInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:tenant-config-manager-alpha',
      kind: 'human',
      roleRefs: ['system_administrator'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['tenant_configuration_manage', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    configurationPackage: {
      configRef: 'tenant-config-site-alpha',
      configVersion: 'v1',
      schemaVersion: 'cybermedica.tenant_configuration.v1',
      status: 'approved',
      tenantProfileHash: DIGEST_B,
      siteProfileHash: DIGEST_C,
      previousConfigHash: null,
      packageHash: DIGEST_D,
      metadataOnly: true,
      productionTrustClaim: false,
    },
    changeControl: {
      changeRef: 'tenant-config-change-001',
      requestedByDid: 'did:exo:tenant-config-manager-alpha',
      requestedAtHlc: { physicalMs: 1796600000000, logical: 0 },
      approvedByDid: 'did:exo:quality-director-alpha',
      approvedAtHlc: { physicalMs: 1796600100000, logical: 0 },
      effectiveAtHlc: { physicalMs: 1796600300000, logical: 0 },
      rationaleHash: DIGEST_E,
      impactAssessmentHash: DIGEST_F,
      rollbackPlanHash: DIGEST_1,
      testEvidenceHash: DIGEST_2,
      metadataOnly: true,
    },
    controlSets: [
      {
        controlSetRef: 'site-alpha-core-controls',
        status: 'active',
        controlRefs: ['CM-QMS-CTRL-001', 'CM-QMS-CTRL-002', 'CM-QMS-CTRL-003'],
        applicabilityProfileHash: DIGEST_3,
        standardsCrosswalkHash: DIGEST_4,
        waiverPolicyHash: DIGEST_5,
        metadataOnly: true,
      },
    ],
    workflows: REQUIRED_WORKFLOWS.map(workflow).reverse(),
    roles: REQUIRED_ROLES.map(role).reverse(),
    sopMappings: [0, 1, 2, 3].map(sopMapping).reverse(),
    evidenceRequirements: [0, 1, 2, 3].map(evidenceRequirement).reverse(),
    reviewFrequencies: ['controls', 'evidence', 'sops', 'training', 'reports'].map(reviewFrequency).reverse(),
    reportingTemplates: [0, 1].map(reportingTemplate).reverse(),
    governanceReview: {
      status: 'approved',
      reviewerDid: 'did:exo:quality-director-alpha',
      reviewedAtHlc: { physicalMs: 1796600200000, logical: 0 },
      reviewEvidenceHash: DIGEST_6,
      quorumVerified: true,
      aiFinalAuthorityRejected: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      evidenceRefs: ['tenant-profile-hash', 'control-set-hash'],
      reasoningSummaryHash: DIGEST_A,
      confidenceBasisPoints: 8100,
      limitationHashes: [DIGEST_B],
      unresolvedAssumptionHashes: [DIGEST_C],
      recommendedHumanReviewerDids: ['did:exo:quality-director-alpha'],
    },
    custodyDigest: DIGEST_2,
  };

  return mergeDeep(base, overrides);
}

test('tenant configuration package creates deterministic NFR-008 inactive receipts', async () => {
  const { evaluateTenantConfiguration } = await loadTenantConfigurations();

  const resultA = evaluateTenantConfiguration(tenantConfigurationInput());
  const resultB = evaluateTenantConfiguration(tenantConfigurationInput({
    workflows: REQUIRED_WORKFLOWS.map(workflow),
    roles: REQUIRED_ROLES.map(role),
  }));

  assert.equal(resultA.permitted, true);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.configurationRecord.schema, 'cybermedica.tenant_configuration_record.v1');
  assert.equal(resultA.configurationRecord.status, 'approved');
  assert.equal(resultA.configurationRecord.trustState, 'inactive');
  assert.equal(resultA.configurationRecord.exochainProductionClaim, false);
  assert.equal(resultA.configurationRecord.sectionCoverage.controlSets, 1);
  assert.equal(resultA.configurationRecord.sectionCoverage.workflows, REQUIRED_WORKFLOWS.length);
  assert.equal(resultA.configurationRecord.sectionCoverage.roles, REQUIRED_ROLES.length);
  assert.equal(resultA.configurationRecord.sectionCoverage.sopMappings, 4);
  assert.equal(resultA.configurationRecord.sectionCoverage.evidenceRequirements, 4);
  assert.equal(resultA.configurationRecord.sectionCoverage.reviewFrequencies, 5);
  assert.equal(resultA.configurationRecord.sectionCoverage.reportingTemplates, 2);
  assert.deepEqual(resultA.configurationRecord.workflowFamilies, REQUIRED_WORKFLOWS);
  assert.deepEqual(resultA.configurationRecord.roleRefs, REQUIRED_ROLES);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.containsProtectedContent, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'tenant_configuration');
  assert.equal(resultA.receipt.anchorPayload.classification, 'confidential_metadata_only');
  assert.equal(resultA.configurationRecord.configurationHash, resultB.configurationRecord.configurationHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
});

test('tenant configuration fails closed for missing sections and unsafe role governance', async () => {
  const { evaluateTenantConfiguration } = await loadTenantConfigurations();

  const absent = evaluateTenantConfiguration({});

  assert.equal(absent.permitted, false);
  assert.ok(absent.reasons.includes('tenant_absent'));
  assert.ok(absent.reasons.includes('configuration_ref_absent'));
  assert.ok(absent.reasons.includes('change_control_ref_absent'));
  assert.ok(absent.reasons.includes('control_sets_absent'));
  assert.ok(absent.reasons.includes('workflows_absent'));
  assert.ok(absent.reasons.includes('roles_absent'));
  assert.ok(absent.reasons.includes('sop_mappings_absent'));
  assert.ok(absent.reasons.includes('evidence_requirements_absent'));
  assert.ok(absent.reasons.includes('review_frequencies_absent'));
  assert.ok(absent.reasons.includes('reporting_templates_absent'));
  assert.equal(absent.configurationRecord, null);
  assert.equal(absent.receipt, null);

  const result = evaluateTenantConfiguration(tenantConfigurationInput({
    changeControl: {
      approvedByDid: 'did:exo:tenant-config-manager-alpha',
    },
    roles: [
      role('system_administrator', 0),
      {
        ...role('quality_manager', 1),
        permissionRefs: ['tenant_configuration_manage', 'configuration_approve'],
        separationOfPowersGroup: 'administration',
      },
    ],
    reportingTemplates: [],
    workflows: REQUIRED_WORKFLOWS.filter((workflowFamily) => workflowFamily !== 'decision_forum').map(workflow),
    governanceReview: {
      quorumVerified: false,
    },
  }));

  assert.equal(result.permitted, false);
  assert.ok(result.reasons.includes('reporting_templates_absent'));
  assert.ok(result.reasons.includes('required_workflow_missing:decision_forum'));
  assert.ok(result.reasons.includes('required_role_missing:auditor'));
  assert.ok(result.reasons.includes('change_control_self_approval_forbidden'));
  assert.ok(result.reasons.includes('role_combines_configuration_and_approval:quality_manager'));
  assert.ok(result.reasons.includes('governance_quorum_unverified'));
  assert.equal(result.configurationRecord, null);
  assert.equal(result.receipt, null);
});

test('tenant configuration enforces HLC ordering review frequencies and metadata boundaries', async () => {
  const { evaluateTenantConfiguration } = await loadTenantConfigurations();

  const result = evaluateTenantConfiguration(tenantConfigurationInput({
    changeControl: {
      approvedAtHlc: { physicalMs: 1796599999999, logical: 0 },
      effectiveAtHlc: { physicalMs: 1796599999998, logical: 0 },
    },
    reviewFrequencies: [
      reviewFrequency('controls', 0),
      {
        ...reviewFrequency('evidence', 1),
        frequencyDays: 0,
      },
    ],
    evidenceRequirements: [
      {
        ...evidenceRequirement(0),
        classification: 'raw_phi',
        metadataOnly: false,
        custodyRequired: false,
      },
    ],
  }));

  assert.equal(result.permitted, false);
  assert.ok(result.reasons.includes('change_approval_before_request'));
  assert.ok(result.reasons.includes('change_effective_before_approval'));
  assert.ok(result.reasons.includes('required_review_frequency_missing:reports'));
  assert.ok(result.reasons.includes('review_frequency_days_invalid:evidence'));
  assert.ok(result.reasons.includes('evidence_requirement_classification_invalid:evidence-req-0'));
  assert.ok(result.reasons.includes('evidence_requirement_metadata_boundary_invalid:evidence-req-0'));
  assert.ok(result.reasons.includes('evidence_requirement_custody_not_required:evidence-req-0'));

  const malformedClock = evaluateTenantConfiguration(tenantConfigurationInput({
    changeControl: {
      requestedAtHlc: { physicalMs: 1796600000000, logical: -1 },
    },
  }));

  assert.equal(malformedClock.permitted, false);
  assert.ok(malformedClock.reasons.includes('change_request_time_invalid'));

  const sameTickNonAdvancing = evaluateTenantConfiguration(tenantConfigurationInput({
    changeControl: {
      requestedAtHlc: { physicalMs: 1796600000000, logical: 0 },
      approvedAtHlc: { physicalMs: 1796600000000, logical: 0 },
      effectiveAtHlc: { physicalMs: 1796600000000, logical: 0 },
    },
    governanceReview: {
      reviewedAtHlc: { physicalMs: 1796600000000, logical: 0 },
    },
  }));

  assert.equal(sameTickNonAdvancing.permitted, false);
  assert.ok(sameTickNonAdvancing.reasons.includes('configuration_effective_not_after_request'));

  const sameTickAdvancing = evaluateTenantConfiguration(tenantConfigurationInput({
    changeControl: {
      requestedAtHlc: { physicalMs: 1796600000000, logical: 0 },
      approvedAtHlc: { physicalMs: 1796600000000, logical: 1 },
      effectiveAtHlc: { physicalMs: 1796600000000, logical: 3 },
    },
    governanceReview: {
      reviewedAtHlc: { physicalMs: 1796600000000, logical: 2 },
    },
  }));

  assert.equal(sameTickAdvancing.permitted, true);
});

test('tenant configuration accepts no AI assistance while preserving human governance', async () => {
  const { evaluateTenantConfiguration } = await loadTenantConfigurations();

  const result = evaluateTenantConfiguration(tenantConfigurationInput({
    aiAssistance: { used: false },
  }));

  assert.equal(result.permitted, true);
  assert.equal(result.configurationRecord.aiAssistance.used, false);
  assert.equal(result.configurationRecord.aiAssistance.finalAuthority, false);
  assert.equal(result.configurationRecord.governanceReview.status, 'approved');
  assert.equal(result.receipt.trustState, 'inactive');
});

test('tenant configuration rejects raw configuration content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateTenantConfiguration } = await loadTenantConfigurations();

  assert.throws(
    () => evaluateTenantConfiguration(tenantConfigurationInput({
      sopMappings: [
        {
          ...sopMapping(0),
          rawSopText: 'Patient Jane Example must be called directly.',
        },
      ],
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateTenantConfiguration(tenantConfigurationInput({
      sopMappings: [
        {
          ...sopMapping(0),
          rawConfigurationPayload: [false, null, 1],
        },
      ],
    })),
    ProtectedContentError,
  );

  assert.throws(
    () => evaluateTenantConfiguration(tenantConfigurationInput({
      identityProvider: {
        clientSecret: { vaultRef: 'secret-ref-alpha' },
      },
    })),
    ProtectedContentError,
  );

  const inertSecretMarker = evaluateTenantConfiguration(tenantConfigurationInput({
    identityProvider: {
      clientSecret: false,
    },
  }));

  assert.equal(inertSecretMarker.permitted, true);
});
