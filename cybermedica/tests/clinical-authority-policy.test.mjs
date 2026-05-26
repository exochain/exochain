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

const REQUIRED_PERMISSION_DIMENSIONS = [
  'action_type',
  'confidentiality_classification',
  'cro_visibility',
  'decision_matter',
  'delegation',
  'emergency_access',
  'evidence_type',
  'expiration',
  'phi_pii_classification',
  'protocol',
  'role',
  'site',
  'sponsor_visibility',
  'study',
  'tenant',
];

const REQUIRED_AUTHORITY_ACTIONS = [
  'access_sensitive_participant_linked_evidence',
  'audit_report_finalization',
  'capa_closure',
  'clinical_trial_product_release_use_authorization',
  'consent_form_activation',
  'control_library_publication',
  'critical_risk_acceptance',
  'delegation_approval',
  'deviation_closure',
  'emergency_override',
  'enrollment_authorization',
  'evidence_disclosure',
  'policy_approval',
  'site_qms_passport_approval',
  'sop_approval',
  'sponsor_export_release',
  'trial_acceptance',
  'trial_launch_authorization',
];

const REQUIRED_CLINICAL_ROLES = [
  'ai_quality_reviewer',
  'auditor',
  'clinical_research_coordinator',
  'clinical_research_site_leader',
  'cro_portfolio_manager',
  'data_manager',
  'decision_forum_chair',
  'facility_manager',
  'monitor_cra',
  'pharmacy_investigational_product_manager',
  'principal_investigator',
  'quality_manager',
  'regulatory_coordinator',
  'site_executive_sponsor',
  'sponsor_viewer',
  'system_administrator',
  'training_manager',
];

async function loadClinicalAuthorityPolicy() {
  try {
    return await import('../src/clinical-authority-policy.mjs');
  } catch (error) {
    assert.fail(`CyberMedica clinical authority policy module must exist and load: ${error.message}`);
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

function roleMapping(roleRef, authorityMode, index, overrides = {}) {
  const governanceModes = new Set(['governance_role']);
  const assistantModes = new Set(['ai_assistant']);
  return {
    roleRef,
    authorityMode,
    mappedAtHlc: { physicalMs: 1802000100000 + index, logical: index % 3 },
    evidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    exochainRoleRefs: governanceModes.has(authorityMode) ? [`exo-role-${roleRef}`] : [],
    permissionRefs: governanceModes.has(authorityMode)
      ? []
      : assistantModes.has(authorityMode)
        ? ['assist']
        : ['read', 'write'],
    decisionForumEligible: governanceModes.has(authorityMode),
    humanFinalAuthority: !assistantModes.has(authorityMode),
    metadataOnly: true,
    ...overrides,
  };
}

function actionMapping(actionRef, index, overrides = {}) {
  const governanceActions = new Set([
    'audit_report_finalization',
    'capa_closure',
    'clinical_trial_product_release_use_authorization',
    'consent_form_activation',
    'control_library_publication',
    'critical_risk_acceptance',
    'delegation_approval',
    'deviation_closure',
    'emergency_override',
    'enrollment_authorization',
    'evidence_disclosure',
    'policy_approval',
    'site_qms_passport_approval',
    'sop_approval',
    'sponsor_export_release',
    'trial_acceptance',
    'trial_launch_authorization',
  ]);
  return {
    actionRef,
    requiredPermissionRef: actionRef === 'access_sensitive_participant_linked_evidence' ? 'read_sensitive' : 'govern',
    requiredAuthorityMode: governanceActions.has(actionRef) ? 'governance_role' : 'operational_permission',
    requiredRoleRefs: governanceActions.has(actionRef) ? ['quality_manager', 'principal_investigator'] : ['data_manager'],
    decisionForumRequired: governanceActions.has(actionRef),
    consentRequired: ['access_sensitive_participant_linked_evidence', 'sponsor_export_release'].includes(actionRef),
    participantLinked: actionRef === 'access_sensitive_participant_linked_evidence',
    evidenceHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6][index % 6],
    metadataOnly: true,
    ...overrides,
  };
}

function authorityInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager'],
    },
    requestedAction: 'sponsor_export_release',
    requestedAtHlc: { physicalMs: 1802001000000, logical: 0 },
    accessScope: {
      tenantRef: 'tenant-site-alpha',
      siteRef: 'site-alpha',
      studyRef: 'study-alpha',
      protocolRef: 'protocol-alpha',
      sponsorVisibility: 'limited',
      croVisibility: 'limited',
      confidentialityClassification: 'confidential_metadata_only',
      phiPiiClassification: 'coded_metadata_only',
      evidenceType: 'diligence_export_manifest',
      decisionMatterRef: 'df-sponsor-export-alpha',
      emergencyAccess: false,
      expiresAtHlc: { physicalMs: 1802087400000, logical: 0 },
    },
    authorityChain: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['govern', 'read_sensitive'],
      authorityChainHash: DIGEST_A,
    },
    delegation: {
      status: 'active',
      delegationRef: 'delegation-quality-manager-alpha',
      grantorDid: 'did:exo:site-executive-sponsor-alpha',
      granteeDid: 'did:exo:quality-manager-alpha',
      scopeActionRefs: ['sponsor_export_release', 'trial_launch_authorization'],
      startsAtHlc: { physicalMs: 1801990000000, logical: 0 },
      expiresAtHlc: { physicalMs: 1802087400000, logical: 1 },
      revoked: false,
      evidenceHash: DIGEST_B,
      metadataOnly: true,
    },
    authorityPolicy: {
      policyRef: 'clinical-authority-policy-alpha',
      policyHash: DIGEST_C,
      status: 'active',
      evaluatedAtHlc: { physicalMs: 1802000000000, logical: 0 },
      requiredPermissionDimensions: REQUIRED_PERMISSION_DIMENSIONS,
      requiredAuthorityActions: REQUIRED_AUTHORITY_ACTIONS,
      requiredClinicalRoles: REQUIRED_CLINICAL_ROLES,
      allowedBobEscalationIds: ['ESC-ROLE-MATRIX'],
      activationGateIds: ['PTAG-010'],
      governanceRoleRefs: [
        'decision_forum_chair',
        'principal_investigator',
        'quality_manager',
        'site_executive_sponsor',
      ],
      operationalPermissionRefs: ['assist', 'delegate', 'escalate', 'govern', 'read', 'read_sensitive', 'write'],
      roleMappings: [
        roleMapping('quality_manager', 'governance_role', 0),
        roleMapping('principal_investigator', 'governance_role', 1),
        roleMapping('decision_forum_chair', 'governance_role', 2),
        roleMapping('site_executive_sponsor', 'governance_role', 3),
        roleMapping('clinical_research_site_leader', 'operational_permission', 4),
        roleMapping('clinical_research_coordinator', 'operational_permission', 5),
        roleMapping('training_manager', 'operational_permission', 6),
        roleMapping('facility_manager', 'operational_permission', 7),
        roleMapping('pharmacy_investigational_product_manager', 'operational_permission', 8),
        roleMapping('data_manager', 'operational_permission', 9, { permissionRefs: ['read_sensitive', 'write'] }),
        roleMapping('monitor_cra', 'operational_permission', 10, { permissionRefs: ['read_sensitive'] }),
        roleMapping('auditor', 'operational_permission', 11, { permissionRefs: ['read_sensitive'] }),
        roleMapping('regulatory_coordinator', 'operational_permission', 12),
        roleMapping('system_administrator', 'operational_permission', 13, { permissionRefs: ['read', 'write'] }),
        roleMapping('sponsor_viewer', 'operational_permission', 14, { permissionRefs: ['read'] }),
        roleMapping('cro_portfolio_manager', 'operational_permission', 15, { permissionRefs: ['read'] }),
        roleMapping('ai_quality_reviewer', 'ai_assistant', 16),
      ],
      actionMappings: REQUIRED_AUTHORITY_ACTIONS.map(actionMapping).reverse(),
      metadataOnly: true,
      productionTrustClaim: false,
    },
    consentBoundary: {
      required: true,
      status: 'active',
      revoked: false,
      consentRef: 'consent-sponsor-export-alpha',
      evidenceHash: DIGEST_D,
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_executive_sponsor'],
      decision: 'accepted_inactive_authority_policy',
      decisionHash: DIGEST_E,
      reviewedAtHlc: { physicalMs: 1802002000000, logical: 0 },
      decisionForum: {
        verified: true,
        state: 'approved',
        matterRef: 'df-clinical-authority-policy-alpha',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
      },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_F,
  };
  return mergeDeep(base, overrides);
}

test('clinical authority policy creates deterministic inactive PTAG-010 role mapping receipts', async () => {
  const { evaluateClinicalAuthorityPolicy } = await loadClinicalAuthorityPolicy();

  const resultA = evaluateClinicalAuthorityPolicy(authorityInput());
  const resultB = evaluateClinicalAuthorityPolicy(authorityInput({
    authorityPolicy: {
      requiredPermissionDimensions: [...REQUIRED_PERMISSION_DIMENSIONS].reverse(),
      requiredAuthorityActions: [...REQUIRED_AUTHORITY_ACTIONS].reverse(),
      requiredClinicalRoles: [...REQUIRED_CLINICAL_ROLES].reverse(),
      roleMappings: authorityInput().authorityPolicy.roleMappings.slice().reverse(),
      actionMappings: authorityInput().authorityPolicy.actionMappings.slice().reverse(),
    },
  }));

  assert.equal(resultA.decision, 'permitted');
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.authorityPolicy.schema, 'cybermedica.clinical_authority_policy.v1');
  assert.deepEqual(resultA.authorityPolicy.permissionDimensions, REQUIRED_PERMISSION_DIMENSIONS);
  assert.deepEqual(resultA.authorityPolicy.authorityActions, REQUIRED_AUTHORITY_ACTIONS);
  assert.deepEqual(resultA.authorityPolicy.clinicalRoles, REQUIRED_CLINICAL_ROLES);
  assert.deepEqual(resultA.authorityPolicy.activationGateIds, ['PTAG-010']);
  assert.deepEqual(resultA.authorityPolicy.bobEscalationIds, ['ESC-ROLE-MATRIX']);
  assert.equal(resultA.authorityPolicy.roleMatrixApprovalState, 'requires_bob_approval');
  assert.equal(resultA.authorityPolicy.trustState, 'inactive');
  assert.equal(resultA.authorityPolicy.exochainProductionClaim, false);
  assert.equal(resultA.authorityPolicy.roleModeCounts.governanceRole, 4);
  assert.equal(resultA.authorityPolicy.roleModeCounts.operationalPermission, 12);
  assert.equal(resultA.authorityPolicy.roleModeCounts.aiAssistant, 1);
  assert.equal(resultA.authorityPolicy.requestedActionRef, 'sponsor_export_release');
  assert.equal(resultA.authorityPolicy.requestedActionAuthorized, true);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.containsProtectedContent, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'clinical_authority_policy');
  assert.equal(resultA.authorityPolicy.policyDigest, resultB.authorityPolicy.policyDigest);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
});

test('clinical authority policy fails closed for unsafe role mapping and authority gaps', async () => {
  const { evaluateClinicalAuthorityPolicy } = await loadClinicalAuthorityPolicy();

  const denied = evaluateClinicalAuthorityPolicy(authorityInput({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-beta',
    actor: { kind: 'ai_agent', roleRefs: ['ai_quality_reviewer'] },
    requestedAction: 'trial_launch_authorization',
    accessScope: {
      sponsorVisibility: 'unrestricted',
      phiPiiClassification: 'direct_identifier',
      expiresAtHlc: { physicalMs: 1801990000000, logical: 0 },
    },
    authorityChain: {
      permissions: ['read'],
      authorityChainHash: 'not-a-digest',
    },
    delegation: {
      grantorDid: 'did:exo:quality-manager-alpha',
      granteeDid: 'did:exo:quality-manager-alpha',
      scopeActionRefs: ['sponsor_export_release'],
      expiresAtHlc: { physicalMs: 1801990000000, logical: 0 },
    },
    authorityPolicy: {
      requiredPermissionDimensions: REQUIRED_PERMISSION_DIMENSIONS.filter((dimension) => dimension !== 'expiration'),
      actionMappings: REQUIRED_AUTHORITY_ACTIONS
        .filter((actionRef) => actionRef !== 'clinical_trial_product_release_use_authorization')
        .map(actionMapping),
      roleMappings: [
        ...authorityInput().authorityPolicy.roleMappings.filter((mapping) => mapping.roleRef !== 'system_administrator'),
        roleMapping('system_administrator', 'operational_permission', 13, {
          exochainRoleRefs: ['exo-role-system-administrator'],
          permissionRefs: ['read', 'write'],
        }),
      ],
      productionTrustClaim: true,
    },
    consentBoundary: {
      status: 'revoked',
      revoked: true,
    },
    humanReview: {
      reviewedAtHlc: { physicalMs: 1801990000000, logical: 0 },
      decisionForum: {
        openChallenge: true,
        quorum: { status: 'not_met' },
        humanGate: { verified: false },
      },
    },
  }));

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('authority_permission_missing:govern'));
  assert.ok(denied.reasons.includes('delegation_self_grant_forbidden'));
  assert.ok(denied.reasons.includes('delegation_action_scope_missing'));
  assert.ok(denied.reasons.includes('delegation_expired'));
  assert.ok(denied.reasons.includes('requested_scope_expired'));
  assert.ok(denied.reasons.includes('permission_dimension_missing:expiration'));
  assert.ok(denied.reasons.includes('authority_action_mapping_missing:clinical_trial_product_release_use_authorization'));
  assert.ok(denied.reasons.includes('role_mapping_mode_blended:system_administrator'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('sponsor_visibility_unrestricted'));
  assert.ok(denied.reasons.includes('direct_identifier_scope_forbidden'));
  assert.ok(denied.reasons.includes('consent_revoked'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.equal(denied.authorityPolicy, null);
  assert.equal(denied.receipt, null);
});

test('clinical authority policy rejects raw role matrix content and secret material', async () => {
  const { ProtectedContentError, evaluateClinicalAuthorityPolicy } = await loadClinicalAuthorityPolicy();

  assert.throws(
    () =>
      evaluateClinicalAuthorityPolicy(authorityInput({
        authorityPolicy: {
          rawRoleMatrixNarrative: 'narrative clinical role matrix belongs outside receipts',
        },
      })),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateClinicalAuthorityPolicy(authorityInput({
        adapterConfig: {
          clientSecret: 'client-secret-value',
        },
      })),
    ProtectedContentError,
  );
});
