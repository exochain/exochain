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

const REQUIRED_SECURITY_CONTROLS = [
  'abac',
  'audit_logging',
  'encryption_at_rest',
  'encryption_in_transit',
  'identity_provider_integration',
  'least_privilege',
  'mfa_support',
  'rbac',
  'secrets_management',
  'security_monitoring',
  'session_controls',
];

const REQUIRED_PRIVACY_CONTROLS = [
  'access_restrictions',
  'consent_tracking',
  'data_minimization',
  'disclosure_logging',
  'gdpr_configuration',
  'hipaa_configuration',
  'protected_data_classification',
  'retention_policy',
];

const REQUIRED_SECURITY_SIGNALS = [
  'adapter_failure',
  'authentication',
  'authorization',
  'export_disclosure',
  'privileged_action',
  'secret_rotation',
];

async function loadSecurityPrivacyReadiness() {
  try {
    return await import('../src/security-privacy-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica security privacy readiness module must exist and load: ${error.message}`);
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

function securityControl(controlFamily, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5];
  return {
    controlFamily,
    controlRef: `SEC-${controlFamily.toUpperCase()}-001`,
    controlHash: hashes[index],
    evidenceHash: hashes[(index + 1) % hashes.length],
    status: 'verified',
    ownerDid: 'did:exo:security-owner-alpha',
    failClosed: true,
    metadataOnly: true,
    productionTrustClaim: false,
    reviewedAtHlc: { physicalMs: 1800600100000, logical: index },
    ...overrides,
  };
}

function privacyControl(controlFamily, index, overrides = {}) {
  const hashes = [DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8, DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D];
  return {
    controlFamily,
    controlRef: `PRIV-${controlFamily.toUpperCase()}-001`,
    controlHash: hashes[index],
    evidenceHash: hashes[(index + 1) % hashes.length],
    status: 'verified',
    ownerDid: 'did:exo:privacy-owner-alpha',
    failClosed: true,
    metadataOnly: true,
    productionTrustClaim: false,
    reviewedAtHlc: { physicalMs: 1800600101000, logical: index },
    ...overrides,
  };
}

function readinessInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:security-privacy-reviewer-alpha',
      kind: 'human',
      roleRefs: ['security_owner', 'privacy_officer'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['security_privacy_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    securityPolicy: {
      policyRef: 'security-policy-site-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      encryptionInTransitRequired: true,
      encryptionAtRestRequired: true,
      secretManagerRequired: true,
      roleBasedAccessRequired: true,
      attributeBasedAccessRequired: true,
      leastPrivilegeRequired: true,
      mfaSupported: true,
      identityProviderRequired: true,
      sessionControlRequired: true,
      auditLoggingRequired: true,
      securityMonitoringRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800600000000, logical: 0 },
    },
    privacyPolicy: {
      policyRef: 'privacy-policy-site-alpha',
      policyHash: DIGEST_C,
      status: 'active',
      supportedFrameworks: ['gdpr', 'hipaa'],
      dataMinimizationRequired: true,
      accessRestrictionsRequired: true,
      consentTrackingRequired: true,
      retentionPolicyRequired: true,
      disclosureLoggingRequired: true,
      protectedDataClassificationRequired: true,
      rawPhiAnchoringAllowed: false,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800600001000, logical: 0 },
    },
    securityControls: REQUIRED_SECURITY_CONTROLS.map(securityControl).reverse(),
    privacyControls: REQUIRED_PRIVACY_CONTROLS.map(privacyControl).reverse(),
    accessModel: {
      status: 'verified',
      rbacPolicyHash: DIGEST_D,
      abacPolicyHash: DIGEST_E,
      leastPrivilegeMatrixHash: DIGEST_F,
      privilegedRoleReviewHash: DIGEST_1,
      separationOfPowersHash: DIGEST_2,
      emergencyAccessPolicyHash: DIGEST_3,
      noSharedRootCredentials: true,
      reviewedAtHlc: { physicalMs: 1800600200000, logical: 0 },
      metadataOnly: true,
    },
    identitySession: {
      status: 'verified',
      identityProviderRef: 'idp-site-alpha',
      identityProviderEvidenceHash: DIGEST_4,
      mfaPolicyHash: DIGEST_5,
      sessionPolicyHash: DIGEST_6,
      sessionExpiryMinutes: 30,
      staleSessionRevocation: true,
      serviceAccountInventoryHash: DIGEST_7,
      reviewedAtHlc: { physicalMs: 1800600201000, logical: 0 },
      metadataOnly: true,
    },
    secretsOperations: {
      status: 'verified',
      secretManagerRef: 'cybermedica-secret-scope-alpha',
      secretScope: 'cybermedica_only',
      rootSigningKeysSeparated: true,
      bootstrapTokensAbsentFromRuntime: true,
      missingSecretsFailClosed: true,
      rotationPolicyHash: DIGEST_8,
      lastRotationEvidenceHash: DIGEST_A,
      secretScanPassed: true,
      reviewedAtHlc: { physicalMs: 1800600202000, logical: 0 },
      metadataOnly: true,
    },
    privacyBoundary: {
      status: 'verified',
      classificationModelHash: DIGEST_B,
      dataMinimizationHash: DIGEST_C,
      consentTrackingHash: DIGEST_D,
      retentionRuleHash: DIGEST_E,
      disclosureLogHash: DIGEST_F,
      accessRestrictionHash: DIGEST_1,
      deidentificationPolicyHash: DIGEST_2,
      anchorMetadataPolicyHash: DIGEST_3,
      rawPhiAnchoringAllowed: false,
      protectedContentExcluded: true,
      payloadsRemainExternal: true,
      reviewedAtHlc: { physicalMs: 1800600203000, logical: 0 },
      metadataOnly: true,
    },
    monitoringEvidence: {
      status: 'active',
      monitorRef: 'security-monitor-site-alpha',
      securitySignalCoverage: REQUIRED_SECURITY_SIGNALS,
      alertRouteHash: DIGEST_4,
      incidentResponseHash: DIGEST_5,
      auditEventHash: DIGEST_6,
      evaluatedAtHlc: { physicalMs: 1800600204000, logical: 0 },
      protectedContentExcluded: true,
      metadataOnly: true,
    },
    validationEvidence: {
      commandRefs: ['npm test', 'npm run quality', 'secret scan', 'dependency audit'],
      commandsPassed: true,
      dependencyAuditStatus: 'passed',
      secretScanStatus: 'passed',
      sourceGuardPassed: true,
      coverageLineBasisPoints: 9900,
      testEvidenceHash: DIGEST_7,
      noExochainSourceModified: true,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800600300000, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-director-alpha',
      reviewerRoleRefs: ['security_owner', 'privacy_officer'],
      decision: 'accepted_inactive_trust',
      decisionHash: DIGEST_8,
      noProductionTrustClaim: true,
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800600400000, logical: 0 },
      metadataOnly: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_A,
      limitationHashes: [DIGEST_B],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_C,
  };

  return mergeDeep(base, overrides);
}

test('security privacy readiness creates deterministic NFR-001 NFR-002 inactive receipts', async () => {
  const { evaluateSecurityPrivacyReadiness } = await loadSecurityPrivacyReadiness();

  const resultA = evaluateSecurityPrivacyReadiness(readinessInput());
  const resultB = evaluateSecurityPrivacyReadiness(
    readinessInput({
      securityControls: REQUIRED_SECURITY_CONTROLS.map(securityControl),
      privacyControls: REQUIRED_PRIVACY_CONTROLS.map(privacyControl),
      monitoringEvidence: { securitySignalCoverage: [...REQUIRED_SECURITY_SIGNALS].reverse() },
    }),
  );

  assert.equal(resultA.allowed, true);
  assert.equal(resultA.state, 'ready_inactive_trust');
  assert.equal(resultA.trustState, 'inactive');
  assert.equal(resultA.exochainProductionClaim, false);
  assert.equal(resultA.securityReadinessBasisPoints, 10000);
  assert.equal(resultA.privacyReadinessBasisPoints, 10000);
  assert.deepEqual(resultA.security.coveredControlFamilies, [...REQUIRED_SECURITY_CONTROLS].sort());
  assert.deepEqual(resultA.privacy.coveredControlFamilies, [...REQUIRED_PRIVACY_CONTROLS].sort());
  assert.equal(resultA.readinessHash, resultB.readinessHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'security_privacy_readiness');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
});

test('security privacy readiness fails closed for missing required NFR controls', async () => {
  const { evaluateSecurityPrivacyReadiness } = await loadSecurityPrivacyReadiness();

  const result = evaluateSecurityPrivacyReadiness(
    readinessInput({
      securityControls: REQUIRED_SECURITY_CONTROLS
        .filter((controlFamily) => controlFamily !== 'encryption_at_rest')
        .map(securityControl),
      privacyControls: REQUIRED_PRIVACY_CONTROLS
        .filter((controlFamily) => controlFamily !== 'consent_tracking')
        .map(privacyControl),
      privacyPolicy: {
        rawPhiAnchoringAllowed: true,
      },
    }),
  );

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'denied');
  assert.equal(result.securityReadinessBasisPoints < 10000, true);
  assert.equal(result.privacyReadinessBasisPoints < 10000, true);
  assert.ok(result.blockedBy.includes('missing_security_control:encryption_at_rest'));
  assert.ok(result.blockedBy.includes('missing_privacy_control:consent_tracking'));
  assert.ok(result.blockedBy.includes('privacy_policy_raw_phi_anchoring_not_denied'));
  assert.equal(result.receipt, null);
});

test('security privacy readiness validates access identity session and secret boundaries', async () => {
  const { evaluateSecurityPrivacyReadiness } = await loadSecurityPrivacyReadiness();

  const result = evaluateSecurityPrivacyReadiness(
    readinessInput({
      accessModel: {
        status: 'draft',
        leastPrivilegeMatrixHash: null,
        noSharedRootCredentials: false,
      },
      identitySession: {
        mfaPolicyHash: null,
        sessionExpiryMinutes: 0,
        staleSessionRevocation: false,
      },
      secretsOperations: {
        rootSigningKeysSeparated: false,
        bootstrapTokensAbsentFromRuntime: false,
        missingSecretsFailClosed: false,
        secretScanPassed: false,
      },
    }),
  );

  assert.equal(result.allowed, false);
  assert.ok(result.blockedBy.includes('access_model_not_verified'));
  assert.ok(result.blockedBy.includes('least_privilege_matrix_hash_invalid'));
  assert.ok(result.blockedBy.includes('shared_root_credentials_not_denied'));
  assert.ok(result.blockedBy.includes('mfa_policy_hash_invalid'));
  assert.ok(result.blockedBy.includes('session_expiry_invalid'));
  assert.ok(result.blockedBy.includes('stale_session_revocation_absent'));
  assert.ok(result.blockedBy.includes('root_signing_keys_not_separated'));
  assert.ok(result.blockedBy.includes('bootstrap_tokens_not_excluded'));
  assert.ok(result.blockedBy.includes('missing_secrets_fail_closed_absent'));
  assert.ok(result.blockedBy.includes('secret_scan_not_passed'));
});

test('security privacy readiness enforces HLC human review and advisory AI boundaries', async () => {
  const { evaluateSecurityPrivacyReadiness } = await loadSecurityPrivacyReadiness();

  const result = evaluateSecurityPrivacyReadiness(
    readinessInput({
      actor: { kind: 'ai_agent' },
      monitoringEvidence: {
        evaluatedAtHlc: { physicalMs: 1800599999000, logical: 0 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800600200000, logical: 0 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800600100000, logical: 0 },
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
    }),
  );

  assert.equal(result.allowed, false);
  assert.ok(result.blockedBy.includes('human_security_privacy_reviewer_required'));
  assert.ok(result.blockedBy.includes('monitoring_before_security_policy'));
  assert.ok(result.blockedBy.includes('validation_before_evidence_reviews'));
  assert.ok(result.blockedBy.includes('human_review_before_validation'));
  assert.ok(result.blockedBy.includes('human_review_ai_final_authority_forbidden'));
  assert.ok(result.blockedBy.includes('production_trust_claim_forbidden'));
  assert.ok(result.blockedBy.includes('ai_final_authority_forbidden'));
  assert.ok(result.blockedBy.includes('ai_recommendation_without_human_review'));
});

test('security privacy readiness rejects raw protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateSecurityPrivacyReadiness } = await loadSecurityPrivacyReadiness();

  assert.throws(
    () =>
      evaluateSecurityPrivacyReadiness(
        readinessInput({
          securityPolicy: {
            rawSecurityNarrative: 'full control prose and operational details',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateSecurityPrivacyReadiness(
        readinessInput({
          secretsOperations: {
            apiKey: 'cm-secret-value',
          },
        }),
      ),
    ProtectedContentError,
  );
});
