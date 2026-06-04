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

const REQUIRED_INCIDENT_FAMILIES = [
  'adapter_degraded',
  'availability_outage',
  'data_integrity_event',
  'privacy_boundary_failure',
  'receipt_queue_backlog',
  'root_bundle_unavailable',
  'security_event',
  'sponsor_export_disclosure',
];

const REQUIRED_RELEASE_LINKAGE_DOMAINS = [
  'capa_cqi_drift_linkage',
  'decision_forum_materiality',
  'deployment_manifest_update',
  'incident_register_current',
  'policy_traceability_update',
  'prd_acceptance_update',
  'release_readiness_update',
  'rollback_or_disablement_path',
  'validation_evidence',
];

async function loadReleaseIncidentLinkage() {
  try {
    return await import('../src/release-incident-linkage.mjs');
  } catch (error) {
    assert.fail(`CyberMedica release incident linkage module must exist and load: ${error.message}`);
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

function incident(family, index, overrides = {}) {
  const material = ['data_integrity_event', 'privacy_boundary_failure', 'security_event', 'sponsor_export_disclosure'].includes(
    family,
  );
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    incidentRef: `INC-${String(index + 1).padStart(4, '0')}-${family}`,
    incidentFamily: family,
    severity: material ? 'critical' : 'minor',
    status: material ? 'closed_corrective_action_linked' : 'monitoring',
    detectedAtHlc: { physicalMs: 1800000100000, logical: index },
    closedAtHlc: material ? { physicalMs: 1800000300000, logical: index } : null,
    evidenceHash: hashes[index],
    incidentReceiptHash: hashes[(index + 1) % hashes.length],
    releaseImpact: material ? 'hold_until_corrective_action_linked' : 'monitoring_only',
    materialDecisionForumRequired: material,
    decisionForumMatterRef: material ? `df-incident-${family}` : null,
    decisionForumReceiptHash: material ? hashes[(index + 2) % hashes.length] : null,
    containmentStatus: 'contained',
    restorationStatus: material ? 'verified_restored' : 'monitoring_verified',
    capaRef: material ? `capa-${family}` : null,
    cqiRef: `cqi-${family}`,
    driftSignalRef: `drift-${family}`,
    rollbackPathRef: material ? 'disable-release-candidate-and-freeze-trust-claims' : 'monitor-adapter-health',
    releaseBlocker: false,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function linkageInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    checkedAtHlc: { physicalMs: 1800000700000, logical: 0 },
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'incident_commander'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['release_incident_linkage_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    linkagePolicy: {
      policyRef: 'release-incident-linkage-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredIncidentFamilies: REQUIRED_INCIDENT_FAMILIES,
      requiredReleaseLinkageDomains: REQUIRED_RELEASE_LINKAGE_DOMAINS,
      materialIncidentFamilies: [
        'data_integrity_event',
        'privacy_boundary_failure',
        'security_event',
        'sponsor_export_disclosure',
      ],
      metadataOnly: true,
      protectedContentExcluded: true,
      noProductionTrustClaimWithoutActivation: true,
      evaluatedAtHlc: { physicalMs: 1800000000000, logical: 0 },
    },
    releaseCycle: {
      cycleRef: 'release-incident-linkage-cycle-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      releaseReadinessMatrixRef: 'cmrel-release-readiness-alpha',
      releaseReadinessMatrixHash: DIGEST_C,
      prdAcceptanceMatrixRef: 'cmprd-acceptance-alpha',
      prdAcceptanceMatrixHash: DIGEST_D,
      policyTraceabilityRegisterRef: 'cmpolicy-trace-alpha',
      policyTraceabilityRegisterHash: DIGEST_E,
      deploymentManifestRef: 'cmdeploy-manifest-alpha',
      deploymentManifestHash: DIGEST_F,
      openedAtHlc: { physicalMs: 1800000050000, logical: 0 },
      incidentCutoffAtHlc: { physicalMs: 1800000400000, logical: 0 },
      linkageCompiledAtHlc: { physicalMs: 1800000500000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800000600000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800000650000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    incidents: REQUIRED_INCIDENT_FAMILIES.map((family, index) => incident(family, index)),
    releaseControls: {
      linkageDomainsCovered: REQUIRED_RELEASE_LINKAGE_DOMAINS,
      incidentRegisterRef: 'incident-register-release-alpha',
      incidentRegisterHash: DIGEST_1,
      releaseReadinessUpdated: true,
      prdAcceptanceUpdated: true,
      policyTraceabilityUpdated: true,
      deploymentManifestUpdated: true,
      rollbackPathRef: 'disable-release-candidate-and-freeze-trust-claims',
      rollbackPathHash: DIGEST_2,
      validationCommandRefs: ['node --test tests/release-incident-linkage.test.mjs', 'npm run quality'],
      validationEvidenceHash: DIGEST_3,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      updatedAtHlc: { physicalMs: 1800000500000, logical: 1 },
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'release_incident_linkage_accepted_inactive_trust',
      decisionHash: DIGEST_4,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800000600000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'release-incident-linkage-audit-alpha',
      auditRecordHash: DIGEST_1,
      receiptRecordedAtHlc: { physicalMs: 1800000650000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    custodyDigest: DIGEST_2,
  };

  return mergeDeep(base, overrides);
}

test('release incident linkage creates deterministic inactive release-blocker receipts', async () => {
  const { evaluateReleaseIncidentLinkage } = await loadReleaseIncidentLinkage();

  const resultA = evaluateReleaseIncidentLinkage(linkageInput());
  const resultB = evaluateReleaseIncidentLinkage({
    ...linkageInput(),
    linkagePolicy: {
      ...linkageInput().linkagePolicy,
      requiredIncidentFamilies: [...linkageInput().linkagePolicy.requiredIncidentFamilies].reverse(),
      requiredReleaseLinkageDomains: [...linkageInput().linkagePolicy.requiredReleaseLinkageDomains].reverse(),
      materialIncidentFamilies: [...linkageInput().linkagePolicy.materialIncidentFamilies].reverse(),
    },
    incidents: [...linkageInput().incidents].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.releaseIncidentLinkage.status, 'release_incident_linkage_accepted_inactive_trust');
  assert.equal(resultA.releaseIncidentLinkage.productionTrustState, 'inactive');
  assert.equal(resultA.releaseIncidentLinkage.exochainProductionClaim, false);
  assert.deepEqual(resultA.releaseIncidentLinkage.incidentFamiliesCovered, REQUIRED_INCIDENT_FAMILIES);
  assert.deepEqual(resultA.releaseIncidentLinkage.releaseLinkageDomainsCovered, REQUIRED_RELEASE_LINKAGE_DOMAINS);
  assert.equal(resultA.releaseIncidentLinkage.materialIncidentCount, 4);
  assert.equal(resultA.releaseIncidentLinkage.openMaterialIncidentCount, 0);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'release_incident_linkage_register');
  assert.deepEqual(resultA, resultB);
  assert.doesNotMatch(JSON.stringify(resultA), /raw incident|participant name|medical record|api key|source document/iu);
});

test('release incident linkage fails closed for open material incidents and missing release updates', async () => {
  const { evaluateReleaseIncidentLinkage } = await loadReleaseIncidentLinkage();

  const result = evaluateReleaseIncidentLinkage(
    linkageInput({
      incidents: [
        incident('privacy_boundary_failure', 0, {
          status: 'contained',
          closedAtHlc: null,
          decisionForumReceiptHash: null,
          capaRef: '',
          cqiRef: '',
          driftSignalRef: '',
          rollbackPathRef: '',
          releaseBlocker: true,
        }),
        ...REQUIRED_INCIDENT_FAMILIES.slice(1).map((family, index) => incident(family, index + 1)),
      ],
      releaseControls: {
        releaseReadinessUpdated: false,
        prdAcceptanceUpdated: false,
        policyTraceabilityUpdated: false,
        deploymentManifestUpdated: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('material_incident_not_closed:INC-0001-privacy_boundary_failure'));
  assert.ok(result.reasons.includes('material_decision_forum_receipt_missing:INC-0001-privacy_boundary_failure'));
  assert.ok(result.reasons.includes('incident_capa_linkage_absent:INC-0001-privacy_boundary_failure'));
  assert.ok(result.reasons.includes('incident_cqi_linkage_absent:INC-0001-privacy_boundary_failure'));
  assert.ok(result.reasons.includes('incident_drift_linkage_absent:INC-0001-privacy_boundary_failure'));
  assert.ok(result.reasons.includes('incident_rollback_path_absent:INC-0001-privacy_boundary_failure'));
  assert.ok(result.reasons.includes('incident_release_blocker_open:INC-0001-privacy_boundary_failure'));
  assert.ok(result.reasons.includes('release_readiness_update_absent'));
  assert.ok(result.reasons.includes('prd_acceptance_update_absent'));
  assert.ok(result.reasons.includes('policy_traceability_update_absent'));
  assert.ok(result.reasons.includes('deployment_manifest_update_absent'));
});

test('release incident linkage requires complete incident-family and linkage-domain coverage', async () => {
  const { evaluateReleaseIncidentLinkage } = await loadReleaseIncidentLinkage();

  const result = evaluateReleaseIncidentLinkage(
    linkageInput({
      linkagePolicy: {
        requiredReleaseLinkageDomains: REQUIRED_RELEASE_LINKAGE_DOMAINS.filter(
          (domain) => domain !== 'rollback_or_disablement_path',
        ),
      },
      incidents: REQUIRED_INCIDENT_FAMILIES.filter((family) => family !== 'receipt_queue_backlog').map((family, index) =>
        incident(family, index),
      ),
      releaseControls: {
        linkageDomainsCovered: REQUIRED_RELEASE_LINKAGE_DOMAINS.filter((domain) => domain !== 'validation_evidence'),
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('policy_release_linkage_domain_missing:rollback_or_disablement_path'));
  assert.ok(result.reasons.includes('incident_family_missing:receipt_queue_backlog'));
  assert.ok(result.reasons.includes('release_linkage_domain_missing:validation_evidence'));
});

test('release incident linkage rejects AI final authority production claims and unsafe HLC ordering', async () => {
  const { evaluateReleaseIncidentLinkage } = await loadReleaseIncidentLinkage();

  const result = evaluateReleaseIncidentLinkage(
    linkageInput({
      actor: { did: 'did:exo:ai-release-agent-alpha', kind: 'ai_agent' },
      releaseCycle: {
        productionTrustClaim: true,
        linkageCompiledAtHlc: { physicalMs: 1800000390000, logical: 0 },
      },
      humanReview: {
        aiFinalAuthority: true,
        finalAuthority: 'ai',
        reviewedAtHlc: { physicalMs: 1800000380000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_release_incident_reviewer_required'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('release_linkage_compiled_before_incident_cutoff'));
  assert.ok(result.reasons.includes('human_review_before_linkage_compiled'));
  assert.ok(result.reasons.includes('human_review_ai_final_authority_forbidden'));
});

test('release incident linkage handles absent objects as fail-closed denial states', async () => {
  const { evaluateReleaseIncidentLinkage } = await loadReleaseIncidentLinkage();

  const result = evaluateReleaseIncidentLinkage({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['release_incident_linkage_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('checked_at_hlc_invalid'));
  assert.ok(result.reasons.includes('linkage_policy_ref_absent'));
  assert.ok(result.reasons.includes('release_cycle_ref_absent'));
  assert.ok(result.reasons.includes('incident_records_absent'));
  assert.ok(result.reasons.includes('release_controls_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('release_incident_audit_record_ref_absent'));
});

test('release incident linkage rejects raw incident content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateReleaseIncidentLinkage } = await loadReleaseIncidentLinkage();

  assert.throws(
    () =>
      evaluateReleaseIncidentLinkage(
        linkageInput({
          incidents: [incident('privacy_boundary_failure', 0, { rawIncidentSummary: 'raw incident details stay out' })],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateReleaseIncidentLinkage(
        linkageInput({
          releaseControls: {
            accessToken: DIGEST_A,
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateReleaseIncidentLinkage(
        linkageInput({
          releaseCycle: {
            sourceDocumentBody: 'source document content belongs outside the receipt',
          },
        }),
      ),
    ProtectedContentError,
  );
});
