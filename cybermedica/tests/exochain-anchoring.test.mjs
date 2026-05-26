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

const REQUIRED_ANCHOR_FAMILIES = [
  'audit_anchor',
  'authority_receipt',
  'consent_receipt',
  'decision_receipt',
  'evidence_receipt',
];

async function loadExochainAnchoring() {
  try {
    return await import('../src/exochain-anchoring.mjs');
  } catch (error) {
    assert.fail(`CyberMedica Exochain anchoring module must exist and load: ${error.message}`);
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

function anchorRecord(overrides = {}) {
  return {
    anchorRef: 'anchor-evidence-alpha',
    family: 'evidence_receipt',
    artifactType: 'qms_control_evidence',
    artifactRef: 'evidence-control-alpha',
    artifactHash: DIGEST_A,
    actionHash: DIGEST_B,
    custodyDigest: DIGEST_C,
    classification: 'restricted_metadata_only',
    sensitivityTags: ['metadata_only', 'quality_evidence'],
    participantLinked: false,
    consentRef: null,
    hlcTimestamp: { physicalMs: 1800000000000, logical: 0 },
    sourceSystem: 'cybermedica-qms',
    boundary: {
      metadataOnly: true,
      rawContentExcluded: true,
      sourcePayloadExcluded: true,
      directIdentifiersExcluded: true,
      secretMaterialExcluded: true,
    },
    familyEvidence: {
      evidenceHash: DIGEST_A,
      receiptHash: DIGEST_B,
      custodyDigest: DIGEST_C,
    },
    ...overrides,
  };
}

function anchorRecords() {
  return [
    anchorRecord({
      anchorRef: 'anchor-evidence-alpha',
      family: 'evidence_receipt',
      familyEvidence: {
        evidenceHash: DIGEST_A,
        receiptHash: DIGEST_B,
        custodyDigest: DIGEST_C,
      },
    }),
    anchorRecord({
      anchorRef: 'anchor-decision-alpha',
      family: 'decision_receipt',
      artifactType: 'decision_forum_matter',
      artifactRef: 'df-protocol-launch-alpha',
      artifactHash: DIGEST_D,
      actionHash: DIGEST_E,
      custodyDigest: DIGEST_F,
      sensitivityTags: ['metadata_only', 'decision_metadata'],
      familyEvidence: {
        decisionReceiptHash: DIGEST_D,
        quorumHash: DIGEST_E,
        humanGateHash: DIGEST_F,
      },
    }),
    anchorRecord({
      anchorRef: 'anchor-consent-alpha',
      family: 'consent_receipt',
      artifactType: 'participant_consent_grant',
      artifactRef: 'consent-grant-alpha',
      artifactHash: DIGEST_1,
      actionHash: DIGEST_2,
      custodyDigest: DIGEST_3,
      sensitivityTags: ['metadata_only', 'participant_linked_metadata'],
      participantLinked: true,
      consentRef: 'consent-bailment-alpha',
      familyEvidence: {
        consentPolicyHash: DIGEST_1,
        consentReceiptHash: DIGEST_2,
        participantCodeHash: DIGEST_3,
      },
    }),
    anchorRecord({
      anchorRef: 'anchor-authority-alpha',
      family: 'authority_receipt',
      artifactType: 'authority_chain_validation',
      artifactRef: 'authority-chain-alpha',
      artifactHash: DIGEST_4,
      actionHash: DIGEST_5,
      custodyDigest: DIGEST_6,
      sensitivityTags: ['metadata_only', 'authority_metadata'],
      familyEvidence: {
        authorityChainHash: DIGEST_4,
        authorityReceiptHash: DIGEST_5,
        delegationAuditHash: DIGEST_6,
      },
    }),
    anchorRecord({
      anchorRef: 'anchor-audit-alpha',
      family: 'audit_anchor',
      artifactType: 'audit_event_receipt',
      artifactRef: 'audit-event-alpha',
      artifactHash: DIGEST_7,
      actionHash: DIGEST_8,
      custodyDigest: DIGEST_9,
      sensitivityTags: ['metadata_only', 'audit_metadata'],
      familyEvidence: {
        auditEntryHash: DIGEST_7,
        dagNodeHash: DIGEST_8,
        dagPayloadHash: DIGEST_8,
      },
    }),
  ];
}

function anchoringInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['exochain_anchor', 'write'],
      authorityChainHash: DIGEST_A,
    },
    anchorSet: {
      anchorSetRef: 'fr042-anchor-set-alpha',
      purpose: 'qms_evidence_integrity',
      requestedAtHlc: { physicalMs: 1800000000000, logical: 0 },
      generatedAtHlc: { physicalMs: 1800000000000, logical: 4 },
      metadataOnly: true,
      productionTrustClaim: false,
      externalAnchorRequested: false,
    },
    anchoringPolicy: {
      policyRef: 'fr042-anchoring-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredAnchorFamilies: REQUIRED_ANCHOR_FAMILIES,
      metadataOnly: true,
      sourcePayloadAccessible: false,
      dagPayloadStored: false,
      crossCheckedEnabled: false,
      rootBackedProductionClaim: false,
      evaluatedAtHlc: { physicalMs: 1800000000000, logical: 1 },
      validUntilHlc: { physicalMs: 1800100000000, logical: 0 },
    },
    anchors: anchorRecords(),
    participantConsentMatrix: [
      {
        consentRef: 'consent-bailment-alpha',
        status: 'active',
        scope: 'metadata_anchor',
        participantCodeHash: DIGEST_3,
        consentReceiptHash: DIGEST_2,
        revoked: false,
        expiresAtHlc: { physicalMs: 1800100000000, logical: 0 },
      },
    ],
    adapterBoundary: {
      gatewayVerified: false,
      nodeReceiptVerified: false,
      rootBundleVerified: false,
      decisionForumVerified: false,
      productionTrustActivation: false,
      localSimulationUsed: false,
      cachedOutcomeUsed: false,
      overrideUsed: false,
    },
    humanAuthorization: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      status: 'approved',
      authorizationHash: DIGEST_C,
      authorizedAtHlc: { physicalMs: 1800000000000, logical: 3 },
      aiFinalAuthorityRejected: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      scopeHash: DIGEST_D,
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_E,
  };
  return mergeDeep(base, overrides);
}

test('Exochain anchoring creates deterministic inactive FR-042 metadata package for required receipt families', async () => {
  const { evaluateExochainAnchoring } = await loadExochainAnchoring();

  const resultA = evaluateExochainAnchoring(anchoringInput());
  const resultB = evaluateExochainAnchoring(
    anchoringInput({
      anchors: [...anchorRecords()].reverse(),
      anchoringPolicy: {
        requiredAnchorFamilies: [...REQUIRED_ANCHOR_FAMILIES].reverse(),
      },
    }),
  );
  const resultC = evaluateExochainAnchoring(
    anchoringInput({
      aiAssistance: null,
      rawAnchorPayload: [],
      rawSourceData: null,
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultC.decision, 'permitted');
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.anchorPackage.packageId, resultB.anchorPackage.packageId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.anchorPackage.trustState, 'inactive');
  assert.equal(resultA.anchorPackage.exochainProductionClaim, false);
  assert.equal(resultA.anchorPackage.metadataOnly, true);
  assert.equal(resultA.anchorPackage.protectedContentAnchored, false);
  assert.equal(resultA.anchorPackage.externalAnchoringActive, false);
  assert.deepEqual(resultA.anchorPackage.anchorFamilies, REQUIRED_ANCHOR_FAMILIES);
  assert.deepEqual(
    resultA.anchorPackage.anchors.map((anchor) => anchor.anchorRef),
    [
      'anchor-audit-alpha',
      'anchor-authority-alpha',
      'anchor-consent-alpha',
      'anchor-decision-alpha',
      'anchor-evidence-alpha',
    ],
  );
  assert.deepEqual(Object.keys(resultA.anchorPackage.anchors[0]), [
    'actionHash',
    'anchorRef',
    'artifactHash',
    'artifactRef',
    'artifactType',
    'classification',
    'custodyDigest',
    'family',
    'familyEvidenceHash',
    'hlcTimestamp',
    'participantLinked',
    'sensitivityTags',
  ]);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'exochain_anchor_package');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.deepEqual(resultA.anchorPackage.exochainPrimitiveRefs, [
    'crates/exo-authority/src/chain.rs',
    'crates/exo-consent/src/bailment.rs',
    'crates/exo-core/src/types.rs',
    'crates/exo-dag/src/dag.rs',
    'crates/exo-governance/src/audit.rs',
  ]);
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|source document|private key|bearer token/iu);
});

test('Exochain anchoring fails closed for missing families unsafe policy and production trust claims', async () => {
  const { evaluateExochainAnchoring } = await loadExochainAnchoring();

  const denied = evaluateExochainAnchoring(
    anchoringInput({
      targetTenantId: 'tenant-site-beta',
      actor: { did: 'did:exo:ai-anchor-agent-alpha', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: true,
        expired: true,
        permissions: ['read'],
        authorityChainHash: 'not-a-digest',
      },
      anchorSet: {
        productionTrustClaim: true,
        externalAnchorRequested: true,
      },
      anchoringPolicy: {
        status: 'draft',
        metadataOnly: false,
        sourcePayloadAccessible: true,
        dagPayloadStored: true,
        crossCheckedEnabled: true,
        rootBackedProductionClaim: true,
        requiredAnchorFamilies: REQUIRED_ANCHOR_FAMILIES.filter((family) => family !== 'audit_anchor'),
      },
      adapterBoundary: {
        productionTrustActivation: true,
        localSimulationUsed: true,
        cachedOutcomeUsed: true,
        overrideUsed: true,
      },
      anchors: anchorRecords().filter((anchor) => anchor.family !== 'audit_anchor'),
      aiAssistance: {
        finalAuthority: true,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.anchorPackage, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('anchor_authority_missing'));
  assert.ok(denied.reasons.includes('anchor_set_production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('external_anchor_request_forbidden_before_activation'));
  assert.ok(denied.reasons.includes('anchoring_policy_not_active'));
  assert.ok(denied.reasons.includes('anchoring_policy_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('source_payload_access_forbidden'));
  assert.ok(denied.reasons.includes('dag_payload_storage_forbidden_before_activation'));
  assert.ok(denied.reasons.includes('crosschecked_anchor_forbidden_before_activation'));
  assert.ok(denied.reasons.includes('root_backed_production_claim_forbidden'));
  assert.ok(denied.reasons.includes('required_anchor_family_missing:audit_anchor'));
  assert.ok(denied.reasons.includes('adapter_production_activation_forbidden'));
  assert.ok(denied.reasons.includes('adapter_local_simulation_forbidden'));
  assert.ok(denied.reasons.includes('adapter_cached_outcome_forbidden'));
  assert.ok(denied.reasons.includes('adapter_override_forbidden'));
  assert.ok(denied.reasons.includes('ai_assistance_final_authority_forbidden'));
});

test('Exochain anchoring requires active consent and human authorization for participant-linked receipts', async () => {
  const { evaluateExochainAnchoring } = await loadExochainAnchoring();

  const denied = evaluateExochainAnchoring(
    anchoringInput({
      participantConsentMatrix: [
        {
          consentRef: 'consent-bailment-alpha',
          status: 'revoked',
          scope: 'metadata_anchor',
          participantCodeHash: DIGEST_3,
          consentReceiptHash: DIGEST_2,
          revoked: true,
          expiresAtHlc: { physicalMs: 1800100000000, logical: 0 },
        },
      ],
      humanAuthorization: {
        reviewerDid: 'did:exo:quality-manager-alpha',
        status: 'pending',
        authorizationHash: DIGEST_C,
        authorizedAtHlc: { physicalMs: 'invalid', logical: 3 },
        aiFinalAuthorityRejected: false,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('participant_consent_not_active:anchor-consent-alpha'));
  assert.ok(denied.reasons.includes('participant_consent_revoked:anchor-consent-alpha'));
  assert.ok(denied.reasons.includes('human_authorization_not_approved'));
  assert.ok(denied.reasons.includes('human_authorization_time_invalid'));
  assert.ok(denied.reasons.includes('human_authorization_ai_boundary_absent'));
});

test('Exochain anchoring fails closed on HLC ordering digest and anchor-boundary defects', async () => {
  const { evaluateExochainAnchoring } = await loadExochainAnchoring();

  const denied = evaluateExochainAnchoring(
    anchoringInput({
      anchorSet: {
        requestedAtHlc: { physicalMs: 1800000000000, logical: 4 },
        generatedAtHlc: { physicalMs: 1800000000000, logical: 3 },
      },
      anchoringPolicy: {
        evaluatedAtHlc: { physicalMs: 1799999999000, logical: 0 },
        validUntilHlc: { physicalMs: 1800000000000, logical: 3 },
      },
      anchors: [
        ...anchorRecords().slice(0, 4),
        anchorRecord({
          anchorRef: 'anchor-audit-alpha',
          family: 'audit_anchor',
          artifactHash: 'not-a-digest',
          actionHash: DIGEST_8,
          custodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
          boundary: {
            metadataOnly: false,
            rawContentExcluded: false,
            sourcePayloadExcluded: false,
            directIdentifiersExcluded: false,
            secretMaterialExcluded: false,
          },
          familyEvidence: {
            auditEntryHash: DIGEST_7,
            dagNodeHash: 'not-a-digest',
            dagPayloadHash: DIGEST_8,
          },
        }),
        anchorRecord({
          anchorRef: 'anchor-unknown-alpha',
          family: 'unknown_anchor',
          artifactHash: DIGEST_A,
          actionHash: DIGEST_B,
          custodyDigest: DIGEST_C,
          hlcTimestamp: { physicalMs: 1800000000000, logical: 3 },
        }),
      ],
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('anchor_generated_before_request'));
  assert.ok(denied.reasons.includes('anchoring_policy_before_request'));
  assert.ok(denied.reasons.includes('anchoring_policy_expired'));
  assert.ok(denied.reasons.includes('anchor_family_unsupported:unknown_anchor'));
  assert.ok(denied.reasons.includes('anchor_family_invalid:anchor-unknown-alpha'));
  assert.ok(denied.reasons.includes('anchor_artifact_hash_invalid:anchor-audit-alpha'));
  assert.ok(denied.reasons.includes('anchor_custody_digest_invalid:anchor-audit-alpha'));
  assert.ok(denied.reasons.includes('anchor_metadata_boundary_invalid:anchor-audit-alpha'));
  assert.ok(denied.reasons.includes('anchor_raw_content_boundary_invalid:anchor-audit-alpha'));
  assert.ok(denied.reasons.includes('anchor_source_payload_boundary_invalid:anchor-audit-alpha'));
  assert.ok(denied.reasons.includes('anchor_direct_identifier_boundary_invalid:anchor-audit-alpha'));
  assert.ok(denied.reasons.includes('anchor_secret_boundary_invalid:anchor-audit-alpha'));
  assert.ok(denied.reasons.includes('anchor_family_evidence_hash_invalid:anchor-audit-alpha:dagNodeHash'));
});

test('Exochain anchoring rejects raw payloads protected content and secret material before packaging', async () => {
  const { ProtectedContentError, evaluateExochainAnchoring } = await loadExochainAnchoring();

  assert.throws(
    () => evaluateExochainAnchoring(anchoringInput({ rawSourceData: { note: 'raw source payload' } })),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateExochainAnchoring(anchoringInput({ anchors: [anchorRecord({ dagPayload: { artifactHash: DIGEST_A } })] })),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateExochainAnchoring(anchoringInput({ anchors: [anchorRecord({ privateKey: 'redacted-private-key-placeholder' })] })),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateExochainAnchoring(anchoringInput({ anchors: [anchorRecord({ freeTextNote: 'Participant Alice Example source document detail' })] })),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateExochainAnchoring(anchoringInput({ anchors: [anchorRecord({ rawAnchorPayload: 1 })] })),
    ProtectedContentError,
  );
});
