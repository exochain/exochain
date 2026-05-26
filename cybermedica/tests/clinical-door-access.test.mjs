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

const REQUIRED_DOORS = [
  'site_profile_workspace',
  'protocol_startup_workspace',
  'evidence_vault',
  'consent_workspace',
  'safety_event_desk',
  'deviation_capa_workspace',
  'audit_inspection_workspace',
  'sponsor_diligence_workspace',
  'decision_forum_workspace',
  'deployment_admin_workspace',
];

const DIGESTS = [
  DIGEST_A,
  DIGEST_B,
  DIGEST_C,
  DIGEST_D,
  DIGEST_E,
  DIGEST_F,
  DIGEST_1,
  DIGEST_2,
  DIGEST_3,
  DIGEST_4,
  DIGEST_5,
  DIGEST_6,
  DIGEST_7,
  DIGEST_8,
  DIGEST_9,
];

async function loadClinicalDoorAccess() {
  try {
    return await import('../src/clinical-door-access.mjs');
  } catch (error) {
    assert.fail(`CyberMedica clinical door access module must exist and load: ${error.message}`);
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

function doorFamily(doorRef) {
  if (['site_profile_workspace', 'protocol_startup_workspace'].includes(doorRef)) {
    return 'ground_truth';
  }
  if (['evidence_vault', 'consent_workspace'].includes(doorRef)) {
    return 'data';
  }
  if (['safety_event_desk', 'deviation_capa_workspace'].includes(doorRef)) {
    return 'domain_operations';
  }
  if (['audit_inspection_workspace', 'sponsor_diligence_workspace'].includes(doorRef)) {
    return 'external_oversight';
  }
  if (doorRef === 'decision_forum_workspace') {
    return 'doctrine_governance';
  }
  return 'deployment_operations';
}

function doorEntry(doorRef, index, overrides = {}) {
  const participantLinked = ['evidence_vault', 'consent_workspace', 'safety_event_desk'].includes(doorRef);
  const decisionForumRequired = [
    'protocol_startup_workspace',
    'deviation_capa_workspace',
    'sponsor_diligence_workspace',
    'decision_forum_workspace',
    'deployment_admin_workspace',
  ].includes(doorRef);
  const adminDoor = doorRef === 'deployment_admin_workspace';

  return {
    doorRef,
    family: doorFamily(doorRef),
    routeHash: DIGESTS[index % DIGESTS.length],
    sourceEvidenceHash: DIGESTS[(index + 1) % DIGESTS.length],
    registeredAtHlc: { physicalMs: 1803000000000 + index, logical: index % 3 },
    allowedRoleRefs: adminDoor
      ? ['system_administrator']
      : ['quality_manager', 'principal_investigator', 'site_leader', 'decision_forum_chair'],
    requiredPermissionRefs: adminDoor ? ['admin_configure'] : ['door_access'],
    requiredActorKinds: ['human'],
    participantLinked,
    consentRequired: participantLinked,
    decisionForumRequired,
    serverAdapterRequired: true,
    browserAuthoritative: false,
    metadataOnly: true,
    payloadsExcluded: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function doorAccessInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    requestedDoorRef: 'decision_forum_workspace',
    requestedAtHlc: { physicalMs: 1803001000000, logical: 0 },
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['door_access', 'govern', 'read_sensitive'],
      authorityChainHash: DIGEST_A,
    },
    doorRegistry: {
      registryRef: 'clinical-qms-door-registry-alpha',
      registryHash: DIGEST_B,
      status: 'active',
      evaluatedAtHlc: { physicalMs: 1803000900000, logical: 0 },
      requiredDoorRefs: REQUIRED_DOORS,
      allowedBobEscalationIds: ['ESC-RUNTIME', 'ESC-OPS-SECRETS'],
      activationGateIds: ['PTAG-016', 'PTAG-017', 'PTAG-018'],
      sourceDocRefs: ['docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md#doors-layer'],
      metadataOnly: true,
      productionTrustClaim: false,
      doors: REQUIRED_DOORS.map(doorEntry).reverse(),
    },
    trustBoundary: {
      productionTrustState: 'inactive',
      rootTrustVerified: false,
      runtimeEndpointVerified: false,
      selectedAdapterKind: 'server_side_gateway_node',
      serverSideAdapterRequired: true,
      browserAuthoritative: false,
      inactiveTrustNoticeRequired: true,
      rootSigningMaterialPresent: false,
      boundaryEvidenceHash: DIGEST_C,
    },
    consentBoundary: {
      required: false,
      status: 'not_required',
      revoked: false,
      consentRef: 'not-required',
      evidenceHash: DIGEST_D,
    },
    decisionForumGate: {
      required: true,
      matterRef: 'df-door-access-alpha',
      humanGateVerified: true,
      quorumEvidenceHash: DIGEST_E,
      tncEvidenceHash: DIGEST_F,
      kernelVerdict: 'permit',
      adjudicatedAtHlc: { physicalMs: 1803000950000, logical: 0 },
      metadataOnly: true,
    },
    disclosureLog: {
      disclosureRef: 'door-disclosure-alpha',
      loggedAtHlc: { physicalMs: 1803001000000, logical: 1 },
      disclosureHash: DIGEST_1,
      recipientClass: 'quality_manager',
      purpose: 'clinical_qms_door_access',
      includesRawContent: false,
    },
  };
  return mergeDeep(base, overrides);
}

test('clinical door access creates deterministic inactive product-door receipts', async () => {
  const { evaluateClinicalDoorAccess } = await loadClinicalDoorAccess();

  const input = doorAccessInput();
  const reversed = mergeDeep(input, {
    doorRegistry: {
      doors: [...input.doorRegistry.doors].reverse(),
    },
  });

  const resultA = evaluateClinicalDoorAccess(input);
  const resultB = evaluateClinicalDoorAccess(reversed);

  assert.equal(resultA.status, 'ready');
  assert.equal(resultA.schema, 'cybermedica.clinical_door_access.v1');
  assert.equal(resultA.requestedDoorRef, 'decision_forum_workspace');
  assert.deepEqual(resultA.requiredDoorRefs, REQUIRED_DOORS);
  assert.deepEqual(resultA.registryCoverage.missingDoorRefs, []);
  assert.ok(resultA.authorizedDoorRefs.includes('decision_forum_workspace'));
  assert.ok(!resultA.authorizedDoorRefs.includes('deployment_admin_workspace'));
  assert.equal(resultA.doorDecision.decisionForumRequired, true);
  assert.equal(resultA.trustState, 'inactive');
  assert.equal(resultA.exochainProductionClaim, false);
  assert.equal(resultA.canShowProductionTrustClaim, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.doorAccessHash, resultB.doorAccessHash);
  assert.deepEqual(resultA.authorizedDoorRefs, resultB.authorizedDoorRefs);
});

test('clinical door access fails closed for missing doors unsafe browser authority and production claims', async () => {
  const { evaluateClinicalDoorAccess } = await loadClinicalDoorAccess();

  const unsafe = doorAccessInput({
    requestedDoorRef: 'evidence_vault',
    doorRegistry: {
      productionTrustClaim: true,
      doors: REQUIRED_DOORS.filter((doorRef) => doorRef !== 'consent_workspace').map((doorRef, index) =>
        doorEntry(doorRef, index, doorRef === 'evidence_vault' ? { browserAuthoritative: true } : {}),
      ),
    },
    trustBoundary: {
      productionTrustState: 'verified',
      rootTrustVerified: true,
      runtimeEndpointVerified: true,
      selectedAdapterKind: 'browser_wasm',
      browserAuthoritative: true,
      inactiveTrustNoticeRequired: false,
    },
  });

  const result = evaluateClinicalDoorAccess(unsafe);

  assert.equal(result.status, 'denied');
  assert.ok(result.denialReasons.includes('required_door_missing:consent_workspace'));
  assert.ok(result.denialReasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.denialReasons.includes('browser_authoritative_trust_path_forbidden'));
  assert.ok(result.denialReasons.includes('selected_adapter_not_server_side'));
  assert.ok(result.denialReasons.includes('door_browser_authoritative_forbidden:evidence_vault'));
  assert.equal(result.receipt, null);
});

test('participant-linked clinical doors require active consent and metadata-only privacy boundaries', async () => {
  const { evaluateClinicalDoorAccess } = await loadClinicalDoorAccess();

  const denied = evaluateClinicalDoorAccess(
    doorAccessInput({
      requestedDoorRef: 'evidence_vault',
      consentBoundary: {
        required: true,
        status: 'revoked',
        revoked: true,
        consentRef: 'consent-evidence-alpha',
      },
      doorRegistry: {
        doors: REQUIRED_DOORS.map((doorRef, index) =>
          doorEntry(
            doorRef,
            index,
            doorRef === 'evidence_vault'
              ? {
                  payloadsExcluded: false,
                  protectedContentExcluded: false,
                }
              : {},
          ),
        ),
      },
    }),
  );

  assert.equal(denied.status, 'denied');
  assert.ok(denied.denialReasons.includes('consent_revoked'));
  assert.ok(denied.denialReasons.includes('door_payload_boundary_invalid:evidence_vault'));
  assert.ok(denied.denialReasons.includes('door_protected_boundary_invalid:evidence_vault'));
});

test('material clinical doors require verified human Decision Forum routing and safe HLC order', async () => {
  const { evaluateClinicalDoorAccess } = await loadClinicalDoorAccess();

  const denied = evaluateClinicalDoorAccess(
    doorAccessInput({
      actor: {
        did: 'did:exo:ai-quality-reviewer-alpha',
        kind: 'ai_agent',
        roleRefs: ['ai_quality_reviewer'],
      },
      decisionForumGate: {
        humanGateVerified: false,
        quorumEvidenceHash: 'not-a-digest',
        kernelVerdict: 'deny',
        adjudicatedAtHlc: { physicalMs: 1803000800000, logical: 0 },
      },
      disclosureLog: {
        loggedAtHlc: { physicalMs: 1803000900000, logical: 0 },
      },
    }),
  );

  assert.equal(denied.status, 'denied');
  assert.ok(denied.denialReasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.denialReasons.includes('actor_role_not_authorized_for_requested_door'));
  assert.ok(denied.denialReasons.includes('decision_forum_human_gate_unverified'));
  assert.ok(denied.denialReasons.includes('decision_forum_quorum_hash_invalid'));
  assert.ok(denied.denialReasons.includes('decision_forum_kernel_verdict_not_permit'));
  assert.ok(denied.denialReasons.includes('decision_forum_before_registry_evaluation'));
  assert.ok(denied.denialReasons.includes('disclosure_before_request'));
});

test('clinical door access rejects raw route payloads protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateClinicalDoorAccess } = await loadClinicalDoorAccess();

  assert.throws(
    () =>
      evaluateClinicalDoorAccess(
        doorAccessInput({
          doorRegistry: {
            doors: REQUIRED_DOORS.map((doorRef, index) =>
              doorEntry(doorRef, index, doorRef === 'consent_workspace' ? { rawRoutePayload: 'participant Alice' } : {}),
            ),
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateClinicalDoorAccess(
        doorAccessInput({
          trustBoundary: {
            rootSigningKey: 'secret-key-material',
          },
        }),
      ),
    ProtectedContentError,
  );
});
