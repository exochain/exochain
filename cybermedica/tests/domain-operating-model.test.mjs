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

const REQUIRED_DOMAIN_MODULES = [
  'ai_review',
  'control_library',
  'cqi',
  'decision_forum',
  'deviations_capa',
  'ethics',
  'evaluation_audit_reporting',
  'evidence_custody',
  'facilities_equipment_product',
  'information_management',
  'participant_protection',
  'protocol_readiness',
  'qms_passport',
  'risk',
  'workforce_delegation',
];

const REQUIRED_OPERATING_OBJECTS = [
  'clinical_trial_product',
  'controls',
  'decisions',
  'evidence',
  'facilities',
  'obligations',
  'participants',
  'people',
  'policies',
  'protocols',
  'risks',
  'source_data',
  'standards',
  'training_delegation',
];

const REQUIRED_DECISION_CLASSES = [
  'operational',
  'routine',
  'strategic',
];

const REQUIRED_EVIDENCE_FAMILIES = [
  'authority_chain',
  'consent_bailment_boundary',
  'decision_forum_receipt',
  'evidence_custody_digest',
  'metadata_only_receipt',
  'tenant_scope',
];

async function loadDomainOperatingModel() {
  try {
    return await import('../src/domain-operating-model.mjs');
  } catch (error) {
    assert.fail(`CyberMedica domain operating model module must exist and load: ${error.message}`);
  }
}

function digestFor(index) {
  return (index + 1).toString(16).padStart(2, '0').repeat(32);
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

function moduleRecord(moduleRef, index, overrides = {}) {
  return {
    moduleRef,
    ownerRole: index % 2 === 0 ? 'quality_manager' : 'principal_investigator',
    actorRoleRefs: ['quality_manager', 'principal_investigator', 'sponsor_cro_monitor'],
    controlledObjectRefs: REQUIRED_OPERATING_OBJECTS.slice(index % 3, index % 3 + 5),
    decisionClass: REQUIRED_DECISION_CLASSES[index % REQUIRED_DECISION_CLASSES.length],
    evidenceFamilyRefs: REQUIRED_EVIDENCE_FAMILIES,
    policyRefs: [`policy-domain-${index + 1}`],
    procedureRefs: [`procedure-domain-${index + 1}`],
    sourcePrdRef: 'cybermedica_2_0_sandy_seven_layer_master_prd.md#2-domain-layer',
    implementationModuleRef: `src/${moduleRef.replaceAll('_', '-')}.mjs`,
    testRef: `tests/${moduleRef.replaceAll('_', '-')}.test.mjs`,
    evidenceHash: digestFor(index + 20),
    custodyDigest: digestFor(index + 40),
    reviewedAtHlc: { physicalMs: 1810000000000 + index, logical: index % 4 },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function domainOperatingModelInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-cybermedica-alpha',
    targetTenantId: 'tenant-cybermedica-alpha',
    actor: {
      did: 'did:exo:domain-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'domain_owner'],
    },
    requestedAtHlc: { physicalMs: 1810000100000, logical: 0 },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['govern', 'domain_operating_model_govern'],
      authorityChainHash: DIGEST_A,
    },
    domainPolicy: {
      policyRef: 'domain-operating-model-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredDomainModules: REQUIRED_DOMAIN_MODULES,
      requiredOperatingObjects: REQUIRED_OPERATING_OBJECTS,
      requiredDecisionClasses: REQUIRED_DECISION_CLASSES,
      requiredEvidenceFamilies: REQUIRED_EVIDENCE_FAMILIES,
      sourcePrdRef: 'cybermedica_2_0_sandy_seven_layer_master_prd.md#2-domain-layer',
      evaluatedAtHlc: { physicalMs: 1810000005000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      noProductionTrustClaim: true,
    },
    moduleRecords: REQUIRED_DOMAIN_MODULES.map(moduleRecord).reverse(),
    operatingObjectInventory: REQUIRED_OPERATING_OBJECTS.map((objectRef, index) => ({
      objectRef,
      ownerRole: index % 2 === 0 ? 'quality_manager' : 'data_manager',
      evidenceHash: digestFor(index + 60),
      accessPolicyRef: `access-policy-${objectRef}`,
      retentionPolicyRef: `retention-policy-${objectRef}`,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1810000010000 + index, logical: index % 5 },
    })),
    humanReview: {
      reviewerDid: 'did:exo:quality-governance-alpha',
      reviewerRoleRefs: ['quality_manager'],
      decision: 'domain_model_ready_inactive_trust',
      reviewHash: DIGEST_C,
      aiFinalAuthority: false,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1810000200000, logical: 0 },
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_D,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    validationEvidence: {
      commandRefs: [
        'node --test tests/domain-operating-model.test.mjs',
        'node --test tests/source-guards.test.mjs',
      ],
      sourceGuardPassed: true,
      contractTestsPassed: true,
      pathClassificationCurrent: true,
      validationHash: DIGEST_E,
      metadataOnly: true,
      protectedContentExcluded: true,
      validatedAtHlc: { physicalMs: 1810000300000, logical: 0 },
    },
    custodyDigest: DIGEST_F,
  };

  return mergeDeep(base, overrides);
}

test('domain operating model creates deterministic inactive metadata-only Domain layer receipts', async () => {
  const { evaluateDomainOperatingModel } = await loadDomainOperatingModel();
  const first = evaluateDomainOperatingModel(domainOperatingModelInput());
  const second = evaluateDomainOperatingModel({
    ...domainOperatingModelInput(),
    moduleRecords: [...domainOperatingModelInput().moduleRecords].reverse(),
    operatingObjectInventory: [...domainOperatingModelInput().operatingObjectInventory].reverse(),
    domainPolicy: {
      ...domainOperatingModelInput().domainPolicy,
      requiredDomainModules: [...REQUIRED_DOMAIN_MODULES].reverse(),
      requiredOperatingObjects: [...REQUIRED_OPERATING_OBJECTS].reverse(),
      requiredDecisionClasses: [...REQUIRED_DECISION_CLASSES].reverse(),
      requiredEvidenceFamilies: [...REQUIRED_EVIDENCE_FAMILIES].reverse(),
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first.domainOperatingModel.domainModules, REQUIRED_DOMAIN_MODULES);
  assert.deepEqual(first.domainOperatingModel.operatingObjects, REQUIRED_OPERATING_OBJECTS);
  assert.deepEqual(first.domainOperatingModel.decisionClasses, REQUIRED_DECISION_CLASSES);
  assert.deepEqual(first.domainOperatingModel.evidenceFamilies, REQUIRED_EVIDENCE_FAMILIES);
  assert.equal(first.domainOperatingModel.moduleCount, REQUIRED_DOMAIN_MODULES.length);
  assert.equal(first.domainOperatingModel.metadataOnly, true);
  assert.equal(first.domainOperatingModel.exochainProductionClaim, false);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'domain_operating_model');
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.domainOperatingModel.modelHash, second.domainOperatingModel.modelHash);
  assert.doesNotMatch(JSON.stringify(first), /Participant Alice|client_secret|raw domain/iu);
});

test('domain operating model fails closed for missing modules objects and unsafe trust claims', async () => {
  const { evaluateDomainOperatingModel } = await loadDomainOperatingModel();
  const result = evaluateDomainOperatingModel(
    domainOperatingModelInput({
      moduleRecords: REQUIRED_DOMAIN_MODULES
        .filter((moduleRef) => moduleRef !== 'participant_protection')
        .map(moduleRecord),
      operatingObjectInventory: domainOperatingModelInput().operatingObjectInventory.filter(
        (row) => row.objectRef !== 'source_data',
      ),
      domainPolicy: {
        noProductionTrustClaim: false,
      },
      validationEvidence: {
        contractTestsPassed: false,
        pathClassificationCurrent: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('domain_module_missing:participant_protection'));
  assert.ok(result.reasons.includes('operating_object_missing:source_data'));
  assert.ok(result.reasons.includes('domain_policy_no_production_claim_invalid'));
  assert.ok(result.reasons.includes('validation_contract_tests_not_passed'));
  assert.ok(result.reasons.includes('path_classification_not_current'));
});

test('domain operating model requires human authority safe HLC order and advisory AI only', async () => {
  const { evaluateDomainOperatingModel } = await loadDomainOperatingModel();
  const result = evaluateDomainOperatingModel(
    domainOperatingModelInput({
      actor: {
        did: 'did:exo:assistant-alpha',
        kind: 'ai_agent',
      },
      authority: {
        valid: true,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      requestedAtHlc: { physicalMs: 1810000000000, logical: 0 },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1810000000000, logical: 0 },
        aiFinalAuthority: true,
      },
      aiAssistance: {
        finalAuthority: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('human_domain_owner_required'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('domain_operating_model_authority_missing'));
  assert.ok(result.reasons.includes('human_review_not_after_request'));
  assert.ok(result.reasons.includes('ai_assistance_final_authority_forbidden'));
});

test('domain operating model rejects raw domain content protected data and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDomainOperatingModel } = await loadDomainOperatingModel();

  assert.throws(
    () => evaluateDomainOperatingModel(domainOperatingModelInput({ rawDomainNarrative: 'Participant Alice source notes' })),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateDomainOperatingModel(domainOperatingModelInput({ runtimeConfig: { clientSecret: 'redacted-secret' } })),
    ProtectedContentError,
  );
});
