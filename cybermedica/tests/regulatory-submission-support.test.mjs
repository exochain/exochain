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

const REQUIRED_READINESS_DOMAINS = [
  'consent_form_approvals',
  'continuing_reviews',
  'document_versioning',
  'iec_irb_approvals',
  'investigator_documents',
  'protocol_amendments',
  'regulatory_document_inventory',
  'sponsor_regulatory_exports',
];

const REQUIRED_EXPORT_FAMILIES = [
  'amendment_packet',
  'consent_form_packet',
  'continuing_review_packet',
  'ethics_approval_packet',
  'investigator_document_packet',
  'sponsor_regulatory_export_manifest',
];

async function loadRegulatorySubmissionSupport() {
  try {
    return await import('../src/regulatory-submission-support.mjs');
  } catch (error) {
    assert.fail(`CyberMedica regulatory submission support module must exist and load: ${error.message}`);
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

function readinessDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    domain,
    status: 'complete',
    evidenceHash: hashes[index],
    reviewedByDid: 'did:exo:regulatory-coordinator-alpha',
    reviewedAtHlc: { physicalMs: 1816000010000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function documentInventoryItem(family, index, overrides = {}) {
  const hashes = [DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    documentRef: `reg-doc-${family}-alpha`,
    family,
    currentVersionRef: `${family}:v${index + 1}`,
    artifactHash: hashes[index],
    approvalEvidenceHash: hashes[index + 1],
    status: 'current_approved',
    ownerDid: 'did:exo:regulatory-coordinator-alpha',
    reviewedAtHlc: { physicalMs: 1816000020000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function exportFamily(family, index, overrides = {}) {
  const hashes = [DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    family,
    manifestHash: hashes[index],
    sourcePackageRef: `submission-support-${family}`,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function regulatorySupportInput(overrides = {}) {
  return mergeDeep(
    {
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-alpha',
      actor: {
        did: 'did:exo:regulatory-coordinator-alpha',
        kind: 'human',
        roleRefs: ['regulatory_coordinator', 'quality_manager'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['regulatory_submission_support', 'read'],
        authorityChainHash: DIGEST_A,
      },
      readinessPolicy: {
        policyRef: 'regulatory-submission-support-policy-alpha',
        policyHash: DIGEST_B,
        status: 'active',
        requiredReadinessDomains: REQUIRED_READINESS_DOMAINS,
        requiredExportFamilies: REQUIRED_EXPORT_FAMILIES,
        allowedExportPurposes: ['regulatory_document_readiness', 'sponsor_regulatory_support'],
        metadataOnly: true,
        protectedContentExcluded: true,
        evaluatedAtHlc: { physicalMs: 1816000000000, logical: 0 },
      },
      regulatoryCycle: {
        cycleRef: 'regulatory-support-cycle-alpha',
        siteRef: 'site-alpha',
        studyRef: 'study-cm-001',
        protocolRef: 'protocol-cm-001',
        openedAtHlc: { physicalMs: 1816000005000, logical: 0 },
        inventoryLockedAtHlc: { physicalMs: 1816000025000, logical: 0 },
        packageCompiledAtHlc: { physicalMs: 1816000030000, logical: 0 },
        humanReviewedAtHlc: { physicalMs: 1816000040000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
        noRegulatoryStrategyClaim: true,
        statutoryAuthorityNotReplaced: true,
        productionTrustClaim: false,
      },
      readinessEvidence: REQUIRED_READINESS_DOMAINS.map(readinessDomain).reverse(),
      documentInventory: [
        documentInventoryItem('protocol_document', 0),
        documentInventoryItem('protocol_amendment', 1),
        documentInventoryItem('consent_form', 2),
        documentInventoryItem('iec_irb_approval', 3),
        documentInventoryItem('continuing_review', 4),
        documentInventoryItem('investigator_document', 5),
        documentInventoryItem('sponsor_export_manifest', 6),
      ],
      ethicsTracking: {
        status: 'current',
        approvalRefs: ['irb-approval-alpha'],
        amendmentRefs: ['amendment-approval-alpha'],
        consentFormRefs: ['consent-form-v7-approved'],
        continuingReviewRefs: ['continuing-review-2026-approval'],
        trackingHash: DIGEST_C,
        evaluatedAtHlc: { physicalMs: 1816000021000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      documentVersioning: {
        status: 'controlled',
        lineageHash: DIGEST_D,
        supersessionLogHash: DIGEST_E,
        obsoleteUseBlocked: true,
        currentApprovedVersionsOnly: true,
        versionControlActive: true,
        reviewedAtHlc: { physicalMs: 1816000022000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      exportPackage: {
        packageRef: 'regulatory-support-export-alpha',
        purpose: 'sponsor_regulatory_support',
        recipientTenantId: 'tenant-sponsor-alpha',
        exportGrantStatus: 'active',
        manifestHash: DIGEST_F,
        disclosureLogHash: DIGEST_1,
        suppressionLogHash: DIGEST_2,
        exportFamilies: REQUIRED_EXPORT_FAMILIES.map(exportFamily).reverse(),
        regulatoryStrategyClaim: false,
        statutoryFilingClaim: false,
        protectedContentSuppressed: true,
        directIdentifiersSuppressed: true,
        sponsorConfidentialMinimized: true,
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      humanAuthorization: {
        status: 'approved',
        reviewerDid: 'did:exo:quality-manager-alpha',
        reviewHash: DIGEST_3,
        approvedAtHlc: { physicalMs: 1816000028000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      aiAssistance: {
        used: true,
        finalAuthority: false,
        scopeHash: DIGEST_4,
        evidenceRefs: ['reg-doc-protocol_document-alpha', 'submission-support-ethics_approval_packet'],
        limitationHashes: [DIGEST_5],
      },
      receiptEvidence: {
        custodyDigest: DIGEST_6,
        artifactHash: DIGEST_7,
      },
    },
    overrides,
  );
}

test('regulatory submission support module loads', async () => {
  const mod = await loadRegulatorySubmissionSupport();
  assert.equal(typeof mod.evaluateRegulatorySubmissionSupport, 'function');
});

test('regulatory submission support creates deterministic metadata-only readiness receipts', async () => {
  const { evaluateRegulatorySubmissionSupport } = await loadRegulatorySubmissionSupport();
  const first = evaluateRegulatorySubmissionSupport(regulatorySupportInput());
  const second = evaluateRegulatorySubmissionSupport(
    regulatorySupportInput({
      readinessEvidence: [...regulatorySupportInput().readinessEvidence].reverse(),
      documentInventory: [...regulatorySupportInput().documentInventory].reverse(),
      exportPackage: {
        exportFamilies: [...regulatorySupportInput().exportPackage.exportFamilies].reverse(),
      },
    }),
  );

  assert.equal(first.status, 'ready');
  assert.deepEqual(first.reasons, []);
  assert.equal(first.regulatorySubmissionSupport.ready, true);
  assert.deepEqual(first.regulatorySubmissionSupport.readinessDomains, REQUIRED_READINESS_DOMAINS);
  assert.deepEqual(first.regulatorySubmissionSupport.exportFamilies, REQUIRED_EXPORT_FAMILIES);
  assert.equal(first.regulatorySubmissionSupport.noRegulatoryStrategyClaim, true);
  assert.equal(first.regulatorySubmissionSupport.statutoryAuthorityNotReplaced, true);
  assert.equal(first.regulatorySubmissionSupport.productionTrustClaim, false);
  assert.equal(first.regulatorySubmissionSupport.metadataOnly, true);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'regulatory_submission_support');
  assert.equal(first.regulatorySubmissionSupport.packageHash, second.regulatorySubmissionSupport.packageHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.doesNotMatch(JSON.stringify(first), /participant alice|medical record|raw protocol|source document/iu);
});

test('regulatory submission support fails closed for missing readiness evidence and unsafe claims', async () => {
  const { evaluateRegulatorySubmissionSupport } = await loadRegulatorySubmissionSupport();
  const denied = evaluateRegulatorySubmissionSupport(
    regulatorySupportInput({
      readinessEvidence: regulatorySupportInput().readinessEvidence.filter((item) => item.domain !== 'continuing_reviews'),
      ethicsTracking: {
        status: 'pending',
        approvalRefs: [],
        continuingReviewRefs: [],
      },
      exportPackage: {
        exportGrantStatus: 'pending',
        regulatoryStrategyClaim: true,
        statutoryFilingClaim: true,
        exportFamilies: regulatorySupportInput().exportPackage.exportFamilies.filter(
          (item) => item.family !== 'continuing_review_packet',
        ),
      },
      humanAuthorization: {
        status: 'pending',
      },
    }),
  );

  assert.equal(denied.status, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('readiness_domain_missing:continuing_reviews'));
  assert.ok(denied.reasons.includes('ethics_tracking_not_current'));
  assert.ok(denied.reasons.includes('ethics_approval_refs_absent'));
  assert.ok(denied.reasons.includes('continuing_review_refs_absent'));
  assert.ok(denied.reasons.includes('export_family_missing:continuing_review_packet'));
  assert.ok(denied.reasons.includes('export_grant_not_active'));
  assert.ok(denied.reasons.includes('regulatory_strategy_claim_forbidden'));
  assert.ok(denied.reasons.includes('statutory_submission_authority_claim_forbidden'));
  assert.ok(denied.reasons.includes('human_authorization_invalid'));
});

test('regulatory submission support enforces authority human review and HLC ordering', async () => {
  const { evaluateRegulatorySubmissionSupport } = await loadRegulatorySubmissionSupport();
  const denied = evaluateRegulatorySubmissionSupport(
    regulatorySupportInput({
      actor: {
        did: 'did:exo:ai-regulatory-agent-alpha',
        kind: 'ai_agent',
        roleRefs: ['regulatory_coordinator'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      regulatoryCycle: {
        packageCompiledAtHlc: { physicalMs: 1816000010000, logical: 0 },
        inventoryLockedAtHlc: { physicalMs: 1816000025000, logical: 0 },
      },
      humanAuthorization: {
        approvedAtHlc: { physicalMs: 1816000035000, logical: 0 },
      },
      aiAssistance: {
        finalAuthority: true,
      },
    }),
  );

  assert.equal(denied.status, 'denied');
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_actor_required'));
  assert.ok(denied.reasons.includes('regulatory_submission_support_authority_missing'));
  assert.ok(denied.reasons.includes('cycle_package_before_inventory_lock'));
  assert.ok(denied.reasons.includes('human_authorization_after_package_compile'));
});

test('regulatory submission support rejects raw documents protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateRegulatorySubmissionSupport } = await loadRegulatorySubmissionSupport();

  assert.throws(
    () =>
      evaluateRegulatorySubmissionSupport(
        regulatorySupportInput({
          documentInventory: [
            {
              ...regulatorySupportInput().documentInventory[0],
              rawProtocolBody: 'Participant Alice Example medical record details.',
            },
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRegulatorySubmissionSupport(
        regulatorySupportInput({
          exportPackage: {
            serviceToken: 'cm-regulatory-secret-token',
          },
        }),
      ),
    ProtectedContentError,
  );
});
