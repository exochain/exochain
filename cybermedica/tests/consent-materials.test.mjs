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

async function loadConsentMaterials() {
  try {
    return await import('../src/consent-materials.mjs');
  } catch (error) {
    assert.fail(`CyberMedica consent-materials module must exist and load: ${error.message}`);
  }
}

function consentMaterialInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:consent-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'manage_consent_materials'],
      authorityChainHash: DIGEST_F,
    },
    material: {
      consentFormRef: 'ICF-CARDIO-ALPHA',
      protocolRef: 'protocol-cardiac-alpha',
      version: 'v3.1',
      status: 'approved_for_site_use',
      formArtifactHash: DIGEST_A,
      uploadedAtHlc: { physicalMs: 1790000000000, logical: 0 },
      versionEffectiveAtHlc: { physicalMs: 1791000000000, logical: 1 },
      protocolLinkHash: DIGEST_B,
      iecIrbApproval: {
        status: 'approved',
        approvalRef: 'IRB-APPROVAL-CARDIO-ALPHA-003',
        approvalEvidenceHash: DIGEST_C,
        approvedAtHlc: { physicalMs: 1790500000000, logical: 0 },
        approvedMaterialRefs: ['ICF-CARDIO-ALPHA-v3.1', 'PARTICIPANT-INFO-CARDIO-v3.1'],
      },
      requiredElementReview: {
        status: 'complete',
        reviewerKind: 'ai_advisory',
        promptDigest: DIGEST_D,
        outputDigest: DIGEST_E,
        reviewedAtHlc: { physicalMs: 1790600000000, logical: 0 },
        elements: {
          knownRisks: true,
          unknownRisks: true,
          alternativeProcedures: true,
          confidentiality: true,
          financialConsideration: true,
          questionOpportunity: true,
          nonCoercion: true,
          timeToReview: true,
          privateSetting: true,
          withdrawal: true,
          dataSharing: true,
          participantCopy: true,
        },
      },
      readabilityReview: {
        status: 'acceptable',
        reviewerKind: 'ai_advisory',
        promptDigest: DIGEST_A,
        outputDigest: DIGEST_B,
        readabilityLevel: 'site_policy_acceptable',
        reviewedAtHlc: { physicalMs: 1790600000000, logical: 1 },
      },
      privacyLegalReview: {
        status: 'passed',
        privacyStatementHash: DIGEST_C,
        nonWaiverLegalRightsCheck: true,
        nonReleaseNegligenceCheck: true,
        confidentialityAssuranceHash: DIGEST_D,
        reviewedByDid: 'did:exo:legal-reviewer-alpha',
      },
      vulnerablePopulationRequirements: [
        { population: 'adult_with_lar_available', safeguardHash: DIGEST_E, required: true, approved: true },
        { population: 'minor_assent', safeguardHash: DIGEST_F, required: false, approved: true },
      ],
      ownerDid: 'did:exo:consent-owner-alpha',
      siteUseApproval: {
        approved: true,
        approvedByDid: 'did:exo:principal-investigator-alpha',
        approvalEvidenceHash: DIGEST_A,
        approvedAtHlc: { physicalMs: 1790800000000, logical: 0 },
      },
      publication: {
        publishActiveVersion: true,
        supersededVersionRefs: ['ICF-CARDIO-ALPHA-v3.0', 'ICF-CARDIO-ALPHA-v2.4'],
        supersededRetirementEvidenceHash: DIGEST_B,
        staffNotificationEvidenceHash: DIGEST_C,
        notifiedRoleRefs: ['principal_investigator', 'sub_investigator', 'consent_designee'],
      },
      reconsent: {
        materialNewInformation: true,
        triggerRuleRefs: ['new_safety_information', 'protocol_amendment_consent_change'],
        reviewRequired: true,
        reviewEvidenceHash: DIGEST_D,
      },
      consentBailmentRefs: ['bailment-participant-alpha', 'consent-policy-cardio-alpha'],
    },
    review: {
      humanReviewerDid: 'did:exo:quality-manager-alpha',
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-consent-material-alpha',
        workflowReceiptId: 'df-consent-material-workflow-alpha',
      },
      phiBoundaryAttested: true,
    },
    custodyDigest: DIGEST_E,
  };
}

function consentProcessInput(activeMaterial) {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:consent-designee-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'obtain_consent'],
      authorityChainHash: DIGEST_F,
    },
    participant: {
      participantCodeHash: DIGEST_A,
      larStatus: 'not_applicable',
      witnessRequired: true,
      assentRequired: false,
      vulnerablePopulationSafeguardRefs: ['adult_with_lar_available'],
    },
    activeConsentMaterial: activeMaterial,
    staffReadiness: {
      trained: true,
      delegated: true,
      trainingEvidenceHash: DIGEST_B,
      delegationReceiptId: 'cmdel_training_consent_alpha',
    },
    process: {
      privateSettingConfirmed: true,
      writtenInformationProvided: true,
      questionsAllowed: true,
      sufficientReviewTime: true,
      risksUnderstood: true,
      voluntarinessConfirmed: true,
      assentDocumented: 'not_applicable',
      witnessPresent: true,
      signaturesComplete: true,
      signedAtHlc: { physicalMs: 1792000000000, logical: 0 },
      participantCopyDelivered: true,
      consentEvidenceHash: DIGEST_C,
      dataSharingConsent: { status: 'granted', evidenceHash: DIGEST_D, scopeRefs: ['coded_data_export'] },
      consentBailmentRef: 'bailment-participant-alpha',
    },
    custodyDigest: DIGEST_E,
  };
}

test('consent material readiness creates deterministic inactive active-version receipts', async () => {
  const { evaluateConsentMaterialReadiness } = await loadConsentMaterials();

  const resultA = evaluateConsentMaterialReadiness(consentMaterialInput());
  const resultB = evaluateConsentMaterialReadiness({
    ...consentMaterialInput(),
    material: {
      ...consentMaterialInput().material,
      vulnerablePopulationRequirements: [...consentMaterialInput().material.vulnerablePopulationRequirements].reverse(),
      publication: {
        ...consentMaterialInput().material.publication,
        notifiedRoleRefs: [...consentMaterialInput().material.publication.notifiedRoleRefs].reverse(),
        supersededVersionRefs: [...consentMaterialInput().material.publication.supersededVersionRefs].reverse(),
      },
      consentBailmentRefs: [...consentMaterialInput().material.consentBailmentRefs].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.materialRecord.status, 'active');
  assert.equal(resultA.materialRecord.approvedForSiteUse, true);
  assert.equal(resultA.materialRecord.requiredElementCoverageBasisPoints, 10000);
  assert.equal(resultA.materialRecord.readabilityStatus, 'acceptable');
  assert.equal(resultA.materialRecord.reconsentReviewRequired, true);
  assert.deepEqual(resultA.materialRecord.activationGateIds, ['PTAG-007']);
  assert.equal(resultA.materialRecord.genericBailmentAloneAccepted, false);
  assert.equal(resultA.materialRecord.clinicalConsentEquivalenceClaim, false);
  assert.equal(resultA.materialRecord.materialId, resultB.materialRecord.materialId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'consent_material_readiness');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|raw consent|source document|medical record/iu);
});

test('consent material readiness fails closed for missing reviews approvals notifications and reconsent evidence', async () => {
  const { evaluateConsentMaterialReadiness } = await loadConsentMaterials();

  const result = evaluateConsentMaterialReadiness({
    ...consentMaterialInput(),
      material: {
        ...consentMaterialInput().material,
        genericBailmentOnly: true,
        clinicalConsentEquivalenceClaim: true,
        iecIrbApproval: { status: 'pending', approvalRef: '', approvalEvidenceHash: DIGEST_C },
      requiredElementReview: {
        ...consentMaterialInput().material.requiredElementReview,
        elements: { ...consentMaterialInput().material.requiredElementReview.elements, unknownRisks: false },
      },
      readabilityReview: { ...consentMaterialInput().material.readabilityReview, status: 'needs_revision' },
      privacyLegalReview: {
        ...consentMaterialInput().material.privacyLegalReview,
        nonWaiverLegalRightsCheck: false,
        nonReleaseNegligenceCheck: false,
      },
      publication: {
        ...consentMaterialInput().material.publication,
        staffNotificationEvidenceHash: '',
        supersededRetirementEvidenceHash: '',
      },
      reconsent: {
        materialNewInformation: true,
        triggerRuleRefs: [],
        reviewRequired: true,
        reviewEvidenceHash: '',
      },
    },
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.materialRecord.status, 'blocked');
  assert.equal(result.receipt, null);
  assert.match(result.reasons.join('|'), /iec_irb_approval_not_approved/);
  assert.match(result.reasons.join('|'), /ptag_007_generic_bailment_only_forbidden/);
  assert.match(result.reasons.join('|'), /ptag_007_clinical_consent_equivalence_claim_forbidden/);
  assert.match(result.reasons.join('|'), /required_consent_elements_incomplete/);
  assert.match(result.reasons.join('|'), /readability_review_not_acceptable/);
  assert.match(result.reasons.join('|'), /non_waiver_legal_rights_check_absent/);
  assert.match(result.reasons.join('|'), /superseded_retirement_evidence_absent/);
  assert.match(result.reasons.join('|'), /staff_notification_evidence_absent/);
  assert.match(result.reasons.join('|'), /reconsent_trigger_rules_absent/);
  assert.match(result.reasons.join('|'), /reconsent_review_evidence_absent/);
});

test('participant consent process documentation requires active material trained delegation and metadata-only receipt', async () => {
  const { documentParticipantConsentProcess, evaluateConsentMaterialReadiness } = await loadConsentMaterials();
  const material = evaluateConsentMaterialReadiness(consentMaterialInput()).materialRecord;

  const record = documentParticipantConsentProcess(consentProcessInput(material));

  assert.equal(record.decision, 'permitted');
  assert.equal(record.failClosed, false);
  assert.equal(record.consentProcessRecord.status, 'complete');
  assert.equal(record.consentProcessRecord.enrollmentConsentGate, 'passed');
  assert.equal(record.consentProcessRecord.participantCopyDelivered, true);
  assert.equal(record.consentProcessRecord.dataSharingConsentStatus, 'granted');
  assert.deepEqual(record.consentProcessRecord.activationGateIds, ['PTAG-007']);
  assert.equal(record.consentProcessRecord.genericBailmentAloneAccepted, false);
  assert.equal(record.consentProcessRecord.clinicalConsentEquivalenceClaim, false);
  assert.equal(record.receipt.anchorPayload.artifactType, 'participant_consent_process');
  assert.equal(record.receipt.trustState, 'inactive');
  assert.equal(record.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(record), /Participant Alice|participant name|raw signature|medical record/iu);
});

test('participant consent process fails closed for superseded material untrained staff incomplete signature and raw participant content', async () => {
  const { documentParticipantConsentProcess, evaluateConsentMaterialReadiness } = await loadConsentMaterials();
  const material = evaluateConsentMaterialReadiness(consentMaterialInput()).materialRecord;

  const denied = documentParticipantConsentProcess({
    ...consentProcessInput({
      ...material,
      status: 'superseded',
      genericBailmentAloneAccepted: true,
      clinicalConsentEquivalenceClaim: true,
    }),
    staffReadiness: {
      ...consentProcessInput(material).staffReadiness,
      trained: false,
      delegated: false,
      trainingEvidenceHash: '',
    },
    process: {
      ...consentProcessInput(material).process,
      signaturesComplete: false,
      participantCopyDelivered: false,
      dataSharingConsent: { status: 'expanded_without_consent', evidenceHash: '', scopeRefs: [] },
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.consentProcessRecord.status, 'blocked');
  assert.equal(denied.receipt, null);
  assert.match(denied.reasons.join('|'), /active_approved_consent_material_absent/);
  assert.match(denied.reasons.join('|'), /ptag_007_generic_bailment_only_forbidden/);
  assert.match(denied.reasons.join('|'), /ptag_007_clinical_consent_equivalence_claim_forbidden/);
  assert.match(denied.reasons.join('|'), /consent_staff_training_absent/);
  assert.match(denied.reasons.join('|'), /consent_staff_delegation_absent/);
  assert.match(denied.reasons.join('|'), /consent_signatures_incomplete/);
  assert.match(denied.reasons.join('|'), /participant_copy_delivery_absent/);
  assert.match(denied.reasons.join('|'), /data_sharing_consent_invalid/);

  assert.throws(
    () =>
      documentParticipantConsentProcess({
        ...consentProcessInput(material),
        participant: { ...consentProcessInput(material).participant, participantName: 'Participant Alice Example' },
      }),
    /protected content/i,
  );
});

test('consent readiness uses deterministic HLC ordering for material activation and assent documentation', async () => {
  const { documentParticipantConsentProcess, evaluateConsentMaterialReadiness } = await loadConsentMaterials();

  const beforeUpload = evaluateConsentMaterialReadiness({
    ...consentMaterialInput(),
    material: {
      ...consentMaterialInput().material,
      versionEffectiveAtHlc: { physicalMs: 1789000000000, logical: 0 },
    },
  });
  assert.equal(beforeUpload.decision, 'denied');
  assert.match(beforeUpload.reasons.join('|'), /consent_material_effective_before_upload/);

  const sameTickActivation = evaluateConsentMaterialReadiness({
    ...consentMaterialInput(),
    material: {
      ...consentMaterialInput().material,
      versionEffectiveAtHlc: consentMaterialInput().material.uploadedAtHlc,
    },
  });
  assert.equal(sameTickActivation.decision, 'denied');
  assert.match(sameTickActivation.reasons.join('|'), /consent_material_effective_before_upload/);

  const material = evaluateConsentMaterialReadiness(consentMaterialInput()).materialRecord;
  const signedAfterSamePhysicalTick = documentParticipantConsentProcess({
    ...consentProcessInput({ ...material, versionEffectiveAtHlc: { physicalMs: 1792000000000, logical: 0 } }),
    participant: {
      ...consentProcessInput(material).participant,
      assentRequired: true,
    },
    process: {
      ...consentProcessInput(material).process,
      assentDocumented: 'documented',
      signedAtHlc: { physicalMs: 1792000000000, logical: 1 },
    },
  });
  assert.equal(signedAfterSamePhysicalTick.decision, 'permitted');

  const signedBeforeSamePhysicalTick = documentParticipantConsentProcess({
    ...consentProcessInput({ ...material, versionEffectiveAtHlc: { physicalMs: 1792000000000, logical: 2 } }),
    participant: {
      ...consentProcessInput(material).participant,
      assentRequired: true,
    },
    process: {
      ...consentProcessInput(material).process,
      assentDocumented: 'not_documented',
      signedAtHlc: { physicalMs: 1792000000000, logical: 1 },
    },
  });
  assert.equal(signedBeforeSamePhysicalTick.decision, 'denied');
  assert.match(signedBeforeSamePhysicalTick.reasons.join('|'), /assent_documentation_absent/);
  assert.match(signedBeforeSamePhysicalTick.reasons.join('|'), /consent_signed_before_material_effective/);
});
