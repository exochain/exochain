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

import { ProtectedContentError, canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const CLINICAL_CONSENT_EQUIVALENCE_GATE_ID = 'PTAG-007';

const REQUIRED_CONSENT_ELEMENTS = Object.freeze([
  'alternativeProcedures',
  'confidentiality',
  'dataSharing',
  'financialConsideration',
  'knownRisks',
  'nonCoercion',
  'participantCopy',
  'privateSetting',
  'questionOpportunity',
  'timeToReview',
  'unknownRisks',
  'withdrawal',
]);

const RAW_CONSENT_FIELDS = new Set([
  'assentbody',
  'consentformbody',
  'consentrawtext',
  'participantcommunicationbody',
  'participantname',
  'rawassent',
  'rawconsent',
  'rawconsentform',
  'rawparticipantcommunication',
  'rawsignature',
  'signatureimage',
  'sourcedocumentbody',
]);

const VALID_DATA_SHARING_STATUSES = new Set(['declined', 'granted', 'not_applicable']);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawConsentContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawConsentContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_CONSENT_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`protected content field is not allowed at ${path}.${key}`);
    }
    assertNoRawConsentContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawConsentContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [BigInt(hlc.physicalMs), BigInt(hlc.logical)];
}

function compareHlc(left, right) {
  if (left[0] < right[0]) {
    return -1;
  }
  if (left[0] > right[0]) {
    return 1;
  }
  if (left[1] < right[1]) {
    return -1;
  }
  if (left[1] > right[1]) {
    return 1;
  }
  return 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hlcAfterOrEqual(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) >= 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons, permissions, missingReason) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !permissions.some((permission) => hasAuthorityPermission(input?.authority, permission)), missingReason);
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function consentElementCoverage(elements) {
  const present = REQUIRED_CONSENT_ELEMENTS.filter((element) => elements?.[element] === true);
  return {
    basisPoints: Number((BigInt(present.length) * 10000n) / BigInt(REQUIRED_CONSENT_ELEMENTS.length)),
    missing: REQUIRED_CONSENT_ELEMENTS.filter((element) => elements?.[element] !== true),
  };
}

function evaluateIecIrbApproval(material, reasons) {
  const approval = material?.iecIrbApproval;
  addReason(reasons, approval?.status !== 'approved', 'iec_irb_approval_not_approved');
  addReason(reasons, !hasText(approval?.approvalRef), 'iec_irb_approval_ref_absent');
  addReason(reasons, !isDigest(approval?.approvalEvidenceHash), 'iec_irb_approval_evidence_invalid');
  addReason(reasons, hlcTuple(approval?.approvedAtHlc) === null, 'iec_irb_approval_time_invalid');
  addReason(reasons, sortedTextList(approval?.approvedMaterialRefs).length === 0, 'iec_irb_approved_material_refs_absent');
}

function evaluateRequiredElementReview(material, reasons) {
  const review = material?.requiredElementReview;
  addReason(reasons, review?.status !== 'complete', 'required_element_review_incomplete');
  addReason(reasons, !['ai_advisory', 'human'].includes(review?.reviewerKind), 'required_element_reviewer_invalid');
  addReason(reasons, !isDigest(review?.promptDigest), 'required_element_prompt_digest_invalid');
  addReason(reasons, !isDigest(review?.outputDigest), 'required_element_output_digest_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'required_element_review_time_invalid');

  const coverage = consentElementCoverage(review?.elements);
  addReason(reasons, coverage.missing.length > 0, 'required_consent_elements_incomplete');
  return coverage;
}

function evaluateReadabilityReview(material, reasons) {
  const review = material?.readabilityReview;
  addReason(reasons, review?.status !== 'acceptable', 'readability_review_not_acceptable');
  addReason(reasons, !['ai_advisory', 'human'].includes(review?.reviewerKind), 'readability_reviewer_invalid');
  addReason(reasons, !isDigest(review?.promptDigest), 'readability_prompt_digest_invalid');
  addReason(reasons, !isDigest(review?.outputDigest), 'readability_output_digest_invalid');
  addReason(reasons, !hasText(review?.readabilityLevel), 'readability_level_absent');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'readability_review_time_invalid');
}

function evaluatePrivacyLegalReview(material, reasons) {
  const review = material?.privacyLegalReview;
  addReason(reasons, review?.status !== 'passed', 'privacy_legal_review_not_passed');
  addReason(reasons, !isDigest(review?.privacyStatementHash), 'privacy_statement_hash_invalid');
  addReason(reasons, review?.nonWaiverLegalRightsCheck !== true, 'non_waiver_legal_rights_check_absent');
  addReason(reasons, review?.nonReleaseNegligenceCheck !== true, 'non_release_negligence_check_absent');
  addReason(reasons, !isDigest(review?.confidentialityAssuranceHash), 'confidentiality_assurance_hash_invalid');
  addReason(reasons, !hasText(review?.reviewedByDid), 'privacy_legal_reviewer_absent');
}

function evaluateVulnerablePopulationRequirements(material, reasons) {
  const entries = Array.isArray(material?.vulnerablePopulationRequirements) ? material.vulnerablePopulationRequirements : [];
  addReason(reasons, entries.length === 0, 'vulnerable_population_requirements_absent');
  for (const entry of entries) {
    addReason(reasons, !hasText(entry?.population), 'vulnerable_population_ref_absent');
    addReason(reasons, !isDigest(entry?.safeguardHash), 'vulnerable_population_safeguard_hash_invalid');
    addReason(reasons, typeof entry?.required !== 'boolean', 'vulnerable_population_required_flag_invalid');
    addReason(reasons, entry?.approved !== true, 'vulnerable_population_safeguard_not_approved');
  }
}

function evaluateSiteUseApproval(material, reasons) {
  const approval = material?.siteUseApproval;
  addReason(reasons, approval?.approved !== true, 'site_use_approval_absent');
  addReason(reasons, !hasText(approval?.approvedByDid), 'site_use_approval_actor_absent');
  addReason(reasons, !isDigest(approval?.approvalEvidenceHash), 'site_use_approval_evidence_invalid');
  addReason(reasons, hlcTuple(approval?.approvedAtHlc) === null, 'site_use_approval_time_invalid');
  addReason(
    reasons,
    hlcTuple(approval?.approvedAtHlc) !== null &&
      hlcTuple(material?.iecIrbApproval?.approvedAtHlc) !== null &&
      !hlcAfterOrEqual(approval.approvedAtHlc, material.iecIrbApproval.approvedAtHlc),
    'site_use_approval_before_iec_irb_approval',
  );
}

function evaluatePublication(material, reasons) {
  const publication = material?.publication;
  addReason(reasons, publication?.publishActiveVersion !== true, 'active_version_publication_absent');
  const supersededRefs = sortedTextList(publication?.supersededVersionRefs);
  addReason(
    reasons,
    supersededRefs.length > 0 && !isDigest(publication?.supersededRetirementEvidenceHash),
    'superseded_retirement_evidence_absent',
  );
  addReason(reasons, !isDigest(publication?.staffNotificationEvidenceHash), 'staff_notification_evidence_absent');
  addReason(reasons, sortedTextList(publication?.notifiedRoleRefs).length === 0, 'staff_notification_roles_absent');
}

function evaluateReconsent(material, reasons) {
  const reconsent = material?.reconsent;
  addReason(reasons, typeof reconsent?.materialNewInformation !== 'boolean', 'material_new_information_flag_invalid');
  if (reconsent?.materialNewInformation === true) {
    addReason(reasons, reconsent?.reviewRequired !== true, 'reconsent_review_required_flag_absent');
    addReason(reasons, sortedTextList(reconsent?.triggerRuleRefs).length === 0, 'reconsent_trigger_rules_absent');
    addReason(reasons, !isDigest(reconsent?.reviewEvidenceHash), 'reconsent_review_evidence_absent');
  }
}

function evaluateConsentMaterial(input, reasons) {
  const material = input?.material;
  addReason(reasons, !hasText(material?.consentFormRef), 'consent_form_ref_absent');
  addReason(reasons, !hasText(material?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(material?.version), 'consent_material_version_absent');
  addReason(reasons, material?.status !== 'approved_for_site_use', 'consent_material_not_approved_for_site_use');
  addReason(reasons, material?.genericBailmentOnly === true, 'ptag_007_generic_bailment_only_forbidden');
  addReason(reasons, material?.clinicalConsentEquivalenceClaim === true, 'ptag_007_clinical_consent_equivalence_claim_forbidden');
  addReason(reasons, !isDigest(material?.formArtifactHash), 'consent_form_artifact_hash_invalid');
  addReason(reasons, !isDigest(material?.protocolLinkHash), 'protocol_link_hash_invalid');
  addReason(reasons, hlcTuple(material?.uploadedAtHlc) === null, 'consent_material_upload_time_invalid');
  addReason(reasons, hlcTuple(material?.versionEffectiveAtHlc) === null, 'consent_material_effective_time_invalid');
  addReason(
    reasons,
    hlcTuple(material?.uploadedAtHlc) !== null && hlcTuple(material?.versionEffectiveAtHlc) !== null && !hlcAfter(material.versionEffectiveAtHlc, material.uploadedAtHlc),
    'consent_material_effective_before_upload',
  );

  evaluateIecIrbApproval(material, reasons);
  const coverage = evaluateRequiredElementReview(material, reasons);
  evaluateReadabilityReview(material, reasons);
  evaluatePrivacyLegalReview(material, reasons);
  evaluateVulnerablePopulationRequirements(material, reasons);
  addReason(reasons, !hasText(material?.ownerDid), 'consent_process_owner_absent');
  evaluateSiteUseApproval(material, reasons);
  evaluatePublication(material, reasons);
  evaluateReconsent(material, reasons);
  addReason(reasons, sortedTextList(material?.consentBailmentRefs).length === 0, 'consent_bailment_refs_absent');

  return coverage;
}

function evaluateConsentMaterialGovernance(input, reasons) {
  const forum = input?.review?.decisionForum;
  addReason(reasons, !hasText(input?.review?.humanReviewerDid), 'human_consent_reviewer_absent');
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, input?.review?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function materialId(input) {
  const material = input?.material;
  return `cmicf_${sha256Hex({
    consentFormRef: material?.consentFormRef ?? null,
    protocolRef: material?.protocolRef ?? null,
    tenantId: input?.tenantId ?? null,
    version: material?.version ?? null,
  }).slice(0, 32)}`;
}

function materialRequirementRefs(material) {
  return sortedTextList((Array.isArray(material?.vulnerablePopulationRequirements) ? material.vulnerablePopulationRequirements : []).map((entry) => entry?.population));
}

function buildMaterialRecord(input, coverage, status, receiptId = null) {
  const material = input?.material;
  return {
    schema: 'cybermedica.consent_material_record.v1',
    materialId: materialId(input),
    tenantId: input?.tenantId ?? null,
    consentFormRef: material?.consentFormRef ?? null,
    protocolRef: material?.protocolRef ?? null,
    version: material?.version ?? null,
    status,
    approvedForSiteUse: status === 'active',
    iecIrbApprovalRef: material?.iecIrbApproval?.approvalRef ?? null,
    requiredElementCoverageBasisPoints: coverage.basisPoints,
    missingRequiredElements: [...coverage.missing].sort(),
    readabilityStatus: material?.readabilityReview?.status ?? null,
    privacyLegalReviewStatus: material?.privacyLegalReview?.status ?? null,
    vulnerablePopulationRefs: materialRequirementRefs(material),
    vulnerablePopulationRequirementCount: materialRequirementRefs(material).length,
    reconsentReviewRequired: material?.reconsent?.materialNewInformation === true,
    reconsentTriggerRuleRefs: sortedTextList(material?.reconsent?.triggerRuleRefs),
    supersededVersionRefs: sortedTextList(material?.publication?.supersededVersionRefs),
    notifiedRoleRefs: sortedTextList(material?.publication?.notifiedRoleRefs),
    consentBailmentRefs: sortedTextList(material?.consentBailmentRefs),
    versionEffectiveAtHlc: material?.versionEffectiveAtHlc ?? null,
    receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    activationGateIds: [CLINICAL_CONSENT_EQUIVALENCE_GATE_ID],
    genericBailmentAloneAccepted: false,
    clinicalConsentEquivalenceClaim: false,
    containsProtectedContent: false,
  };
}

function createConsentMaterialReceipt(input, record, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'consent_material_readiness',
    artifactVersion: `${record.consentFormRef}@${record.version}`,
    classification: 'consent_material_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.material.versionEffectiveAtHlc,
    sensitivityTags: ['consent_material', 'metadata_only', 'participant_rights'],
    sourceSystem: 'cybermedica.consent_materials',
    tenantId: input.tenantId,
  });
}

export function evaluateConsentMaterialReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons, ['manage_consent_materials', 'govern', 'write'], 'consent_material_authority_missing');
  const coverage = evaluateConsentMaterial(input, reasons);
  evaluateConsentMaterialGovernance(input, reasons);
  const uniqueReasons = uniqueSorted(reasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.consent_material_readiness.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      materialRecord: buildMaterialRecord(input, coverage, 'blocked'),
      receipt: null,
    };
  }

  const record = buildMaterialRecord(input, coverage, 'active');
  const artifactHash = sha256Hex({
    consentBailmentRefs: record.consentBailmentRefs,
    consentFormRef: record.consentFormRef,
    decisionForumReceiptId: input.review.decisionForum.workflowReceiptId,
    materialId: record.materialId,
    notifiedRoleRefs: record.notifiedRoleRefs,
    protocolRef: record.protocolRef,
    reconsentTriggerRuleRefs: record.reconsentTriggerRuleRefs,
    requiredElementCoverageBasisPoints: record.requiredElementCoverageBasisPoints,
    supersededVersionRefs: record.supersededVersionRefs,
    tenantId: input.tenantId,
    version: record.version,
    versionEffectiveAtHlc: record.versionEffectiveAtHlc,
    vulnerablePopulationRefs: record.vulnerablePopulationRefs,
  });
  const receipt = createConsentMaterialReceipt(input, record, artifactHash);

  return {
    schema: 'cybermedica.consent_material_readiness.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    materialRecord: {
      ...record,
      receiptId: receipt.receiptId,
    },
    receipt,
  };
}

function evaluateParticipant(input, reasons) {
  const participant = input?.participant;
  addReason(reasons, !isDigest(participant?.participantCodeHash), 'participant_code_hash_invalid');
  addReason(reasons, !hasText(participant?.larStatus), 'lar_status_absent');
  addReason(reasons, typeof participant?.witnessRequired !== 'boolean', 'witness_requirement_invalid');
  addReason(reasons, typeof participant?.assentRequired !== 'boolean', 'assent_requirement_invalid');
  addReason(
    reasons,
    sortedTextList(participant?.vulnerablePopulationSafeguardRefs).length === 0,
    'vulnerable_population_safeguard_refs_absent',
  );
}

function evaluateActiveMaterialForProcess(input, reasons) {
  const material = input?.activeConsentMaterial;
  addReason(reasons, material?.status !== 'active' || material?.approvedForSiteUse !== true, 'active_approved_consent_material_absent');
  addReason(reasons, !hasText(material?.materialId), 'active_consent_material_id_absent');
  addReason(reasons, !hasText(material?.consentFormRef), 'active_consent_form_ref_absent');
  addReason(reasons, !hasText(material?.version), 'active_consent_version_absent');
  addReason(reasons, !hasText(material?.protocolRef), 'active_protocol_ref_absent');
  addReason(reasons, !hasText(material?.receiptId), 'active_consent_material_receipt_absent');
  addReason(reasons, hlcTuple(material?.versionEffectiveAtHlc) === null, 'active_consent_effective_time_invalid');
  addReason(reasons, material?.genericBailmentAloneAccepted === true, 'ptag_007_generic_bailment_only_forbidden');
  addReason(
    reasons,
    material?.clinicalConsentEquivalenceClaim === true,
    'ptag_007_clinical_consent_equivalence_claim_forbidden',
  );
}

function evaluateStaffReadiness(input, reasons) {
  const staff = input?.staffReadiness;
  addReason(reasons, staff?.trained !== true, 'consent_staff_training_absent');
  addReason(reasons, staff?.delegated !== true, 'consent_staff_delegation_absent');
  addReason(reasons, !isDigest(staff?.trainingEvidenceHash), 'consent_staff_training_evidence_invalid');
  addReason(reasons, !hasText(staff?.delegationReceiptId), 'consent_staff_delegation_receipt_absent');
}

function evaluateDataSharingConsent(consent, reasons) {
  addReason(reasons, !VALID_DATA_SHARING_STATUSES.has(consent?.status), 'data_sharing_consent_invalid');
  if (consent?.status === 'granted' || consent?.status === 'declined') {
    addReason(reasons, !isDigest(consent?.evidenceHash), 'data_sharing_consent_evidence_invalid');
  }
  if (consent?.status === 'granted') {
    addReason(reasons, sortedTextList(consent?.scopeRefs).length === 0, 'data_sharing_scope_refs_absent');
  }
}

function evaluateConsentProcessDetails(input, reasons) {
  const process = input?.process;
  addReason(reasons, process?.privateSettingConfirmed !== true, 'private_setting_absent');
  addReason(reasons, process?.writtenInformationProvided !== true, 'written_information_absent');
  addReason(reasons, process?.questionsAllowed !== true, 'question_opportunity_absent');
  addReason(reasons, process?.sufficientReviewTime !== true, 'sufficient_review_time_absent');
  addReason(reasons, process?.risksUnderstood !== true, 'risk_understanding_absent');
  addReason(reasons, process?.voluntarinessConfirmed !== true, 'voluntariness_absent');
  if (input?.participant?.assentRequired === true) {
    addReason(reasons, process?.assentDocumented !== 'documented', 'assent_documentation_absent');
  }
  if (input?.participant?.witnessRequired === true) {
    addReason(reasons, process?.witnessPresent !== true, 'witness_absent');
  }
  addReason(reasons, process?.signaturesComplete !== true, 'consent_signatures_incomplete');
  addReason(reasons, hlcTuple(process?.signedAtHlc) === null, 'consent_signed_time_invalid');
  addReason(
    reasons,
    hlcTuple(process?.signedAtHlc) !== null &&
      hlcTuple(input?.activeConsentMaterial?.versionEffectiveAtHlc) !== null &&
      !hlcAfterOrEqual(process.signedAtHlc, input.activeConsentMaterial.versionEffectiveAtHlc),
    'consent_signed_before_material_effective',
  );
  addReason(reasons, process?.participantCopyDelivered !== true, 'participant_copy_delivery_absent');
  addReason(reasons, !isDigest(process?.consentEvidenceHash), 'consent_process_evidence_hash_invalid');
  addReason(reasons, !hasText(process?.consentBailmentRef), 'consent_bailment_ref_absent');
  evaluateDataSharingConsent(process?.dataSharingConsent, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function processRecordId(input) {
  return `cmcproc_${sha256Hex({
    materialId: input?.activeConsentMaterial?.materialId ?? null,
    participantCodeHash: input?.participant?.participantCodeHash ?? null,
    signedAtHlc: input?.process?.signedAtHlc ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function buildConsentProcessRecord(input, status, receiptId = null) {
  return {
    schema: 'cybermedica.participant_consent_process_record.v1',
    consentProcessId: processRecordId(input),
    tenantId: input?.tenantId ?? null,
    participantCodeHash: input?.participant?.participantCodeHash ?? null,
    consentMaterialId: input?.activeConsentMaterial?.materialId ?? null,
    consentFormRef: input?.activeConsentMaterial?.consentFormRef ?? null,
    consentVersion: input?.activeConsentMaterial?.version ?? null,
    protocolRef: input?.activeConsentMaterial?.protocolRef ?? null,
    status,
    enrollmentConsentGate: status === 'complete' ? 'passed' : 'blocked',
    consentStaffDid: input?.actor?.did ?? null,
    staffTrained: input?.staffReadiness?.trained === true,
    staffDelegated: input?.staffReadiness?.delegated === true,
    larStatus: input?.participant?.larStatus ?? null,
    witnessRequired: input?.participant?.witnessRequired === true,
    assentRequired: input?.participant?.assentRequired === true,
    participantCopyDelivered: input?.process?.participantCopyDelivered === true,
    dataSharingConsentStatus: input?.process?.dataSharingConsent?.status ?? null,
    dataSharingScopeRefs: sortedTextList(input?.process?.dataSharingConsent?.scopeRefs),
    signedAtHlc: input?.process?.signedAtHlc ?? null,
    consentBailmentRef: input?.process?.consentBailmentRef ?? null,
    receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    activationGateIds: [CLINICAL_CONSENT_EQUIVALENCE_GATE_ID],
    genericBailmentAloneAccepted: false,
    clinicalConsentEquivalenceClaim: false,
    containsProtectedContent: false,
  };
}

function createConsentProcessReceipt(input, record, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'participant_consent_process',
    artifactVersion: `${record.consentMaterialId}@${record.consentProcessId}`,
    classification: 'participant_consent_process_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.process.signedAtHlc,
    sensitivityTags: ['consent_process', 'metadata_only', 'participant_rights'],
    sourceSystem: 'cybermedica.consent_materials',
    tenantId: input.tenantId,
  });
}

export function documentParticipantConsentProcess(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons, ['obtain_consent', 'write', 'govern'], 'consent_process_authority_missing');
  evaluateParticipant(input, reasons);
  evaluateActiveMaterialForProcess(input, reasons);
  evaluateStaffReadiness(input, reasons);
  evaluateConsentProcessDetails(input, reasons);
  const uniqueReasons = uniqueSorted(reasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.participant_consent_process_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      consentProcessRecord: buildConsentProcessRecord(input, 'blocked'),
      receipt: null,
    };
  }

  const record = buildConsentProcessRecord(input, 'complete');
  const artifactHash = sha256Hex({
    consentBailmentRef: record.consentBailmentRef,
    consentEvidenceHash: input.process.consentEvidenceHash,
    consentMaterialReceiptId: input.activeConsentMaterial.receiptId,
    consentProcessId: record.consentProcessId,
    dataSharingConsentStatus: record.dataSharingConsentStatus,
    dataSharingScopeRefs: record.dataSharingScopeRefs,
    participantCodeHash: record.participantCodeHash,
    protocolRef: record.protocolRef,
    signedAtHlc: record.signedAtHlc,
    staffDelegationReceiptId: input.staffReadiness.delegationReceiptId,
    tenantId: input.tenantId,
  });
  const receipt = createConsentProcessReceipt(input, record, artifactHash);

  return {
    schema: 'cybermedica.participant_consent_process_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    consentProcessRecord: {
      ...record,
      receiptId: receipt.receiptId,
    },
    receipt,
  };
}
