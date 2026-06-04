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
const STUDY_REGISTRY_SCHEMA = 'cybermedica.study_registry.v1';
const STUDY_REGISTRY_RECORD_SCHEMA = 'cybermedica.study_registry_record.v1';

const REQUIRED_STUDY_DOMAINS = Object.freeze([
  'authority_boundary',
  'consent_boundary',
  'ethics_review',
  'information_management',
  'protocol_binding',
  'receipt_boundary',
  'site_binding',
  'sponsor_cro_boundary',
  'study_identity',
]);

const REQUIRED_RECEIPT_FAMILIES = Object.freeze([
  'audit',
  'authority',
  'consent',
  'decision_forum',
  'ethics_review',
  'evidence',
  'protocol',
]);

const LIFECYCLE_STATES = new Set(['startup', 'active', 'closeout']);
const PROTOCOL_APPROVAL_STATES = new Set(['approved_for_startup', 'approved_active']);
const ETHICS_STATUSES = new Set(['current_approved']);
const HUMAN_REVIEW_DECISIONS = new Set(['study_registry_ready', 'study_registry_hold']);

const RAW_STUDY_FIELDS = new Set([
  'clinicalnote',
  'contractbody',
  'directidentifier',
  'directidentifiers',
  'freetextstudy',
  'participantidentifier',
  'participantlisting',
  'participantname',
  'patientname',
  'protocolbody',
  'rawconsent',
  'rawconsenttext',
  'rawparticipant',
  'rawparticipantlisting',
  'rawprotocol',
  'rawprotocolbody',
  'rawprotocoltext',
  'rawsite',
  'rawsponsor',
  'rawsponsorcontract',
  'rawstudy',
  'rawstudynarrative',
  'sourcebody',
  'sourcedocumentbody',
  'sponsorconfidentialbody',
  'sponsorcontractbody',
  'studynarrative',
]);

const SECRET_STUDY_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'clientsecret',
  'credential',
  'credentialsecret',
  'password',
  'privatekey',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'sessionsecret',
  'signaturesecret',
  'signingkey',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function sensitiveValuePresent(value) {
  if (value === null || value === undefined || value === false) {
    return false;
  }
  if (typeof value === 'string') {
    return value.trim().length > 0;
  }
  if (Array.isArray(value)) {
    return value.some((item) => sensitiveValuePresent(item));
  }
  if (typeof value === 'object') {
    return Object.keys(value).length > 0;
  }
  return true;
}

function assertNoRawStudyRegistryContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawStudyRegistryContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_STUDY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw study registry content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_STUDY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`study registry secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawStudyRegistryContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawStudyRegistryContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlcTuple(left, right) {
  if (left[0] !== right[0]) {
    return left[0] < right[0] ? -1 : 1;
  }
  if (left[1] !== right[1]) {
    return left[1] < right[1] ? -1 : 1;
  }
  return 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) < 0;
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_study_registry_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, 'study_registry_manage') && !hasAuthorityPermission(input?.authority, 'govern'),
    'study_registry_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateStudy(input, reasons) {
  const study = input?.study;
  addReason(reasons, !hasText(study?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(study?.studyVersion), 'study_version_absent');
  addReason(reasons, study?.schemaVersion !== STUDY_REGISTRY_SCHEMA, 'study_schema_invalid');
  addReason(reasons, !LIFECYCLE_STATES.has(study?.lifecycleState), 'study_lifecycle_state_invalid');
  addReason(reasons, study?.tenantRef !== input?.tenantId, 'study_tenant_ref_mismatch');
  addReason(reasons, !hasText(study?.organizationRef), 'study_organization_ref_absent');
  addReason(reasons, !hasText(study?.siteRef), 'study_site_ref_absent');
  addReason(reasons, !hasText(study?.protocolRef), 'study_protocol_ref_absent');
  addReason(reasons, !hasText(study?.protocolVersionRef), 'study_protocol_version_ref_absent');
  addReason(reasons, study?.protocolRef !== input?.protocolBinding?.protocolRef, 'study_protocol_binding_mismatch');
  addReason(reasons, study?.protocolVersionRef !== input?.protocolBinding?.protocolVersionRef, 'study_protocol_version_mismatch');
  addReason(reasons, !hasText(study?.sponsorRef), 'study_sponsor_ref_absent');
  addReason(reasons, study?.sponsorRef !== input?.sponsorCroBoundary?.sponsorRef, 'study_sponsor_boundary_mismatch');
  addReason(reasons, sortedTextList(study?.croRefs).length === 0, 'study_cro_refs_absent');
  addReason(reasons, !hasText(study?.principalInvestigatorDid), 'principal_investigator_absent');
  addReason(reasons, !hasText(study?.qualityManagerDid), 'quality_manager_absent');
  addReason(reasons, !isDigest(study?.studyProfileHash), 'study_profile_hash_invalid');
  addReason(reasons, !isDigest(study?.studyPlanHash), 'study_plan_hash_invalid');
  addReason(reasons, !isDigest(study?.configurationHash), 'study_configuration_hash_invalid');
  addReason(reasons, hlcTuple(study?.registeredAtHlc) === null, 'study_registration_time_invalid');
  addReason(reasons, hlcBefore(study?.registeredAtHlc, input?.humanReview?.reviewedAtHlc), 'study_registered_before_human_review');
  addReason(reasons, study?.metadataOnly !== true, 'study_metadata_boundary_invalid');
  addReason(reasons, study?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateDomainCoverage(input, reasons) {
  const coverage = sortedTextList(input?.domainCoverage);
  for (const domain of REQUIRED_STUDY_DOMAINS) {
    addReason(reasons, !coverage.includes(domain), `domain_missing:${domain}`);
  }
}

function evaluateProtocolBinding(binding, reasons) {
  addReason(reasons, !hasText(binding?.protocolRef), 'protocol_binding_ref_absent');
  addReason(reasons, !hasText(binding?.protocolVersionRef), 'protocol_binding_version_absent');
  addReason(reasons, !isDigest(binding?.protocolHash), 'protocol_hash_invalid');
  addReason(reasons, !hasText(binding?.protocolIntakeReceiptRef), 'protocol_intake_receipt_absent');
  addReason(reasons, !hasText(binding?.protocolControlReceiptRef), 'protocol_control_receipt_absent');
  addReason(reasons, !PROTOCOL_APPROVAL_STATES.has(binding?.currentApprovalState), 'protocol_not_approved_for_startup');
  addReason(reasons, sortedTextList(binding?.activeAmendmentRefs).length === 0, 'active_amendment_ref_absent');
  addReason(reasons, hlcTuple(binding?.effectiveAtHlc) === null, 'protocol_effective_time_invalid');
  addReason(reasons, binding?.metadataOnly !== true, 'protocol_binding_metadata_boundary_invalid');
}

function evaluateSponsorCroBoundary(input, reasons) {
  const boundary = input?.sponsorCroBoundary;
  const studyCroRefs = sortedTextList(input?.study?.croRefs);
  const boundaryCroRefs = sortedTextList(boundary?.croRefs);
  addReason(reasons, !hasText(boundary?.sponsorRef), 'sponsor_ref_absent');
  addReason(reasons, boundary?.sponsorRef !== input?.study?.sponsorRef, 'sponsor_ref_mismatch');
  addReason(reasons, boundaryCroRefs.length === 0, 'cro_ref_absent');
  addReason(
    reasons,
    studyCroRefs.length !== boundaryCroRefs.length || studyCroRefs.some((ref, index) => ref !== boundaryCroRefs[index]),
    'cro_boundary_mismatch',
  );
  addReason(reasons, !hasText(boundary?.clinicalTrialAgreementRef), 'cta_ref_absent');
  addReason(reasons, !isDigest(boundary?.clinicalTrialAgreementHash), 'cta_hash_invalid');
  addReason(reasons, boundary?.sponsorConfidentialBodyExcluded !== true, 'sponsor_confidential_body_guard_absent');
  addReason(reasons, !hasText(boundary?.controlledRequestPolicyRef), 'controlled_request_policy_ref_absent');
  addReason(reasons, !isDigest(boundary?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, boundary?.metadataOnly !== true, 'sponsor_cro_metadata_boundary_invalid');
}

function evaluateEthicsReview(input, reasons) {
  const ethics = input?.ethicsReview;
  addReason(reasons, sortedTextList(ethics?.iecIrbRefs).length === 0, 'ethics_committee_absent');
  addReason(reasons, sortedTextList(ethics?.approvalRefs).length === 0, 'ethics_approval_absent');
  addReason(
    reasons,
    input?.study?.participantLinked === true && sortedTextList(ethics?.consentMaterialRefs).length === 0,
    'participant_consent_material_absent',
  );
  addReason(reasons, !ETHICS_STATUSES.has(ethics?.status), 'ethics_review_not_current');
  addReason(reasons, hlcTuple(ethics?.approvedAtHlc) === null, 'ethics_approval_time_invalid');
  addReason(reasons, hlcTuple(ethics?.continuingReviewDueAtHlc) === null, 'continuing_review_due_time_invalid');
  addReason(reasons, hlcBefore(ethics?.continuingReviewDueAtHlc, ethics?.approvedAtHlc), 'continuing_review_due_before_approval');
  addReason(reasons, ethics?.metadataOnly !== true, 'ethics_metadata_boundary_invalid');
}

function evaluateConsentBoundary(input, reasons) {
  const consent = input?.consentBoundary;
  if (input?.study?.participantLinked !== true) {
    return;
  }
  addReason(reasons, consent?.required !== true, 'participant_consent_required_absent');
  addReason(reasons, !hasText(consent?.consentMaterialVersionRef), 'consent_material_version_absent');
  addReason(reasons, !isDigest(consent?.consentPolicyHash), 'consent_policy_hash_invalid');
  addReason(reasons, !isDigest(consent?.dataSharingConsentPolicyHash), 'data_sharing_consent_policy_hash_invalid');
  addReason(reasons, !hasText(consent?.revocationPathRef), 'consent_revocation_path_absent');
  addReason(reasons, consent?.noRawParticipantIdentifiers !== true, 'participant_identifier_guard_absent');
  addReason(reasons, consent?.metadataOnly !== true, 'consent_boundary_metadata_invalid');
}

function evaluateInformationManagement(info, reasons) {
  addReason(reasons, !hasText(info?.planRef), 'information_management_plan_ref_absent');
  addReason(reasons, !isDigest(info?.planHash), 'information_management_plan_hash_invalid');
  addReason(reasons, !hasText(info?.sourceDataTraceabilityRef), 'source_traceability_ref_absent');
  addReason(reasons, !isDigest(info?.crfMediaHash), 'crf_media_hash_invalid');
  addReason(reasons, !isDigest(info?.retentionRuleHash), 'retention_rule_hash_invalid');
  addReason(reasons, !isDigest(info?.finalReportRequirementHash), 'final_report_requirement_hash_invalid');
  addReason(reasons, !isDigest(info?.distributionRuleHash), 'distribution_rule_hash_invalid');
  addReason(reasons, hlcTuple(info?.approvedAtHlc) === null, 'information_management_approval_time_invalid');
  addReason(reasons, info?.metadataOnly !== true, 'information_management_metadata_boundary_invalid');
}

function evaluateReceiptBoundary(receiptBoundary, reasons) {
  const receiptFamilies = sortedTextList(receiptBoundary?.requiredReceiptFamilies);
  for (const family of REQUIRED_RECEIPT_FAMILIES) {
    addReason(reasons, !receiptFamilies.includes(family), `receipt_family_missing:${family}`);
  }
  addReason(reasons, receiptBoundary?.exochainReceiptCapable !== true, 'receipt_capability_absent');
  addReason(reasons, receiptBoundary?.rawPayloadAnchoringForbidden !== true, 'raw_payload_anchor_guard_absent');
  addReason(reasons, receiptBoundary?.productionTrustState !== 'inactive', 'production_trust_state_not_inactive');
  addReason(reasons, receiptBoundary?.rootTrustVerified === true, 'root_trust_verified_before_activation');
  addReason(reasons, receiptBoundary?.metadataOnly !== true, 'receipt_boundary_metadata_invalid');
}

function evaluateAiAssistance(ai, reasons) {
  if (ai === undefined || ai === null || ai.used !== true) {
    return;
  }
  addReason(reasons, !isDigest(ai.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, sortedTextList(ai.limitationHashes).length === 0, 'ai_limitation_hashes_absent');
  addReason(reasons, ai.advisoryOnly !== true, 'ai_advisory_only_absent');
  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, ai.reviewedByHuman !== true, 'ai_human_review_absent');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, review?.decision === 'study_registry_hold', 'study_registry_human_hold');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, input?.ethicsReview?.approvedAtHlc), 'human_review_before_ethics_approval');
  addReason(
    reasons,
    hlcBefore(review?.reviewedAtHlc, input?.informationManagement?.approvedAtHlc),
    'human_review_before_information_management_approval',
  );
}

function buildStudyRegistry(input) {
  const material = {
    domainCoverage: REQUIRED_STUDY_DOMAINS,
    informationPlanHash: input.informationManagement.planHash,
    protocolHash: input.protocolBinding.protocolHash,
    studyPlanHash: input.study.studyPlanHash,
    studyProfileHash: input.study.studyProfileHash,
    studyRef: input.study.studyRef,
    studyVersion: input.study.studyVersion,
    tenantId: input.tenantId,
  };

  return {
    schema: STUDY_REGISTRY_RECORD_SCHEMA,
    registryId: `cm_study_registry_${sha256Hex(material).slice(0, 32)}`,
    tenantId: input.tenantId,
    studyRef: input.study.studyRef,
    studyVersion: input.study.studyVersion,
    lifecycleState: input.study.lifecycleState,
    organizationRef: input.study.organizationRef,
    siteRef: input.study.siteRef,
    protocolRef: input.study.protocolRef,
    protocolVersionRef: input.study.protocolVersionRef,
    sponsorRef: input.study.sponsorRef,
    croRefs: sortedTextList(input.study.croRefs),
    principalInvestigatorDid: input.study.principalInvestigatorDid,
    qualityManagerDid: input.study.qualityManagerDid,
    participantLinked: input.study.participantLinked === true,
    domainCoverage: [...REQUIRED_STUDY_DOMAINS],
    requiredReceiptFamilies: [...REQUIRED_RECEIPT_FAMILIES],
    ethicsCommitteeRefs: sortedTextList(input.ethicsReview.iecIrbRefs),
    ethicsApprovalRefs: sortedTextList(input.ethicsReview.approvalRefs),
    consentMaterialRefs: sortedTextList(input.ethicsReview.consentMaterialRefs),
    consentMaterialVersionRef: input.consentBoundary?.consentMaterialVersionRef ?? null,
    informationManagementPlanRef: input.informationManagement.planRef,
    sourceDataTraceabilityRef: input.informationManagement.sourceDataTraceabilityRef,
    clinicalTrialAgreementRef: input.sponsorCroBoundary.clinicalTrialAgreementRef,
    disclosureLogHash: input.sponsorCroBoundary.disclosureLogHash,
    receiptBoundary: {
      exochainReceiptCapable: true,
      rawPayloadAnchoringForbidden: true,
      productionTrustState: 'inactive',
      rootTrustVerified: false,
    },
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
    metadataOnly: true,
    humanReviewerDid: input.humanReview.reviewerDid,
    custodyDigest: input.custodyDigest,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#Data-model-overview',
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#FR-001',
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#FR-010',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
    ],
  };
}

function createStudyRegistryReceipt(input, studyRegistry, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.humanReview.reviewerDid,
    artifactHash,
    artifactType: 'study_registry',
    artifactVersion: input.study.studyVersion,
    classification: 'metadata_only_study_registry',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.study.registeredAtHlc,
    sensitivityTags: [
      'metadata_only',
      'study_registry',
      input.study.participantLinked === true ? 'participant_linked_boundary' : 'non_participant_registry',
      'sponsor_cro_confidential_metadata',
    ],
    sourceSystem: 'cybermedica.study_registry',
    tenantId: input.tenantId,
  });
}

export function evaluateStudyRegistry(input = {}) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateStudy(input, reasons);
  evaluateDomainCoverage(input, reasons);
  evaluateProtocolBinding(input?.protocolBinding, reasons);
  evaluateSponsorCroBoundary(input, reasons);
  evaluateEthicsReview(input, reasons);
  evaluateConsentBoundary(input, reasons);
  evaluateInformationManagement(input?.informationManagement, reasons);
  evaluateReceiptBoundary(input?.receiptBoundary, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      studyRegistry: null,
      receipt: null,
    };
  }

  const studyRegistry = buildStudyRegistry(input);
  const artifactHash = sha256Hex(studyRegistry);
  const receipt = createStudyRegistryReceipt(input, studyRegistry, artifactHash);

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    studyRegistry,
    receipt,
  };
}
