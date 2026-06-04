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
const REQUIRED_PERMISSION = 'protocol_amendment_impact';
const AMENDMENT_IMPACT_SCHEMA = 'cybermedica.protocol_amendment_impact.v1';

const REQUIRED_IMPACT_DOMAINS = Object.freeze([
  'budget_contract',
  'consent_reconsent',
  'ethics_review',
  'participant_communication',
  'product_blinding_randomization',
  'regulatory_submission',
  'risk_capa_deviation',
  'safety_reporting',
  'source_data_crf',
  'training_delegation',
  'vendor_lab_pharmacy',
  'visit_schedule',
]);

const PARTICIPANT_AFFECTING_DOMAINS = Object.freeze([
  'consent_reconsent',
  'ethics_review',
  'participant_communication',
  'training_delegation',
  'visit_schedule',
]);

const SUPPORTED_IMPACT_DOMAINS = new Set(REQUIRED_IMPACT_DOMAINS);
const SUPPORTED_IMPACT_LEVELS = new Set(['none', 'minor', 'material', 'participant_affecting']);
const MATERIAL_IMPACT_LEVELS = new Set(['material', 'participant_affecting']);
const COMPLETE_IMPACT_STATUSES = new Set(['complete', 'not_applicable']);

const RAW_AMENDMENT_FIELDS = new Set([
  'amendmentbody',
  'amendmentnarrative',
  'clinicalnotebody',
  'directidentifier',
  'freetextamendment',
  'freetextimpact',
  'labresultbody',
  'medicalrecord',
  'participantname',
  'patientname',
  'protocolbody',
  'rawamendment',
  'rawamendmentbody',
  'rawimpactassessment',
  'rawparticipantcommunication',
  'rawprotocol',
  'sourcedocumentbody',
]);

const SECRET_AMENDMENT_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'apitoken',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credentialsecret',
  'integrationsecret',
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
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
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

function assertNoAmendmentProtectedContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoAmendmentProtectedContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_AMENDMENT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protocol amendment source content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_AMENDMENT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protocol amendment secret field is not allowed at ${path}.${key}`);
    }
    assertNoAmendmentProtectedContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoAmendmentProtectedContent(input ?? {});
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

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'protocol_amendment_impact_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateAmendmentHeader(amendment, reasons) {
  addReason(reasons, !hasText(amendment?.amendmentRef), 'amendment_ref_absent');
  addReason(reasons, !hasText(amendment?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(amendment?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(amendment?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(amendment?.supersedesVersionRef), 'supersedes_version_ref_absent');
  addReason(reasons, !hasText(amendment?.proposedVersionRef), 'proposed_version_ref_absent');
  addReason(reasons, !isDigest(amendment?.amendmentPackageHash), 'amendment_package_hash_invalid');
  addReason(reasons, !isDigest(amendment?.amendmentSummaryHash), 'amendment_summary_hash_invalid');
  addReason(reasons, !isDigest(amendment?.implementationPlanHash), 'implementation_plan_hash_invalid');
  addReason(reasons, amendment?.status !== 'ready_for_implementation', 'amendment_not_ready_for_implementation');
  addReason(reasons, hlcTuple(amendment?.assessedAtHlc) === null, 'amendment_assessment_time_invalid');
  addReason(reasons, hlcTuple(amendment?.targetEffectiveAtHlc) === null, 'target_effective_time_invalid');
  addReason(reasons, hlcBefore(amendment?.targetEffectiveAtHlc, amendment?.assessedAtHlc), 'target_effective_before_assessment');
  addReason(reasons, amendment?.metadataOnly !== true, 'amendment_metadata_boundary_invalid');
  addReason(reasons, amendment?.protectedContentExcluded !== true, 'amendment_protected_boundary_invalid');
  addReason(reasons, amendment?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateDomainImpacts(input, reasons) {
  const impacts = Array.isArray(input?.domainImpacts) ? [...input.domainImpacts] : [];
  addReason(reasons, impacts.length === 0, 'impact_domains_absent');
  const presentDomains = new Set();
  const materialDomains = new Set();
  const participantAffectingDomains = new Set();
  const actionRefs = [];

  for (const impact of impacts) {
    const domain = hasText(impact?.domain) ? impact.domain : 'unknown';
    addReason(reasons, !SUPPORTED_IMPACT_DOMAINS.has(domain), `impact_domain_unsupported:${domain}`);
    if (SUPPORTED_IMPACT_DOMAINS.has(domain)) {
      presentDomains.add(domain);
    }
    addReason(reasons, !SUPPORTED_IMPACT_LEVELS.has(impact?.impactLevel), `impact_level_invalid:${domain}`);
    addReason(reasons, !COMPLETE_IMPACT_STATUSES.has(impact?.status), `impact_status_incomplete:${domain}`);
    addReason(reasons, !isDigest(impact?.evidenceHash), `impact_evidence_hash_invalid:${domain}`);
    addReason(reasons, !hasText(impact?.ownerRoleRef), `impact_owner_role_absent:${domain}`);
    addReason(reasons, hlcTuple(impact?.reviewedAtHlc) === null, `impact_review_time_invalid:${domain}`);
    addReason(reasons, hlcBefore(impact?.reviewedAtHlc, input?.amendment?.assessedAtHlc), `impact_review_before_assessment:${domain}`);
    addReason(reasons, impact?.metadataOnly !== true, `impact_metadata_boundary_invalid:${domain}`);
    addReason(reasons, impact?.protectedContentExcluded !== true, `impact_protected_boundary_invalid:${domain}`);
    if (MATERIAL_IMPACT_LEVELS.has(impact?.impactLevel)) {
      materialDomains.add(domain);
      addReason(reasons, sortedTextList(impact?.requiredActionRefs).length === 0, `impact_action_refs_absent:${domain}`);
      actionRefs.push(...sortedTextList(impact?.requiredActionRefs));
    }
    if (impact?.impactLevel === 'participant_affecting') {
      participantAffectingDomains.add(domain);
    }
    if (impact?.status === 'not_applicable') {
      addReason(reasons, !isDigest(impact?.rationaleHash), `impact_not_applicable_rationale_hash_invalid:${domain}`);
    }
  }

  for (const domain of REQUIRED_IMPACT_DOMAINS) {
    addReason(reasons, !presentDomains.has(domain), `impact_domain_missing:${domain}`);
  }
  for (const domain of PARTICIPANT_AFFECTING_DOMAINS) {
    addReason(reasons, !participantAffectingDomains.has(domain), `participant_affecting_impact_missing:${domain}`);
  }

  return {
    impactDomains: [...presentDomains].sort(),
    materialDomains: [...materialDomains].sort(),
    participantAffectingDomains: [...participantAffectingDomains].sort(),
    requiredActionRefs: uniqueSorted(actionRefs),
  };
}

function evaluateEthicsApproval(readiness, reasons) {
  const ethics = readiness?.ethicsApproval;
  addReason(reasons, ethics?.required !== true, 'ethics_approval_required_absent');
  addReason(reasons, ethics?.status !== 'approved', 'ethics_approval_not_approved');
  addReason(reasons, !hasText(ethics?.independentEthicsReviewRef), 'independent_ethics_review_ref_absent');
  addReason(reasons, !isDigest(ethics?.approvalEvidenceHash), 'ethics_approval_evidence_hash_invalid');
}

function evaluateConsentMaterials(readiness, reasons) {
  const consent = readiness?.consentMaterials;
  addReason(reasons, !hasText(consent?.consentVersionRef), 'consent_version_ref_absent');
  if (consent?.reconsentRequired === true) {
    addReason(reasons, consent?.approvalStatus !== 'approved', 'consent_material_approval_not_approved');
    addReason(reasons, !isDigest(consent?.reconsentPlanHash), 'reconsent_plan_hash_invalid');
    addReason(reasons, !hasText(consent?.participantCommunicationRef), 'participant_communication_ref_absent');
  } else {
    addReason(reasons, typeof consent?.reconsentRequired !== 'boolean', 'reconsent_requirement_invalid');
  }
}

function evaluateParticipantCommunication(readiness, reasons) {
  const communication = readiness?.participantCommunication;
  addReason(reasons, communication?.required !== true, 'participant_communication_required_absent');
  addReason(reasons, !hasText(communication?.communicationPlanRef), 'participant_communication_plan_ref_absent');
  addReason(reasons, !isDigest(communication?.approvedMaterialHash), 'participant_communication_material_hash_invalid');
  addReason(reasons, communication?.disseminationReady !== true, 'amendment_communication_not_ready');
}

function evaluateTrainingDelegation(readiness, reasons) {
  const training = readiness?.trainingDelegation;
  addReason(reasons, training?.required !== true, 'training_update_required_absent');
  addReason(reasons, !hasText(training?.trainingMatrixRef), 'training_matrix_ref_absent');
  addReason(reasons, !isDigest(training?.updateEvidenceHash), 'training_update_evidence_hash_invalid');
  addReason(reasons, training?.allAffectedRolesTrained !== true, 'training_update_incomplete');
  addReason(reasons, training?.delegationEligibilityUpdated !== true, 'delegation_eligibility_not_updated');
}

function evaluateProtocolControl(readiness, reasons) {
  const protocol = readiness?.protocolControl;
  addReason(reasons, protocol?.activeVersionReady !== true, 'protocol_active_version_not_ready');
  addReason(reasons, protocol?.obsoleteVersionsWithdrawn !== true, 'obsolete_protocol_versions_not_withdrawn');
  addReason(reasons, !isDigest(protocol?.documentSecurityHash), 'document_security_hash_invalid');
}

function evaluateSafetyData(readiness, reasons) {
  const safety = readiness?.safetyData;
  addReason(reasons, safety?.safetyPlanUpdated !== true, 'safety_plan_not_updated');
  addReason(reasons, !isDigest(safety?.sourceDataMapHash), 'source_data_map_hash_invalid');
  addReason(reasons, !isDigest(safety?.crfUpdateHash), 'crf_update_hash_invalid');
  addReason(reasons, !isDigest(safety?.reportingTimelineHash), 'reporting_timeline_hash_invalid');
}

function evaluateProductOperations(readiness, reasons) {
  const product = readiness?.productOperations;
  addReason(reasons, product?.randomizationBlindingAssessed !== true, 'randomization_blinding_assessment_absent');
  addReason(reasons, !isDigest(product?.productAccountabilityImpactHash), 'product_accountability_impact_hash_invalid');
  addReason(reasons, !hasText(product?.pharmacyReadinessRef), 'pharmacy_readiness_ref_absent');
  addReason(reasons, !hasText(product?.labVendorReadinessRef), 'lab_vendor_readiness_ref_absent');
}

function evaluateRiskGovernance(readiness, reasons) {
  const risk = readiness?.riskGovernance;
  addReason(reasons, !hasText(risk?.riskAssessmentRef), 'risk_assessment_ref_absent');
  addReason(reasons, !isDigest(risk?.deviationCapaImpactHash), 'deviation_capa_impact_hash_invalid');
  addReason(reasons, !isDigest(risk?.budgetContractImpactHash), 'budget_contract_impact_hash_invalid');
  addReason(reasons, !isDigest(risk?.vendorImpactHash), 'vendor_impact_hash_invalid');
}

function evaluateDownstreamReadiness(input, reasons) {
  const readiness = input?.downstreamReadiness;
  evaluateEthicsApproval(readiness, reasons);
  evaluateConsentMaterials(readiness, reasons);
  evaluateParticipantCommunication(readiness, reasons);
  evaluateTrainingDelegation(readiness, reasons);
  evaluateProtocolControl(readiness, reasons);
  evaluateSafetyData(readiness, reasons);
  evaluateProductOperations(readiness, reasons);
  evaluateRiskGovernance(readiness, reasons);
}

function evaluateReviewGovernance(input, reasons) {
  const governance = input?.reviewGovernance;
  const forum = governance?.decisionForum;
  addReason(reasons, !hasText(governance?.humanReviewerDid), 'human_reviewer_absent');
  addReason(reasons, typeof governance?.aiAssisted !== 'boolean', 'ai_assistance_state_invalid');
  addReason(reasons, governance?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, forum?.required !== true, 'decision_forum_required_absent');
  addReason(reasons, forum?.verified !== true, 'decision_forum_not_verified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'decision_forum_human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'decision_forum_quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'decision_forum_open_challenge');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
}

function buildImpactHashInput(input, coverage) {
  return {
    actionRefs: coverage.requiredActionRefs,
    amendmentRef: input?.amendment?.amendmentRef ?? null,
    domainImpacts: (Array.isArray(input?.domainImpacts) ? input.domainImpacts : [])
      .map((impact) => ({
        domain: impact?.domain ?? null,
        evidenceHash: impact?.evidenceHash ?? null,
        impactLevel: impact?.impactLevel ?? null,
        ownerRoleRef: impact?.ownerRoleRef ?? null,
        requiredActionRefs: sortedTextList(impact?.requiredActionRefs),
        status: impact?.status ?? null,
      }))
      .sort((left, right) => String(left.domain).localeCompare(String(right.domain))),
    proposedVersionRef: input?.amendment?.proposedVersionRef ?? null,
    protocolRef: input?.amendment?.protocolRef ?? null,
    tenantId: input?.tenantId ?? null,
  };
}

function buildAmendmentImpactRecord(input, coverage, impactHash, implementationReady) {
  const amendment = input?.amendment ?? {};
  return {
    schema: AMENDMENT_IMPACT_SCHEMA,
    implementationReady,
    protocolRef: hasText(amendment.protocolRef) ? amendment.protocolRef : null,
    amendmentRef: hasText(amendment.amendmentRef) ? amendment.amendmentRef : null,
    supersedesVersionRef: hasText(amendment.supersedesVersionRef) ? amendment.supersedesVersionRef : null,
    proposedVersionRef: hasText(amendment.proposedVersionRef) ? amendment.proposedVersionRef : null,
    impactDomains: coverage.impactDomains,
    materialDomains: coverage.materialDomains,
    participantAffectingDomains: coverage.participantAffectingDomains,
    requiredActionRefs: coverage.requiredActionRefs,
    ethicsApprovalReady: input?.downstreamReadiness?.ethicsApproval?.status === 'approved',
    consentReconsentReady:
      input?.downstreamReadiness?.consentMaterials?.reconsentRequired === true &&
      input?.downstreamReadiness?.consentMaterials?.approvalStatus === 'approved',
    participantCommunicationReady: input?.downstreamReadiness?.participantCommunication?.disseminationReady === true,
    trainingDelegationReady:
      input?.downstreamReadiness?.trainingDelegation?.allAffectedRolesTrained === true &&
      input?.downstreamReadiness?.trainingDelegation?.delegationEligibilityUpdated === true,
    aiAssisted: input?.reviewGovernance?.aiAssisted === true,
    trustState: 'inactive',
    exochainProductionClaim: false,
    impactHash,
  };
}

function buildReceipt(input, impactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: impactHash,
    artifactType: 'protocol_amendment_impact',
    artifactVersion: `${input.amendment.amendmentRef}@${input.amendment.proposedVersionRef}`,
    classification: 'protocol_amendment_impact_metadata',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: `${input.amendment.assessedAtHlc.physicalMs}:${input.amendment.assessedAtHlc.logical}`,
    sensitivityTags: ['metadata_only', 'protocol_amendment', 'qms_policy_8'],
    sourceSystem: 'cybermedica.protocol_amendment_impact',
    tenantId: input.tenantId,
  });
}

export function evaluateProtocolAmendmentImpact(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateAmendmentHeader(input?.amendment, reasons);
  const coverage = evaluateDomainImpacts(input, reasons);
  evaluateDownstreamReadiness(input, reasons);
  evaluateReviewGovernance(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const denialReasons = uniqueReasons(reasons);
  if (denialReasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: denialReasons,
      amendmentImpact: buildAmendmentImpactRecord(input, coverage, null, false),
      receipt: null,
    };
  }

  const impactHash = sha256Hex(buildImpactHashInput(input, coverage));
  const amendmentImpact = buildAmendmentImpactRecord(input, coverage, impactHash, true);

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    amendmentImpact,
    receipt: buildReceipt(input, impactHash),
  };
}
