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
const REQUIRED_PERMISSION = 'protocol_control';
const PROTOCOL_CONTROL_SCHEMA = 'cybermedica.protocol_control.v1';

const REQUIRED_POLICY_DOMAINS = Object.freeze([
  'approved_protocol_version',
  'deviation_management',
  'document_security',
  'iec_irb_approval_tracking',
  'staff_communication',
  'training_update',
]);

const REQUIRED_COMMUNICATION_AUDIENCES = Object.freeze([
  'investigator',
  'pharmacy',
  'site_quality',
  'sponsor_cro',
  'study_staff',
]);

const COVERAGE_STATUSES = new Set(['verified']);

const RAW_PROTOCOL_CONTROL_FIELDS = new Set([
  'amendmentbody',
  'clinicalnotebody',
  'communicationbody',
  'directidentifier',
  'freetextprotocolchange',
  'medicalrecord',
  'participantname',
  'patientname',
  'protocolbody',
  'protocolnarrative',
  'rawamendment',
  'rawcommunication',
  'rawdeviationnarrative',
  'rawprotocol',
  'rawprotocolbody',
  'sourcedocumentbody',
  'trainingattestationbody',
]);

const SECRET_PROTOCOL_CONTROL_FIELDS = new Set([
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
  'servicetoken',
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

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
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

function assertNoProtocolControlPayloadOrSecrets(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoProtocolControlPayloadOrSecrets(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_PROTOCOL_CONTROL_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protocol control source content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_PROTOCOL_CONTROL_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`protocol control secret field is not allowed at ${path}.${key}`);
    }
    assertNoProtocolControlPayloadOrSecrets(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoProtocolControlPayloadOrSecrets(input ?? {});
  canonicalize(input ?? {});
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueSortedReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function basisPoints(numerator, denominator) {
  if (denominator === 0) {
    return 0;
  }
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
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

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) &&
    (authority.permissions.includes(REQUIRED_PERMISSION) || authority.permissions.includes('govern'));
}

function coverageSort(left, right) {
  return String(left.domain).localeCompare(String(right.domain));
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
  addReason(reasons, !hasAuthorityPermission(input?.authority), 'protocol_control_authority_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateProtocolControlHeader(control, reasons) {
  addReason(reasons, !hasText(control?.controlRef), 'protocol_control_ref_absent');
  addReason(reasons, !hasText(control?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(control?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(control?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(control?.activeProtocolVersionRef), 'active_protocol_version_ref_absent');
  addReason(reasons, control?.status !== 'active', 'protocol_control_not_active');
  addReason(reasons, hlcTuple(control?.approvedAtHlc) === null, 'protocol_control_approval_time_invalid');
  addReason(reasons, hlcTuple(control?.effectiveAtHlc) === null, 'protocol_control_effective_time_invalid');
  addReason(reasons, hlcTuple(control?.evaluatedAtHlc) === null, 'protocol_control_evaluation_time_invalid');
  addReason(reasons, hlcBefore(control?.effectiveAtHlc, control?.approvedAtHlc), 'effective_before_approval');
  addReason(reasons, control?.metadataOnly !== true, 'protocol_control_metadata_boundary_invalid');
  addReason(reasons, control?.protectedContentExcluded !== true, 'protocol_control_protected_boundary_invalid');
  addReason(reasons, control?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function normalizePolicyCoverage(input, reasons) {
  const coverage = Array.isArray(input?.policyCoverage) ? [...input.policyCoverage].sort(coverageSort) : [];
  addReason(reasons, coverage.length === 0, 'policy_coverage_absent');

  const presentDomains = new Set();
  for (const item of coverage) {
    const domain = hasText(item?.domain) ? item.domain : 'unknown';
    addReason(reasons, !REQUIRED_POLICY_DOMAINS.includes(domain), `policy_domain_unsupported:${domain}`);
    if (REQUIRED_POLICY_DOMAINS.includes(domain)) {
      presentDomains.add(domain);
    }
    addReason(reasons, !COVERAGE_STATUSES.has(item?.status), `policy_domain_not_verified:${domain}`);
    addReason(reasons, !isDigest(item?.evidenceHash), `policy_domain_evidence_hash_invalid:${domain}`);
    addReason(reasons, item?.metadataOnly !== true, `policy_domain_metadata_boundary_invalid:${domain}`);
  }

  for (const domain of REQUIRED_POLICY_DOMAINS) {
    addReason(reasons, !presentDomains.has(domain), `policy_domain_missing:${domain}`);
  }

  return {
    policyCoverage: [...presentDomains].sort(),
    policyCoverageBasisPoints: basisPoints(presentDomains.size, REQUIRED_POLICY_DOMAINS.length),
  };
}

function evaluateVersionControl(input, reasons) {
  const version = input?.versionControl;
  addReason(reasons, !isDigest(version?.protocolDocumentHash), 'protocol_document_hash_invalid');
  addReason(reasons, !hasText(version?.approvedVersionReceiptId), 'approved_protocol_version_receipt_absent');
  addReason(reasons, !hasText(version?.documentVersionReceiptId), 'document_version_receipt_absent');
  addReason(reasons, version?.currentVersionConfirmed !== true, 'current_protocol_version_not_confirmed');
  addReason(reasons, !isDigest(version?.amendmentPackageHash), 'amendment_package_hash_invalid');
  addReason(reasons, !isDigest(version?.implementationPlanHash), 'implementation_plan_hash_invalid');
}

function evaluateEthicsApproval(input, reasons) {
  const approval = input?.ethicsApproval;
  addReason(reasons, !hasText(approval?.independentEthicsReviewRef), 'independent_ethics_review_ref_absent');
  addReason(reasons, !hasText(approval?.ethicsReceiptId), 'ethics_receipt_absent');
  addReason(reasons, approval?.approvalStatus !== 'approved', 'ethics_approval_not_approved');
  addReason(reasons, !isDigest(approval?.approvalEvidenceHash), 'ethics_approval_evidence_hash_invalid');
  addReason(reasons, approval?.approvalAppliesToActiveVersion !== true, 'ethics_approval_not_version_bound');
  addReason(
    reasons,
    approval?.amendmentApprovalRequired === true && approval?.amendmentApprovalStatus !== 'approved',
    'amendment_approval_not_approved',
  );
  addReason(reasons, hlcTuple(approval?.approvalExpiresAtHlc) === null, 'approval_expiration_time_invalid');
  addReason(
    reasons,
    hlcBefore(approval?.approvalExpiresAtHlc, input?.protocolControl?.evaluatedAtHlc),
    'approval_expires_before_evaluation',
  );
}

function normalizeStaffCommunication(input, reasons) {
  const communication = input?.staffCommunication;
  const audiences = sortedTextList(communication?.audienceRefs);
  addReason(reasons, !hasText(communication?.communicationPlanRef), 'communication_plan_ref_absent');
  addReason(reasons, !isDigest(communication?.communicationEvidenceHash), 'communication_evidence_hash_invalid');
  addReason(reasons, hlcTuple(communication?.deliveredAtHlc) === null, 'communication_delivery_time_invalid');
  addReason(
    reasons,
    hlcBefore(communication?.deliveredAtHlc, input?.protocolControl?.effectiveAtHlc),
    'communication_before_protocol_effective',
  );
  addReason(reasons, !isBasisPoints(communication?.acknowledgementCoverageBasisPoints), 'communication_acknowledgement_invalid');
  addReason(
    reasons,
    isBasisPoints(communication?.acknowledgementCoverageBasisPoints) &&
      communication.acknowledgementCoverageBasisPoints < 10_000,
    'communication_acknowledgement_incomplete',
  );
  addReason(reasons, !isDigest(communication?.disclosureLogHash), 'communication_disclosure_log_hash_invalid');
  addReason(reasons, sortedTextList(communication?.channelPolicyRefs).length === 0, 'communication_channel_policy_absent');
  addReason(reasons, communication?.metadataOnly !== true, 'communication_metadata_boundary_invalid');

  for (const audience of REQUIRED_COMMUNICATION_AUDIENCES) {
    addReason(reasons, !audiences.includes(audience), `communication_audience_missing:${audience}`);
  }

  return audiences;
}

function evaluateDeviationManagement(input, reasons) {
  const deviation = input?.deviationManagement;
  addReason(reasons, !hasText(deviation?.deviationProcessRef), 'deviation_process_ref_absent');
  addReason(reasons, !hasText(deviation?.deviationLogRef), 'deviation_log_ref_absent');
  addReason(reasons, deviation?.deviationLogLinked !== true, 'deviation_log_not_linked');
  addReason(reasons, !Number.isSafeInteger(deviation?.openCriticalDeviations), 'open_critical_deviation_count_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(deviation?.openCriticalDeviations) && deviation.openCriticalDeviations > 0,
    'open_critical_deviations_present',
  );
  addReason(reasons, !isDigest(deviation?.escalationPathHash), 'deviation_escalation_path_hash_invalid');
  addReason(reasons, deviation?.capaLinkageRequired === true && deviation?.capaLinkageReady !== true, 'capa_linkage_not_ready');
}

function evaluateDocumentSecurity(input, reasons) {
  const security = input?.documentSecurity;
  addReason(reasons, !hasText(security?.accessPolicyRef), 'document_access_policy_ref_absent');
  addReason(reasons, security?.leastPrivilege !== true, 'document_least_privilege_absent');
  addReason(reasons, security?.currentVersionOnly !== true, 'document_current_version_only_absent');
  addReason(reasons, security?.obsoleteVersionsWithdrawn !== true, 'obsolete_versions_not_withdrawn');
  addReason(reasons, !isDigest(security?.accessLogHash), 'document_access_log_hash_invalid');
  addReason(reasons, !isDigest(security?.securityEvidenceHash), 'document_security_evidence_hash_invalid');
  addReason(reasons, sortedTextList(security?.controlledDocumentRefs).length === 0, 'controlled_document_refs_absent');
}

function evaluateTrainingUpdate(input, reasons) {
  const training = input?.trainingUpdate;
  addReason(reasons, !hasText(training?.trainingMatrixRef), 'training_matrix_ref_absent');
  addReason(reasons, !isDigest(training?.updateEvidenceHash), 'training_update_evidence_hash_invalid');
  addReason(reasons, sortedTextList(training?.affectedRoleRefs).length === 0, 'training_affected_roles_absent');
  addReason(reasons, training?.allAffectedStaffTrained !== true, 'training_update_incomplete');
  addReason(reasons, training?.delegationEligibilityUpdated !== true, 'delegation_eligibility_not_updated');
  addReason(reasons, training?.effectiveBeforeProtocolUse !== true, 'training_not_effective_before_protocol_use');
  addReason(reasons, hlcTuple(training?.trainingCompletedAtHlc) === null, 'training_completed_time_invalid');
  addReason(
    reasons,
    hlcBefore(training?.trainingCompletedAtHlc, input?.staffCommunication?.deliveredAtHlc),
    'training_before_staff_communication',
  );
}

function evaluateReviewGovernance(input, reasons) {
  const governance = input?.reviewGovernance;
  const forum = governance?.decisionForum;
  addReason(reasons, !hasText(governance?.humanReviewerDid), 'human_reviewer_absent');
  addReason(reasons, governance?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, typeof governance?.aiAssisted !== 'boolean', 'ai_assistance_state_invalid');
  addReason(reasons, forum?.required !== true, 'decision_forum_required_absent');
  addReason(reasons, forum?.verified !== true, 'decision_forum_not_verified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'decision_forum_human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'decision_forum_quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'decision_forum_open_challenge');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
}

function buildProtocolControlRecord(input, coverageSummary, communicationAudiences, controlHash, ready) {
  const control = input?.protocolControl ?? {};
  return {
    schema: PROTOCOL_CONTROL_SCHEMA,
    controlReady: ready,
    controlState: ready ? control.status : 'blocked',
    protocolRef: hasText(control.protocolRef) ? control.protocolRef : null,
    activeProtocolVersionRef: hasText(control.activeProtocolVersionRef) ? control.activeProtocolVersionRef : null,
    amendmentRef: hasText(control.amendmentRef) ? control.amendmentRef : null,
    ethicsApprovalStatus: hasText(input?.ethicsApproval?.approvalStatus) ? input.ethicsApproval.approvalStatus : 'unknown',
    policyCoverage: coverageSummary.policyCoverage,
    policyCoverageBasisPoints: coverageSummary.policyCoverageBasisPoints,
    communicationAudiences,
    staffCommunicationReady: ready,
    documentSecurityReady: ready,
    trainingUpdateReady: ready,
    aiAssisted: input?.reviewGovernance?.aiAssisted === true,
    trustState: 'inactive',
    exochainProductionClaim: false,
    controlHash,
  };
}

function buildReceipt(input, controlHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: controlHash,
    artifactType: 'protocol_control',
    artifactVersion: `${input.protocolControl.controlRef}@${input.protocolControl.activeProtocolVersionRef}`,
    classification: 'protocol_control_metadata',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: `${input.protocolControl.evaluatedAtHlc.physicalMs}:${input.protocolControl.evaluatedAtHlc.logical}`,
    sensitivityTags: ['metadata_only', 'protocol_control', 'qms_policy_8'],
    sourceSystem: 'cybermedica.protocol_control',
    tenantId: input.tenantId,
  });
}

export function evaluateProtocolControl(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateProtocolControlHeader(input?.protocolControl, reasons);
  const coverageSummary = normalizePolicyCoverage(input, reasons);
  evaluateVersionControl(input, reasons);
  evaluateEthicsApproval(input, reasons);
  const communicationAudiences = normalizeStaffCommunication(input, reasons);
  evaluateDeviationManagement(input, reasons);
  evaluateDocumentSecurity(input, reasons);
  evaluateTrainingUpdate(input, reasons);
  evaluateReviewGovernance(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const denialReasons = uniqueSortedReasons(reasons);
  if (denialReasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: denialReasons,
      protocolControl: buildProtocolControlRecord(input, coverageSummary, communicationAudiences, null, false),
      receipt: null,
    };
  }

  const normalizedControl = {
    activeProtocolVersionRef: input.protocolControl.activeProtocolVersionRef,
    amendmentRef: input.protocolControl.amendmentRef ?? null,
    communicationAudiences,
    controlledDocumentRefs: sortedTextList(input.documentSecurity.controlledDocumentRefs),
    ethicsApprovalStatus: input.ethicsApproval.approvalStatus,
    policyCoverage: coverageSummary.policyCoverage,
    protocolRef: input.protocolControl.protocolRef,
    siteRef: input.protocolControl.siteRef,
    studyRef: input.protocolControl.studyRef,
    supersededVersionRefs: sortedTextList(input.versionControl.supersededVersionRefs),
    tenantId: input.tenantId,
    trainingRoleRefs: sortedTextList(input.trainingUpdate.affectedRoleRefs),
  };
  const controlHash = sha256Hex(normalizedControl);
  const receipt = buildReceipt(input, controlHash);

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    protocolControl: buildProtocolControlRecord(input, coverageSummary, communicationAudiences, controlHash, true),
    receipt,
  };
}
