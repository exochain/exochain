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

import { canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const REQUIRED_PERMISSION = 'perform_protocol_task';

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

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical)) {
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

function expiredAtCheck(checkedAt, expiresAt) {
  return checkedAt !== null && expiresAt !== null && compareHlc(checkedAt, expiresAt) > 0;
}

function startsAfterCheck(checkedAt, startsAt) {
  return checkedAt !== null && startsAt !== null && compareHlc(checkedAt, startsAt) < 0;
}

function normalizeRequirement(requirement) {
  if (requirement === null || typeof requirement !== 'object') {
    return null;
  }
  return {
    actionScopes: sortedTextList(requirement.actionScopes),
    appliesToRoles: sortedTextList(requirement.appliesToRoles),
    controlId: hasText(requirement.controlId) ? requirement.controlId : null,
    protocolId: hasText(requirement.protocolId) ? requirement.protocolId : null,
    requiredCompetencyId: hasText(requirement.requiredCompetencyId) ? requirement.requiredCompetencyId : null,
    requiredEvidenceType: hasText(requirement.requiredEvidenceType) ? requirement.requiredEvidenceType : null,
    requiredVersion: Number.isSafeInteger(requirement.requiredVersion) ? requirement.requiredVersion : null,
    requirementId: hasText(requirement.requirementId) ? requirement.requirementId : null,
  };
}

function appliesToRequest(requirement, input) {
  if (requirement === null || !hasText(requirement.requirementId)) {
    return false;
  }
  if (requirement.protocolId !== null && requirement.protocolId !== input?.protocolId) {
    return false;
  }
  if (requirement.appliesToRoles.length > 0 && !requirement.appliesToRoles.includes(input?.roleAssignment?.role)) {
    return false;
  }
  return requirement.actionScopes.length === 0 || requirement.actionScopes.includes(input?.controlledAction);
}

function relevantRequirements(input) {
  if (!Array.isArray(input?.requirements)) {
    return [];
  }
  return input.requirements
    .map(normalizeRequirement)
    .filter((requirement) => appliesToRequest(requirement, input))
    .sort((left, right) => String(left.requirementId).localeCompare(String(right.requirementId)));
}

function trainingRecordsByRequirement(input) {
  const records = new Map();
  if (!Array.isArray(input?.trainingRecords)) {
    return records;
  }
  for (const record of input.trainingRecords) {
    if (record?.actorDid === input?.actor?.did && hasText(record?.requirementId)) {
      records.set(record.requirementId, record);
    }
  }
  return records;
}

function addTrainingGap(trainingGaps, requirementId, reason) {
  trainingGaps.push({ requirementId, reason });
}

function validateTrainingMatrix(matrix, reasons) {
  addReason(reasons, matrix?.verified !== true, 'training_matrix_unverified');
  addReason(reasons, matrix?.status !== 'approved', 'training_matrix_not_approved');
  addReason(reasons, !hasText(matrix?.receiptId), 'training_matrix_receipt_absent');
  addReason(reasons, matrix?.humanGate?.verified !== true, 'training_matrix_human_gate_unverified');
  addReason(reasons, matrix?.quorum?.status !== 'met', 'training_matrix_quorum_not_met');
  addReason(reasons, matrix?.openChallenge === true, 'training_matrix_challenge_open');
}

function validateRequestShape(input, checkedAt, reasons) {
  addReason(reasons, !hasText(input?.requestId), 'request_id_absent');
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, !hasText(input?.siteId), 'site_absent');
  addReason(reasons, !hasText(input?.protocolId), 'protocol_absent');
  addReason(reasons, !hasText(input?.controlledAction), 'controlled_action_absent');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_controlled_action_forbidden');
  addReason(reasons, checkedAt === null, 'checked_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function validateRoleAssignment(input, reasons) {
  const role = input?.roleAssignment;
  addReason(reasons, role?.status !== 'active', 'role_assignment_not_active');
  addReason(reasons, role?.actorDid !== input?.actor?.did, 'role_assignment_actor_mismatch');
  addReason(reasons, role?.tenantId !== input?.tenantId, 'role_assignment_tenant_mismatch');
  addReason(reasons, role?.siteId !== input?.siteId, 'role_assignment_site_mismatch');
  addReason(reasons, !sortedTextList(role?.protocolIds).includes(input?.protocolId), 'role_assignment_protocol_missing');
  addReason(reasons, !hasText(role?.role), 'role_absent');
}

function validateAuthority(input, reasons) {
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !Array.isArray(input?.authority?.permissions) || !input.authority.permissions.includes(REQUIRED_PERMISSION),
    'authority_permission_missing',
  );
}

function validateTrainingRequirements(input, checkedAt, reasons, trainingGaps) {
  const requirements = relevantRequirements(input);
  const records = trainingRecordsByRequirement(input);

  addReason(reasons, requirements.length === 0, 'training_requirements_absent');

  for (const requirement of requirements) {
    const record = records.get(requirement.requirementId);
    if (record === undefined) {
      reasons.push('training_requirement_missing_record');
      addTrainingGap(trainingGaps, requirement.requirementId, 'training_requirement_missing_record');
      continue;
    }

    const expiresAt = hlcTuple(record.expiresAtHlc);
    const completedAt = hlcTuple(record.completedAtHlc);

    addReason(reasons, record.status !== 'completed' && record.status !== 'expired', 'training_requirement_not_completed');
    if (record.status === 'expired' || expiredAtCheck(checkedAt, expiresAt)) {
      reasons.push('training_requirement_expired');
      addTrainingGap(trainingGaps, requirement.requirementId, 'training_requirement_expired');
    }
    if (requirement.requiredVersion !== null && record.version < requirement.requiredVersion) {
      reasons.push('training_requirement_version_stale');
      addTrainingGap(trainingGaps, requirement.requirementId, 'training_requirement_version_stale');
    }
    addReason(reasons, !Number.isSafeInteger(record.version), 'training_requirement_version_invalid');
    addReason(
      reasons,
      hasText(requirement.requiredEvidenceType) && record.evidenceType !== requirement.requiredEvidenceType,
      'training_requirement_evidence_type_invalid',
    );
    addReason(reasons, !isDigest(record.evidenceHash), 'training_requirement_evidence_hash_invalid');
    addReason(reasons, completedAt === null, 'training_requirement_completion_time_invalid');
    addReason(reasons, expiresAt === null, 'training_requirement_expiry_time_invalid');
    addReason(
      reasons,
      checkedAt !== null && completedAt !== null && compareHlc(completedAt, checkedAt) > 0,
      'training_requirement_completed_after_check',
    );
  }

  return requirements;
}

function competencyApplies(evidence, input, competencyId) {
  return (
    evidence?.actorDid === input?.actor?.did &&
    evidence?.competencyId === competencyId &&
    sortedTextList(evidence?.scopes).includes(input?.controlledAction)
  );
}

function validateCompetencies(input, checkedAt, requirements, reasons) {
  const requiredCompetencyIds = sortedTextList(
    requirements.map((requirement) => requirement.requiredCompetencyId).filter(hasText),
  );

  for (const competencyId of requiredCompetencyIds) {
    const evidence = Array.isArray(input?.competencyEvidence)
      ? input.competencyEvidence.find((item) => competencyApplies(item, input, competencyId))
      : undefined;
    if (evidence === undefined) {
      reasons.push('competency_missing');
      continue;
    }

    const expiresAt = hlcTuple(evidence.expiresAtHlc);
    addReason(reasons, evidence.status !== 'verified', 'competency_unverified');
    addReason(reasons, evidence.verifiedByHuman !== true, 'competency_human_verification_absent');
    addReason(reasons, !isDigest(evidence.evidenceHash), 'competency_evidence_hash_invalid');
    addReason(reasons, expiresAt === null, 'competency_expiry_time_invalid');
    addReason(reasons, expiredAtCheck(checkedAt, expiresAt), 'competency_expired');
  }

  return requiredCompetencyIds;
}

function validateQualifications(input, checkedAt, reasons) {
  const qualifications = Array.isArray(input?.qualifications)
    ? input.qualifications.filter((qualification) => qualification?.actorDid === input?.actor?.did)
    : [];

  addReason(reasons, qualifications.length === 0, 'qualification_absent');

  for (const qualification of qualifications) {
    const expiresAt = hlcTuple(qualification.expiresAtHlc);
    addReason(reasons, qualification.status !== 'active', 'qualification_not_active');
    addReason(reasons, !hasText(qualification.qualificationId), 'qualification_id_absent');
    addReason(reasons, !isDigest(qualification.evidenceHash), 'qualification_evidence_hash_invalid');
    addReason(reasons, expiresAt === null, 'qualification_expiry_time_invalid');
    addReason(reasons, expiredAtCheck(checkedAt, expiresAt), 'qualification_expired');
  }

  return qualifications.map((qualification) => qualification.qualificationId).filter(hasText).sort();
}

function validateDelegation(input, checkedAt, reasons) {
  const delegation = input?.delegation;
  const notBefore = hlcTuple(delegation?.notBeforeHlc);
  const expiresAt = hlcTuple(delegation?.expiresAtHlc);

  addReason(reasons, !hasText(delegation?.delegationId), 'delegation_id_absent');
  addReason(reasons, delegation?.status !== 'active', 'delegation_not_active');
  addReason(reasons, delegation?.revoked === true || delegation?.status === 'revoked', 'delegation_revoked');
  addReason(reasons, delegation?.actorDid !== input?.actor?.did, 'delegation_actor_mismatch');
  addReason(reasons, delegation?.tenantId !== input?.tenantId, 'delegation_tenant_mismatch');
  addReason(reasons, delegation?.siteId !== input?.siteId, 'delegation_site_mismatch');
  addReason(reasons, delegation?.protocolId !== input?.protocolId, 'delegation_protocol_mismatch');
  addReason(reasons, !sortedTextList(delegation?.allowedActions).includes(input?.controlledAction), 'delegation_action_not_allowed');
  addReason(reasons, !isDigest(delegation?.authorityChainHash), 'delegation_authority_chain_hash_invalid');
  addReason(
    reasons,
    hasText(input?.authority?.authorityChainHash) && delegation?.authorityChainHash !== input.authority.authorityChainHash,
    'delegation_authority_chain_invalid',
  );
  addReason(reasons, notBefore === null, 'delegation_start_time_invalid');
  addReason(reasons, expiresAt === null, 'delegation_expiry_time_invalid');
  addReason(reasons, startsAfterCheck(checkedAt, notBefore), 'delegation_not_yet_active');
  addReason(reasons, expiredAtCheck(checkedAt, expiresAt), 'delegation_expired');
}

function validateConflictAndRecusal(input, reasons) {
  addReason(
    reasons,
    input?.conflictDisclosure?.status === 'active' || input?.conflictDisclosure?.status === 'unresolved',
    'conflict_active',
  );
  addReason(reasons, input?.recusal?.active === true, 'recusal_active');
}

function selectedTrainingRecordHashes(input, requirementIds) {
  const records = trainingRecordsByRequirement(input);
  return requirementIds
    .map((requirementId) => records.get(requirementId)?.evidenceHash)
    .filter(isDigest)
    .sort();
}

function buildEligibility(input, requirements, competencyIds, qualificationIds, receiptId) {
  const requirementIds = requirements.map((requirement) => requirement.requirementId).sort();
  const trainingRecordHashes = selectedTrainingRecordHashes(input, requirementIds);
  const material = {
    actorDid: input.actor.did,
    authorityChainHash: input.delegation.authorityChainHash,
    checkedAtHlc: input.checkedAtHlc,
    competencyIds,
    controlledAction: input.controlledAction,
    delegationId: input.delegation.delegationId,
    protocolId: input.protocolId,
    qualificationIds,
    requirementIds,
    role: input.roleAssignment.role,
    schema: 'cybermedica.training_delegation_eligibility_material.v1',
    siteId: input.siteId,
    tenantId: input.tenantId,
    trainingRecordHashes,
  };
  const eligibilityHash = sha256Hex(material);

  return {
    schema: 'cybermedica.training_delegation_eligibility.v1',
    eligibilityId: `cmtd_${eligibilityHash.slice(0, 32)}`,
    eligibilityHash,
    tenantId: input.tenantId,
    siteId: input.siteId,
    protocolId: input.protocolId,
    actorDid: input.actor.did,
    role: input.roleAssignment.role,
    controlledAction: input.controlledAction,
    checkedAtHlc: input.checkedAtHlc,
    requirementIds,
    trainingRecordHashes,
    competencyIds,
    qualificationIds,
    delegationId: input.delegation.delegationId,
    authorityChainHash: input.delegation.authorityChainHash,
    receiptId,
  };
}

function buildReceipt(input, eligibilityHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'training_delegation_eligibility',
    artifactVersion: `${input.protocolId}@${input.controlledAction}`,
    artifactHash: eligibilityHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.checkedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['authority', 'competency', 'metadata_only', 'training'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateTrainingDelegationReadiness(input) {
  canonicalize(input ?? {});

  const reasons = [];
  const trainingGaps = [];
  const checkedAt = hlcTuple(input?.checkedAtHlc);

  validateRequestShape(input, checkedAt, reasons);
  validateRoleAssignment(input, reasons);
  validateTrainingMatrix(input?.trainingMatrix, reasons);
  validateAuthority(input, reasons);
  const requirements = validateTrainingRequirements(input, checkedAt, reasons, trainingGaps);
  const competencyIds = validateCompetencies(input, checkedAt, requirements, reasons);
  const qualificationIds = validateQualifications(input, checkedAt, reasons);
  validateDelegation(input, checkedAt, reasons);
  validateConflictAndRecusal(input, reasons);

  const uniqueReasons = [...new Set(reasons)].sort();
  const uniqueTrainingGaps = [...new Map(
    trainingGaps
      .sort((left, right) => {
        const requirementOrder = left.requirementId.localeCompare(right.requirementId);
        return requirementOrder === 0 ? left.reason.localeCompare(right.reason) : requirementOrder;
      })
      .map((gap) => [`${gap.requirementId}:${gap.reason}`, gap]),
  ).values()];
  const denied = uniqueReasons.length > 0;

  if (denied) {
    return {
      schema: 'cybermedica.training_delegation_readiness_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      trainingGaps: uniqueTrainingGaps,
      eligibility: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const materialEligibility = buildEligibility(input, requirements, competencyIds, qualificationIds, null);
  const receipt = buildReceipt(input, materialEligibility.eligibilityHash);
  const eligibility = {
    ...materialEligibility,
    receiptId: receipt.receiptId,
  };

  return {
    schema: 'cybermedica.training_delegation_readiness_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    trainingGaps: [],
    eligibility,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
