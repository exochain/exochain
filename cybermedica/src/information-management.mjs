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

const HEX_64 = /^[0-9a-f]{64}$/u;
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const REQUIRED_PLAN_COMPONENTS = Object.freeze([
  'access_permissions',
  'ae_reporting',
  'alcoac_requirements',
  'approval_dates',
  'correction_rules',
  'crf_media',
  'deadlines',
  'discrepancy_reporting',
  'distribution_rules',
  'document_inventory',
  'document_security_rules',
  'document_storage_rules',
  'dsmb_reporting',
  'final_report_requirements',
  'milestones',
  'participant_code_rules',
  'required_records',
  'retention_period',
  'review_frequency',
  'sae_reporting',
  'source_data_definition',
  'source_data_traceability',
  'sponsor_reporting_frequency',
  'staff_communication_evidence',
  'susar_reporting',
  'urgent_change_reporting',
  'version_history',
]);

const REQUIRED_ALCOAC_PRINCIPLES = Object.freeze([
  'accurate',
  'attributable',
  'complete',
  'contemporaneous',
  'legible',
  'original',
]);

const REQUIRED_SYSTEM_CONTROLS = Object.freeze([
  'authorized_access_list',
  'availability_procedure',
  'backup_procedure',
  'business_continuity_procedure',
  'confidentiality_procedure',
  'data_loss_protection',
  'data_protection_regulation_checks',
  'disaster_recovery_procedure',
  'integrity_procedure',
  'maintenance_procedure',
  'monitor_auditor_regulator_access_controls',
  'recovery_procedure',
  'regulatory_compliance_mapping',
  'setup_installation_use_procedure',
  'tampering_protection',
  'unauthorized_use_protection',
]);

const APPROVED_PLAN_STATUSES = new Set(['approved', 'approved_with_conditions']);
const APPROVED_COMPONENT_STATUSES = new Set(['approved', 'approved_with_conditions']);
const IMPLEMENTED_CONTROL_STATUSES = new Set(['implemented', 'verified']);
const VALIDATED_SYSTEM_STATUSES = new Set(['validated', 'active_validated']);
const RAW_INFORMATION_FIELDS = new Set([
  'freeformcorrection',
  'rawcorrectiontext',
  'rawcrfdata',
  'rawdiscrepancydetails',
  'raweventdetails',
  'rawparticipantdata',
  'rawrecordcontent',
  'rawsafetyevent',
  'rawsourcedata',
  'sourcebody',
  'sourcedatabody',
  'trialrecordbody',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function isDigestOrZero(value) {
  return value === ZERO_HASH || isDigest(value);
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueSorted(reasons) {
  return [...new Set(reasons)].sort();
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawInformationText(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawInformationText(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_INFORMATION_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw information content field is not allowed at ${path}.${key}`);
    }
    assertNoRawInformationText(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawInformationText(input ?? {});
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

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, permission, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority, permission), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateHumanGovernance(input, reasons) {
  const forum = input?.review?.decisionForum;
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, input?.review?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, input?.review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, !hasText(input?.review?.qualityReviewerDid), 'quality_reviewer_absent');
}

function evaluatePlanShape(plan, reasons) {
  const effectiveAt = hlcTuple(plan?.effectiveAtHlc);
  const reviewDue = hlcTuple(plan?.reviewDueHlc);

  addReason(reasons, !hasText(plan?.planRef), 'information_plan_ref_absent');
  addReason(reasons, !hasText(plan?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(plan?.sponsorRef), 'sponsor_ref_absent');
  addReason(reasons, !hasText(plan?.siteRef), 'site_ref_absent');
  addReason(reasons, !APPROVED_PLAN_STATUSES.has(plan?.status), 'information_plan_not_approved');
  addReason(reasons, !Number.isSafeInteger(plan?.version) || plan.version < 1, 'information_plan_version_invalid');
  addReason(reasons, !isDigest(plan?.planHash), 'information_plan_hash_invalid');
  addReason(reasons, effectiveAt === null, 'information_plan_effective_time_invalid');
  addReason(reasons, reviewDue === null, 'information_plan_review_due_time_invalid');
  addReason(
    reasons,
    effectiveAt !== null && reviewDue !== null && compareHlc(reviewDue, effectiveAt) <= 0,
    'information_plan_review_due_not_after_effective',
  );
}

function normalizeComponentEvidence(plan, reasons) {
  const evidence = Array.isArray(plan?.componentEvidence) ? plan.componentEvidence : [];
  const byComponent = new Map();
  for (const item of evidence) {
    if (hasText(item?.component)) {
      byComponent.set(item.component, item);
    }
  }

  const covered = [];
  for (const component of REQUIRED_PLAN_COMPONENTS) {
    const item = byComponent.get(component);
    if (item === undefined) {
      reasons.push(`plan_component_missing:${component}`);
      continue;
    }
    addReason(reasons, !APPROVED_COMPONENT_STATUSES.has(item.status), `plan_component_not_approved:${component}`);
    addReason(reasons, !isDigest(item.evidenceHash), `plan_component_evidence_invalid:${component}`);
    addReason(reasons, !hasText(item.ownerDid), `plan_component_owner_absent:${component}`);
    addReason(reasons, hlcTuple(item.reviewDueHlc) === null, `plan_component_review_due_invalid:${component}`);
    if (APPROVED_COMPONENT_STATUSES.has(item.status) && isDigest(item.evidenceHash) && hasText(item.ownerDid)) {
      covered.push({
        component,
        evidenceHash: item.evidenceHash,
        ownerDid: item.ownerDid,
        reviewDueHlc: item.reviewDueHlc,
        status: item.status,
      });
    }
  }
  return covered.sort((left, right) => left.component.localeCompare(right.component));
}

function normalizeAlcoacControls(plan, reasons) {
  const controls = Array.isArray(plan?.alcoacControls) ? plan.alcoacControls : [];
  const byPrinciple = new Map();
  for (const control of controls) {
    if (hasText(control?.principle)) {
      byPrinciple.set(control.principle, control);
    }
  }

  const covered = [];
  for (const principle of REQUIRED_ALCOAC_PRINCIPLES) {
    const control = byPrinciple.get(principle);
    if (control === undefined) {
      reasons.push(`alcoac_principle_missing:${principle}`);
      continue;
    }
    addReason(reasons, !IMPLEMENTED_CONTROL_STATUSES.has(control.status), `alcoac_principle_unverified:${principle}`);
    addReason(reasons, !isDigest(control.evidenceHash), `alcoac_principle_evidence_invalid:${principle}`);
    addReason(reasons, !hasText(control.controlRef), `alcoac_control_ref_absent:${principle}`);
    if (IMPLEMENTED_CONTROL_STATUSES.has(control.status) && isDigest(control.evidenceHash) && hasText(control.controlRef)) {
      covered.push({
        controlRef: control.controlRef,
        evidenceHash: control.evidenceHash,
        principle,
        status: control.status,
      });
    }
  }
  return covered.sort((left, right) => left.principle.localeCompare(right.principle));
}

function normalizeSystemControls(system, systemRef, reasons) {
  const controls = Array.isArray(system?.controlEvidence) ? system.controlEvidence : [];
  const byControl = new Map();
  for (const control of controls) {
    if (hasText(control?.control)) {
      byControl.set(control.control, control);
    }
  }

  const normalized = [];
  for (const controlName of REQUIRED_SYSTEM_CONTROLS) {
    const control = byControl.get(controlName);
    if (control === undefined) {
      reasons.push(`system_control_missing:${systemRef}:${controlName}`);
      continue;
    }
    addReason(reasons, !IMPLEMENTED_CONTROL_STATUSES.has(control.status), `system_control_unverified:${systemRef}:${controlName}`);
    addReason(reasons, !isDigest(control.evidenceHash), `system_control_evidence_invalid:${systemRef}:${controlName}`);
    if (IMPLEMENTED_CONTROL_STATUSES.has(control.status) && isDigest(control.evidenceHash)) {
      normalized.push({
        control: controlName,
        evidenceHash: control.evidenceHash,
        status: control.status,
      });
    }
  }
  return normalized;
}

function normalizeElectronicSystems(plan, reasons) {
  const systems = Array.isArray(plan?.electronicSystems) ? plan.electronicSystems : [];
  addReason(reasons, systems.length === 0, 'electronic_systems_absent');

  const normalized = [];
  for (const system of systems) {
    const systemRef = hasText(system?.systemRef) ? system.systemRef : 'unknown';
    const start = hlcTuple(system?.accessStartHlc);
    const removal = hlcTuple(system?.accessRemovalHlc);
    const beforeReasonCount = reasons.length;

    addReason(reasons, !hasText(system?.systemRef), `system_ref_absent:${systemRef}`);
    addReason(reasons, !VALIDATED_SYSTEM_STATUSES.has(system?.status), `system_not_validated:${systemRef}`);
    addReason(reasons, !isDigest(system?.validationEvidenceHash), `system_validation_evidence_invalid:${systemRef}`);
    addReason(reasons, !isDigest(system?.verificationEvidenceHash), `system_verification_evidence_invalid:${systemRef}`);
    addReason(reasons, !isDigest(system?.authorizedAccessListHash), `system_authorized_access_list_invalid:${systemRef}`);
    addReason(reasons, start === null || removal === null || compareHlc(removal, start) <= 0, `system_access_window_invalid:${systemRef}`);
    const controlEvidence = normalizeSystemControls(system, systemRef, reasons);
    const valid = reasons.length === beforeReasonCount;

    normalized.push({
      systemRef,
      status: system?.status ?? null,
      validationEvidenceHash: system?.validationEvidenceHash ?? null,
      verificationEvidenceHash: system?.verificationEvidenceHash ?? null,
      authorizedAccessListHash: system?.authorizedAccessListHash ?? null,
      accessStartHlc: system?.accessStartHlc ?? null,
      accessRemovalHlc: system?.accessRemovalHlc ?? null,
      controlEvidence,
      validated: valid,
    });
  }

  return normalized.sort((left, right) => left.systemRef.localeCompare(right.systemRef));
}

function evaluateRetention(retention, reasons) {
  addReason(reasons, !hasText(retention?.retentionClass), 'retention_class_absent');
  addReason(reasons, !Number.isSafeInteger(retention?.periodMonths) || retention.periodMonths < 1, 'retention_period_invalid');
  addReason(reasons, retention?.conflictPolicy !== 'longest_applicable_retention', 'retention_conflict_policy_invalid');
  addReason(reasons, !isDigest(retention?.governingRuleHash), 'retention_rule_hash_invalid');
  addReason(reasons, typeof retention?.legalHoldActive !== 'boolean', 'retention_legal_hold_state_invalid');
}

function evaluateAccessPolicy(accessPolicy, reasons) {
  addReason(reasons, !hasText(accessPolicy?.policyRef), 'access_policy_ref_absent');
  addReason(reasons, accessPolicy?.leastPrivilege !== true, 'access_policy_not_least_privilege');
  addReason(reasons, accessPolicy?.revocable !== true, 'access_policy_not_revocable');
  addReason(reasons, accessPolicy?.timeBound !== true, 'access_policy_not_time_bound');
  addReason(reasons, accessPolicy?.auditTrailRequired !== true, 'access_policy_audit_trail_absent');
  addReason(reasons, sortedTextList(accessPolicy?.authorizedRoleRefs).length === 0, 'access_policy_roles_absent');
}

function evaluateStaffCommunication(plan, reasons) {
  const communication = plan?.staffCommunication;
  const communicatedAt = hlcTuple(communication?.communicatedAtHlc);
  const effectiveAt = hlcTuple(plan?.effectiveAtHlc);

  addReason(reasons, communication?.communicated !== true, 'staff_communication_absent');
  addReason(reasons, !isDigest(communication?.communicationEvidenceHash), 'staff_communication_evidence_invalid');
  addReason(reasons, !hasText(communication?.communicatedByDid), 'staff_communication_actor_absent');
  addReason(reasons, communicatedAt === null, 'staff_communication_time_invalid');
  addReason(
    reasons,
    communicatedAt !== null && effectiveAt !== null && compareHlc(communicatedAt, effectiveAt) < 0,
    'staff_communication_before_effective_plan',
  );
}

function systemValidationSummary(systems) {
  return {
    total: systems.length,
    validated: systems.filter((system) => system.validated).length,
    blocked: systems.filter((system) => !system.validated).length,
  };
}

function buildPlanFingerprint(input, components, alcoacControls, systems) {
  const plan = input.informationPlan;
  return sha256Hex({
    accessPolicy: {
      auditTrailRequired: plan.accessPolicy.auditTrailRequired,
      authorizedRoleRefs: sortedTextList(plan.accessPolicy.authorizedRoleRefs),
      leastPrivilege: plan.accessPolicy.leastPrivilege,
      policyRef: plan.accessPolicy.policyRef,
      revocable: plan.accessPolicy.revocable,
      timeBound: plan.accessPolicy.timeBound,
    },
    alcoacControls,
    authorityChainHash: input.authority.authorityChainHash,
    componentEvidence: components,
    custodyDigest: input.custodyDigest,
    electronicSystems: systems,
    effectiveAtHlc: plan.effectiveAtHlc,
    planHash: plan.planHash,
    planRef: plan.planRef,
    protocolRef: plan.protocolRef,
    retention: plan.retention,
    reviewDueHlc: plan.reviewDueHlc,
    schema: 'cybermedica.information_management_plan_fingerprint.v1',
    siteRef: plan.siteRef,
    sponsorRef: plan.sponsorRef,
    staffCommunication: plan.staffCommunication,
    status: plan.status,
    tenantId: input.tenantId,
    version: plan.version,
  });
}

function buildInformationPlan(input, components, alcoacControls, systems, planFingerprint, receipt) {
  const plan = input.informationPlan;
  const coveredComponents = components.map((component) => component.component);
  const coveredAlcoacPrinciples = alcoacControls.map((control) => control.principle);

  return {
    schema: 'cybermedica.information_management_plan.v1',
    informationPlanId: `cmimp_${sha256Hex({
      planFingerprint,
      planRef: plan.planRef,
      protocolRef: plan.protocolRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    planFingerprint,
    tenantId: input.tenantId,
    planRef: plan.planRef,
    protocolRef: plan.protocolRef,
    sponsorRef: plan.sponsorRef,
    siteRef: plan.siteRef,
    version: plan.version,
    readinessStatus: 'ready',
    componentCoverageBasisPoints: basisPoints(coveredComponents.length, REQUIRED_PLAN_COMPONENTS.length),
    alcoacCoverageBasisPoints: basisPoints(coveredAlcoacPrinciples.length, REQUIRED_ALCOAC_PRINCIPLES.length),
    coveredComponents,
    coveredAlcoacPrinciples,
    systemValidationSummary: systemValidationSummary(systems),
    retentionClass: plan.retention.retentionClass,
    accessPolicyRef: plan.accessPolicy.policyRef,
    staffCommunicationEvidenceHash: plan.staffCommunication.communicationEvidenceHash,
    effectiveAtHlc: plan.effectiveAtHlc,
    reviewDueHlc: plan.reviewDueHlc,
    authorityChainHash: input.authority.authorityChainHash,
    decisionForumReceiptId: input.review.decisionForum.workflowReceiptId,
    receiptId: receipt.receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function deniedInformationPlan(reasons) {
  return {
    schema: 'cybermedica.information_management_plan_decision.v1',
    decision: 'denied',
    failClosed: true,
    reasons,
    informationPlan: {
      schema: 'cybermedica.information_management_plan.v1',
      readinessStatus: 'blocked',
      trustState: 'inactive',
      exochainProductionClaim: false,
    },
    receipt: null,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function evaluateInformationManagementPlan(input) {
  const reasons = [];
  assertMetadataOnly(input);
  evaluateTenantActorAuthority(input, 'govern', reasons);
  evaluatePlanShape(input?.informationPlan, reasons);
  const components = normalizeComponentEvidence(input?.informationPlan, reasons);
  const alcoacControls = normalizeAlcoacControls(input?.informationPlan, reasons);
  const systems = normalizeElectronicSystems(input?.informationPlan, reasons);
  evaluateRetention(input?.informationPlan?.retention, reasons);
  evaluateAccessPolicy(input?.informationPlan?.accessPolicy, reasons);
  evaluateStaffCommunication(input?.informationPlan, reasons);
  evaluateHumanGovernance(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return deniedInformationPlan(uniqueReasons);
  }

  const planFingerprint = buildPlanFingerprint(input, components, alcoacControls, systems);
  const receipt = createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'information_management_plan',
    artifactVersion: `${input.informationPlan.planRef}@v${input.informationPlan.version}`,
    artifactHash: planFingerprint,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.informationPlan.effectiveAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['alcoac', 'data_integrity', 'information_management', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });

  return {
    schema: 'cybermedica.information_management_plan_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    informationPlan: buildInformationPlan(input, components, alcoacControls, systems, planFingerprint, receipt),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function evaluateCorrectionShape(input, reasons) {
  const correction = input?.correction;
  const correctedAt = hlcTuple(correction?.correctionAtHlc);
  const originalAt = hlcTuple(correction?.originalRecordedAtHlc);

  addReason(reasons, !hasText(correction?.correctionRef), 'correction_ref_absent');
  addReason(reasons, !hasText(correction?.recordRef), 'correction_record_ref_absent');
  addReason(reasons, !hasText(correction?.recordType), 'correction_record_type_absent');
  addReason(reasons, correction?.correctedByDid !== input?.actor?.did, 'correction_actor_mismatch');
  addReason(reasons, !isDigest(correction?.originalArtifactHash), 'correction_original_hash_invalid');
  addReason(reasons, !isDigest(correction?.correctedArtifactHash), 'correction_corrected_hash_invalid');
  addReason(
    reasons,
    isDigest(correction?.originalArtifactHash) &&
      isDigest(correction?.correctedArtifactHash) &&
      correction.originalArtifactHash === correction.correctedArtifactHash,
    'correction_no_change',
  );
  addReason(reasons, !isDigestOrZero(correction?.previousAuditHash), 'previous_audit_hash_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(correction?.sequence) && correction.sequence > 1 && correction.previousAuditHash === ZERO_HASH,
    'previous_audit_hash_missing_for_sequence',
  );
  addReason(reasons, !Number.isSafeInteger(correction?.sequence) || correction.sequence < 1, 'correction_sequence_invalid');
  addReason(reasons, !hasText(correction?.correctionMethod), 'correction_method_absent');
  addReason(reasons, !hasText(correction?.reasonCode), 'correction_reason_absent');
  addReason(reasons, correction?.originalContentPreserved !== true, 'original_content_not_preserved');
  addReason(reasons, correctedAt === null, 'correction_time_invalid');
  addReason(reasons, originalAt === null, 'original_record_time_invalid');
  addReason(
    reasons,
    correctedAt !== null && originalAt !== null && compareHlc(correctedAt, originalAt) <= 0,
    'correction_time_not_after_original',
  );
}

function evaluateSourceTraceability(traceability, reasons) {
  addReason(reasons, !hasText(traceability?.traceabilityRef), 'traceability_ref_absent');
  addReason(reasons, !isDigest(traceability?.sourceRecordHash), 'traceability_source_record_hash_invalid');
  addReason(reasons, !isDigest(traceability?.crfFieldHash), 'traceability_crf_field_hash_invalid');
  addReason(reasons, !hasText(traceability?.discrepancyRef), 'traceability_discrepancy_ref_absent');
  addReason(
    reasons,
    traceability?.preservesParticipantCodeBoundary !== true,
    'traceability_participant_code_boundary_unattested',
  );
}

function evaluateCorrectionApproval(input, reasons) {
  const correction = input?.correction;
  const approval = input?.approval;
  if (correction?.approvalRequired !== true) {
    return;
  }

  const correctedAt = hlcTuple(correction?.correctionAtHlc);
  const approvedAt = hlcTuple(approval?.approvedAtHlc);

  addReason(reasons, approval?.status !== 'approved', 'correction_approval_not_approved');
  addReason(reasons, !hasText(approval?.approverDid), 'correction_approver_absent');
  addReason(reasons, approval?.humanGate?.verified !== true, 'correction_approval_human_gate_unverified');
  addReason(reasons, approvedAt === null, 'correction_approval_time_invalid');
  addReason(reasons, !isDigest(approval?.rationaleHash), 'correction_approval_rationale_invalid');
  addReason(
    reasons,
    approvedAt !== null && correctedAt !== null && compareHlc(approvedAt, correctedAt) <= 0,
    'correction_approval_time_not_after_correction',
  );
}

function correctionMaterial(input) {
  const correction = input.correction;
  return {
    approval: input.approval ?? null,
    authorityChainHash: input.authority.authorityChainHash,
    correctedArtifactHash: correction.correctedArtifactHash,
    correctedByDid: correction.correctedByDid,
    correctionAtHlc: correction.correctionAtHlc,
    correctionMethod: correction.correctionMethod,
    correctionRef: correction.correctionRef,
    originalArtifactHash: correction.originalArtifactHash,
    originalContentPreserved: correction.originalContentPreserved,
    originalRecordedAtHlc: correction.originalRecordedAtHlc,
    previousAuditHash: correction.previousAuditHash,
    reasonCode: correction.reasonCode,
    recordRef: correction.recordRef,
    recordType: correction.recordType,
    schema: 'cybermedica.attributable_record_correction_material.v1',
    sequence: correction.sequence,
    sourceTraceability: correction.sourceTraceability,
    tenantId: input.tenantId,
  };
}

function buildCorrectionRecord(input, correctionRecordHash, receipt) {
  const correction = input.correction;
  return {
    schema: 'cybermedica.attributable_record_correction.v1',
    correctionRecordId: `cmcorr_${sha256Hex({
      correctionRecordHash,
      correctionRef: correction.correctionRef,
      recordRef: correction.recordRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    correctionRecordHash,
    tenantId: input.tenantId,
    recordRef: correction.recordRef,
    recordType: correction.recordType,
    correctionRef: correction.correctionRef,
    correctedByDid: correction.correctedByDid,
    originalArtifactHash: correction.originalArtifactHash,
    correctedArtifactHash: correction.correctedArtifactHash,
    previousAuditHash: correction.previousAuditHash,
    sequence: correction.sequence,
    correctionMethod: correction.correctionMethod,
    reasonCode: correction.reasonCode,
    originalContentPreserved: correction.originalContentPreserved,
    correctionAtHlc: correction.correctionAtHlc,
    originalRecordedAtHlc: correction.originalRecordedAtHlc,
    sourceTraceability: {
      traceabilityRef: correction.sourceTraceability.traceabilityRef,
      sourceRecordHash: correction.sourceTraceability.sourceRecordHash,
      crfFieldHash: correction.sourceTraceability.crfFieldHash,
      discrepancyRef: correction.sourceTraceability.discrepancyRef,
      preservesParticipantCodeBoundary: correction.sourceTraceability.preservesParticipantCodeBoundary,
    },
    approvalRef: input.approval?.approverDid ?? null,
    authorityChainHash: input.authority.authorityChainHash,
    receiptId: receipt.receiptId,
    immutableCorrectionReceipt: true,
    operationalStateMutable: true,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function recordAttributableCorrection(input) {
  const reasons = [];
  assertMetadataOnly(input);
  evaluateTenantActorAuthority(input, 'record_correction', reasons);
  evaluateCorrectionShape(input, reasons);
  evaluateSourceTraceability(input?.correction?.sourceTraceability, reasons);
  evaluateCorrectionApproval(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.attributable_record_correction_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      correctionRecord: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const correctionRecordHash = sha256Hex(correctionMaterial(input));
  const receipt = createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'attributable_record_correction',
    artifactVersion: `${input.correction.correctionRef}@${input.correction.sequence}`,
    artifactHash: correctionRecordHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.correction.correctionAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['alcoac', 'attributable_correction', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });

  return {
    schema: 'cybermedica.attributable_record_correction_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    correctionRecord: buildCorrectionRecord(input, correctionRecordHash, receipt),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
