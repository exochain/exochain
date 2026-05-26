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

import { sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;

const LAUNCH_CHECK_REASONS = Object.freeze({
  aiReviewComplete: 'ai_launch_review_incomplete',
  authorizedRepresentativeApproved: 'authorized_representative_not_approved',
  clinicalTrialAgreementExecuted: 'clinical_trial_agreement_not_executed',
  consentVersionReady: 'consent_version_not_ready',
  delegationLogComplete: 'delegation_log_incomplete',
  documentInventoryComplete: 'document_inventory_incomplete',
  equipmentReady: 'equipment_not_ready',
  facilityReady: 'facility_not_ready',
  feasibilityApproved: 'site_feasibility_not_approved',
  informationManagementPlanApproved: 'information_management_plan_not_approved',
  irbApproved: 'irb_not_approved',
  monitoringArrangementsReady: 'monitoring_arrangements_not_ready',
  piSigned: 'pi_readiness_signature_absent',
  productHandlingReady: 'product_handling_not_ready',
  protocolApproved: 'protocol_not_approved',
  qualityManagerSigned: 'quality_manager_recommendation_absent',
  saeAeReportingReady: 'sae_ae_reporting_not_ready',
  sponsorCroApprovalsComplete: 'sponsor_cro_approvals_incomplete',
  staffTrainingComplete: 'staff_training_incomplete',
  startupRiskAssessmentApproved: 'startup_risk_assessment_not_approved',
});

const EXCLUSION_APPLICABILITY = new Set(['deferred', 'not_applicable', 'superseded', 'waived']);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function compareById(left, right) {
  return String(left.id).localeCompare(String(right.id));
}

function isSafeInteger(value) {
  return Number.isSafeInteger(value);
}

function hlcPhysicalMs(hlc, fieldName) {
  if (!hlc || !isSafeInteger(hlc.physicalMs)) {
    throw new Error(`${fieldName}.physicalMs must be a safe integer`);
  }
  return hlc.physicalMs;
}

function isApplicable(control) {
  return control?.applicability === 'applicable' || control?.applicability === 'conditionally_applicable';
}

function isExclusionApplicability(control) {
  return EXCLUSION_APPLICABILITY.has(control?.applicability);
}

function hasApprovedControlExclusion(control) {
  return hasText(control?.rationale) && control?.approval?.status === 'approved' && hasText(control?.approval?.actorDid);
}

function hasApprovedWaiver(evidence) {
  return evidence?.waiver?.status === 'approved' && hasText(evidence?.waiver?.authorityDid);
}

function assertEvidenceHash(evidence) {
  if (!hasText(evidence?.artifactHash) || !HEX_64.test(evidence.artifactHash) || /^0+$/u.test(evidence.artifactHash)) {
    throw new Error('evidence.artifactHash must be a non-zero lowercase 64 hex character digest');
  }
}

function evidenceIsFresh(evidence, assessmentHlc) {
  const observedAt = hlcPhysicalMs(evidence.observedAtHlc, 'evidence.observedAtHlc');
  if (!isSafeInteger(evidence.freshnessWindowMs) || evidence.freshnessWindowMs < 0) {
    throw new Error('evidence.freshnessWindowMs must be a non-negative safe integer');
  }
  return observedAt + evidence.freshnessWindowMs >= hlcPhysicalMs(assessmentHlc, 'assessmentHlc');
}

function controlBlockers(control, assessmentHlc) {
  const blockers = [];
  const evidence = Array.isArray(control.evidence) ? [...control.evidence].sort(compareById) : [];
  const requiredEvidenceCount = Array.isArray(control.requiredEvidence) ? control.requiredEvidence.length : 0;

  if (requiredEvidenceCount === 0) {
    return blockers;
  }
  if (evidence.length < requiredEvidenceCount) {
    blockers.push({
      controlId: control.id,
      evidenceId: null,
      reason: 'required_evidence_missing',
      severity: control.riskCriticality,
    });
  }

  for (const item of evidence) {
    assertEvidenceHash(item);
    if (item.status !== 'approved') {
      blockers.push({
        controlId: control.id,
        evidenceId: item.id,
        reason: 'evidence_not_approved',
        severity: control.riskCriticality,
      });
    } else if (!evidenceIsFresh(item, assessmentHlc) && !hasApprovedWaiver(item)) {
      blockers.push({
        controlId: control.id,
        evidenceId: item.id,
        reason: 'evidence_stale',
        severity: control.riskCriticality,
      });
    }
  }

  return blockers;
}

function basisPoints(numerator, denominator) {
  if (denominator === 0) {
    return 0;
  }
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

export function buildControlReadinessSnapshot(input) {
  const controls = Array.isArray(input?.controls) ? [...input.controls].sort(compareById) : [];
  const blockers = [];
  if (controls.length === 0) {
    blockers.push({
      controlId: null,
      evidenceId: null,
      reason: 'control_inventory_empty',
      severity: 'critical',
    });
  }
  const controlResults = controls.map((control) => {
    if (isExclusionApplicability(control)) {
      if (!hasApprovedControlExclusion(control)) {
        blockers.push({
          controlId: control.id,
          evidenceId: null,
          reason: 'control_exclusion_unapproved',
          severity: control.riskCriticality,
        });
        return {
          id: control.id,
          status: 'blocked',
          applicability: control.applicability,
          riskCriticality: control.riskCriticality,
          requiredEvidence: Array.isArray(control.requiredEvidence) ? [...control.requiredEvidence].sort() : [],
          evidenceIds: Array.isArray(control.evidence) ? control.evidence.map((item) => item.id).sort() : [],
        };
      }
      return {
        id: control.id,
        status: 'excluded',
        applicability: control.applicability,
        riskCriticality: control.riskCriticality,
        requiredEvidence: Array.isArray(control.requiredEvidence) ? [...control.requiredEvidence].sort() : [],
        evidenceIds: Array.isArray(control.evidence) ? control.evidence.map((item) => item.id).sort() : [],
      };
    }
    if (!isApplicable(control)) {
      blockers.push({
        controlId: control.id,
        evidenceId: null,
        reason: 'control_applicability_invalid',
        severity: control.riskCriticality,
      });
      return {
        id: control.id,
        status: 'blocked',
        applicability: control.applicability,
        riskCriticality: control.riskCriticality,
        requiredEvidence: Array.isArray(control.requiredEvidence) ? [...control.requiredEvidence].sort() : [],
        evidenceIds: Array.isArray(control.evidence) ? control.evidence.map((item) => item.id).sort() : [],
      };
    }
    const controlSpecificBlockers = controlBlockers(control, input.assessmentHlc);
    blockers.push(...controlSpecificBlockers);
    return {
      id: control.id,
      status: controlSpecificBlockers.length === 0 ? 'ready' : 'blocked',
      applicability: control.applicability,
      riskCriticality: control.riskCriticality,
      requiredEvidence: Array.isArray(control.requiredEvidence) ? [...control.requiredEvidence].sort() : [],
      evidenceIds: Array.isArray(control.evidence) ? control.evidence.map((item) => item.id).sort() : [],
    };
  });
  const readyCount = controlResults.filter((control) => control.status === 'ready' || control.status === 'excluded').length;
  const completenessBasisPoints = basisPoints(readyCount, controlResults.length);
  const sortedBlockers = blockers.sort((left, right) => {
    return `${left.controlId}:${left.evidenceId ?? ''}:${left.reason}`.localeCompare(
      `${right.controlId}:${right.evidenceId ?? ''}:${right.reason}`,
    );
  });

  const snapshotMaterial = {
    tenantId: input?.tenantId,
    assessmentHlc: input?.assessmentHlc,
    controls: controlResults,
    blockers: sortedBlockers,
    completenessBasisPoints,
  };

  return {
    schema: 'cybermedica.control_readiness_snapshot.v1',
    tenantId: input?.tenantId,
    status: sortedBlockers.length === 0 ? 'ready' : 'blocked',
    activeReadinessClaim: sortedBlockers.length === 0,
    completenessBasisPoints,
    blockers: sortedBlockers,
    controls: controlResults,
    snapshotId: `cmrs_${sha256Hex(snapshotMaterial).slice(0, 32)}`,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function evaluateHumanGovernance(input, reasons) {
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !input?.decisionForum || input.decisionForum.verified !== true, 'decision_forum_unverified');
  addReason(reasons, input?.decisionForum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, input?.decisionForum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, input?.decisionForum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, input?.decisionForum?.openChallenge === true, 'challenge_open');
  addReason(reasons, input?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, input?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
}

export function evaluateProtocolLaunchGate(input) {
  const reasons = [];
  const checks = input?.launchChecks ?? {};

  for (const key of Object.keys(LAUNCH_CHECK_REASONS).sort()) {
    addReason(reasons, checks[key] !== true, LAUNCH_CHECK_REASONS[key]);
  }
  addReason(
    reasons,
    Array.isArray(input?.unresolvedBlockers) &&
      input.unresolvedBlockers.some((blocker) => blocker.severity === 'critical'),
    'unresolved_critical_blocker',
  );
  evaluateHumanGovernance(input, reasons);

  const denied = reasons.length > 0;
  return {
    schema: 'cybermedica.protocol_launch_gate_decision.v1',
    protocolId: input?.protocolId,
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons: [...new Set(reasons)].sort(),
    enrollmentAuthorizationActive: !denied,
    trustState: 'inactive',
    exochainProductionClaim: false,
    inputEcho: input,
  };
}

export function evaluateEnrollmentGate(input) {
  const reasons = [];
  addReason(reasons, input?.protocol?.status !== 'active', 'protocol_not_active');
  addReason(
    reasons,
    input?.launchGate?.status !== 'approved' || input?.launchGate?.enrollmentAuthorizationActive !== true,
    'launch_gate_not_approved',
  );
  addReason(reasons, input?.consentForm?.status !== 'active', 'consent_form_not_active');
  addReason(reasons, input?.consentForm?.status === 'superseded', 'consent_form_superseded');
  addReason(reasons, input?.staffTraining?.complete !== true || input?.staffTraining?.current !== true, 'staff_training_invalid');
  addReason(
    reasons,
    input?.delegation?.authorized !== true || input?.delegation?.expired === true || input?.delegation?.revoked === true,
    'delegation_invalid',
  );
  addReason(
    reasons,
    Array.isArray(input?.blockingRisks) && input.blockingRisks.some((risk) => risk.status !== 'closed'),
    'blocking_risk_active',
  );
  addReason(reasons, input?.participantConsent?.status !== 'active', 'participant_consent_not_active');
  addReason(reasons, input?.participantConsent?.revoked === true, 'participant_consent_revoked');
  evaluateHumanGovernance(input, reasons);

  const denied = reasons.length > 0;
  return {
    schema: 'cybermedica.enrollment_gate_decision.v1',
    protocolId: input?.protocolId,
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons: [...new Set(reasons)].sort(),
    participantMayEnroll: !denied,
    trustState: 'inactive',
    exochainProductionClaim: false,
    inputEcho: input,
  };
}
