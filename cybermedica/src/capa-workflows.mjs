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

import { createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;

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

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
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

function evaluateCapaPrerequisites(input, reasons) {
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.capaId), 'capa_id_absent');
  addReason(reasons, input?.capa?.status !== 'verification_ready', 'capa_not_verification_ready');
  addReason(reasons, input?.capa?.rootCauseComplete !== true, 'root_cause_incomplete');
  addReason(reasons, input?.capa?.correctiveActionImplemented !== true, 'corrective_action_not_implemented');
  addReason(reasons, input?.capa?.preventiveActionImplemented !== true, 'preventive_action_not_implemented');
  addReason(reasons, input?.capa?.impactedPoliciesReviewed !== true, 'impacted_policies_not_reviewed');
  addReason(reasons, input?.capa?.impactedTrainingReviewed !== true, 'impacted_training_not_reviewed');
  addReason(reasons, input?.capa?.verificationMethodDefined !== true, 'verification_method_absent');
}

function evaluateObjectiveEvidence(input, reasons) {
  const hashes = input?.evidencePackage?.objectiveEvidenceHashes;
  addReason(reasons, input?.evidencePackage?.complete !== true, 'evidence_package_incomplete');
  addReason(reasons, !Array.isArray(hashes) || hashes.length === 0, 'objective_evidence_absent');
  addReason(reasons, Array.isArray(hashes) && hashes.some((hash) => !isDigest(hash)), 'objective_evidence_hash_invalid');
  addReason(reasons, !isDigest(input?.evidencePackage?.custodyDigest), 'custody_digest_invalid');
}

function evaluateEffectiveness(effectiveness, reasons) {
  if (effectiveness?.status === 'met') {
    addReason(reasons, !isDigest(effectiveness.criteriaHash), 'effectiveness_criteria_hash_invalid');
    addReason(reasons, !hlcPresent(effectiveness.checkedAtHlc), 'effectiveness_check_time_invalid');
    return { closureState: 'closed', effectivenessFinal: true, followUpRequired: false };
  }

  if (effectiveness?.status === 'not_determinable_yet') {
    addReason(reasons, !isDigest(effectiveness.criteriaHash), 'effectiveness_criteria_hash_invalid');
    addReason(reasons, !hasText(effectiveness.rationale), 'effectiveness_followup_rationale_absent');
    addReason(reasons, !hlcPresent(effectiveness.followUpHlc), 'effectiveness_followup_time_invalid');
    return {
      closureState: 'closed_with_effectiveness_followup',
      effectivenessFinal: false,
      followUpRequired: true,
    };
  }

  reasons.push('effectiveness_not_established');
  return { closureState: 'open', effectivenessFinal: false, followUpRequired: false };
}

function buildClosureReceipt(input, effectivenessResult) {
  const artifactHash = sha256Hex({
    capaId: input.capaId,
    sourceEventId: input.sourceEventId,
    objectiveEvidenceHashes: [...input.evidencePackage.objectiveEvidenceHashes].sort(),
    effectiveness: input.effectiveness,
    closureState: effectivenessResult.closureState,
  });
  const hlcTimestamp = input.effectiveness.checkedAtHlc ?? input.effectiveness.followUpHlc;

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'capa_closure',
    artifactVersion: `${input.capaId}@closure`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp,
    custodyDigest: input.evidencePackage.custodyDigest,
    sensitivityTags: ['capa', 'quality_evidence', 'participant_safety_relevant'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateCapaClosure(input) {
  const reasons = [];
  evaluateCapaPrerequisites(input, reasons);
  evaluateObjectiveEvidence(input, reasons);
  evaluateHumanGovernance(input, reasons);
  const effectivenessResult = evaluateEffectiveness(input?.effectiveness, reasons);
  const denied = reasons.length > 0;

  return {
    schema: 'cybermedica.capa_closure_decision.v1',
    capaId: input?.capaId,
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons: [...new Set(reasons)].sort(),
    closureState: denied ? 'open' : effectivenessResult.closureState,
    terminalImmutable: !denied && effectivenessResult.effectivenessFinal,
    effectivenessFinal: !denied && effectivenessResult.effectivenessFinal,
    followUpRequired: !denied && effectivenessResult.followUpRequired,
    trustState: 'inactive',
    exochainProductionClaim: false,
    receipt: denied ? null : buildClosureReceipt(input, effectivenessResult),
    inputEcho: input,
  };
}
