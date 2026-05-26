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
const ACTIVE_OBJECTIVE_STATES = new Set(['active']);
const GOVERNED_OBJECTIVE_STATES = new Set(['active', 'retired']);
const OBJECTIVE_LIFECYCLE_STATES = new Set(['active', 'draft', 'retired']);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
}

function isNonNegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function hlcOrder(left, right) {
  if (!hlcPresent(left) || !hlcPresent(right)) {
    return 0;
  }
  if (left.physicalMs !== right.physicalMs) {
    return left.physicalMs < right.physicalMs ? -1 : 1;
  }
  if (left.logical !== right.logical) {
    return left.logical < right.logical ? -1 : 1;
  }
  return 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function requiredPermission(lifecycleState) {
  return GOVERNED_OBJECTIVE_STATES.has(lifecycleState) ? 'govern' : 'write';
}

function requiresHumanGovernance(input) {
  return GOVERNED_OBJECTIVE_STATES.has(input?.objective?.lifecycleState);
}

function requiresMeasurement(input) {
  return OBJECTIVE_LIFECYCLE_STATES.has(input?.objective?.lifecycleState);
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  const permission = requiredPermission(input?.objective?.lifecycleState);

  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority, permission), 'authority_permission_missing');
}

function evaluateHumanGovernance(input, reasons) {
  if (!requiresHumanGovernance(input)) {
    return;
  }

  const forum = input?.review?.decisionForum;
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, input?.review?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, input?.review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(reasons, !hasText(input?.review?.approverDid), 'approver_did_absent');
}

function evaluateObjectiveDefinition(input, reasons) {
  const objective = input?.objective;
  addReason(reasons, !hasText(objective?.objectiveId), 'objective_id_absent');
  addReason(reasons, !hasText(objective?.name), 'objective_name_absent');
  addReason(reasons, !hasText(objective?.sourceStrategyRef), 'source_strategy_absent');
  addReason(reasons, sortedTextList(objective?.sourceControlIds).length === 0, 'source_control_linkage_absent');
  addReason(reasons, !hasText(objective?.definition), 'objective_definition_absent');
  addReason(reasons, !hasText(objective?.numeratorDefinition), 'numerator_definition_absent');
  addReason(reasons, !hasText(objective?.denominatorDefinition), 'denominator_definition_absent');
  addReason(reasons, !hasText(objective?.collectionMethod), 'collection_method_absent');
  addReason(reasons, !hasText(objective?.frequency), 'frequency_absent');
  addReason(reasons, !hasText(objective?.ownerDid), 'owner_did_absent');
  addReason(reasons, sortedTextList(objective?.riskRefs).length === 0, 'risk_linkage_absent');
  addReason(reasons, !hasText(objective?.qualityObjectiveLinkage), 'quality_objective_linkage_absent');
  addReason(reasons, sortedTextList(objective?.reportingAudience).length === 0, 'reporting_audience_absent');
  addReason(reasons, !hasText(objective?.decisionUse), 'decision_use_absent');
  addReason(reasons, !OBJECTIVE_LIFECYCLE_STATES.has(objective?.lifecycleState), 'objective_lifecycle_state_invalid');

  addReason(reasons, !isBasisPoints(objective?.thresholdBasisPoints), 'threshold_basis_points_invalid');
  addReason(reasons, !isBasisPoints(objective?.targetBasisPoints), 'target_basis_points_invalid');
  if (isBasisPoints(objective?.thresholdBasisPoints) && isBasisPoints(objective?.targetBasisPoints)) {
    addReason(reasons, objective.targetBasisPoints < objective.thresholdBasisPoints, 'target_below_threshold');
  }

  const warning = objective?.alertRule?.warningBelowBasisPoints;
  const critical = objective?.alertRule?.criticalBelowBasisPoints;
  addReason(reasons, !isBasisPoints(warning), 'warning_basis_points_invalid');
  addReason(reasons, !isBasisPoints(critical), 'critical_basis_points_invalid');
  if (isBasisPoints(warning) && isBasisPoints(critical) && isBasisPoints(objective?.thresholdBasisPoints)) {
    addReason(reasons, critical > warning || warning > objective.thresholdBasisPoints, 'alert_threshold_order_invalid');
  }
}

function evaluateMeasurement(input, reasons) {
  if (!requiresMeasurement(input)) {
    return;
  }

  const measurement = input?.measurement;
  if (measurement === null || measurement === undefined) {
    reasons.push('measurement_absent');
    return;
  }
  addReason(reasons, !isNonNegativeSafeInteger(measurement?.numerator), 'measurement_numerator_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(measurement?.denominator) || measurement.denominator <= 0,
    'measurement_denominator_invalid',
  );
  addReason(
    reasons,
    isNonNegativeSafeInteger(measurement?.numerator) &&
      Number.isSafeInteger(measurement?.denominator) &&
      measurement.denominator > 0 &&
      measurement.numerator > measurement.denominator,
    'measurement_numerator_exceeds_denominator',
  );
  addReason(reasons, !hlcPresent(measurement?.measuredAtHlc), 'measurement_time_invalid');
  addReason(reasons, sortedTextList(measurement?.evidenceHashes).length === 0, 'measurement_evidence_absent');
  addReason(
    reasons,
    Array.isArray(measurement?.evidenceHashes) && measurement.evidenceHashes.some((hash) => !isDigest(hash)),
    'measurement_evidence_hash_invalid',
  );
  addReason(reasons, !isDigest(measurement?.custodyDigest), 'custody_digest_invalid');

  if (input?.previousMeasurement !== undefined && input.previousMeasurement !== null) {
    addReason(reasons, !isBasisPoints(input.previousMeasurement.actualBasisPoints), 'previous_measurement_basis_points_invalid');
    addReason(reasons, !hlcPresent(input.previousMeasurement.measuredAtHlc), 'previous_measurement_time_invalid');
    addReason(
      reasons,
      hlcPresent(input.previousMeasurement.measuredAtHlc) &&
        hlcPresent(measurement?.measuredAtHlc) &&
        hlcOrder(input.previousMeasurement.measuredAtHlc, measurement.measuredAtHlc) >= 0,
      'previous_measurement_not_before_current',
    );
  }
}

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function objectiveStatus(actualBasisPoints, objective) {
  if (actualBasisPoints >= objective.targetBasisPoints) {
    return 'target_met';
  }
  if (actualBasisPoints >= objective.thresholdBasisPoints) {
    return 'within_threshold';
  }
  return 'below_threshold';
}

function alertLevel(actualBasisPoints, objective) {
  if (actualBasisPoints < objective.alertRule.criticalBelowBasisPoints) {
    return 'critical';
  }
  if (actualBasisPoints < objective.alertRule.warningBelowBasisPoints) {
    return 'warning';
  }
  return 'none';
}

function trend(actualBasisPoints, previousMeasurement) {
  if (!previousMeasurement || !isBasisPoints(previousMeasurement.actualBasisPoints)) {
    return 'not_established';
  }
  if (actualBasisPoints > previousMeasurement.actualBasisPoints) {
    return 'improving';
  }
  if (actualBasisPoints < previousMeasurement.actualBasisPoints) {
    return 'declining';
  }
  return 'unchanged';
}

function buildReceipt(input, qualityObjective) {
  const artifactHash = sha256Hex({
    actualBasisPoints: qualityObjective.actualBasisPoints,
    alertLevel: qualityObjective.alertLevel,
    collectionMethod: qualityObjective.collectionMethod,
    decisionUse: qualityObjective.decisionUse,
    denominatorDefinition: qualityObjective.denominatorDefinition,
    evidenceHashes: qualityObjective.evidenceHashes,
    frequency: qualityObjective.frequency,
    numeratorDefinition: qualityObjective.numeratorDefinition,
    objectiveId: qualityObjective.objectiveId,
    qualityObjectiveLinkage: qualityObjective.qualityObjectiveLinkage,
    sourceControlIds: qualityObjective.sourceControlIds,
    sourceStrategyRef: qualityObjective.sourceStrategyRef,
    status: qualityObjective.status,
    thresholdBasisPoints: qualityObjective.thresholdBasisPoints,
    targetBasisPoints: qualityObjective.targetBasisPoints,
    trend: qualityObjective.trend,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'quality_objective_measurement',
    artifactVersion: `${input.objective.objectiveId}@${input.measurement.measuredAtHlc.physicalMs}.${input.measurement.measuredAtHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.measurement.measuredAtHlc,
    custodyDigest: input.measurement.custodyDigest,
    sensitivityTags: ['quality_objective', 'kpi', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildQualityObjective(input) {
  const actualBasisPoints = basisPoints(input.measurement.numerator, input.measurement.denominator);
  const objective = input.objective;

  return {
    schema: 'cybermedica.quality_objective.v1',
    objectiveId: objective.objectiveId,
    tenantId: input.tenantId,
    name: objective.name,
    sourceStrategyRef: objective.sourceStrategyRef,
    sourceControlIds: sortedTextList(objective.sourceControlIds),
    definition: objective.definition,
    numeratorDefinition: objective.numeratorDefinition,
    denominatorDefinition: objective.denominatorDefinition,
    collectionMethod: objective.collectionMethod,
    frequency: objective.frequency,
    ownerDid: objective.ownerDid,
    thresholdBasisPoints: objective.thresholdBasisPoints,
    targetBasisPoints: objective.targetBasisPoints,
    warningBelowBasisPoints: objective.alertRule.warningBelowBasisPoints,
    criticalBelowBasisPoints: objective.alertRule.criticalBelowBasisPoints,
    riskRefs: sortedTextList(objective.riskRefs),
    qualityObjectiveLinkage: objective.qualityObjectiveLinkage,
    reportingAudience: sortedTextList(objective.reportingAudience),
    decisionUse: objective.decisionUse,
    lifecycleState: objective.lifecycleState,
    numerator: input.measurement.numerator,
    denominator: input.measurement.denominator,
    actualBasisPoints,
    status: objectiveStatus(actualBasisPoints, objective),
    alertLevel: alertLevel(actualBasisPoints, objective),
    trend: trend(actualBasisPoints, input.previousMeasurement),
    measuredAtHlc: input.measurement.measuredAtHlc,
    evidenceHashes: sortedTextList(input.measurement.evidenceHashes),
    evidenceHashDigest: sha256Hex(sortedTextList(input.measurement.evidenceHashes)),
    custodyDigest: input.measurement.custodyDigest,
    humanGovernanceRequired: requiresHumanGovernance(input),
    operationalStateMutable: true,
    immutableMeasurementReceipt: true,
  };
}

export function evaluateQualityObjective(input) {
  canonicalize(input ?? {});
  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateObjectiveDefinition(input, reasons);
  evaluateMeasurement(input, reasons);
  evaluateHumanGovernance(input, reasons);

  const normalizedReasons = uniqueReasons(reasons);
  if (normalizedReasons.length > 0) {
    return {
      schema: 'cybermedica.quality_objective_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: normalizedReasons,
      qualityObjective: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const qualityObjective = buildQualityObjective(input);
  const receipt = buildReceipt(input, qualityObjective);
  qualityObjective.receiptId = receipt.receiptId;

  return {
    schema: 'cybermedica.quality_objective_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    qualityObjective,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
