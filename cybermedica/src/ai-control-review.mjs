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

import { canonicalize, createEvidenceReceipt, ProtectedContentError, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const REQUIRED_PERMISSION = 'ai_control_review';
const AI_CONTROL_REVIEW_SOURCE_REQUIREMENTS = Object.freeze(['FR-008']);
const REVIEW_CLASSES = new Set([
  'control_evidence_completeness',
  'evidence_freshness_review',
  'policy_procedure_gap_review',
  'risk_signal_review',
]);
const REQUIRED_SCOPE_PERMISSIONS = new Set(['generate_advisory_findings', 'read_metadata_evidence']);
const ALLOWED_SCOPE_PERMISSIONS = new Set([
  'detect_contradictions',
  'flag_missing_evidence',
  'generate_advisory_findings',
  'read_metadata_evidence',
]);
const CONTROL_RISK_CRITICALITIES = new Set(['critical', 'major', 'minor']);
const EVIDENCE_STATUSES = new Set(['approved', 'pending', 'rejected', 'superseded']);
const EVIDENCE_CLASSIFICATIONS = new Set([
  'audit_metadata_only',
  'qms_metadata_only',
  'restricted_metadata_only',
  'sponsor_confidential_metadata_only',
  'training_metadata_only',
]);
const FINDING_TYPES = new Set([
  'contradiction',
  'data_integrity_risk',
  'evidence_complete',
  'missing_evidence',
  'policy_gap',
  'privacy_risk',
  'safety_risk',
  'stale_evidence',
]);
const FINDING_SEVERITIES = new Set(['critical', 'major', 'minor', 'observation']);
const RAW_AI_REVIEW_FIELDS = new Set([
  'aichat',
  'aidialog',
  'aifreeformoutput',
  'aioutput',
  'findingnarrative',
  'findingtext',
  'freeformfinding',
  'limitationtext',
  'rawaioutput',
  'rawanalysis',
  'rawfinding',
  'reasoningtext',
  'sourcecontent',
  'sourcedocument',
  'sourcedocumentbody',
  'unresolvedassumptiontext',
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

function assertNoRawAiReviewText(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAiReviewText(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_AI_REVIEW_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw AI control review content field is not allowed at ${path}.${key}`);
    }
    assertNoRawAiReviewText(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAiReviewText(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function uniqueSorted(value) {
  return [...new Set(value.filter(hasText))].sort();
}

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical) && hlc.logical >= 0;
}

function compareHlc(left, right) {
  if (left.physicalMs !== right.physicalMs) {
    return left.physicalMs - right.physicalMs;
  }
  return left.logical - right.logical;
}

function hasPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasPermission(input?.authority, REQUIRED_PERMISSION), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateAiAgent(input, reasons) {
  addReason(reasons, !hasText(input?.aiAgent?.did), 'ai_agent_did_absent');
  addReason(reasons, input?.aiAgent?.kind !== 'ai_agent', 'ai_agent_kind_invalid');
  addReason(reasons, input?.aiAgent?.authorizedScope !== 'control_evidence_review', 'ai_agent_scope_invalid');
  addReason(reasons, !hasText(input?.aiAgent?.policyRef), 'ai_policy_ref_absent');
}

function evaluateReview(input, reasons) {
  const review = input?.review;
  addReason(reasons, !hasText(review?.reviewId), 'ai_review_id_absent');
  addReason(reasons, !REVIEW_CLASSES.has(review?.reviewClass), 'ai_review_class_invalid');
  addReason(reasons, !isDigest(review?.modelRefHash), 'ai_model_ref_hash_invalid');
  addReason(reasons, !isDigest(review?.modelVersionHash), 'ai_model_version_hash_invalid');
  addReason(reasons, !isDigest(review?.modelConfigurationHash), 'ai_model_configuration_hash_invalid');
  addReason(reasons, !isDigest(review?.promptHash), 'ai_prompt_hash_invalid');
  addReason(reasons, !isDigest(review?.inputManifestHash), 'ai_input_manifest_hash_invalid');
  addReason(reasons, !isDigest(review?.outputHash), 'ai_output_hash_invalid');
  addReason(reasons, !hlcPresent(review?.startedAtHlc), 'ai_review_start_time_invalid');
  addReason(reasons, !hlcPresent(review?.completedAtHlc), 'ai_review_completed_time_invalid');
  addReason(
    reasons,
    hlcPresent(review?.startedAtHlc) &&
      hlcPresent(review?.completedAtHlc) &&
      compareHlc(review.completedAtHlc, review.startedAtHlc) <= 0,
    'ai_review_completed_before_start',
  );
  addReason(reasons, review?.advisoryOnly !== true || review?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.advisoryOnly !== true || review?.finalAuthority === true, 'ai_advisory_disposition_invalid');
  addReason(reasons, review?.logged !== true, 'ai_review_not_logged');
  addReason(reasons, review?.promptOutputRetained !== true, 'ai_prompt_output_retention_absent');
  addReason(reasons, !hasText(review?.tenantPolicyRef), 'ai_tenant_policy_ref_absent');

  const scopePermissions = sortedTextList(review?.scopePermissions);
  for (const required of REQUIRED_SCOPE_PERMISSIONS) {
    addReason(reasons, !scopePermissions.includes(required), `ai_scope_permission_missing:${required}`);
  }
  for (const permission of scopePermissions) {
    addReason(reasons, !ALLOWED_SCOPE_PERMISSIONS.has(permission), `ai_scope_permission_invalid:${permission}`);
  }
}

function evaluateHumanReviewPolicy(input, reasons) {
  const policy = input?.humanReviewPolicy;
  const reviewerRoles = sortedTextList(policy?.reviewerRoles);
  addReason(reasons, policy?.required !== true, 'human_review_policy_absent');
  addReason(reasons, reviewerRoles.length === 0, 'human_review_roles_absent');
  addReason(reasons, policy?.contestable !== true, 'human_contestation_absent');
  addReason(reasons, policy?.allowAiFinalAuthority === true, 'human_review_policy_allows_ai_final_authority');
  return reviewerRoles;
}

function controlSort(left, right) {
  return String(left.controlId).localeCompare(String(right.controlId));
}

function evidenceSort(left, right) {
  return String(left.controlId).localeCompare(String(right.controlId)) || String(left.evidenceRef).localeCompare(String(right.evidenceRef));
}

function findingSort(left, right) {
  return String(left.findingRef).localeCompare(String(right.findingRef));
}

function normalizeControls(input, reasons) {
  const controls = Array.isArray(input?.controls) ? [...input.controls].sort(controlSort) : [];
  addReason(reasons, controls.length === 0, 'controls_absent');

  const normalizedControls = controls.map((control) => {
    const controlId = hasText(control?.controlId) ? control.controlId : 'unknown';
    const requiredEvidenceTypes = sortedTextList(control?.requiredEvidenceTypes);
    addReason(reasons, !hasText(control?.controlId), 'control_id_absent');
    addReason(reasons, !hasText(control?.versionId), `control_version_absent:${controlId}`);
    addReason(reasons, !CONTROL_RISK_CRITICALITIES.has(control?.riskCriticality), `control_risk_criticality_invalid:${controlId}`);
    addReason(reasons, !hasText(control?.ownerRole), `control_owner_role_absent:${controlId}`);
    addReason(reasons, !isDigest(control?.objectiveHash), `control_objective_hash_invalid:${controlId}`);
    addReason(reasons, requiredEvidenceTypes.length === 0, `control_required_evidence_absent:${controlId}`);
    addReason(reasons, control?.applicable !== true, `control_not_applicable:${controlId}`);
    addReason(reasons, !hasText(control?.controlApprovalRef), `control_approval_ref_absent:${controlId}`);
    return {
      applicable: control?.applicable === true,
      controlApprovalRef: control?.controlApprovalRef ?? null,
      controlId,
      objectiveHash: control?.objectiveHash ?? null,
      ownerRole: control?.ownerRole ?? null,
      requiredEvidenceTypes,
      riskCriticality: control?.riskCriticality ?? null,
      versionId: control?.versionId ?? null,
    };
  });

  return {
    controlById: new Map(normalizedControls.map((control) => [control.controlId, control])),
    normalizedControls,
  };
}

function normalizeEvidenceLinks(input, controlById, reasons) {
  const evidenceLinks = Array.isArray(input?.evidenceLinks) ? [...input.evidenceLinks].sort(evidenceSort) : [];
  addReason(reasons, evidenceLinks.length === 0, 'evidence_links_absent');

  const normalizedEvidenceLinks = evidenceLinks.map((evidence) => {
    const evidenceRef = hasText(evidence?.evidenceRef) ? evidence.evidenceRef : 'unknown';
    const controlId = hasText(evidence?.controlId) ? evidence.controlId : 'unknown';
    addReason(reasons, !hasText(evidence?.controlId), `evidence_control_id_absent:${evidenceRef}`);
    addReason(reasons, !controlById.has(controlId), `evidence_control_unknown:${evidenceRef}`);
    addReason(reasons, !hasText(evidence?.evidenceRef), 'evidence_ref_absent');
    addReason(reasons, !hasText(evidence?.evidenceType), `evidence_type_absent:${evidenceRef}`);
    addReason(reasons, !isDigest(evidence?.artifactHash), `evidence_artifact_hash_invalid:${evidenceRef}`);
    addReason(reasons, !isDigest(evidence?.custodyDigest), `evidence_custody_digest_invalid:${evidenceRef}`);
    addReason(reasons, !EVIDENCE_STATUSES.has(evidence?.status), `evidence_status_invalid:${evidenceRef}`);
    addReason(reasons, evidence?.status !== 'approved', `evidence_not_approved:${evidenceRef}`);
    addReason(reasons, typeof evidence?.fresh !== 'boolean', `evidence_freshness_state_invalid:${evidenceRef}`);
    addReason(reasons, !EVIDENCE_CLASSIFICATIONS.has(evidence?.classification), `evidence_classification_invalid:${evidenceRef}`);
    addReason(reasons, evidence?.reviewedByHuman !== true, `evidence_human_review_absent:${evidenceRef}`);
    addReason(reasons, evidence?.phiBoundaryAttested !== true, `evidence_phi_boundary_unattested:${evidenceRef}`);
    return {
      artifactHash: evidence?.artifactHash ?? null,
      classification: evidence?.classification ?? null,
      controlId,
      custodyDigest: evidence?.custodyDigest ?? null,
      evidenceRef,
      evidenceType: evidence?.evidenceType ?? null,
      fresh: evidence?.fresh === true,
      reviewedByHuman: evidence?.reviewedByHuman === true,
      status: evidence?.status ?? null,
    };
  });

  return {
    evidenceByRef: new Map(normalizedEvidenceLinks.map((evidence) => [evidence.evidenceRef, evidence])),
    normalizedEvidenceLinks,
  };
}

function normalizeFindings(input, controlById, evidenceByRef, reasons) {
  const findings = Array.isArray(input?.findings) ? [...input.findings].sort(findingSort) : [];
  addReason(reasons, findings.length === 0, 'ai_findings_absent');

  return findings.map((finding) => {
    const findingRef = hasText(finding?.findingRef) ? finding.findingRef : 'unknown';
    const controlId = hasText(finding?.controlId) ? finding.controlId : 'unknown';
    const evidenceRefs = sortedTextList(finding?.evidenceRefs);
    const unresolvedAssumptionHashes = sortedTextList(finding?.unresolvedAssumptionHashes);
    const potentialConflictRefs = sortedTextList(finding?.potentialConflictRefs);

    addReason(reasons, !hasText(finding?.findingRef), 'finding_ref_absent');
    addReason(reasons, !hasText(finding?.controlId), `finding_control_id_absent:${findingRef}`);
    addReason(reasons, !controlById.has(controlId), `finding_control_unknown:${findingRef}`);
    addReason(reasons, !FINDING_TYPES.has(finding?.findingType), `finding_type_invalid:${findingRef}`);
    addReason(reasons, !FINDING_SEVERITIES.has(finding?.severity), `finding_severity_invalid:${findingRef}`);
    addReason(
      reasons,
      !Number.isSafeInteger(finding?.confidenceBasisPoints) ||
        finding.confidenceBasisPoints < 0 ||
        finding.confidenceBasisPoints > 10_000,
      `finding_confidence_invalid:${findingRef}`,
    );
    addReason(reasons, !isDigest(finding?.humanReadableFindingHash), `finding_human_readable_hash_invalid:${findingRef}`);
    addReason(reasons, evidenceRefs.length === 0, `finding_evidence_refs_absent:${findingRef}`);
    for (const evidenceRef of evidenceRefs) {
      addReason(reasons, !evidenceByRef.has(evidenceRef), `finding_evidence_ref_unknown:${findingRef}:${evidenceRef}`);
    }
    addReason(reasons, !isDigest(finding?.reasoningSummaryHash), `finding_reasoning_hash_invalid:${findingRef}`);
    addReason(reasons, !isDigest(finding?.limitationsHash), `finding_limitations_hash_invalid:${findingRef}`);
    for (const assumptionHash of unresolvedAssumptionHashes) {
      addReason(reasons, !isDigest(assumptionHash), `finding_unresolved_assumption_hash_invalid:${findingRef}`);
    }
    addReason(reasons, !hasText(finding?.recommendedHumanReviewerRole), `finding_reviewer_role_absent:${findingRef}`);
    addReason(reasons, finding?.requiresHumanReview !== true, `finding_human_review_absent:${findingRef}`);
    addReason(reasons, finding?.severity === 'critical' && finding?.escalationRequired !== true, `critical_finding_escalation_absent:${findingRef}`);
    addReason(
      reasons,
      (finding?.severity === 'critical' || finding?.severity === 'major') && finding?.capaRecommended !== true,
      `finding_capa_recommendation_absent:${findingRef}`,
    );

    return {
      capaRecommended: finding?.capaRecommended === true,
      confidenceBasisPoints: finding?.confidenceBasisPoints ?? null,
      controlId,
      dataIntegrityRisk: finding?.dataIntegrityRisk === true,
      escalationRequired: finding?.escalationRequired === true,
      evidenceRefs,
      findingRef,
      findingType: finding?.findingType ?? null,
      humanReadableFindingHash: finding?.humanReadableFindingHash ?? null,
      limitationsHash: finding?.limitationsHash ?? null,
      participantSafetyRisk: finding?.participantSafetyRisk === true,
      potentialConflictRefs,
      privacyRisk: finding?.privacyRisk === true,
      reasoningSummaryHash: finding?.reasoningSummaryHash ?? null,
      recommendedHumanReviewerRole: finding?.recommendedHumanReviewerRole ?? null,
      requiresHumanReview: finding?.requiresHumanReview === true,
      severity: finding?.severity ?? null,
      unresolvedAssumptionHashes,
    };
  });
}

function evaluateRequiredFindingCoverage(normalizedControls, normalizedEvidenceLinks, normalizedFindings, reasons) {
  const approvedEvidence = normalizedEvidenceLinks.filter((evidence) => evidence.status === 'approved');
  const findingKeys = new Set(normalizedFindings.map((finding) => `${finding.controlId}:${finding.findingType}`));

  for (const control of normalizedControls.filter((item) => item.applicable)) {
    for (const evidenceType of control.requiredEvidenceTypes) {
      const matching = approvedEvidence.filter((evidence) => evidence.controlId === control.controlId && evidence.evidenceType === evidenceType);
      addReason(
        reasons,
        matching.length === 0 && !findingKeys.has(`${control.controlId}:missing_evidence`),
        `missing_evidence_finding_absent:${control.controlId}:${evidenceType}`,
      );
    }
  }

  for (const evidence of approvedEvidence) {
    addReason(
      reasons,
      evidence.fresh === false && !findingKeys.has(`${evidence.controlId}:stale_evidence`),
      `stale_evidence_finding_absent:${evidence.evidenceRef}`,
    );
  }
}

function metricsForControls(normalizedControls, normalizedEvidenceLinks) {
  const approvedEvidence = normalizedEvidenceLinks.filter((evidence) => evidence.status === 'approved');
  const applicableControls = normalizedControls.filter((control) => control.applicable);
  const requiredRows = applicableControls.flatMap((control) =>
    control.requiredEvidenceTypes.map((evidenceType) => ({ controlId: control.controlId, evidenceType })),
  );
  const satisfiedRows = requiredRows.filter((required) =>
    approvedEvidence.some((evidence) => evidence.controlId === required.controlId && evidence.evidenceType === required.evidenceType),
  );
  const notStaleRows = requiredRows.filter((required) => {
    const matching = approvedEvidence.filter((evidence) => evidence.controlId === required.controlId && evidence.evidenceType === required.evidenceType);
    return matching.length === 0 || matching.some((evidence) => evidence.fresh);
  });
  const linkedApprovedEvidence = approvedEvidence.filter((evidence) =>
    applicableControls.some((control) => control.controlId === evidence.controlId && control.requiredEvidenceTypes.includes(evidence.evidenceType)),
  );

  return {
    evidenceCompletenessBasisPoints: basisPoints(satisfiedRows.length, requiredRows.length),
    evidenceFreshnessBasisPoints: basisPoints(notStaleRows.length, requiredRows.length),
    requiredEvidenceCount: requiredRows.length,
    satisfiedEvidenceCount: satisfiedRows.length,
    staleEvidenceRefs: linkedApprovedEvidence.filter((evidence) => !evidence.fresh).map((evidence) => evidence.evidenceRef).sort(),
  };
}

function findingSummary(normalizedFindings) {
  return {
    critical: normalizedFindings.filter((finding) => finding.severity === 'critical').length,
    major: normalizedFindings.filter((finding) => finding.severity === 'major').length,
    minor: normalizedFindings.filter((finding) => finding.severity === 'minor').length,
    observation: normalizedFindings.filter((finding) => finding.severity === 'observation').length,
  };
}

function requiredEscalationRoles(normalizedFindings) {
  const roles = [];
  for (const finding of normalizedFindings) {
    if (finding.escalationRequired || finding.severity === 'critical') {
      roles.push('site_quality_lead');
    }
    if (finding.severity === 'critical') {
      roles.push('decision_forum_chair');
    }
    if (finding.participantSafetyRisk) {
      roles.push('principal_investigator');
    }
    if (finding.dataIntegrityRisk) {
      roles.push('data_integrity_owner');
    }
    if (finding.privacyRisk) {
      roles.push('privacy_officer');
    }
    if (finding.capaRecommended) {
      roles.push('capa_owner');
    }
  }
  return uniqueSorted(roles);
}

function buildArtifactHash(input, normalizedControls, normalizedEvidenceLinks, normalizedFindings, reviewerRoles, metrics, escalationRoles) {
  return sha256Hex({
    aiAgentDid: input.aiAgent.did,
    controlIds: normalizedControls.map((control) => control.controlId),
    controls: normalizedControls,
    evidenceCompletenessBasisPoints: metrics.evidenceCompletenessBasisPoints,
    evidenceFreshnessBasisPoints: metrics.evidenceFreshnessBasisPoints,
    evidenceLinks: normalizedEvidenceLinks,
    findingSummary: findingSummary(normalizedFindings),
    findings: normalizedFindings,
    humanReviewPolicy: {
      contestable: input.humanReviewPolicy.contestable,
      reviewerRoles,
    },
    requiredEscalationRoles: escalationRoles,
    sourceRequirements: AI_CONTROL_REVIEW_SOURCE_REQUIREMENTS,
    review: {
      completedAtHlc: input.review.completedAtHlc,
      inputManifestHash: input.review.inputManifestHash,
      modelConfigurationHash: input.review.modelConfigurationHash,
      modelRefHash: input.review.modelRefHash,
      modelVersionHash: input.review.modelVersionHash,
      outputHash: input.review.outputHash,
      promptHash: input.review.promptHash,
      reviewClass: input.review.reviewClass,
      reviewId: input.review.reviewId,
      startedAtHlc: input.review.startedAtHlc,
      tenantPolicyRef: input.review.tenantPolicyRef,
    },
    tenantId: input.tenantId,
  });
}

function buildReceipt(input, artifactHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'ai_control_review_findings',
    artifactVersion: `${input.review.reviewId}@${input.review.reviewClass}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.review.completedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['ai_review', 'control_evidence', 'human_review_required', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function runAiControlReview(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateAiAgent(input, reasons);
  evaluateReview(input, reasons);
  const reviewerRoles = evaluateHumanReviewPolicy(input, reasons);
  const { controlById, normalizedControls } = normalizeControls(input, reasons);
  const { evidenceByRef, normalizedEvidenceLinks } = normalizeEvidenceLinks(input, controlById, reasons);
  const normalizedFindings = normalizeFindings(input, controlById, evidenceByRef, reasons);
  evaluateRequiredFindingCoverage(normalizedControls, normalizedEvidenceLinks, normalizedFindings, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = [...new Set(reasons)].sort();
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.ai_control_review_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      aiControlReview: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const metrics = metricsForControls(normalizedControls, normalizedEvidenceLinks);
  const escalationRoles = requiredEscalationRoles(normalizedFindings);
  const summary = findingSummary(normalizedFindings);
  const artifactHash = buildArtifactHash(input, normalizedControls, normalizedEvidenceLinks, normalizedFindings, reviewerRoles, metrics, escalationRoles);
  const receipt = buildReceipt(input, artifactHash);
  const humanReviewQueue = normalizedFindings
    .map((finding) => `${finding.recommendedHumanReviewerRole}:${finding.findingRef}`)
    .sort();

  return {
    schema: 'cybermedica.ai_control_review_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    aiControlReview: {
      schema: 'cybermedica.ai_control_review_findings.v1',
      reviewId: `cmaicr_${sha256Hex({
        artifactHash,
        reviewId: input.review.reviewId,
        tenantId: input.tenantId,
      }).slice(0, 32)}`,
      tenantId: input.tenantId,
      sourceReviewId: input.review.reviewId,
      reviewClass: input.review.reviewClass,
      sourceRequirements: [...AI_CONTROL_REVIEW_SOURCE_REQUIREMENTS],
      aiAgentDid: input.aiAgent.did,
      modelRefHash: input.review.modelRefHash,
      modelVersionHash: input.review.modelVersionHash,
      modelConfigurationHash: input.review.modelConfigurationHash,
      controlIds: normalizedControls.map((control) => control.controlId),
      evidenceCompletenessBasisPoints: metrics.evidenceCompletenessBasisPoints,
      evidenceFreshnessBasisPoints: metrics.evidenceFreshnessBasisPoints,
      requiredEvidenceCount: metrics.requiredEvidenceCount,
      satisfiedEvidenceCount: metrics.satisfiedEvidenceCount,
      staleEvidenceRefs: metrics.staleEvidenceRefs,
      findingSummary: summary,
      findingRefs: normalizedFindings.map((finding) => finding.findingRef),
      humanReviewQueue,
      capaRecommendedFindingRefs: normalizedFindings
        .filter((finding) => finding.capaRecommended)
        .map((finding) => finding.findingRef)
        .sort(),
      requiredEscalationRoles: escalationRoles,
      reviewerRoles,
      assistanceOnly: true,
      aiFinalAuthority: false,
      humanFinalAuthorityRequired: true,
      contestable: true,
      receiptId: receipt.receiptId,
      trustState: 'inactive',
      exochainProductionClaim: false,
      operationalStateMutable: true,
      immutableReviewReceipt: true,
    },
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
