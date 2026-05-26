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
const REQUIRED_SECTIONS = Object.freeze([
  'calibration_records',
  'clinical_trial_product_handling_readiness',
  'communication_plan',
  'competency_records',
  'decision_forum_determinations',
  'delegation_logs',
  'deviation_capa_readiness',
  'document_control_status',
  'equipment_inventory',
  'ethical_framework',
  'evidence_completeness_score',
  'evidence_freshness_score',
  'exochain_evidence_receipt_refs',
  'facility_readiness_evidence',
  'facility_types',
  'informed_consent_process_readiness',
  'internal_audit_status',
  'investigator_roster',
  'kpi_trends',
  'last_review_date',
  'legal_entity',
  'mission_vision_values',
  'next_review_due_date',
  'open_critical_gaps',
  'open_major_gaps',
  'open_minor_gaps',
  'organization_chart',
  'ownership_structure',
  'performance_objectives',
  'principal_investigator_qualifications',
  'quality_manager_designation',
  'quality_plan',
  'quality_risk_level',
  'readiness_status',
  'regulatory_inspection_history',
  'risk_management_framework',
  'role_definitions',
  'sae_ae_reporting_readiness',
  'site_identity',
  'site_locations',
  'sop_inventory',
  'sponsor_cro_evidence_summary',
  'sponsor_cro_oversight_summary',
  'staff_roster',
  'therapeutic_areas',
  'training_records',
  'vulnerable_population_safeguards',
]);

const READY_SECTION_STATUSES = new Set(['complete', 'complete_with_conditions']);
const SECTION_STATUSES = new Set(['blocked', 'complete', 'complete_with_conditions', 'deferred', 'incomplete']);
const PROFILE_STATUSES = new Set(['approved', 'approved_with_conditions', 'deferred', 'rejected']);
const READINESS_STATUSES = new Set(['not_ready', 'ready', 'ready_with_conditions']);
const QUALITY_RISK_LEVELS = new Set(['controlled', 'critical', 'elevated', 'high', 'low']);
const EVIDENCE_STATUSES = new Set(['approved', 'pending', 'rejected', 'superseded']);
const EVIDENCE_CLASSIFICATIONS = new Set([
  'confidential_metadata_only',
  'restricted_metadata_only',
  'sponsor_confidential_metadata_only',
]);
const FINDING_SEVERITIES = new Set(['critical', 'major', 'minor']);
const FINDING_STATUSES = new Set(['accepted', 'closed', 'deferred', 'mitigated', 'open']);
const QUALITY_REVIEW_DECISIONS = new Set(['approve', 'approve_with_conditions', 'defer', 'reject']);
const DETERMINATION_STATUSES = new Set(['accepted', 'approved', 'closed', 'superseded']);
const RAW_PROFILE_FIELDS = new Set([
  'freetextprofile',
  'investigatorcvbody',
  'profilebody',
  'profilenarrative',
  'rawdocumentbody',
  'rawfacilitydescription',
  'rawprofile',
  'rawprofilenarrative',
  'rawsopcontent',
  'sourcedocument',
  'sourcedocumentbody',
  'staffbiography',
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

function assertNoRawProfileText(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawProfileText(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_PROFILE_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw profile content field is not allowed at ${path}.${key}`);
    }
    assertNoRawProfileText(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawProfileText(input ?? {});
  canonicalize(input ?? {});
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function compareHlc(left, right) {
  if (left.physicalMs !== right.physicalMs) {
    return left.physicalMs - right.physicalMs;
  }
  return left.logical - right.logical;
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function sortedDigestList(value) {
  return Array.isArray(value) ? value.filter(isDigest).sort() : [];
}

function uniqueSorted(value) {
  return [...new Set(value)].sort();
}

function hasPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
}

function sectionSort(left, right) {
  return String(left.section).localeCompare(String(right.section));
}

function evidenceSort(left, right) {
  return String(left.evidenceRef).localeCompare(String(right.evidenceRef));
}

function findingSort(left, right) {
  return String(left.findingRef).localeCompare(String(right.findingRef));
}

function determinationSort(left, right) {
  return String(left.decisionId).localeCompare(String(right.decisionId));
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
  addReason(reasons, !hasPermission(input?.authority, 'govern'), 'authority_permission_missing');
}

function evaluateSiteProfile(profile, reasons) {
  addReason(reasons, !hasText(profile?.passportRef), 'passport_ref_absent');
  addReason(reasons, !hasText(profile?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(profile?.legalEntityRef), 'legal_entity_ref_absent');
  addReason(reasons, !hasText(profile?.ownerOrgRef), 'owner_org_ref_absent');
  addReason(reasons, !hasText(profile?.version), 'passport_version_absent');
  addReason(reasons, !READINESS_STATUSES.has(profile?.readinessStatus), 'readiness_status_invalid');
  addReason(reasons, !QUALITY_RISK_LEVELS.has(profile?.qualityRiskLevel), 'quality_risk_level_invalid');
  addReason(reasons, !PROFILE_STATUSES.has(profile?.status), 'passport_status_invalid');
  addReason(reasons, profile?.status === 'deferred', 'site_qms_passport_deferred');
  addReason(reasons, profile?.status === 'rejected', 'site_qms_passport_rejected');
  addReason(reasons, !hasText(profile?.qualityManagerDid), 'quality_manager_absent');
  addReason(reasons, !hasText(profile?.principalInvestigatorDid), 'principal_investigator_absent');
  addReason(reasons, !hlcPresent(profile?.createdAtHlc), 'passport_created_time_invalid');
  addReason(reasons, !hlcPresent(profile?.lastReviewedAtHlc), 'last_review_time_invalid');
  addReason(reasons, !hlcPresent(profile?.nextReviewDueHlc), 'next_review_time_invalid');
  addReason(
    reasons,
    hlcPresent(profile?.lastReviewedAtHlc) &&
      hlcPresent(profile?.nextReviewDueHlc) &&
      compareHlc(profile.nextReviewDueHlc, profile.lastReviewedAtHlc) <= 0,
    'next_review_not_after_last_review',
  );
  addReason(reasons, sortedTextList(profile?.policyRefs).length === 0, 'policy_refs_absent');
}

function evaluateSection(section, reasons) {
  const sectionName = hasText(section?.section) ? section.section : 'unknown';
  const evidenceRefs = sortedTextList(section?.evidenceRefs);
  const controlRefs = sortedTextList(section?.controlRefs);

  addReason(reasons, !REQUIRED_SECTIONS.includes(section?.section), `passport_section_invalid:${sectionName}`);
  addReason(reasons, !SECTION_STATUSES.has(section?.status), `passport_section_status_invalid:${sectionName}`);
  addReason(
    reasons,
    SECTION_STATUSES.has(section?.status) && !READY_SECTION_STATUSES.has(section?.status),
    `passport_section_not_ready:${sectionName}`,
  );
  addReason(reasons, !hasText(section?.ownerDid), `passport_section_owner_absent:${sectionName}`);
  addReason(reasons, !isDigest(section?.artifactHash), `passport_section_artifact_hash_invalid:${sectionName}`);
  addReason(reasons, evidenceRefs.length === 0, `passport_section_evidence_absent:${sectionName}`);
  addReason(reasons, controlRefs.length === 0, `passport_section_control_absent:${sectionName}`);
  if (section?.updatedAtHlc !== undefined) {
    addReason(reasons, !hlcPresent(section.updatedAtHlc), `passport_section_time_invalid:${sectionName}`);
  }

  return {
    schema: 'cybermedica.site_qms_passport_section.v1',
    section: sectionName,
    status: section?.status,
    ready: READY_SECTION_STATUSES.has(section?.status),
    ownerDid: section?.ownerDid,
    artifactHash: section?.artifactHash,
    evidenceRefs,
    controlRefs,
    updatedAtHlc: section?.updatedAtHlc,
  };
}

function normalizeSections(input, reasons) {
  const sections = Array.isArray(input?.sections) ? [...input.sections].sort(sectionSort) : [];
  addReason(reasons, sections.length === 0, 'passport_section_inventory_empty');

  const counts = new Map();
  for (const section of sections) {
    counts.set(section?.section, (counts.get(section?.section) ?? 0) + 1);
  }
  for (const [section, count] of counts.entries()) {
    if (REQUIRED_SECTIONS.includes(section)) {
      addReason(reasons, count > 1, `passport_section_duplicate:${section}`);
    }
  }

  const coveredSections = [...counts.keys()].filter((section) => REQUIRED_SECTIONS.includes(section)).sort();
  for (const section of REQUIRED_SECTIONS) {
    addReason(reasons, !coveredSections.includes(section), `required_passport_section_missing:${section}`);
  }

  return {
    coveredSections,
    normalizedSections: sections.map((section) => evaluateSection(section, reasons)),
  };
}

function evaluateEvidence(evidence, reasons) {
  const evidenceRef = hasText(evidence?.evidenceRef) ? evidence.evidenceRef : 'unknown';

  addReason(reasons, !hasText(evidence?.evidenceRef), 'evidence_ref_absent');
  addReason(reasons, !REQUIRED_SECTIONS.includes(evidence?.section), `evidence_section_invalid:${evidenceRef}`);
  addReason(reasons, !isDigest(evidence?.artifactHash), `evidence_hash_invalid:${evidenceRef}`);
  addReason(reasons, !EVIDENCE_STATUSES.has(evidence?.status), `evidence_status_invalid:${evidenceRef}`);
  addReason(reasons, evidence?.status !== 'approved', `evidence_not_approved:${evidenceRef}`);
  addReason(reasons, evidence?.fresh !== true, `evidence_stale:${evidenceRef}`);
  addReason(reasons, !EVIDENCE_CLASSIFICATIONS.has(evidence?.classification), `evidence_classification_invalid:${evidenceRef}`);
  addReason(reasons, !isDigest(evidence?.custodyDigest), `evidence_custody_digest_invalid:${evidenceRef}`);

  return {
    schema: 'cybermedica.site_qms_passport_evidence.v1',
    evidenceRef,
    section: evidence?.section,
    artifactHash: evidence?.artifactHash,
    status: evidence?.status,
    fresh: evidence?.fresh === true,
    classification: evidence?.classification,
    custodyDigest: evidence?.custodyDigest,
  };
}

function normalizeEvidence(input, sections, reasons) {
  const evidenceInventory = Array.isArray(input?.evidenceInventory) ? [...input.evidenceInventory].sort(evidenceSort) : [];
  addReason(reasons, evidenceInventory.length === 0, 'passport_evidence_inventory_empty');
  const normalizedEvidence = evidenceInventory.map((evidence) => evaluateEvidence(evidence, reasons));
  const evidenceByRef = new Map(normalizedEvidence.map((evidence) => [evidence.evidenceRef, evidence]));

  for (const section of sections) {
    for (const evidenceRef of section.evidenceRefs) {
      addReason(reasons, !evidenceByRef.has(evidenceRef), `passport_section_evidence_missing:${section.section}:${evidenceRef}`);
    }
  }

  return {
    evidenceByRef,
    normalizedEvidence,
  };
}

function sectionHasCompleteEvidence(section, evidenceByRef) {
  return (
    section.ready === true &&
    section.evidenceRefs.length > 0 &&
    section.evidenceRefs.every((evidenceRef) => {
      const evidence = evidenceByRef.get(evidenceRef);
      return (
        evidence !== undefined &&
        evidence.status === 'approved' &&
        isDigest(evidence.artifactHash) &&
        isDigest(evidence.custodyDigest)
      );
    })
  );
}

function sectionHasFreshEvidence(section, evidenceByRef) {
  return sectionHasCompleteEvidence(section, evidenceByRef) && section.evidenceRefs.every((evidenceRef) => evidenceByRef.get(evidenceRef)?.fresh === true);
}

function openGapSummary(findings) {
  const summary = { critical: 0, major: 0, minor: 0 };
  for (const finding of findings) {
    if (FINDING_SEVERITIES.has(finding.severity) && finding.status !== 'closed' && finding.status !== 'mitigated') {
      summary[finding.severity] += 1;
    }
  }
  return summary;
}

function evaluateFinding(finding, reasons) {
  const findingRef = hasText(finding?.findingRef) ? finding.findingRef : 'unknown';
  const needsMitigation = finding?.status !== 'closed';

  addReason(reasons, !hasText(finding?.findingRef), 'finding_ref_absent');
  addReason(reasons, !FINDING_SEVERITIES.has(finding?.severity), `finding_severity_invalid:${findingRef}`);
  addReason(reasons, !FINDING_STATUSES.has(finding?.status), `finding_status_invalid:${findingRef}`);
  addReason(reasons, !hasText(finding?.ownerDid), `finding_owner_absent:${findingRef}`);
  addReason(reasons, needsMitigation && !isDigest(finding?.mitigationHash), `finding_mitigation_invalid:${findingRef}`);
  addReason(
    reasons,
    finding?.severity === 'critical' && finding?.status !== 'closed' && finding?.status !== 'mitigated',
    `critical_gap_unresolved:${findingRef}`,
  );

  return {
    schema: 'cybermedica.site_qms_passport_finding.v1',
    findingRef,
    severity: finding?.severity,
    status: finding?.status,
    ownerDid: finding?.ownerDid,
    mitigationHash: finding?.mitigationHash,
    openForPassportCondition:
      FINDING_SEVERITIES.has(finding?.severity) && finding?.status !== 'closed' && finding?.status !== 'mitigated',
  };
}

function normalizeFindings(input, reasons) {
  const findings = Array.isArray(input?.findings) ? [...input.findings].sort(findingSort) : [];
  return findings.map((finding) => evaluateFinding(finding, reasons));
}

function requiredEscalationRoles(findings) {
  const roles = [];
  for (const finding of findings) {
    if (!finding.openForPassportCondition) {
      continue;
    }
    if (finding.severity === 'major') {
      roles.push('site_quality_lead');
    }
    if (finding.severity === 'critical') {
      roles.push('decision_forum', 'principal_investigator', 'site_quality_lead');
    }
  }
  return uniqueSorted(roles);
}

function evaluateCapaSummary(summary, reasons) {
  const openCritical = summary?.openCritical;
  const openMajor = summary?.openMajor;
  const overdue = summary?.overdue;
  addReason(reasons, !Number.isSafeInteger(openCritical) || openCritical < 0, 'capa_open_critical_invalid');
  addReason(reasons, !Number.isSafeInteger(openMajor) || openMajor < 0, 'capa_open_major_invalid');
  addReason(reasons, !Number.isSafeInteger(overdue) || overdue < 0, 'capa_overdue_invalid');
  addReason(reasons, Number.isSafeInteger(openCritical) && openCritical > 0, 'capa_open_critical_present');
  addReason(reasons, Number.isSafeInteger(overdue) && overdue > 0, 'capa_overdue_present');

  return {
    openCritical: Number.isSafeInteger(openCritical) ? openCritical : null,
    openMajor: Number.isSafeInteger(openMajor) ? openMajor : null,
    overdue: Number.isSafeInteger(overdue) ? overdue : null,
    linkedCapaRefs: sortedTextList(summary?.linkedCapaRefs),
  };
}

function evaluateRiskRegisterSummary(summary, siteProfile, reasons) {
  addReason(reasons, !QUALITY_RISK_LEVELS.has(summary?.qualityRiskLevel), 'risk_register_level_invalid');
  addReason(
    reasons,
    QUALITY_RISK_LEVELS.has(summary?.qualityRiskLevel) &&
      QUALITY_RISK_LEVELS.has(siteProfile?.qualityRiskLevel) &&
      summary.qualityRiskLevel !== siteProfile.qualityRiskLevel,
    'risk_register_profile_mismatch',
  );
  addReason(
    reasons,
    !Number.isSafeInteger(summary?.activeHighRiskCount) || summary.activeHighRiskCount < 0,
    'active_high_risk_count_invalid',
  );
  addReason(
    reasons,
    !Number.isSafeInteger(summary?.activeCriticalRiskCount) || summary.activeCriticalRiskCount < 0,
    'active_critical_risk_count_invalid',
  );
  addReason(reasons, Number.isSafeInteger(summary?.activeCriticalRiskCount) && summary.activeCriticalRiskCount > 0, 'active_critical_risk_present');

  return {
    qualityRiskLevel: summary?.qualityRiskLevel,
    activeHighRiskCount: Number.isSafeInteger(summary?.activeHighRiskCount) ? summary.activeHighRiskCount : null,
    activeCriticalRiskCount: Number.isSafeInteger(summary?.activeCriticalRiskCount) ? summary.activeCriticalRiskCount : null,
    startupRiskAssessmentRefs: sortedTextList(summary?.startupRiskAssessmentRefs),
  };
}

function evaluateQualityObjective(objective, reasons) {
  const objectiveRef = hasText(objective?.objectiveRef) ? objective.objectiveRef : 'unknown';
  addReason(reasons, !hasText(objective?.objectiveRef), 'quality_objective_ref_absent');
  addReason(reasons, objective?.status !== 'active', `quality_objective_not_active:${objectiveRef}`);
  addReason(
    reasons,
    !Number.isSafeInteger(objective?.scoreBasisPoints) || objective.scoreBasisPoints < 0 || objective.scoreBasisPoints > 10_000,
    `quality_objective_score_invalid:${objectiveRef}`,
  );
  addReason(reasons, !isDigest(objective?.evidenceHash), `quality_objective_evidence_invalid:${objectiveRef}`);

  return {
    schema: 'cybermedica.site_qms_passport_quality_objective.v1',
    objectiveRef,
    status: objective?.status,
    scoreBasisPoints: Number.isSafeInteger(objective?.scoreBasisPoints) ? objective.scoreBasisPoints : null,
    evidenceHash: objective?.evidenceHash,
  };
}

function normalizeQualityObjectives(input, reasons) {
  const objectives = Array.isArray(input?.qualityObjectives)
    ? [...input.qualityObjectives].sort((left, right) => String(left.objectiveRef).localeCompare(String(right.objectiveRef)))
    : [];
  addReason(reasons, objectives.length === 0, 'quality_objectives_absent');
  return objectives.map((objective) => evaluateQualityObjective(objective, reasons));
}

function averageBasisPoints(objectives) {
  const validScores = objectives
    .map((objective) => objective.scoreBasisPoints)
    .filter((score) => Number.isSafeInteger(score) && score >= 0 && score <= 10_000);
  if (validScores.length === 0) {
    return 0;
  }
  const total = validScores.reduce((sum, score) => sum + BigInt(score), 0n);
  return Number(total / BigInt(validScores.length));
}

function evaluateAiEvidenceReview(review, reasons) {
  addReason(reasons, review?.completed !== true, 'ai_evidence_review_incomplete');
  addReason(reasons, review?.advisoryOnly !== true || review?.finalAuthority === true, 'ai_evidence_review_must_be_advisory');
  addReason(reasons, review?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !hasText(review?.reviewerRole), 'ai_evidence_review_human_reviewer_role_absent');
  addReason(reasons, !isDigest(review?.outputHash), 'ai_evidence_review_output_invalid');
  addReason(
    reasons,
    !Array.isArray(review?.evidenceUsedHashes) ||
      review.evidenceUsedHashes.length === 0 ||
      review.evidenceUsedHashes.some((hash) => !isDigest(hash)),
    'ai_evidence_review_evidence_hash_invalid',
  );

  return {
    completed: review?.completed === true,
    advisoryOnly: review?.advisoryOnly === true && review?.finalAuthority !== true,
    reviewerRole: review?.reviewerRole,
    outputHash: review?.outputHash,
    evidenceUsedHashes: sortedDigestList(review?.evidenceUsedHashes),
    unresolvedGaps: sortedTextList(review?.unresolvedGaps),
  };
}

function evaluateDecisionForumDetermination(determination, reasons) {
  const decisionId = hasText(determination?.decisionId) ? determination.decisionId : 'unknown';
  const invalid =
    !hasText(determination?.decisionId) ||
    !hasText(determination?.workflowReceiptId) ||
    !DETERMINATION_STATUSES.has(determination?.status) ||
    !isDigest(determination?.receiptHash);
  addReason(reasons, invalid, `decision_forum_determination_invalid:${decisionId}`);

  return {
    decisionId,
    workflowReceiptId: determination?.workflowReceiptId,
    status: determination?.status,
    receiptHash: determination?.receiptHash,
  };
}

function evaluateQualityReview(review, reasons) {
  addReason(reasons, !QUALITY_REVIEW_DECISIONS.has(review?.decision), 'quality_review_decision_invalid');
  addReason(reasons, review?.decision === 'defer', 'quality_review_deferred');
  addReason(reasons, review?.decision === 'reject', 'quality_review_rejected');
  addReason(reasons, !hasText(review?.reviewerDid), 'quality_reviewer_absent');
  addReason(reasons, review?.humanVerified !== true, 'quality_review_human_unverified');
  addReason(reasons, !isDigest(review?.rationaleHash), 'quality_review_rationale_invalid');
  addReason(reasons, !hlcPresent(review?.approvedAtHlc), 'quality_review_time_invalid');
  addReason(reasons, !hasText(review?.decisionReceiptRef), 'decision_receipt_ref_absent');
  addReason(reasons, !isDigest(review?.decisionReceiptHash), 'decision_receipt_hash_invalid');
  addReason(reasons, review?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, review?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');

  const determinations = Array.isArray(review?.decisionForumDeterminations)
    ? [...review.decisionForumDeterminations].sort(determinationSort).map((determination) => evaluateDecisionForumDetermination(determination, reasons))
    : [];

  return {
    decision: review?.decision,
    reviewerDid: review?.reviewerDid,
    humanVerified: review?.humanVerified === true,
    rationaleHash: review?.rationaleHash,
    approvedAtHlc: review?.approvedAtHlc,
    decisionReceiptRef: review?.decisionReceiptRef,
    decisionReceiptHash: review?.decisionReceiptHash,
    evidenceBundleComplete: review?.evidenceBundle?.complete === true,
    phiBoundaryAttested: review?.evidenceBundle?.phiBoundaryAttested === true,
    decisionForumDeterminations: determinations,
  };
}

function passportStatus(input, reasons) {
  if (reasons.length > 0) {
    return 'blocked';
  }
  if (input?.siteProfile?.status === 'approved') {
    return 'approved';
  }
  return 'approved_with_conditions';
}

function buildPassport(input, normalizedSections, coveredSections, evidenceByRef, normalizedEvidence, normalizedFindings, reasons) {
  const sortedReasons = uniqueSorted(reasons);
  const requiredSectionSet = new Set(REQUIRED_SECTIONS);
  const relevantSections = normalizedSections.filter((section) => requiredSectionSet.has(section.section));
  const completeCount = relevantSections.filter((section) => sectionHasCompleteEvidence(section, evidenceByRef)).length;
  const freshCount = relevantSections.filter((section) => sectionHasFreshEvidence(section, evidenceByRef)).length;
  const openSummary = openGapSummary(normalizedFindings);
  const requiredRoles = requiredEscalationRoles(normalizedFindings);
  const capaSummary = evaluateCapaSummary(input?.capaSummary, reasons);
  const riskRegisterSummary = evaluateRiskRegisterSummary(input?.riskRegisterSummary, input?.siteProfile, reasons);
  const qualityObjectives = normalizeQualityObjectives(input, reasons);
  const aiEvidenceReview = evaluateAiEvidenceReview(input?.aiEvidenceReview, reasons);
  const qualityReview = evaluateQualityReview(input?.qualityReview, reasons);
  const status = passportStatus(input, reasons);
  const material = {
    coveredSections,
    evidenceCompletenessBasisPoints: basisPoints(completeCount, REQUIRED_SECTIONS.length),
    evidenceFreshnessBasisPoints: basisPoints(freshCount, REQUIRED_SECTIONS.length),
    findings: normalizedFindings,
    passportRef: input?.siteProfile?.passportRef ?? null,
    siteRef: input?.siteProfile?.siteRef ?? null,
    status,
    tenantId: input?.tenantId ?? null,
    version: input?.siteProfile?.version ?? null,
  };

  return {
    schema: 'cybermedica.site_qms_passport.v1',
    tenantId: input?.tenantId,
    passportRef: input?.siteProfile?.passportRef,
    siteRef: input?.siteProfile?.siteRef,
    legalEntityRef: input?.siteProfile?.legalEntityRef,
    ownerOrgRef: input?.siteProfile?.ownerOrgRef,
    version: input?.siteProfile?.version,
    passportStatus: status,
    readinessStatus: sortedReasons.length === 0 ? input?.siteProfile?.readinessStatus : 'blocked',
    qualityRiskLevel: input?.siteProfile?.qualityRiskLevel,
    qualityManagerDid: input?.siteProfile?.qualityManagerDid,
    principalInvestigatorDid: input?.siteProfile?.principalInvestigatorDid,
    lastReviewedAtHlc: input?.siteProfile?.lastReviewedAtHlc,
    nextReviewDueHlc: input?.siteProfile?.nextReviewDueHlc,
    aiFinalAuthority: false,
    exochainProductionClaim: false,
    trustState: 'inactive',
    coveredSections,
    missingSections: REQUIRED_SECTIONS.filter((section) => !coveredSections.includes(section)),
    evidenceCompletenessBasisPoints: basisPoints(completeCount, REQUIRED_SECTIONS.length),
    evidenceFreshnessBasisPoints: basisPoints(freshCount, REQUIRED_SECTIONS.length),
    sections: normalizedSections,
    evidenceInventory: normalizedEvidence,
    findings: normalizedFindings,
    openGapSummary: openSummary,
    requiredEscalationRoles: requiredRoles,
    capaSummary,
    riskRegisterSummary,
    qualityObjectives,
    qualityObjectiveScoreBasisPoints: averageBasisPoints(qualityObjectives),
    aiEvidenceReview,
    qualityReview,
    passportId: `cmpass_${sha256Hex(material).slice(0, 32)}`,
  };
}

function buildReceipt(input, passport) {
  const artifactHash = sha256Hex({
    coveredSections: passport.coveredSections,
    evidenceCompletenessBasisPoints: passport.evidenceCompletenessBasisPoints,
    evidenceFreshnessBasisPoints: passport.evidenceFreshnessBasisPoints,
    findings: passport.findings,
    passportId: passport.passportId,
    passportStatus: passport.passportStatus,
    readinessStatus: passport.readinessStatus,
    siteRef: passport.siteRef,
    version: passport.version,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'site_qms_passport',
    artifactVersion: `${input.siteProfile.passportRef}@${input.siteProfile.createdAtHlc.physicalMs}.${input.siteProfile.createdAtHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.siteProfile.createdAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['site_qms_passport', 'quality_readiness', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateSiteQmsPassport(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateSiteProfile(input?.siteProfile, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  const { coveredSections, normalizedSections } = normalizeSections(input, reasons);
  const { evidenceByRef, normalizedEvidence } = normalizeEvidence(input, normalizedSections, reasons);
  const normalizedFindings = normalizeFindings(input, reasons);
  const passport = buildPassport(input, normalizedSections, coveredSections, evidenceByRef, normalizedEvidence, normalizedFindings, reasons);
  const sortedReasons = uniqueSorted(reasons);

  if (sortedReasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: sortedReasons,
      passport,
    };
  }

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    passport,
    receipt: buildReceipt(input, passport),
  };
}
