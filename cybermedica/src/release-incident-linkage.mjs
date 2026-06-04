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
const LINKAGE_SCHEMA = 'cybermedica.release_incident_linkage.v1';
const DECISION_SCHEMA = 'cybermedica.release_incident_linkage_decision.v1';
const REQUIRED_PERMISSION = 'release_incident_linkage_review';

const REQUIRED_INCIDENT_FAMILIES = Object.freeze([
  'adapter_degraded',
  'availability_outage',
  'data_integrity_event',
  'privacy_boundary_failure',
  'receipt_queue_backlog',
  'root_bundle_unavailable',
  'security_event',
  'sponsor_export_disclosure',
]);

const REQUIRED_RELEASE_LINKAGE_DOMAINS = Object.freeze([
  'capa_cqi_drift_linkage',
  'decision_forum_materiality',
  'deployment_manifest_update',
  'incident_register_current',
  'policy_traceability_update',
  'prd_acceptance_update',
  'release_readiness_update',
  'rollback_or_disablement_path',
  'validation_evidence',
]);

const MATERIAL_INCIDENT_FAMILIES = Object.freeze([
  'data_integrity_event',
  'privacy_boundary_failure',
  'security_event',
  'sponsor_export_disclosure',
]);

const POLICY_STATUSES = new Set(['active']);
const INCIDENT_SEVERITIES = new Set(['minor', 'major', 'critical']);
const INCIDENT_STATUSES = new Set(['closed_corrective_action_linked', 'contained', 'monitoring', 'restored']);
const CONTAINMENT_STATUSES = new Set(['contained', 'monitoring']);
const RESTORATION_STATUSES = new Set(['monitoring_verified', 'verified_restored']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_incident_response_gap',
  'release_incident_linkage_accepted_inactive_trust',
]);

const RAW_LINKAGE_FIELDS = new Set([
  'body',
  'content',
  'debugpayload',
  'freetext',
  'healthpayload',
  'incidentbody',
  'incidentcontent',
  'incidentnarrative',
  'participantname',
  'rawcapa',
  'rawcommunication',
  'rawdeploymentmanifest',
  'rawevidence',
  'rawincident',
  'rawincidentcontent',
  'rawincidentdetails',
  'rawincidentsummary',
  'rawpayload',
  'rawprdacceptance',
  'rawreleaseevidence',
  'rawreleasegate',
  'rawreleasereadiness',
  'rawvalidationoutput',
  'reviewnotes',
  'sourcedocumentbody',
  'validationlog',
]);

const SECRET_LINKAGE_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'bootstraptoken',
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

function assertNoRawLinkageContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawLinkageContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_LINKAGE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw release incident linkage content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_LINKAGE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`release incident linkage secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawLinkageContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawLinkageContent(input ?? {});
  canonicalize(input ?? {});
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

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlc(left, right) {
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
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_release_incident_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'release_incident_linkage_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
  addReason(reasons, hlcTuple(input?.checkedAtHlc) === null, 'checked_at_hlc_invalid');
}

function evaluatePolicy(policy, checkedAtHlc, reasons) {
  const families = sortedTextList(policy?.requiredIncidentFamilies);
  const domains = sortedTextList(policy?.requiredReleaseLinkageDomains);
  const materialFamilies = sortedTextList(policy?.materialIncidentFamilies);

  addReason(reasons, !hasText(policy?.policyRef), 'linkage_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'linkage_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'linkage_policy_not_active');
  addReason(reasons, policy?.metadataOnly !== true, 'linkage_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'linkage_policy_protected_boundary_invalid');
  addReason(reasons, policy?.noProductionTrustClaimWithoutActivation !== true, 'linkage_policy_trust_claim_guard_absent');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'linkage_policy_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, checkedAtHlc), 'linkage_policy_evaluated_after_check');

  evaluateRequiredSet(families, REQUIRED_INCIDENT_FAMILIES, 'policy_incident_family_missing', 'policy_incident_family_unsupported', reasons);
  evaluateRequiredSet(
    domains,
    REQUIRED_RELEASE_LINKAGE_DOMAINS,
    'policy_release_linkage_domain_missing',
    'policy_release_linkage_domain_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    materialFamilies,
    MATERIAL_INCIDENT_FAMILIES,
    'policy_material_incident_family_missing',
    'policy_material_incident_family_unsupported',
    reasons,
  );
}

function evaluateReleaseCycle(cycle, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'release_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseReadinessMatrixRef), 'release_readiness_matrix_ref_absent');
  addReason(reasons, !isDigest(cycle?.releaseReadinessMatrixHash), 'release_readiness_matrix_hash_invalid');
  addReason(reasons, !hasText(cycle?.prdAcceptanceMatrixRef), 'prd_acceptance_matrix_ref_absent');
  addReason(reasons, !isDigest(cycle?.prdAcceptanceMatrixHash), 'prd_acceptance_matrix_hash_invalid');
  addReason(reasons, !hasText(cycle?.policyTraceabilityRegisterRef), 'policy_traceability_register_ref_absent');
  addReason(reasons, !isDigest(cycle?.policyTraceabilityRegisterHash), 'policy_traceability_register_hash_invalid');
  addReason(reasons, !hasText(cycle?.deploymentManifestRef), 'deployment_manifest_ref_absent');
  addReason(reasons, !isDigest(cycle?.deploymentManifestHash), 'deployment_manifest_hash_invalid');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'release_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'release_cycle_protected_boundary_invalid');

  addReason(reasons, hlcTuple(cycle?.openedAtHlc) === null, 'release_cycle_opened_hlc_invalid');
  addReason(reasons, hlcTuple(cycle?.incidentCutoffAtHlc) === null, 'incident_cutoff_hlc_invalid');
  addReason(reasons, hlcTuple(cycle?.linkageCompiledAtHlc) === null, 'release_linkage_compiled_hlc_invalid');
  addReason(reasons, hlcTuple(cycle?.humanReviewedAtHlc) === null, 'human_review_hlc_invalid');
  addReason(reasons, hlcTuple(cycle?.auditRecordedAtHlc) === null, 'audit_recorded_hlc_invalid');
  addReason(reasons, hlcBefore(cycle?.incidentCutoffAtHlc, cycle?.openedAtHlc), 'incident_cutoff_before_release_open');
  addReason(reasons, hlcBefore(cycle?.linkageCompiledAtHlc, cycle?.incidentCutoffAtHlc), 'release_linkage_compiled_before_incident_cutoff');
  addReason(reasons, hlcBefore(cycle?.humanReviewedAtHlc, cycle?.linkageCompiledAtHlc), 'human_review_before_linkage_compiled');
  addReason(reasons, hlcBefore(cycle?.auditRecordedAtHlc, cycle?.humanReviewedAtHlc), 'audit_before_human_review');
}

function isMaterialIncident(incident, materialFamilies) {
  return (
    materialFamilies.includes(incident?.incidentFamily) ||
    incident?.severity === 'critical' ||
    incident?.materialDecisionForumRequired === true ||
    incident?.releaseImpact === 'hold_until_corrective_action_linked'
  );
}

function evaluateIncidentRecord(incident, cycle, materialFamilies, reasons) {
  const incidentRef = hasText(incident?.incidentRef) ? incident.incidentRef : 'unknown';
  const material = isMaterialIncident(incident, materialFamilies);

  addReason(reasons, !hasText(incident?.incidentRef), 'incident_ref_absent');
  addReason(reasons, !REQUIRED_INCIDENT_FAMILIES.includes(incident?.incidentFamily), `incident_family_unsupported:${incidentRef}`);
  addReason(reasons, !INCIDENT_SEVERITIES.has(incident?.severity), `incident_severity_invalid:${incidentRef}`);
  addReason(reasons, !INCIDENT_STATUSES.has(incident?.status), `incident_status_invalid:${incidentRef}`);
  addReason(reasons, !isDigest(incident?.evidenceHash), `incident_evidence_hash_invalid:${incidentRef}`);
  addReason(reasons, !isDigest(incident?.incidentReceiptHash), `incident_receipt_hash_invalid:${incidentRef}`);
  addReason(reasons, incident?.metadataOnly !== true, `incident_metadata_boundary_invalid:${incidentRef}`);
  addReason(reasons, incident?.protectedContentExcluded !== true, `incident_protected_boundary_invalid:${incidentRef}`);
  addReason(reasons, incident?.productionTrustClaim === true, `incident_production_claim_forbidden:${incidentRef}`);
  addReason(reasons, hlcTuple(incident?.detectedAtHlc) === null, `incident_detected_hlc_invalid:${incidentRef}`);
  addReason(reasons, hlcAfter(incident?.detectedAtHlc, cycle?.incidentCutoffAtHlc), `incident_detected_after_cutoff:${incidentRef}`);
  addReason(reasons, !CONTAINMENT_STATUSES.has(incident?.containmentStatus), `incident_containment_status_invalid:${incidentRef}`);
  addReason(reasons, !RESTORATION_STATUSES.has(incident?.restorationStatus), `incident_restoration_status_invalid:${incidentRef}`);
  addReason(reasons, !hasText(incident?.cqiRef), `incident_cqi_linkage_absent:${incidentRef}`);
  addReason(reasons, !hasText(incident?.driftSignalRef), `incident_drift_linkage_absent:${incidentRef}`);
  addReason(reasons, incident?.releaseBlocker === true, `incident_release_blocker_open:${incidentRef}`);

  if (!material) {
    return;
  }

  addReason(reasons, incident?.status !== 'closed_corrective_action_linked', `material_incident_not_closed:${incidentRef}`);
  addReason(reasons, hlcTuple(incident?.closedAtHlc) === null, `material_incident_closure_hlc_invalid:${incidentRef}`);
  addReason(reasons, hlcBefore(incident?.closedAtHlc, incident?.detectedAtHlc), `material_incident_closed_before_detected:${incidentRef}`);
  addReason(reasons, incident?.materialDecisionForumRequired !== true, `material_decision_forum_not_required:${incidentRef}`);
  addReason(reasons, !hasText(incident?.decisionForumMatterRef), `material_decision_forum_matter_missing:${incidentRef}`);
  addReason(reasons, !isDigest(incident?.decisionForumReceiptHash), `material_decision_forum_receipt_missing:${incidentRef}`);
  addReason(reasons, incident?.containmentStatus !== 'contained', `material_incident_not_contained:${incidentRef}`);
  addReason(reasons, incident?.restorationStatus !== 'verified_restored', `material_incident_restoration_unverified:${incidentRef}`);
  addReason(reasons, !hasText(incident?.capaRef), `incident_capa_linkage_absent:${incidentRef}`);
  addReason(reasons, !hasText(incident?.rollbackPathRef), `incident_rollback_path_absent:${incidentRef}`);
}

function evaluateIncidents(input, reasons) {
  const incidents = Array.isArray(input?.incidents) ? input.incidents : [];
  const families = uniqueSorted(incidents.map((incident) => incident?.incidentFamily));
  const materialFamilies = sortedTextList(input?.linkagePolicy?.materialIncidentFamilies);

  addReason(reasons, incidents.length === 0, 'incident_records_absent');
  evaluateRequiredSet(families, REQUIRED_INCIDENT_FAMILIES, 'incident_family_missing', 'incident_family_unsupported', reasons);

  for (const incident of incidents) {
    evaluateIncidentRecord(incident, input?.releaseCycle, materialFamilies, reasons);
  }
}

function evaluateReleaseControls(controls, cycle, reasons) {
  const domains = sortedTextList(controls?.linkageDomainsCovered);
  addReason(reasons, controls === null || controls === undefined, 'release_controls_absent');
  evaluateRequiredSet(
    domains,
    REQUIRED_RELEASE_LINKAGE_DOMAINS,
    'release_linkage_domain_missing',
    'release_linkage_domain_unsupported',
    reasons,
  );
  addReason(reasons, !hasText(controls?.incidentRegisterRef), 'incident_register_ref_absent');
  addReason(reasons, !isDigest(controls?.incidentRegisterHash), 'incident_register_hash_invalid');
  addReason(reasons, controls?.releaseReadinessUpdated !== true, 'release_readiness_update_absent');
  addReason(reasons, controls?.prdAcceptanceUpdated !== true, 'prd_acceptance_update_absent');
  addReason(reasons, controls?.policyTraceabilityUpdated !== true, 'policy_traceability_update_absent');
  addReason(reasons, controls?.deploymentManifestUpdated !== true, 'deployment_manifest_update_absent');
  addReason(reasons, !hasText(controls?.rollbackPathRef), 'release_rollback_path_ref_absent');
  addReason(reasons, !isDigest(controls?.rollbackPathHash), 'release_rollback_path_hash_invalid');
  addReason(reasons, !Array.isArray(controls?.validationCommandRefs) || controls.validationCommandRefs.length === 0, 'validation_commands_absent');
  addReason(
    reasons,
    Array.isArray(controls?.validationCommandRefs) &&
      !controls.validationCommandRefs.includes('node --test tests/release-incident-linkage.test.mjs'),
    'focused_validation_command_absent',
  );
  addReason(
    reasons,
    Array.isArray(controls?.validationCommandRefs) && !controls.validationCommandRefs.includes('npm run quality'),
    'quality_validation_command_absent',
  );
  addReason(reasons, !isDigest(controls?.validationEvidenceHash), 'validation_evidence_hash_invalid');
  addReason(reasons, controls?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, controls?.noExochainSourceModified !== true, 'exochain_source_modification_not_excluded');
  addReason(reasons, controls?.metadataOnly !== true, 'release_controls_metadata_boundary_invalid');
  addReason(reasons, controls?.protectedContentExcluded !== true, 'release_controls_protected_boundary_invalid');
  addReason(reasons, hlcTuple(controls?.updatedAtHlc) === null, 'release_controls_updated_hlc_invalid');
  addReason(reasons, hlcBefore(controls?.updatedAtHlc, cycle?.incidentCutoffAtHlc), 'release_controls_updated_before_incident_cutoff');
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_did_absent');
  addReason(reasons, !Array.isArray(review?.reviewerRoleRefs) || review.reviewerRoleRefs.length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_final_authority_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'human_review_ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_reviewed_hlc_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.linkageCompiledAtHlc), 'human_review_before_linkage_compiled');
}

function evaluateAuditRecord(auditRecord, cycle, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'release_incident_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'release_incident_audit_record_hash_invalid');
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'release_incident_audit_record_hlc_invalid');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.humanReviewedAtHlc), 'release_incident_audit_before_review');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'release_incident_audit_metadata_boundary_invalid');
  addReason(reasons, auditRecord?.includesProtectedContent === true, 'release_incident_audit_protected_content_forbidden');
}

function incidentSummary(incidents, materialFamilies) {
  const materialIncidents = incidents.filter((incident) => isMaterialIncident(incident, materialFamilies));
  const openMaterialIncidents = materialIncidents.filter(
    (incident) =>
      incident?.status !== 'closed_corrective_action_linked' ||
      !hasText(incident?.capaRef) ||
      !hasText(incident?.cqiRef) ||
      !hasText(incident?.driftSignalRef) ||
      incident?.releaseBlocker === true,
  );

  return {
    materialIncidentCount: materialIncidents.length,
    openMaterialIncidentCount: openMaterialIncidents.length,
    blockingIncidentRefs: uniqueSorted(openMaterialIncidents.map((incident) => incident?.incidentRef)),
  };
}

function linkageId(input) {
  return `cmril_${sha256Hex({
    cycleRef: input?.releaseCycle?.cycleRef ?? null,
    incidentRefs: sortedTextList(input?.incidents?.map((incident) => incident?.incidentRef) ?? []),
    releaseCandidateRef: input?.releaseCycle?.releaseCandidateRef ?? null,
  }).slice(0, 32)}`;
}

function buildReleaseIncidentLinkage(input) {
  const incidents = Array.isArray(input.incidents) ? input.incidents : [];
  const materialFamilies = sortedTextList(input.linkagePolicy.materialIncidentFamilies);
  const summary = incidentSummary(incidents, materialFamilies);

  return {
    schema: LINKAGE_SCHEMA,
    releaseIncidentLinkageId: linkageId(input),
    status: input.humanReview.decision,
    tenantId: input.tenantId,
    releaseCandidateRef: input.releaseCycle.releaseCandidateRef,
    releaseCycleRef: input.releaseCycle.cycleRef,
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    aiFinalAuthority: false,
    incidentFamiliesCovered: uniqueSorted(incidents.map((incident) => incident.incidentFamily)),
    releaseLinkageDomainsCovered: sortedTextList(input.releaseControls.linkageDomainsCovered),
    materialIncidentFamilies: materialFamilies,
    materialIncidentCount: summary.materialIncidentCount,
    openMaterialIncidentCount: summary.openMaterialIncidentCount,
    blockingIncidentRefs: summary.blockingIncidentRefs,
    releaseReadinessMatrixRef: input.releaseCycle.releaseReadinessMatrixRef,
    prdAcceptanceMatrixRef: input.releaseCycle.prdAcceptanceMatrixRef,
    policyTraceabilityRegisterRef: input.releaseCycle.policyTraceabilityRegisterRef,
    deploymentManifestRef: input.releaseCycle.deploymentManifestRef,
    incidentRegisterRef: input.releaseControls.incidentRegisterRef,
    rollbackPathRef: input.releaseControls.rollbackPathRef,
    validationCommandRefs: sortedTextList(input.releaseControls.validationCommandRefs),
    humanReviewerDid: input.humanReview.reviewerDid,
    auditRecordRef: input.auditRecord.auditRecordRef,
    checkedAtHlc: input.checkedAtHlc,
    compiledAtHlc: input.releaseCycle.linkageCompiledAtHlc,
  };
}

function buildReceipt(input, linkage) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(linkage),
    artifactType: 'release_incident_linkage_register',
    artifactVersion: `${linkage.releaseCandidateRef}@${linkage.status}`,
    classification: 'release_incident_linkage_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: ['incident_response', 'release_readiness', 'metadata_only'],
    sourceSystem: 'cybermedica.release_incident_linkage',
    tenantId: input.tenantId,
  });
}

export function evaluateReleaseIncidentLinkage(input) {
  assertMetadataOnly(input ?? {});

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.linkagePolicy, input?.checkedAtHlc, reasons);
  evaluateReleaseCycle(input?.releaseCycle, reasons);
  evaluateIncidents(input, reasons);
  evaluateReleaseControls(input?.releaseControls, input?.releaseCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.releaseCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.releaseCycle, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const denialReasons = uniqueReasons(reasons);
  if (denialReasons.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      trustState: 'inactive',
      exochainProductionClaim: false,
      reasons: denialReasons,
      releaseIncidentLinkage: null,
      receipt: null,
    };
  }

  const releaseIncidentLinkage = buildReleaseIncidentLinkage(input);
  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
    reasons: [],
    releaseIncidentLinkage,
    receipt: buildReceipt(input, releaseIncidentLinkage),
  };
}
