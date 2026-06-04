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
const DOCUMENTATION_PUBLICATION_SCHEMA = 'cybermedica.documentation_change_publication.v1';
const REQUIRED_PERMISSION = 'documentation_publish';
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const HUMAN_DECISIONS = new Set(['documentation_publication_ready', 'hold_for_documentation_gap']);

const REQUIRED_PUBLICATION_DOMAINS = Object.freeze([
  'audit_trail',
  'change_control',
  'crosslink_refresh',
  'distribution_acknowledgement',
  'draft_review',
  'drift_feedback',
  'manual_versioning',
  'training_update',
]);

const REQUIRED_CHANGE_TYPES = Object.freeze([
  'crosslink_refresh',
  'inspection_guide_update',
  'manual_revision',
  'runbook_update',
  'training_notice',
  'workflow_guide_update',
]);
const REQUIRED_EXPORT_FORMATS = Object.freeze(['markdown', 'pdf', 'print', 'word']);
const REQUIRED_EXPORT_PACKET_SCOPES = Object.freeze([
  'audit_training_packet',
  'role_manual_packet',
  'workflow_manual_packet',
]);
const REQUIRED_ORIENTATION_CITATION_FAMILIES = Object.freeze(['control', 'manual_section', 'procedure']);
const REQUIRED_ORIENTATION_SIGNAL_FAMILIES = Object.freeze([
  'ai_orientation_question',
  'manual_confusion',
  'missing_documentation',
  'product_gap',
]);
const REQUIRED_ORIENTATION_GUIDANCE_LABEL = 'guidance_not_policy_authority';

const RAW_PUBLICATION_FIELDS = new Set([
  'assistantbody',
  'body',
  'changebody',
  'changenarrative',
  'content',
  'draftcontent',
  'exportbody',
  'exportcontent',
  'exportpayload',
  'freetext',
  'freetextnote',
  'manualbody',
  'manualcontent',
  'manualtext',
  'notes',
  'publicationcopy',
  'packetbody',
  'packetcontent',
  'rawassistantcontent',
  'rawchangecontent',
  'rawcontent',
  'rawexportcontent',
  'rawmanualcontent',
  'rawmanualpacket',
  'rawpublicationcontent',
  'rawquery',
  'releasecopy',
  'releasenotesbody',
  'renderedcontent',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
  'trainingbody',
  'trainingcontent',
  'workflowbody',
]);

const SECRET_PUBLICATION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'password',
  'privatekey',
  'railwaytoken',
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

function assertNoRawPublicationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawPublicationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_PUBLICATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw documentation publication content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_PUBLICATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`documentation publication secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawPublicationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawPublicationContent(input ?? {});
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

function missingValues(required, actual) {
  return required.filter((value) => !actual.includes(value));
}

function includesAll(actual, expected) {
  return expected.every((value) => actual.includes(value));
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

function evaluateRequiredSet(actual, required, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of required) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !required.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_documentation_publisher_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'documentation_publish_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  const requiredPublicationDomains = sortedTextList(policy?.requiredPublicationDomains);
  const requiredChangeTypes = sortedTextList(policy?.requiredChangeTypes);

  addReason(reasons, !hasText(policy?.policyRef), 'publication_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'publication_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'publication_policy_not_active');
  addReason(reasons, policy?.humanApprovalRequired !== true, 'human_publication_approval_policy_absent');
  addReason(reasons, policy?.versionGovernanceRequired !== true, 'manual_version_governance_policy_absent');
  addReason(reasons, policy?.crosslinkValidationRequired !== true, 'crosslink_validation_policy_absent');
  addReason(
    reasons,
    policy?.effectiveUseAcknowledgementRequired !== true,
    'effective_use_acknowledgement_policy_absent',
  );
  addReason(reasons, policy?.driftFeedbackRequired !== true, 'drift_feedback_policy_absent');
  addReason(reasons, policy?.aiAssistanceAdvisoryOnly !== true, 'ai_assistance_policy_not_advisory_only');
  addReason(reasons, policy?.metadataOnly !== true, 'publication_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'publication_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'publication_policy_time_invalid');

  evaluateRequiredSet(
    requiredPublicationDomains,
    REQUIRED_PUBLICATION_DOMAINS,
    'policy_publication_domain_missing',
    'policy_publication_domain_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredChangeTypes,
    REQUIRED_CHANGE_TYPES,
    'policy_change_type_missing',
    'policy_change_type_unsupported',
    reasons,
  );
}

function evaluateCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'publication_cycle_ref_absent');
  addReason(reasons, cycle?.metadataOnly !== true, 'publication_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'publication_cycle_protected_boundary_invalid');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['draftReadyAtHlc', cycle?.draftReadyAtHlc],
    ['crosslinksValidatedAtHlc', cycle?.crosslinksValidatedAtHlc],
    ['humanApprovedAtHlc', cycle?.humanApprovedAtHlc],
    ['publishedAtHlc', cycle?.publishedAtHlc],
    ['distributionRecordedAtHlc', cycle?.distributionRecordedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `publication_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'publication_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(
      reasons,
      hlcBefore(currentValue, previousValue),
      `publication_cycle_${currentLabel}_before_${previousLabel}`,
    );
  }
}

function evaluateSourceBacklog(sourceBacklog, cycle, reasons) {
  const acknowledgedRoleRefs = sortedTextList(sourceBacklog?.manualNavigationAcknowledgedRoleRefs);
  const requiredAcknowledgementRoleRefs = sortedTextList(sourceBacklog?.manualNavigationRequiredAcknowledgementRoleRefs);

  addReason(reasons, !isDigest(sourceBacklog?.inquiryCqiBacklogReceiptHash), 'source_backlog_receipt_hash_invalid');
  addReason(reasons, !isDigest(sourceBacklog?.inquiryCqiBacklogDigest), 'source_backlog_digest_invalid');
  addReason(reasons, !isDigest(sourceBacklog?.userAssistanceReceiptHash), 'source_user_assistance_receipt_hash_invalid');
  addReason(
    reasons,
    !isDigest(sourceBacklog?.userAssistanceAnalyticsDigest),
    'source_user_assistance_analytics_digest_invalid',
  );
  addReason(reasons, !isDigest(sourceBacklog?.documentationRunbookReceiptHash), 'source_runbook_receipt_hash_invalid');
  addReason(reasons, !isDigest(sourceBacklog?.currentManualSetHash), 'source_manual_set_hash_invalid');
  addReason(reasons, !isDigest(sourceBacklog?.currentManualIndexHash), 'source_manual_index_hash_invalid');
  addReason(reasons, !isDigest(sourceBacklog?.cqiActionPackageHash), 'source_cqi_action_package_hash_invalid');
  addReason(reasons, !hasText(sourceBacklog?.driftImprovementRef), 'source_drift_improvement_ref_absent');
  addReason(
    reasons,
    !isDigest(sourceBacklog?.contextualManualDrawerReceiptHash),
    'source_manual_navigation_drawer_receipt_hash_invalid',
  );
  addReason(reasons, !isDigest(sourceBacklog?.contextualManualDrawerHash), 'source_manual_navigation_drawer_hash_invalid');
  addReason(
    reasons,
    !isDigest(sourceBacklog?.controlledDocumentDistributionReceiptHash),
    'source_manual_navigation_distribution_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(sourceBacklog?.priorDocumentationPublicationReceiptHash),
    'source_prior_publication_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(sourceBacklog?.manualExportReceiptHash),
    'source_manual_navigation_manual_export_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(sourceBacklog?.roleManualCoverageReceiptHash),
    'source_manual_navigation_role_manual_coverage_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(sourceBacklog?.acknowledgementRosterHash),
    'source_manual_navigation_acknowledgement_roster_hash_invalid',
  );
  addReason(
    reasons,
    acknowledgedRoleRefs.length === 0 || requiredAcknowledgementRoleRefs.length === 0,
    'source_manual_navigation_acknowledgement_roles_absent',
  );
  addReason(
    reasons,
    acknowledgedRoleRefs.length > 0 &&
      requiredAcknowledgementRoleRefs.length > 0 &&
      !includesAll(acknowledgedRoleRefs, requiredAcknowledgementRoleRefs),
    'source_manual_navigation_acknowledgement_incomplete',
  );
  addReason(
    reasons,
    sourceBacklog?.manualNavigationCurrentVersionOnly !== true,
    'source_manual_navigation_current_version_boundary_invalid',
  );
  addReason(
    reasons,
    sourceBacklog?.manualNavigationObsoleteVersionUseBlocked !== true,
    'source_manual_navigation_obsolete_version_boundary_invalid',
  );
  addReason(
    reasons,
    sourceBacklog?.manualNavigationEffectiveUseAcknowledged !== true,
    'source_manual_navigation_effective_use_absent',
  );
  addReason(reasons, sourceBacklog?.noRawInquiryContent !== true, 'source_raw_inquiry_boundary_absent');
  addReason(reasons, hlcTuple(sourceBacklog?.reviewedAtHlc) === null, 'source_backlog_review_time_invalid');
  addReason(reasons, hlcBefore(sourceBacklog?.reviewedAtHlc, cycle?.openedAtHlc), 'source_backlog_review_before_cycle_open');
  addReason(reasons, sourceBacklog?.metadataOnly !== true, 'source_backlog_metadata_boundary_invalid');
  addReason(reasons, sourceBacklog?.protectedContentExcluded !== true, 'source_backlog_protected_boundary_invalid');

  return {
    acknowledgementRosterHash: sourceBacklog?.acknowledgementRosterHash ?? null,
    acknowledgedRoleRefs,
    contextualManualDrawerHash: sourceBacklog?.contextualManualDrawerHash ?? null,
    contextualManualDrawerReceiptHash: sourceBacklog?.contextualManualDrawerReceiptHash ?? null,
    controlledDocumentDistributionReceiptHash: sourceBacklog?.controlledDocumentDistributionReceiptHash ?? null,
    currentVersionOnly: sourceBacklog?.manualNavigationCurrentVersionOnly === true,
    inquiryCqiBacklogDigest: sourceBacklog?.inquiryCqiBacklogDigest ?? null,
    inquiryCqiBacklogReceiptHash: sourceBacklog?.inquiryCqiBacklogReceiptHash ?? null,
    manualExportReceiptHash: sourceBacklog?.manualExportReceiptHash ?? null,
    manualNavigationEffectiveUseAcknowledged: sourceBacklog?.manualNavigationEffectiveUseAcknowledged === true,
    obsoleteVersionUseBlocked: sourceBacklog?.manualNavigationObsoleteVersionUseBlocked === true,
    priorDocumentationPublicationReceiptHash: sourceBacklog?.priorDocumentationPublicationReceiptHash ?? null,
    requiredAcknowledgementRoleRefs,
    roleManualCoverageReceiptHash: sourceBacklog?.roleManualCoverageReceiptHash ?? null,
    userAssistanceAnalyticsDigest: sourceBacklog?.userAssistanceAnalyticsDigest ?? null,
    userAssistanceReceiptHash: sourceBacklog?.userAssistanceReceiptHash ?? null,
  };
}

function evaluatePublicationEvidence(evidence, reasons) {
  const rows = Array.isArray(evidence) ? evidence : [];
  const actualDomains = uniqueSorted(rows.map((row) => row?.domain));
  evaluateRequiredSet(
    actualDomains,
    REQUIRED_PUBLICATION_DOMAINS,
    'publication_domain_missing',
    'publication_domain_unsupported',
    reasons,
  );

  for (const row of rows) {
    const prefix = `publication_evidence_invalid:${row?.domain ?? 'unknown'}`;
    addReason(reasons, !hasText(row?.evidenceRef), `${prefix}:evidence_ref_absent`);
    addReason(reasons, !isDigest(row?.evidenceHash), `${prefix}:evidence_hash_invalid`);
    addReason(reasons, !hasText(row?.ownerRoleRef), `${prefix}:owner_role_absent`);
    addReason(reasons, row?.approved !== true, `${prefix}:not_approved`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `${prefix}:review_time_invalid`);
    addReason(reasons, row?.metadataOnly !== true, `${prefix}:metadata_boundary_invalid`);
    addReason(reasons, row?.protectedContentExcluded !== true, `${prefix}:protected_boundary_invalid`);
  }

  return actualDomains;
}

function evaluateChangeRequests(changeRequests, cycle, reasons) {
  const rows = Array.isArray(changeRequests) ? changeRequests : [];
  const actualChangeTypes = uniqueSorted(rows.map((row) => row?.changeType));
  evaluateRequiredSet(actualChangeTypes, REQUIRED_CHANGE_TYPES, 'change_type_missing', 'change_type_unsupported', reasons);

  for (const row of rows) {
    const prefix = `change_request_invalid:${row?.changeRef ?? 'unknown'}`;
    addReason(reasons, !hasText(row?.changeRef), `${prefix}:change_ref_absent`);
    addReason(reasons, !hasText(row?.sourceBacklogItemRef), `${prefix}:source_backlog_item_ref_absent`);
    addReason(reasons, !hasText(row?.sourceSignalRef), `${prefix}:source_signal_ref_absent`);
    addReason(reasons, !REQUIRED_CHANGE_TYPES.includes(row?.changeType), `${prefix}:change_type_unsupported`);
    addReason(reasons, !isDigest(row?.draftHash), `${prefix}:draft_hash_invalid`);
    addReason(reasons, !isDigest(row?.rationaleHash), `${prefix}:rationale_hash_invalid`);
    addReason(
      reasons,
      !Array.isArray(row?.affectedManualRefs) || row.affectedManualRefs.filter(hasText).length === 0,
      `${prefix}:affected_manual_refs_absent`,
    );
    addReason(
      reasons,
      !Array.isArray(row?.affectedWorkflowRefs) || row.affectedWorkflowRefs.filter(hasText).length === 0,
      `${prefix}:affected_workflow_refs_absent`,
    );
    addReason(reasons, !hasText(row?.ownerRoleRef), `${prefix}:owner_role_absent`);
    addReason(
      reasons,
      row?.changeType === 'training_notice' && row?.requiresTrainingUpdate !== true,
      `${prefix}:training_update_flag_absent`,
    );
    addReason(
      reasons,
      row?.highRiskReviewRequired === true && !isDigest(row?.highRiskReviewHash),
      `${prefix}:high_risk_review_hash_invalid`,
    );
    addReason(reasons, hlcTuple(row?.draftedAtHlc) === null, `${prefix}:draft_time_invalid`);
    addReason(reasons, hlcBefore(row?.draftedAtHlc, cycle?.openedAtHlc), `${prefix}:draft_before_cycle_open`);
    addReason(reasons, row?.metadataOnly !== true, `${prefix}:metadata_boundary_invalid`);
    addReason(reasons, row?.protectedContentExcluded !== true, `${prefix}:protected_boundary_invalid`);
  }

  return {
    actualChangeTypes,
    changeRefs: uniqueSorted(rows.map((row) => row?.changeRef)),
    highRiskChangeRefs: uniqueSorted(
      rows.filter((row) => row?.highRiskReviewRequired === true).map((row) => row?.changeRef),
    ),
  };
}

function evaluateCrosslinkRefresh(refresh, cycle, reasons) {
  addReason(reasons, !hasText(refresh?.matrixRef), 'crosslink_refresh_matrix_ref_absent');
  addReason(reasons, !isDigest(refresh?.matrixHash), 'crosslink_refresh_matrix_hash_invalid');
  addReason(reasons, !isDigest(refresh?.priorMatrixHash), 'crosslink_refresh_prior_matrix_hash_invalid');
  addReason(reasons, refresh?.linksControls !== true, 'crosslink_controls_missing');
  addReason(reasons, refresh?.linksEvidence !== true, 'crosslink_evidence_missing');
  addReason(reasons, refresh?.linksProcedures !== true, 'crosslink_procedures_missing');
  addReason(reasons, refresh?.linksWorkflows !== true, 'crosslink_workflows_missing');
  addReason(reasons, refresh?.linksPolicies !== true, 'crosslink_policies_missing');
  addReason(
    reasons,
    !Number.isSafeInteger(refresh?.brokenLinkCount) || refresh.brokenLinkCount !== 0,
    'crosslink_refresh_has_broken_links',
  );
  addReason(
    reasons,
    !Array.isArray(refresh?.affectedControlRefs) || refresh.affectedControlRefs.filter(hasText).length === 0,
    'crosslink_affected_control_refs_absent',
  );
  addReason(
    reasons,
    !Array.isArray(refresh?.affectedEvidenceRefs) || refresh.affectedEvidenceRefs.filter(hasText).length === 0,
    'crosslink_affected_evidence_refs_absent',
  );
  addReason(reasons, hlcTuple(refresh?.refreshedAtHlc) === null, 'crosslink_refresh_time_invalid');
  addReason(reasons, hlcBefore(refresh?.refreshedAtHlc, cycle?.crosslinksValidatedAtHlc), 'crosslink_refresh_before_cycle_validation');
  addReason(reasons, refresh?.metadataOnly !== true, 'crosslink_refresh_metadata_boundary_invalid');
  addReason(reasons, refresh?.protectedContentExcluded !== true, 'crosslink_refresh_protected_boundary_invalid');
}

function evaluateVersionGovernance(versionGovernance, sourceBacklog, cycle, reasons) {
  addReason(reasons, !isDigest(versionGovernance?.newManualSetHash), 'new_manual_set_hash_invalid');
  addReason(reasons, !isDigest(versionGovernance?.priorManualSetHash), 'prior_manual_set_hash_invalid');
  addReason(
    reasons,
    isDigest(versionGovernance?.priorManualSetHash) &&
      isDigest(sourceBacklog?.currentManualSetHash) &&
      versionGovernance.priorManualSetHash !== sourceBacklog.currentManualSetHash,
    'prior_manual_set_mismatch',
  );
  addReason(reasons, !hasText(versionGovernance?.versionRef), 'manual_version_ref_absent');
  addReason(reasons, !hasText(versionGovernance?.changeControlRef), 'manual_change_control_ref_absent');
  addReason(reasons, versionGovernance?.supersededVersionsRetained !== true, 'manual_superseded_retention_missing');
  addReason(reasons, !hasText(versionGovernance?.rollbackVersionRef), 'manual_rollback_version_ref_absent');
  addReason(reasons, !isDigest(versionGovernance?.rollbackVersionHash), 'manual_rollback_hash_invalid');
  addReason(reasons, !isDigest(versionGovernance?.distributionPlanHash), 'manual_distribution_plan_hash_invalid');
  addReason(
    reasons,
    versionGovernance?.effectiveUseAcknowledgementRequired !== true,
    'manual_effective_use_acknowledgement_missing',
  );
  addReason(reasons, versionGovernance?.approvedByHuman !== true, 'manual_version_human_approval_missing');
  addReason(reasons, hlcTuple(versionGovernance?.approvedAtHlc) === null, 'manual_version_approval_time_invalid');
  addReason(
    reasons,
    !hlcAfter(versionGovernance?.approvedAtHlc, cycle?.crosslinksValidatedAtHlc),
    'manual_version_approval_time_not_after_crosslinks',
  );
  addReason(reasons, versionGovernance?.metadataOnly !== true, 'manual_version_metadata_boundary_invalid');
  addReason(reasons, versionGovernance?.protectedContentExcluded !== true, 'manual_version_protected_boundary_invalid');
}

function evaluatePublicationPackage(pkg, changeRefs, cycle, versionGovernance, reasons) {
  const linkedChangeRefs = sortedTextList(pkg?.linkedChangeRefs);

  addReason(reasons, !hasText(pkg?.packageRef), 'publication_package_ref_absent');
  addReason(reasons, !isDigest(pkg?.publicationArtifactHash), 'publication_artifact_hash_invalid');
  addReason(reasons, !isDigest(pkg?.releaseNotesHash), 'release_notes_hash_invalid');
  addReason(reasons, !isDigest(pkg?.manualIndexHash), 'manual_index_hash_invalid');
  addReason(reasons, !isDigest(pkg?.accessPolicyHash), 'publication_access_policy_hash_invalid');
  addReason(reasons, !isDigest(pkg?.communicationEvidenceHash), 'publication_communication_hash_invalid');
  addReason(reasons, !isDigest(pkg?.staffNotificationHash), 'publication_staff_notification_hash_invalid');
  for (const changeRef of changeRefs) {
    addReason(reasons, !linkedChangeRefs.includes(changeRef), `publication_package_missing_change:${changeRef}`);
  }
  for (const changeRef of linkedChangeRefs) {
    addReason(reasons, !changeRefs.includes(changeRef), `publication_package_unknown_change:${changeRef}`);
  }
  addReason(reasons, hlcTuple(pkg?.publishedAtHlc) === null, 'publication_package_time_invalid');
  addReason(reasons, hlcBefore(pkg?.publishedAtHlc, cycle?.publishedAtHlc), 'publication_package_before_cycle_publication');
  addReason(
    reasons,
    hlcBefore(pkg?.publishedAtHlc, versionGovernance?.approvedAtHlc),
    'publication_package_before_version_approval',
  );
  addReason(reasons, pkg?.metadataOnly !== true, 'publication_package_metadata_boundary_invalid');
  addReason(reasons, pkg?.protectedContentExcluded !== true, 'publication_package_protected_boundary_invalid');
}

function evaluateAcknowledgementPlan(plan, cycle, reasons) {
  addReason(reasons, !hasText(plan?.planRef), 'acknowledgement_plan_ref_absent');
  addReason(
    reasons,
    !Array.isArray(plan?.requiredRoleRefs) || plan.requiredRoleRefs.filter(hasText).length === 0,
    'acknowledgement_required_roles_absent',
  );
  addReason(reasons, !isDigest(plan?.acknowledgementPolicyHash), 'acknowledgement_policy_hash_invalid');
  addReason(reasons, hlcTuple(plan?.dueAtHlc) === null, 'acknowledgement_due_time_invalid');
  addReason(reasons, !hlcAfter(plan?.dueAtHlc, cycle?.distributionRecordedAtHlc), 'acknowledgement_due_not_after_distribution');
  addReason(reasons, plan?.blockedSupersededUse !== true, 'superseded_manual_use_not_blocked');
  addReason(reasons, !isDigest(plan?.staffCommunicationHash), 'acknowledgement_staff_communication_hash_invalid');
  addReason(reasons, hlcTuple(plan?.recordedAtHlc) === null, 'acknowledgement_record_time_invalid');
  addReason(reasons, hlcBefore(plan?.recordedAtHlc, cycle?.distributionRecordedAtHlc), 'acknowledgement_record_before_distribution');
  addReason(reasons, plan?.metadataOnly !== true, 'acknowledgement_plan_metadata_boundary_invalid');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'acknowledgement_plan_protected_boundary_invalid');
}

function evaluateDriftFeedback(feedback, cycle, reasons) {
  addReason(reasons, !hasText(feedback?.driftSignalRef), 'drift_feedback_signal_ref_absent');
  addReason(reasons, !isDigest(feedback?.driftSignalHash), 'drift_feedback_signal_hash_invalid');
  addReason(reasons, feedback?.cqiBacklogUpdated !== true, 'drift_feedback_cqi_backlog_update_missing');
  addReason(reasons, feedback?.runbookIndexUpdated !== true, 'drift_feedback_runbook_index_update_missing');
  addReason(reasons, feedback?.effectivenessReviewScheduled !== true, 'drift_feedback_effectiveness_review_missing');
  addReason(reasons, hlcTuple(feedback?.scheduledReviewAtHlc) === null, 'drift_feedback_review_time_invalid');
  addReason(reasons, !hlcAfter(feedback?.scheduledReviewAtHlc, cycle?.publishedAtHlc), 'drift_feedback_review_not_after_publication');
  addReason(reasons, feedback?.metadataOnly !== true, 'drift_feedback_metadata_boundary_invalid');
  addReason(reasons, feedback?.protectedContentExcluded !== true, 'drift_feedback_protected_boundary_invalid');
}

function evaluateAiAssistant(aiAssistant, cycle, reasons) {
  if (aiAssistant?.used === false) {
    return false;
  }

  addReason(reasons, !hasText(aiAssistant?.assistantRef), 'ai_assistant_ref_absent');
  addReason(reasons, !isDigest(aiAssistant?.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(
    reasons,
    !Array.isArray(aiAssistant?.limitationHashes) || !aiAssistant.limitationHashes.every(isDigest),
    'ai_limitation_hashes_invalid',
  );
  addReason(reasons, aiAssistant?.advisoryOnly !== true, 'ai_assistant_not_advisory_only');
  addReason(reasons, aiAssistant?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistant?.humanReviewed !== true, 'ai_human_review_missing');
  addReason(reasons, hlcTuple(aiAssistant?.reviewedAtHlc) === null, 'ai_review_time_invalid');
  addReason(reasons, hlcBefore(aiAssistant?.reviewedAtHlc, cycle?.draftReadyAtHlc), 'ai_review_before_draft_ready');
  addReason(reasons, aiAssistant?.metadataOnly !== true, 'ai_assistant_metadata_boundary_invalid');
  addReason(reasons, aiAssistant?.protectedContentExcluded !== true, 'ai_assistant_protected_boundary_invalid');

  return true;
}

function evaluateManualExportReadiness(readiness, versionGovernance, publicationPackage, aiAssistant, reasons) {
  const exportFormats = sortedTextList(readiness?.exportFormats);
  const packetScopes = sortedTextList(readiness?.packetScopes);
  const orientationCitationFamilies = sortedTextList(readiness?.orientationCitationFamilies);
  const orientationConfusionSignalFamilies = sortedTextList(readiness?.orientationConfusionSignalFamilies);
  const roleRefs = sortedTextList(readiness?.roleRefs);
  const workflowRefs = sortedTextList(readiness?.workflowRefs);

  addReason(reasons, !hasText(readiness?.exportPacketRef), 'manual_export_packet_ref_absent');
  addReason(reasons, !isDigest(readiness?.manualExportReceiptHash), 'manual_export_receipt_hash_invalid');
  addReason(reasons, !isDigest(readiness?.manualExportPacketHash), 'manual_export_packet_hash_invalid');
  addReason(reasons, !isDigest(readiness?.sourceManualSetHash), 'manual_export_source_manual_set_hash_invalid');
  addReason(reasons, !isDigest(readiness?.sourceManualIndexHash), 'manual_export_source_manual_index_hash_invalid');
  addReason(
    reasons,
    !isDigest(readiness?.roleManualCoverageReceiptHash),
    'manual_export_role_manual_coverage_receipt_hash_invalid',
  );
  addReason(
    reasons,
    isDigest(readiness?.sourceManualSetHash) &&
      isDigest(versionGovernance?.newManualSetHash) &&
      readiness.sourceManualSetHash !== versionGovernance.newManualSetHash,
    'manual_export_manual_set_mismatch',
  );
  addReason(
    reasons,
    isDigest(readiness?.sourceManualIndexHash) &&
      isDigest(publicationPackage?.manualIndexHash) &&
      readiness.sourceManualIndexHash !== publicationPackage.manualIndexHash,
    'manual_export_manual_index_mismatch',
  );
  addReason(
    reasons,
    !isDigest(readiness?.orientationAssistantReceiptHash),
    'manual_export_orientation_receipt_hash_invalid',
  );
  addReason(reasons, !isDigest(readiness?.orientationRecordHash), 'manual_export_orientation_record_hash_invalid');
  addReason(
    reasons,
    aiAssistant?.used !== false &&
      isDigest(readiness?.orientationAssistantReceiptHash) &&
      hasText(aiAssistant?.orientationReceiptHash) &&
      readiness.orientationAssistantReceiptHash !== aiAssistant.orientationReceiptHash,
    'manual_export_orientation_receipt_mismatch',
  );
  addReason(
    reasons,
    readiness?.orientationGuidanceLabel !== REQUIRED_ORIENTATION_GUIDANCE_LABEL,
    'manual_export_orientation_guidance_label_invalid',
  );
  evaluateRequiredSet(
    orientationCitationFamilies,
    REQUIRED_ORIENTATION_CITATION_FAMILIES,
    'manual_export_orientation_citation_family_missing',
    'manual_export_orientation_citation_family_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    orientationConfusionSignalFamilies,
    REQUIRED_ORIENTATION_SIGNAL_FAMILIES,
    'manual_export_orientation_signal_family_missing',
    'manual_export_orientation_signal_family_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    exportFormats,
    REQUIRED_EXPORT_FORMATS,
    'manual_export_format_missing',
    'manual_export_format_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    packetScopes,
    REQUIRED_EXPORT_PACKET_SCOPES,
    'manual_export_packet_scope_missing',
    'manual_export_packet_scope_unsupported',
    reasons,
  );
  addReason(reasons, roleRefs.length === 0, 'manual_export_roles_absent');
  addReason(reasons, workflowRefs.length === 0, 'manual_export_workflows_absent');
  addReason(reasons, !isDigest(readiness?.exportPolicyHash), 'manual_export_policy_hash_invalid');
  addReason(reasons, !isDigest(readiness?.boundaryAttestationHash), 'manual_export_boundary_hash_invalid');
  addReason(reasons, readiness?.humanAuthorized !== true, 'manual_export_human_authorization_absent');
  addReason(reasons, readiness?.noRawManualContent !== true, 'manual_export_raw_manual_boundary_absent');
  addReason(reasons, readiness?.noUnapprovedClaims !== true, 'manual_export_claim_review_boundary_absent');
  addReason(reasons, readiness?.metadataOnly !== true, 'manual_export_metadata_boundary_invalid');
  addReason(reasons, readiness?.protectedContentExcluded !== true, 'manual_export_protected_boundary_invalid');
  addReason(reasons, readiness?.noProductionTrustClaim !== true, 'manual_export_production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(readiness?.readyAtHlc) === null, 'manual_export_ready_time_invalid');
  addReason(
    reasons,
    hlcBefore(readiness?.readyAtHlc, publicationPackage?.publishedAtHlc),
    'manual_export_ready_before_publication',
  );

  return {
    exportFormats,
    packetScopes,
    orientationCitationFamilies,
    orientationConfusionSignalFamilies,
    roleRefs,
    workflowRefs,
  };
}

function evaluateSourceBacklogManualNavigationLinkage(sourceSummary, manualExportReadiness, reasons) {
  addReason(
    reasons,
    isDigest(sourceSummary.manualExportReceiptHash) &&
      isDigest(manualExportReadiness?.manualExportReceiptHash) &&
      sourceSummary.manualExportReceiptHash !== manualExportReadiness.manualExportReceiptHash,
    'source_manual_export_receipt_mismatch',
  );
  addReason(
    reasons,
    isDigest(sourceSummary.roleManualCoverageReceiptHash) &&
      isDigest(manualExportReadiness?.roleManualCoverageReceiptHash) &&
      sourceSummary.roleManualCoverageReceiptHash !== manualExportReadiness.roleManualCoverageReceiptHash,
    'source_role_manual_coverage_receipt_mismatch',
  );
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(
    reasons,
    !Array.isArray(review?.reviewerRoleRefs) || review.reviewerRoleRefs.filter(hasText).length === 0,
    'human_review_roles_absent',
  );
  addReason(reasons, !HUMAN_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_missing');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, cycle?.crosslinksValidatedAtHlc), 'human_review_time_not_after_crosslinks');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_review_protected_boundary_invalid');
}

function evaluateValidationEvidence(validationEvidence, cycle, reasons) {
  addReason(
    reasons,
    !Array.isArray(validationEvidence?.commandRefs) || validationEvidence.commandRefs.filter(hasText).length === 0,
    'validation_command_refs_absent',
  );
  addReason(reasons, validationEvidence?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, validationEvidence?.sourceGuardPassed !== true, 'validation_source_guard_not_passed');
  addReason(reasons, validationEvidence?.noExochainSourceModified !== true, 'exochain_source_modification_forbidden');
  addReason(reasons, hlcTuple(validationEvidence?.recordedAtHlc) === null, 'validation_record_time_invalid');
  addReason(reasons, hlcBefore(validationEvidence?.recordedAtHlc, cycle?.auditRecordedAtHlc), 'validation_record_before_audit');
  addReason(reasons, validationEvidence?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
}

function createPublicationDigest(input, publicationDomains, changeTypes) {
  return sha256Hex({
    schema: DOCUMENTATION_PUBLICATION_SCHEMA,
    tenantId: input?.tenantId ?? null,
    cycleRef: input?.publicationCycle?.cycleRef ?? null,
    publicationDomains,
    changeTypes,
    sourceBacklogReceiptHash: input?.sourceBacklog?.inquiryCqiBacklogReceiptHash ?? null,
    sourceBacklogDigest: input?.sourceBacklog?.inquiryCqiBacklogDigest ?? null,
    userAssistanceReceiptHash: input?.sourceBacklog?.userAssistanceReceiptHash ?? null,
    userAssistanceAnalyticsDigest: input?.sourceBacklog?.userAssistanceAnalyticsDigest ?? null,
    contextualManualDrawerReceiptHash: input?.sourceBacklog?.contextualManualDrawerReceiptHash ?? null,
    controlledDocumentDistributionReceiptHash:
      input?.sourceBacklog?.controlledDocumentDistributionReceiptHash ?? null,
    priorDocumentationPublicationReceiptHash: input?.sourceBacklog?.priorDocumentationPublicationReceiptHash ?? null,
    crosslinkMatrixHash: input?.crosslinkRefresh?.matrixHash ?? null,
    newManualSetHash: input?.versionGovernance?.newManualSetHash ?? null,
    publicationArtifactHash: input?.publicationPackage?.publicationArtifactHash ?? null,
    manualIndexHash: input?.publicationPackage?.manualIndexHash ?? null,
    manualExportReceiptHash: input?.manualExportReadiness?.manualExportReceiptHash ?? null,
    manualExportPacketHash: input?.manualExportReadiness?.manualExportPacketHash ?? null,
    roleManualCoverageReceiptHash: input?.manualExportReadiness?.roleManualCoverageReceiptHash ?? null,
    orientationAssistantReceiptHash: input?.manualExportReadiness?.orientationAssistantReceiptHash ?? null,
    driftSignalHash: input?.driftFeedback?.driftSignalHash ?? null,
  });
}

function createPublicationSummary(
  input,
  reasons,
  publicationDomains,
  changeTypes,
  highRiskChangeRefs,
  aiAssistanceUsed,
  sourceBacklogSummary,
  manualExportReadiness,
  digest,
) {
  return {
    schema: DOCUMENTATION_PUBLICATION_SCHEMA,
    ready: reasons.length === 0,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    documentationPublicationDigest: digest,
    publicationDomains,
    missingPublicationDomains: missingValues(REQUIRED_PUBLICATION_DOMAINS, publicationDomains),
    changeTypes,
    missingChangeTypes: missingValues(REQUIRED_CHANGE_TYPES, changeTypes),
    changeCount: Array.isArray(input?.changeRequests) ? input.changeRequests.length : 0,
    highRiskChangeRefs,
    crosslinkRefreshReady: reasons.length === 0 && isDigest(input?.crosslinkRefresh?.matrixHash),
    distributionReady: reasons.length === 0 && input?.acknowledgementPlan?.blockedSupersededUse === true,
    driftFeedbackReady: reasons.length === 0 && input?.driftFeedback?.cqiBacklogUpdated === true,
    aiAssistanceUsed,
    manualExportReady: reasons.length === 0,
    inquiryCqiBacklogReceiptHash: sourceBacklogSummary.inquiryCqiBacklogReceiptHash,
    inquiryCqiBacklogDigest: sourceBacklogSummary.inquiryCqiBacklogDigest,
    userAssistanceReceiptHash: sourceBacklogSummary.userAssistanceReceiptHash,
    userAssistanceAnalyticsDigest: sourceBacklogSummary.userAssistanceAnalyticsDigest,
    contextualManualDrawerHash: sourceBacklogSummary.contextualManualDrawerHash,
    contextualManualDrawerReceiptHash: sourceBacklogSummary.contextualManualDrawerReceiptHash,
    controlledDocumentDistributionReceiptHash: sourceBacklogSummary.controlledDocumentDistributionReceiptHash,
    priorDocumentationPublicationReceiptHash: sourceBacklogSummary.priorDocumentationPublicationReceiptHash,
    sourceBacklogManualNavigationAcknowledgedRoleRefs: sourceBacklogSummary.acknowledgedRoleRefs,
    sourceBacklogManualNavigationRequiredAcknowledgementRoleRefs:
      sourceBacklogSummary.requiredAcknowledgementRoleRefs,
    sourceBacklogManualNavigationCurrentVersionOnly: sourceBacklogSummary.currentVersionOnly,
    sourceBacklogManualNavigationObsoleteVersionUseBlocked: sourceBacklogSummary.obsoleteVersionUseBlocked,
    sourceBacklogManualNavigationEffectiveUseAcknowledged:
      sourceBacklogSummary.manualNavigationEffectiveUseAcknowledged,
    manualExportReceiptHash: input?.manualExportReadiness?.manualExportReceiptHash ?? null,
    manualExportPacketHash: input?.manualExportReadiness?.manualExportPacketHash ?? null,
    roleManualCoverageReceiptHash: input?.manualExportReadiness?.roleManualCoverageReceiptHash ?? null,
    manualExportFormats: manualExportReadiness.exportFormats,
    manualExportPacketScopes: manualExportReadiness.packetScopes,
    manualExportRoleRefs: manualExportReadiness.roleRefs,
    manualExportWorkflowRefs: manualExportReadiness.workflowRefs,
    orientationAssistantReceiptHash: input?.manualExportReadiness?.orientationAssistantReceiptHash ?? null,
    orientationCitationFamilies: manualExportReadiness.orientationCitationFamilies,
    orientationConfusionSignalFamilies: manualExportReadiness.orientationConfusionSignalFamilies,
    manualSetHash: input?.versionGovernance?.newManualSetHash ?? null,
    publicationPackageRef: input?.publicationPackage?.packageRef ?? null,
    sourceEvidence: [
      'cyber_medica_qms_prd_master.md',
      'README.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

export function evaluateDocumentationChangePublication(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.publicationPolicy, reasons);
  evaluateCycle(input?.publicationCycle, input?.publicationPolicy, reasons);
  const sourceBacklogSummary = evaluateSourceBacklog(input?.sourceBacklog, input?.publicationCycle, reasons);
  const publicationDomains = evaluatePublicationEvidence(input?.publicationEvidence, reasons);
  const { actualChangeTypes, changeRefs, highRiskChangeRefs } = evaluateChangeRequests(
    input?.changeRequests,
    input?.publicationCycle,
    reasons,
  );
  evaluateCrosslinkRefresh(input?.crosslinkRefresh, input?.publicationCycle, reasons);
  evaluateVersionGovernance(input?.versionGovernance, input?.sourceBacklog, input?.publicationCycle, reasons);
  evaluatePublicationPackage(
    input?.publicationPackage,
    changeRefs,
    input?.publicationCycle,
    input?.versionGovernance,
    reasons,
  );
  evaluateAcknowledgementPlan(input?.acknowledgementPlan, input?.publicationCycle, reasons);
  evaluateDriftFeedback(input?.driftFeedback, input?.publicationCycle, reasons);
  const aiAssistanceUsed = evaluateAiAssistant(input?.aiAssistant, input?.publicationCycle, reasons);
  const manualExportReadiness = evaluateManualExportReadiness(
    input?.manualExportReadiness,
    input?.versionGovernance,
    input?.publicationPackage,
    input?.aiAssistant,
    reasons,
  );
  evaluateSourceBacklogManualNavigationLinkage(sourceBacklogSummary, input?.manualExportReadiness, reasons);
  evaluateHumanReview(input?.humanReview, input?.publicationCycle, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.publicationCycle, reasons);

  const finalReasons = uniqueReasons(reasons);
  const publicationDigest = createPublicationDigest(input, publicationDomains, actualChangeTypes);
  const documentationPublication = createPublicationSummary(
    input,
    finalReasons,
    publicationDomains,
    actualChangeTypes,
    highRiskChangeRefs,
    aiAssistanceUsed,
    sourceBacklogSummary,
    manualExportReadiness,
    publicationDigest,
  );

  if (finalReasons.length > 0) {
    return {
      schema: DOCUMENTATION_PUBLICATION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: finalReasons,
      documentationPublication,
      receipt: null,
    };
  }

  const receipt = createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'documentation_change_publication',
    artifactVersion: input.publicationCycle.cycleRef,
    artifactHash: publicationDigest,
    classification: 'metadata_only_documentation_publication',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.publicationCycle.publishedAtHlc,
    sensitivityTags: [
      'documentation_metadata',
      'manual_export_packet_metadata',
      'manual_navigation_readiness',
      'manual_publication_metadata',
      'no_raw_content',
      'orientation_guidance_metadata',
      'role_manual_coverage_metadata',
    ],
    sourceSystem: 'cybermedica',
  });

  return {
    schema: DOCUMENTATION_PUBLICATION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    documentationPublication,
    receipt,
  };
}
