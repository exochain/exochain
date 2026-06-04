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
const DRAWER_SCHEMA = 'cybermedica.contextual_manual_drawer.v1';
const DECISION_SCHEMA = 'cybermedica.contextual_manual_drawer_decision.v1';
const REQUIRED_PERMISSION = 'manual_drawer_read';

const REQUIRED_CONTEXT_FAMILIES = Object.freeze([
  'control',
  'dashboard_card',
  'decision_matter',
  'evidence_object',
  'major_page',
  'procedure',
  'workflow',
]);

const REQUIRED_INSTRUCTION_SLOTS = Object.freeze([
  'approval_required',
  'audit_export_result',
  'common_failure_modes',
  'evidence_needed',
  'step_by_step',
  'what_this_is',
  'when_to_use_it',
  'who_owns_it',
]);

const REQUIRED_CROSSLINK_KINDS = Object.freeze([
  'acceptance_test',
  'ai_review_prompt',
  'audit_export',
  'dashboard',
  'decision_forum_escalation',
  'evidence_object',
  'exochain_receipt',
  'open_question',
  'policy',
  'procedure',
  'role_authority',
  'source_control',
  'version_effective_date',
  'workflow',
]);

const ACTIVE_POLICY_STATUSES = new Set(['active']);
const HUMAN_REVIEW_DECISIONS = new Set(['manual_drawer_ready_inactive_trust', 'hold_for_manual_drawer_gap']);

const RAW_MANUAL_DRAWER_FIELDS = new Set([
  'answer',
  'body',
  'content',
  'drawerbody',
  'drawercontent',
  'drawertext',
  'freetext',
  'freetextnote',
  'helpbody',
  'helpcontent',
  'helptext',
  'manualbody',
  'manualcontent',
  'manualsectionbody',
  'manualsectioncontent',
  'manualtext',
  'notes',
  'orientationcopy',
  'rawcontent',
  'rawdrawercontent',
  'rawhelpcontent',
  'rawmanualcontent',
  'rawmanualsection',
  'rawmanualtext',
  'reviewnotes',
  'sectionbody',
  'sectioncontent',
  'sourcedocumentbody',
]);

const SECRET_MANUAL_DRAWER_FIELDS = new Set([
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

function assertNoRawManualDrawerContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawManualDrawerContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_MANUAL_DRAWER_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw manual drawer content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_MANUAL_DRAWER_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`manual drawer secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawManualDrawerContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawManualDrawerContent(input ?? {});
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

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_manual_drawer_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'manual_drawer_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  const contextFamilies = sortedTextList(policy?.requiredContextFamilies);
  const instructionSlots = sortedTextList(policy?.requiredInstructionSlots);
  const crosslinkKinds = sortedTextList(policy?.requiredCrosslinkKinds);

  addReason(reasons, !hasText(policy?.policyRef), 'manual_drawer_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'manual_drawer_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'manual_drawer_policy_not_active');
  addReason(reasons, policy?.roleAwareRequired !== true, 'manual_drawer_role_awareness_required_absent');
  addReason(reasons, policy?.rightSideDrawerRequired !== true, 'right_side_drawer_required_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'manual_drawer_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'manual_drawer_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'manual_drawer_policy_time_invalid');

  evaluateRequiredSet(
    contextFamilies,
    REQUIRED_CONTEXT_FAMILIES,
    'policy_context_family_missing',
    'policy_context_family_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    instructionSlots,
    REQUIRED_INSTRUCTION_SLOTS,
    'policy_instruction_slot_missing',
    'policy_instruction_slot_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    crosslinkKinds,
    REQUIRED_CROSSLINK_KINDS,
    'policy_crosslink_kind_missing',
    'policy_crosslink_kind_unsupported',
    reasons,
  );

  return { contextFamilies, crosslinkKinds, instructionSlots };
}

function evaluateManualIndex(index, policy, reasons) {
  addReason(reasons, !hasText(index?.indexRef), 'manual_index_ref_absent');
  addReason(reasons, !isDigest(index?.currentManualSetHash), 'manual_index_current_set_hash_invalid');
  addReason(reasons, !isDigest(index?.manualIndexHash), 'manual_index_hash_invalid');
  addReason(reasons, !isDigest(index?.documentationRunbookReceiptHash), 'manual_index_runbook_receipt_hash_invalid');
  addReason(reasons, !isDigest(index?.crosslinkMatrixHash), 'manual_index_crosslink_hash_invalid');
  addReason(reasons, !isDigest(index?.versionGovernanceHash), 'manual_index_version_governance_hash_invalid');
  addReason(reasons, !hasText(index?.currentVersionRef), 'manual_index_current_version_absent');
  addReason(reasons, index?.metadataOnly !== true, 'manual_index_metadata_boundary_invalid');
  addReason(reasons, index?.protectedContentExcluded !== true, 'manual_index_protected_boundary_invalid');
  addReason(reasons, hlcTuple(index?.effectiveAtHlc) === null, 'manual_index_effective_time_invalid');
  addReason(reasons, hlcTuple(index?.reviewedAtHlc) === null, 'manual_index_review_time_invalid');
  addReason(reasons, !hlcAfter(index?.effectiveAtHlc, policy?.evaluatedAtHlc), 'manual_index_effective_before_policy');
  addReason(reasons, !hlcAfter(index?.reviewedAtHlc, index?.effectiveAtHlc), 'manual_index_review_before_effective');
}

function evaluateDrawerRequest(request, actor, manualIndex, reasons) {
  const contextFamily = hasText(request?.contextFamily) ? request.contextFamily : 'unknown';
  addReason(reasons, !hasText(request?.requestRef), 'manual_drawer_request_ref_absent');
  addReason(
    reasons,
    hasText(request?.contextFamily) && !REQUIRED_CONTEXT_FAMILIES.includes(request.contextFamily),
    `manual_drawer_context_unsupported:${contextFamily}`,
  );
  addReason(reasons, !hasText(request?.objectType), 'manual_drawer_object_type_absent');
  addReason(reasons, !hasText(request?.objectRef), 'manual_drawer_object_ref_absent');
  addReason(reasons, !hasText(request?.requestedRoleRef), 'manual_drawer_requested_role_absent');
  addReason(
    reasons,
    hasText(request?.requestedRoleRef) &&
      Array.isArray(actor?.roleRefs) &&
      !actor.roleRefs.includes(request.requestedRoleRef),
    'manual_drawer_requested_role_not_actor_role',
  );
  addReason(reasons, request?.metadataOnly !== true, 'manual_drawer_request_metadata_boundary_invalid');
  addReason(reasons, request?.protectedContentExcluded !== true, 'manual_drawer_request_protected_boundary_invalid');
  addReason(reasons, request?.productionTrustClaim === true, 'manual_drawer_request_production_claim_forbidden');
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'manual_drawer_request_time_invalid');
  addReason(reasons, !hlcAfter(request?.requestedAtHlc, manualIndex?.reviewedAtHlc), 'drawer_request_before_manual_index_review');
}

function evaluateDistributionReadiness(readiness, request, manualIndex, reasons) {
  const requiredAcknowledgementRoleRefs = sortedTextList(readiness?.requiredAcknowledgementRoleRefs);
  const acknowledgedRoleRefs = sortedTextList(readiness?.acknowledgedRoleRefs);
  const distributionAt = hlcTuple(readiness?.distributionPublishedAtHlc);
  const requestedRoleRef = request?.requestedRoleRef;

  addReason(reasons, !hasText(readiness?.controlledDocumentDistributionRecordId), 'manual_drawer_distribution_record_absent');
  addReason(
    reasons,
    !isDigest(readiness?.controlledDocumentDistributionReceiptHash),
    'manual_drawer_distribution_receipt_hash_invalid',
  );
  addReason(reasons, !isDigest(readiness?.documentationPublicationReceiptHash), 'manual_drawer_publication_receipt_hash_invalid');
  addReason(reasons, !isDigest(readiness?.manualExportReceiptHash), 'manual_drawer_manual_export_receipt_hash_invalid');
  addReason(
    reasons,
    !isDigest(readiness?.roleManualCoverageReceiptHash),
    'manual_drawer_role_manual_coverage_receipt_hash_invalid',
  );
  addReason(reasons, !isDigest(readiness?.acknowledgementRosterHash), 'manual_drawer_acknowledgement_roster_hash_invalid');
  addReason(
    reasons,
    requiredAcknowledgementRoleRefs.length === 0 || acknowledgedRoleRefs.length === 0,
    'manual_drawer_acknowledgement_roles_missing',
  );
  addReason(
    reasons,
    hasText(requestedRoleRef) && !requiredAcknowledgementRoleRefs.includes(requestedRoleRef),
    `manual_drawer_requested_role_acknowledgement_required:${requestedRoleRef}`,
  );
  addReason(
    reasons,
    hasText(requestedRoleRef) && !acknowledgedRoleRefs.includes(requestedRoleRef),
    `manual_drawer_requested_role_acknowledgement_missing:${requestedRoleRef}`,
  );
  addReason(reasons, readiness?.effectiveUseAcknowledged !== true, 'manual_drawer_effective_use_acknowledgement_absent');
  addReason(reasons, readiness?.currentVersionOnly !== true, 'manual_drawer_current_document_version_boundary_invalid');
  addReason(reasons, readiness?.obsoleteVersionUseBlocked !== true, 'manual_drawer_obsolete_document_boundary_invalid');
  addReason(reasons, readiness?.metadataOnly !== true, 'manual_drawer_distribution_metadata_boundary_invalid');
  addReason(reasons, readiness?.protectedContentExcluded !== true, 'manual_drawer_distribution_protected_boundary_invalid');
  addReason(reasons, readiness?.productionTrustClaim === true, 'manual_drawer_distribution_production_claim_forbidden');
  addReason(reasons, distributionAt === null, 'manual_drawer_distribution_time_invalid');
  addReason(
    reasons,
    distributionAt !== null && !hlcAfter(readiness?.distributionPublishedAtHlc, manualIndex?.reviewedAtHlc),
    'manual_drawer_distribution_before_manual_index_review',
  );
  addReason(
    reasons,
    distributionAt !== null && hlcAfter(readiness?.distributionPublishedAtHlc, request?.requestedAtHlc),
    'manual_drawer_distribution_after_request',
  );

  return {
    acknowledgedRoleRefs,
    acknowledgementRosterHash: readiness?.acknowledgementRosterHash ?? null,
    controlledDocumentDistributionReceiptHash: readiness?.controlledDocumentDistributionReceiptHash ?? null,
    controlledDocumentDistributionRecordId: readiness?.controlledDocumentDistributionRecordId ?? null,
    currentVersionOnly: readiness?.currentVersionOnly === true,
    distributionPublishedAtHlc: readiness?.distributionPublishedAtHlc ?? null,
    documentationPublicationReceiptHash: readiness?.documentationPublicationReceiptHash ?? null,
    effectiveUseAcknowledged: readiness?.effectiveUseAcknowledged === true,
    manualExportReceiptHash: readiness?.manualExportReceiptHash ?? null,
    metadataOnly: readiness?.metadataOnly === true,
    obsoleteVersionUseBlocked: readiness?.obsoleteVersionUseBlocked === true,
    productionTrustClaim: readiness?.productionTrustClaim === true,
    protectedContentExcluded: readiness?.protectedContentExcluded === true,
    requiredAcknowledgementRoleRefs,
    roleManualCoverageReceiptHash: readiness?.roleManualCoverageReceiptHash ?? null,
  };
}

function sectionLabel(section, index) {
  return hasText(section?.sectionRef) ? section.sectionRef : `manual_section_${index}`;
}

function evaluateCrosslinks(section, label, reasons) {
  const rows = Array.isArray(section?.crosslinks) ? [...section.crosslinks] : [];
  const summaries = rows
    .sort((left, right) => String(left?.kind ?? '').localeCompare(String(right?.kind ?? '')))
    .map((link, index) => {
      const kind = hasText(link?.kind) ? link.kind : `unknown_${index}`;
      addReason(reasons, !REQUIRED_CROSSLINK_KINDS.includes(kind), `manual_section_crosslink_unsupported:${label}:${kind}`);
      addReason(reasons, !hasText(link?.targetRef), `manual_section_crosslink_target_absent:${label}:${kind}`);
      addReason(reasons, !isDigest(link?.targetHash), `manual_section_crosslink_hash_invalid:${label}:${kind}`);
      addReason(reasons, link?.metadataOnly !== true, `manual_section_crosslink_metadata_boundary_invalid:${label}:${kind}`);
      addReason(reasons, link?.protectedContentExcluded !== true, `manual_section_crosslink_protected_boundary_invalid:${label}:${kind}`);
      return {
        kind,
        targetHash: link?.targetHash ?? null,
        targetRef: link?.targetRef ?? null,
      };
    });

  const actualKinds = uniqueSorted(summaries.map((link) => link.kind).filter(hasText));
  evaluateRequiredSet(
    actualKinds,
    REQUIRED_CROSSLINK_KINDS,
    `manual_section_crosslink_missing:${label}`,
    `manual_section_crosslink_unsupported:${label}`,
    reasons,
  );

  return { actualKinds, summaries };
}

function evaluateInstructionHashes(section, label, reasons) {
  const instructionHashes = section?.instructionHashes ?? {};
  const actualSlots = uniqueSorted(Object.keys(instructionHashes).filter((slot) => isDigest(instructionHashes[slot])));
  for (const slot of REQUIRED_INSTRUCTION_SLOTS) {
    addReason(reasons, !isDigest(instructionHashes[slot]), `manual_section_instruction_missing:${label}:${slot}`);
  }
  for (const slot of Object.keys(instructionHashes).sort()) {
    addReason(reasons, !REQUIRED_INSTRUCTION_SLOTS.includes(slot), `manual_section_instruction_unsupported:${label}:${slot}`);
  }
  return actualSlots;
}

function evaluateManualSections(sections, request, reasons) {
  const rows = Array.isArray(sections) ? [...sections] : [];
  const byContext = new Map();
  let selected = null;
  const summaries = rows
    .sort((left, right) => String(left?.sectionRef ?? '').localeCompare(String(right?.sectionRef ?? '')))
    .map((section, index) => {
      const label = sectionLabel(section, index);
      const roleScopes = sortedTextList(section?.roleScopes);
      const instructionSlots = evaluateInstructionHashes(section, label, reasons);
      const crosslinkSummary = evaluateCrosslinks(section, label, reasons);

      addReason(reasons, !hasText(section?.sectionRef), `manual_section_ref_absent:${label}`);
      addReason(reasons, !hasText(section?.manualRef), `manual_section_manual_ref_absent:${label}`);
      addReason(reasons, !hasText(section?.manualVersionRef), `manual_section_version_ref_absent:${label}`);
      addReason(
        reasons,
        hasText(section?.contextFamily) && !REQUIRED_CONTEXT_FAMILIES.includes(section.contextFamily),
        `manual_section_context_unsupported:${label}:${section?.contextFamily}`,
      );
      addReason(reasons, !hasText(section?.objectType), `manual_section_object_type_absent:${label}`);
      addReason(reasons, !hasText(section?.objectRef), `manual_section_object_ref_absent:${label}`);
      addReason(reasons, !isDigest(section?.sectionHash), `manual_section_hash_invalid:${label}`);
      addReason(reasons, roleScopes.length === 0, `manual_section_role_scopes_absent:${label}`);
      addReason(reasons, !hasText(section?.ownerRoleRef), `manual_section_owner_role_absent:${label}`);
      addReason(reasons, !isDigest(section?.highLevelOrientationHash), `manual_section_orientation_hash_invalid:${label}`);
      addReason(reasons, section?.reviewedByHuman !== true, `manual_section_human_review_absent:${label}`);
      addReason(reasons, hlcTuple(section?.reviewedAtHlc) === null, `manual_section_review_time_invalid:${label}`);
      addReason(reasons, section?.metadataOnly !== true, `manual_section_metadata_boundary_invalid:${label}`);
      addReason(reasons, section?.protectedContentExcluded !== true, `manual_section_protected_boundary_invalid:${label}`);
      addReason(reasons, section?.productionTrustClaim === true, `manual_section_production_claim_forbidden:${label}`);

      if (hasText(section?.contextFamily)) {
        byContext.set(section.contextFamily, section);
      }
      if (
        section?.contextFamily === request?.contextFamily &&
        section?.objectType === request?.objectType &&
        section?.objectRef === request?.objectRef
      ) {
        selected = {
          crosslinkKinds: crosslinkSummary.actualKinds,
          crosslinks: crosslinkSummary.summaries,
          instructionSlots,
          section,
        };
      }

      return {
        contextFamily: section?.contextFamily ?? null,
        crosslinkKinds: crosslinkSummary.actualKinds,
        instructionSlots,
        manualRef: section?.manualRef ?? null,
        manualVersionRef: section?.manualVersionRef ?? null,
        objectRef: section?.objectRef ?? null,
        objectType: section?.objectType ?? null,
        roleScopes,
        sectionHash: section?.sectionHash ?? null,
        sectionRef: label,
      };
    });

  const actualContextFamilies = uniqueSorted(summaries.map((section) => section.contextFamily).filter(hasText));
  evaluateRequiredSet(
    actualContextFamilies,
    REQUIRED_CONTEXT_FAMILIES,
    'manual_section_context_missing',
    'manual_section_context_unsupported',
    reasons,
  );

  if (selected === null) {
    addReason(reasons, true, 'manual_drawer_section_not_found');
  } else {
    const roleScopes = sortedTextList(selected.section.roleScopes);
    addReason(
      reasons,
      hasText(request?.requestedRoleRef) && !roleScopes.includes(request.requestedRoleRef),
      `manual_section_role_scope_denied:${selected.section.sectionRef}`,
    );
  }

  return { actualContextFamilies, byContext, selected, summaries };
}

function evaluateHumanReview(review, request, reasons) {
  addReason(reasons, !hasText(review?.reviewedByDid), 'manual_drawer_human_reviewer_absent');
  addReason(reasons, review?.status !== 'approved', 'manual_drawer_human_review_not_approved');
  addReason(
    reasons,
    hasText(review?.decision) && !HUMAN_REVIEW_DECISIONS.has(review.decision),
    'manual_drawer_human_review_decision_unsupported',
  );
  addReason(reasons, !hasText(review?.decision), 'manual_drawer_human_review_decision_absent');
  addReason(reasons, review?.humanGate?.verified !== true, 'manual_drawer_human_gate_unverified');
  addReason(reasons, !isDigest(review?.rationaleHash), 'manual_drawer_review_rationale_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'manual_drawer_human_review_time_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, request?.requestedAtHlc), 'manual_drawer_review_before_request');
}

function buildDrawerMaterial(input, selected, sections, distributionReadiness) {
  const selectedSection = selected.section;
  return {
    actorDid: input.actor.did,
    authorityChainHash: input.authority.authorityChainHash,
    availableContextFamilies: sections.actualContextFamilies,
    contextFamily: input.drawerRequest.contextFamily,
    crosslinks: selected.crosslinks,
    distributionReadiness,
    drawerPolicyHash: input.drawerPolicy.policyHash,
    instructionHashes: selectedSection.instructionHashes,
    manualIndexHash: input.manualIndex.manualIndexHash,
    manualRef: selectedSection.manualRef,
    manualSetHash: input.manualIndex.currentManualSetHash,
    manualVersionRef: selectedSection.manualVersionRef,
    objectRef: input.drawerRequest.objectRef,
    objectType: input.drawerRequest.objectType,
    requestedAtHlc: input.drawerRequest.requestedAtHlc,
    requestedRoleRef: input.drawerRequest.requestedRoleRef,
    schema: 'cybermedica.contextual_manual_drawer_material.v1',
    sectionHash: selectedSection.sectionHash,
    sectionRef: selectedSection.sectionRef,
    tenantId: input.tenantId,
  };
}

function buildSelectedSection(input, selected, distributionReadiness) {
  const section = selected.section;
  return {
    schema: 'cybermedica.contextual_manual_drawer_section.v1',
    sectionRef: section.sectionRef,
    manualRef: section.manualRef,
    manualVersionRef: section.manualVersionRef,
    contextFamily: section.contextFamily,
    objectType: section.objectType,
    objectRef: section.objectRef,
    sectionHash: section.sectionHash,
    ownerRoleRef: section.ownerRoleRef,
    roleScopeMatched: input.drawerRequest.requestedRoleRef,
    highLevelOrientationHash: section.highLevelOrientationHash,
    instructionSlots: REQUIRED_INSTRUCTION_SLOTS,
    crosslinkKinds: REQUIRED_CROSSLINK_KINDS,
    crosslinks: selected.crosslinks,
    controlledDocumentDistributionReceiptHash: distributionReadiness.controlledDocumentDistributionReceiptHash,
    controlledDocumentDistributionRecordId: distributionReadiness.controlledDocumentDistributionRecordId,
    documentationPublicationReceiptHash: distributionReadiness.documentationPublicationReceiptHash,
    effectiveUseAcknowledged: distributionReadiness.effectiveUseAcknowledged,
    manualExportReceiptHash: distributionReadiness.manualExportReceiptHash,
    roleManualCoverageReceiptHash: distributionReadiness.roleManualCoverageReceiptHash,
    metadataOnly: true,
    protectedContentExcluded: true,
    rawContentIncluded: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildDrawerView(input, selected, sections, drawerHash, receipt, distributionReadiness) {
  const selectedSection = selected.section;
  return {
    schema: DRAWER_SCHEMA,
    drawerId: `cmdrawer_${sha256Hex({
      drawerHash,
      requestRef: input.drawerRequest.requestRef,
      sectionRef: selectedSection.sectionRef,
    }).slice(0, 32)}`,
    drawerSide: 'right',
    state: 'ready_inactive_trust',
    trustState: 'inactive',
    exochainProductionClaim: false,
    rawContentIncluded: false,
    tenantId: input.tenantId,
    requestRef: input.drawerRequest.requestRef,
    requestedContextFamily: input.drawerRequest.contextFamily,
    requestedObjectType: input.drawerRequest.objectType,
    requestedObjectRef: input.drawerRequest.objectRef,
    requestedRoleRef: input.drawerRequest.requestedRoleRef,
    selectedSectionRef: selectedSection.sectionRef,
    manualRef: selectedSection.manualRef,
    manualVersionRef: selectedSection.manualVersionRef,
    availableContextFamilies: REQUIRED_CONTEXT_FAMILIES,
    instructionSlotCount: REQUIRED_INSTRUCTION_SLOTS.length,
    crosslinkCount: REQUIRED_CROSSLINK_KINDS.length,
    controlledDocumentDistributionReceiptHash: distributionReadiness.controlledDocumentDistributionReceiptHash,
    controlledDocumentDistributionRecordId: distributionReadiness.controlledDocumentDistributionRecordId,
    distributionPublishedAtHlc: distributionReadiness.distributionPublishedAtHlc,
    documentationPublicationReceiptHash: distributionReadiness.documentationPublicationReceiptHash,
    effectiveUseAcknowledged: distributionReadiness.effectiveUseAcknowledged,
    manualExportReceiptHash: distributionReadiness.manualExportReceiptHash,
    roleManualCoverageReceiptHash: distributionReadiness.roleManualCoverageReceiptHash,
    drawerHash,
    receiptId: receipt.receiptId,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md:DOC-001-DOC-004',
      'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

function createDrawerReceipt(input, selected, drawerHash, distributionReadiness) {
  const custodyDigest = sha256Hex({
    authorityChainHash: input.authority.authorityChainHash,
    controlledDocumentDistributionReceiptHash: distributionReadiness.controlledDocumentDistributionReceiptHash,
    documentationRunbookReceiptHash: input.manualIndex.documentationRunbookReceiptHash,
    humanReviewerDid: input.humanReview.reviewedByDid,
    manualIndexHash: input.manualIndex.manualIndexHash,
    roleManualCoverageReceiptHash: distributionReadiness.roleManualCoverageReceiptHash,
    sectionHash: selected.section.sectionHash,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'contextual_manual_drawer',
    artifactVersion: `${input.manualIndex.currentVersionRef}:${selected.section.sectionRef}`,
    artifactHash: drawerHash,
    custodyDigest,
    hlcTimestamp: input.drawerRequest.requestedAtHlc,
    classification: 'metadata_only_documentation_guidance',
    sensitivityTags: [
      'contextual_manual_drawer',
      'controlled_document_distribution_metadata',
      'documentation',
      'inactive_trust_state',
      'manual_export_packet_metadata',
      'metadata_only',
      'role_manual_coverage_metadata',
    ],
    sourceSystem: 'cybermedica-qms-contracts',
  });
}

export function evaluateContextualManualDrawer(input) {
  assertMetadataOnly(input ?? {});

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.drawerPolicy, reasons);
  evaluateManualIndex(input?.manualIndex, input?.drawerPolicy, reasons);
  evaluateDrawerRequest(input?.drawerRequest, input?.actor, input?.manualIndex, reasons);
  const distributionReadiness = evaluateDistributionReadiness(
    input?.distributionReadiness,
    input?.drawerRequest,
    input?.manualIndex,
    reasons,
  );
  const sections = evaluateManualSections(input?.manualSections, input?.drawerRequest, reasons);
  evaluateHumanReview(input?.humanReview, input?.drawerRequest, reasons);

  if (reasons.length > 0 || sections.selected === null) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons(reasons),
      drawerView: null,
      selectedSection: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const drawerHash = sha256Hex(buildDrawerMaterial(input, sections.selected, sections, distributionReadiness));
  const receipt = createDrawerReceipt(input, sections.selected, drawerHash, distributionReadiness);
  const drawerView = buildDrawerView(input, sections.selected, sections, drawerHash, receipt, distributionReadiness);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    drawerView,
    selectedSection: buildSelectedSection(input, sections.selected, distributionReadiness),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
