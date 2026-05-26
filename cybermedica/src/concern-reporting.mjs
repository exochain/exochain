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
const CONCERN_TYPES = new Set([
  'complaint',
  'consent',
  'data_integrity',
  'ethics',
  'participant_safety',
  'product_handling',
  'quality_system',
  'unauthorized_access',
]);
const IMPACT_LEVELS = new Set(['none', 'minor', 'moderate', 'elevated', 'high', 'critical']);
const CRITICAL_LEVELS = new Set(['high', 'critical']);
const IMPACT_FIELDS = Object.freeze([
  'participantSafetyImpact',
  'ethicalImpact',
  'dataIntegrityImpact',
  'consentImpact',
  'productHandlingImpact',
  'unauthorizedAccessImpact',
]);
const RAW_NARRATIVE_FIELDS = new Set([
  'communicationrecord',
  'correctiveaction',
  'description',
  'finding',
  'findings',
  'investigationnotes',
  'narrative',
  'rawnarrative',
  'sourcebody',
  'sourcetext',
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

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function assertNoRawNarrative(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawNarrative(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_NARRATIVE_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw narrative field is not allowed at ${path}.${key}`);
    }
    assertNoRawNarrative(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawNarrative(input ?? {});
  canonicalize(input ?? {});
}

function hasPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasPermission(input?.authority, 'write'), 'authority_permission_missing');
}

function evaluateReporter(reporter, reasons) {
  addReason(reasons, reporter === null || reporter === undefined, 'reporter_absent');
  addReason(reasons, typeof reporter?.anonymous !== 'boolean', 'reporter_anonymous_flag_invalid');
  addReason(reasons, reporter?.anonymous !== true && !hasText(reporter?.reporterDid), 'reporter_did_absent');
  addReason(reasons, !hasText(reporter?.intakeChannel), 'reporter_intake_channel_absent');
  addReason(reasons, typeof reporter?.notificationPermitted !== 'boolean', 'reporter_notification_flag_invalid');
}

function normalizeReporter(reporter) {
  return {
    anonymous: reporter.anonymous,
    intakeChannel: reporter.intakeChannel,
    notificationPermitted: reporter.notificationPermitted,
    reporterDid: reporter.anonymous ? null : reporter.reporterDid,
  };
}

function evaluateConcern(concern, reasons) {
  addReason(reasons, !hasText(concern?.concernRef), 'concern_ref_absent');
  addReason(reasons, !CONCERN_TYPES.has(concern?.concernType), 'concern_type_invalid');
  addReason(reasons, !hasText(concern?.siteRef), 'concern_site_ref_absent');
  addReason(reasons, !isDigest(concern?.descriptionHash), 'concern_description_hash_invalid');
  addReason(reasons, !hasText(concern?.classification), 'concern_classification_absent');

  for (const field of IMPACT_FIELDS) {
    addReason(reasons, !IMPACT_LEVELS.has(concern?.[field]), 'concern_impact_invalid');
  }
  addReason(reasons, !IMPACT_LEVELS.has(concern?.retaliationRisk), 'concern_impact_invalid');
  addReason(reasons, sortedTextList(concern?.policyRefs).length === 0, 'policy_refs_absent');
}

function normalizeEvidenceRefs(evidenceRefs, reasons) {
  if (!Array.isArray(evidenceRefs) || evidenceRefs.length === 0) {
    reasons.push('evidence_refs_absent');
    return [];
  }

  return evidenceRefs
    .map((evidence) => {
      const invalid =
        !hasText(evidence?.artifactType) ||
        !isDigest(evidence?.artifactHash) ||
        !isDigest(evidence?.custodyDigest) ||
        !hasText(evidence?.receiptId) ||
        !hasText(evidence?.classification);
      addReason(reasons, invalid, 'evidence_ref_invalid');

      return {
        artifactHash: evidence?.artifactHash ?? null,
        artifactType: evidence?.artifactType ?? null,
        classification: evidence?.classification ?? null,
        custodyDigest: evidence?.custodyDigest ?? null,
        receiptId: evidence?.receiptId ?? null,
      };
    })
    .sort((left, right) => `${left.artifactType}:${left.receiptId}`.localeCompare(`${right.artifactType}:${right.receiptId}`));
}

function evaluateInvestigator(investigator, reasons) {
  addReason(reasons, !hasText(investigator?.did), 'investigator_did_absent');
  addReason(reasons, investigator?.kind !== 'human', 'investigator_human_required');
  addReason(reasons, !hasText(investigator?.role), 'investigator_role_absent');
}

function normalizedImpacts(concern) {
  return {
    consentImpact: concern.consentImpact,
    dataIntegrityImpact: concern.dataIntegrityImpact,
    ethicalImpact: concern.ethicalImpact,
    participantSafetyImpact: concern.participantSafetyImpact,
    productHandlingImpact: concern.productHandlingImpact,
    retaliationRisk: concern.retaliationRisk,
    unauthorizedAccessImpact: concern.unauthorizedAccessImpact,
  };
}

function impactIsCritical(value) {
  return CRITICAL_LEVELS.has(value);
}

function requiresImmediateEscalation(concern) {
  return IMPACT_FIELDS.some((field) => impactIsCritical(concern?.[field])) || impactIsCritical(concern?.retaliationRisk);
}

function requiredEscalationRoles(concern, immediateEscalationRequired) {
  const roles = new Set(['site_quality_lead']);
  if (hasText(concern?.participantSafetyImpact) && concern.participantSafetyImpact !== 'none') {
    roles.add('principal_investigator');
  }
  if (
    concern?.concernType === 'ethics' ||
    (hasText(concern?.ethicalImpact) && concern.ethicalImpact !== 'none') ||
    impactIsCritical(concern?.retaliationRisk)
  ) {
    roles.add('ethics_governance_reviewer');
  }
  if (impactIsCritical(concern?.dataIntegrityImpact)) {
    roles.add('data_integrity_officer');
  }
  if (impactIsCritical(concern?.consentImpact)) {
    roles.add('consent_authority_reviewer');
  }
  if (impactIsCritical(concern?.productHandlingImpact)) {
    roles.add('product_accountable_person');
  }
  if (impactIsCritical(concern?.unauthorizedAccessImpact)) {
    roles.add('security_privacy_officer');
  }
  if (immediateEscalationRequired) {
    roles.add('decision_forum');
  }
  return [...roles].sort();
}

function evaluateEscalationRoute(decisionForum, immediateEscalationRequired, reasons) {
  if (!immediateEscalationRequired) {
    return;
  }

  const routeAbsent =
    decisionForum?.linkageRequired !== true ||
    !hasText(decisionForum?.decisionId) ||
    !hasText(decisionForum?.workflowReceiptId);
  addReason(reasons, routeAbsent, 'critical_escalation_route_absent');
}

function concernArtifactHash(input, normalizedReporter, normalizedEvidenceRefs, roles, immediateEscalationRequired) {
  return sha256Hex({
    assignedInvestigator: {
      did: input.assignedInvestigator.did,
      role: input.assignedInvestigator.role,
    },
    concern: {
      classification: input.concern.classification,
      concernRef: input.concern.concernRef,
      concernType: input.concern.concernType,
      descriptionHash: input.concern.descriptionHash,
      impactSummary: normalizedImpacts(input.concern),
      policyRefs: sortedTextList(input.concern.policyRefs),
      protocolRef: input.concern.protocolRef ?? null,
      siteRef: input.concern.siteRef,
    },
    decisionForum: immediateEscalationRequired
      ? {
          decisionId: input.decisionForum.decisionId,
          workflowReceiptId: input.decisionForum.workflowReceiptId,
        }
      : null,
    evidenceRefs: normalizedEvidenceRefs,
    immediateEscalationRequired,
    reportedAtHlc: input.reportedAtHlc,
    reporter: normalizedReporter,
    requiredEscalationRoles: roles,
    tenantId: input.tenantId,
  });
}

function buildReceipt(input, artifactHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'concern_report',
    artifactVersion: `${input.concern.concernRef}@${input.reportedAtHlc.physicalMs}.${input.reportedAtHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.reportedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['concern_reporting', 'metadata_only', 'participant_safety_relevant'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildConcern(input, normalizedReporter, normalizedEvidenceRefs, roles, immediateEscalationRequired, receipt) {
  return {
    schema: 'cybermedica.concern_report.v1',
    concernId: `cmcon_${sha256Hex({
      concernRef: input.concern.concernRef,
      reportedAtHlc: input.reportedAtHlc,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    concernRef: input.concern.concernRef,
    tenantId: input.tenantId,
    siteRef: input.concern.siteRef,
    protocolRef: input.concern.protocolRef ?? null,
    concernType: input.concern.concernType,
    classification: input.concern.classification,
    descriptionHash: input.concern.descriptionHash,
    reporter: normalizedReporter,
    impactSummary: normalizedImpacts(input.concern),
    retaliationRisk: input.concern.retaliationRisk,
    immediateEscalationRequired,
    escalationStatus: immediateEscalationRequired ? 'required_ready' : 'not_required',
    requiredEscalationRoles: roles,
    decisionForumLinkage: immediateEscalationRequired
      ? {
          decisionId: input.decisionForum.decisionId,
          workflowReceiptId: input.decisionForum.workflowReceiptId,
        }
      : null,
    assignedInvestigator: {
      did: input.assignedInvestigator.did,
      kind: 'human',
      role: input.assignedInvestigator.role,
    },
    investigationStatus: 'assigned',
    closureDecision: 'open',
    reporterNotificationStatus: normalizedReporter.notificationPermitted ? 'permitted_pending' : 'not_permitted',
    policyRefs: sortedTextList(input.concern.policyRefs),
    evidenceRefs: normalizedEvidenceRefs,
    evidenceReceiptIds: normalizedEvidenceRefs.map((evidence) => evidence.receiptId).sort(),
    reportedAtHlc: input.reportedAtHlc,
    receiptId: receipt.receiptId,
    operationalStateMutable: true,
    immutableConcernReceipt: true,
    aiFinalAuthority: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function evaluateConcernReport(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateReporter(input?.reporter, reasons);
  evaluateConcern(input?.concern, reasons);
  const normalizedEvidenceRefs = normalizeEvidenceRefs(input?.evidenceRefs, reasons);
  evaluateInvestigator(input?.assignedInvestigator, reasons);
  addReason(reasons, !hlcPresent(input?.reportedAtHlc), 'reported_time_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const immediateEscalationRequired = requiresImmediateEscalation(input?.concern);
  const roles = requiredEscalationRoles(input?.concern, immediateEscalationRequired);
  evaluateEscalationRoute(input?.decisionForum, immediateEscalationRequired, reasons);

  const uniqueReasons = [...new Set(reasons)].sort();
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.concern_report_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      concern: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const normalizedReporter = normalizeReporter(input.reporter);
  const artifactHash = concernArtifactHash(
    input,
    normalizedReporter,
    normalizedEvidenceRefs,
    roles,
    immediateEscalationRequired,
  );
  const receipt = buildReceipt(input, artifactHash);

  return {
    schema: 'cybermedica.concern_report_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    concern: buildConcern(input, normalizedReporter, normalizedEvidenceRefs, roles, immediateEscalationRequired, receipt),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
