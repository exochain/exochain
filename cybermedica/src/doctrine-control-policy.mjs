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
const DOCTRINE_CONTROL_SCHEMA = 'cybermedica.doctrine_control_policy.v1';
const REQUIRED_PERMISSION = 'doctrine_governance';
const DECISION_READY = 'doctrine_policy_ready';
const DECISION_HOLD = 'hold_for_doctrine_gap';

const REQUIRED_DOCTRINE_DECISIONS = Object.freeze([
  'ai_non_final_authority_rules',
  'non_negotiable_doctrine_statements',
  'participant_protection_data_integrity_gates',
  'privacy_preserving_exochain_receipt_policy',
  'sponsor_cro_visibility_defaults',
]);

const REQUIRED_OPERATING_RULES = Object.freeze([
  'access_defaults_to_deny',
  'ai_assists_never_authorizes',
  'contestability_and_recourse',
  'data_integrity_non_negotiable',
  'delegation_valid_scoped_trained_time_bound_revocable',
  'evidence_before_assertion',
  'exochain_receipts_preserve_proof_without_exposure',
  'human_authority_explicit',
  'participant_protection_paramount',
  'standards_become_controls',
]);

const REGULATED_AI_ACTIONS = Object.freeze([
  'capa_closure',
  'clinical_trial_product_release',
  'consent',
  'deviation_closure',
  'enrollment',
  'ethics_approval',
  'launch',
  'participant_affecting_decision',
  'protocol_amendment_approval',
  'risk_acceptance',
]);

const REQUIRED_GATE_FAMILIES = Object.freeze([
  'alcoac_records',
  'authority_chain',
  'consent_status',
  'data_correction_control',
  'evidence_traceability',
  'participant_rights',
  'privacy_boundary',
  'protocol_conformance',
]);

const REQUIRED_ACTIVATION_GATES = Object.freeze(['PTAG-001', 'PTAG-005', 'PTAG-009', 'PTAG-010']);
const ALLOWED_BOB_ESCALATIONS = Object.freeze([
  'ESC-CONSENT-LEGAL',
  'ESC-ROLE-MATRIX',
]);

const POLICY_STATUSES = new Set(['active']);
const APPROVED_STATUSES = new Set(['approved']);
const HUMAN_REVIEW_DECISIONS = new Set([DECISION_READY, DECISION_HOLD]);
const SAFE_VISIBILITY_VALUES = new Set(['limited', 'none', 'not_applicable', 'role_scoped']);
const SAFE_DIRECT_IDENTIFIER_VALUES = new Set(['blocked', 'not_applicable', 'suppressed']);
const SAFE_PARTICIPANT_LINKED_VALUES = new Set(['coded_metadata_only', 'not_participant_linked', 'none']);
const SAFE_EXPORT_VALUES = new Set(['deny_by_default', 'explicit_human_authorization', 'not_applicable']);

const RAW_DOCTRINE_FIELDS = new Set([
  'body',
  'content',
  'doctrinebody',
  'doctrinenarrative',
  'freetext',
  'policynarrative',
  'rawdoctrine',
  'rawdoctrinebody',
  'rawdoctrinecontent',
  'rawpolicy',
  'rawpolicybody',
  'rawrequirements',
  'rawsourcecontent',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_DOCTRINE_FIELDS = new Set([
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

function assertNoRawDoctrineContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDoctrineContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_DOCTRINE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw doctrine policy field is not allowed at ${path}.${key}`);
    }
    if (SECRET_DOCTRINE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`doctrine policy secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawDoctrineContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDoctrineContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function sortedDigestList(value) {
  return Array.isArray(value) ? uniqueSorted(value.filter(isDigest)) : [];
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_doctrine_reviewer_required');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, hlcTuple(input?.requestedAtHlc) === null, 'requested_time_invalid');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'doctrine_governance_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateDoctrinePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'doctrine_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'doctrine_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'doctrine_policy_not_active');
  addReason(reasons, policy?.metadataOnly !== true, 'doctrine_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'doctrine_policy_evaluation_time_invalid');

  const requiredDoctrineDecisions = sortedTextList(policy?.requiredDoctrineDecisions);
  const requiredOperatingRules = sortedTextList(policy?.requiredOperatingRules);
  const activationGateIds = sortedTextList(policy?.activationGateIds);
  const allowedBobEscalationIds = sortedTextList(policy?.allowedBobEscalationIds);

  for (const decisionType of REQUIRED_DOCTRINE_DECISIONS) {
    addReason(
      reasons,
      !requiredDoctrineDecisions.includes(decisionType),
      `doctrine_policy_required_decision_missing:${decisionType}`,
    );
  }
  for (const ruleRef of REQUIRED_OPERATING_RULES) {
    addReason(reasons, !requiredOperatingRules.includes(ruleRef), `doctrine_policy_required_rule_missing:${ruleRef}`);
  }
  for (const gateId of REQUIRED_ACTIVATION_GATES) {
    addReason(reasons, !activationGateIds.includes(gateId), `activation_gate_missing:${gateId}`);
  }
  for (const escalationId of allowedBobEscalationIds) {
    addReason(
      reasons,
      !ALLOWED_BOB_ESCALATIONS.includes(escalationId),
      `bob_escalation_not_allowed:${escalationId}`,
    );
  }
  return {
    activationGateIds,
    allowedBobEscalationIds,
    evaluatedAtHlc: policy?.evaluatedAtHlc ?? null,
    policyRef: policy?.policyRef ?? null,
    requiredDoctrineDecisions,
    requiredOperatingRules,
  };
}

function evaluateDoctrineDecisions(decisions, policySummary, reasons) {
  if (!Array.isArray(decisions) || decisions.length === 0) {
    reasons.push('doctrine_decisions_absent');
    return [];
  }

  const seenRefs = new Set();
  const covered = [];
  for (const decision of decisions) {
    const label = decision?.decisionRef ?? 'unknown';
    addReason(reasons, !hasText(decision?.decisionRef), `doctrine_decision_ref_absent:${label}`);
    addReason(reasons, seenRefs.has(decision?.decisionRef), `doctrine_decision_ref_duplicate:${label}`);
    seenRefs.add(decision?.decisionRef);
    addReason(
      reasons,
      !REQUIRED_DOCTRINE_DECISIONS.includes(decision?.decisionType),
      `doctrine_decision_type_unsupported:${label}`,
    );
    addReason(reasons, !APPROVED_STATUSES.has(decision?.status), `doctrine_decision_not_approved:${label}`);
    addReason(reasons, !hasText(decision?.ownerRole), `doctrine_decision_owner_absent:${label}`);
    addReason(reasons, !isDigest(decision?.evidenceHash), `doctrine_decision_evidence_hash_invalid:${label}`);
    addReason(reasons, !hasText(decision?.decisionForumRef), `doctrine_decision_forum_ref_absent:${label}`);
    addReason(reasons, hlcTuple(decision?.approvedAtHlc) === null, `doctrine_decision_approval_time_invalid:${label}`);
    addReason(reasons, decision?.metadataOnly !== true, `doctrine_decision_metadata_boundary_invalid:${label}`);
    addReason(reasons, decision?.protectedContentExcluded !== true, `doctrine_decision_protected_boundary_invalid:${label}`);
    addReason(
      reasons,
      hlcBefore(decision?.approvedAtHlc, policySummary.evaluatedAtHlc),
      `doctrine_decision_before_policy_evaluation:${label}`,
    );
    if (REQUIRED_DOCTRINE_DECISIONS.includes(decision?.decisionType)) {
      covered.push(decision.decisionType);
    }
  }

  const normalizedCovered = uniqueSorted(covered);
  for (const decisionType of REQUIRED_DOCTRINE_DECISIONS) {
    addReason(reasons, !normalizedCovered.includes(decisionType), `doctrine_decision_missing:${decisionType}`);
  }
  return normalizedCovered;
}

function evaluateOperatingRules(rules, policySummary, reasons) {
  if (!Array.isArray(rules) || rules.length === 0) {
    reasons.push('operating_rules_absent');
    return [];
  }

  const seenRefs = new Set();
  const covered = [];
  for (const rule of rules) {
    const label = rule?.ruleRef ?? 'unknown';
    addReason(reasons, !hasText(rule?.ruleRef), `operating_rule_ref_absent:${label}`);
    addReason(reasons, seenRefs.has(rule?.ruleRef), `operating_rule_ref_duplicate:${label}`);
    seenRefs.add(rule?.ruleRef);
    addReason(reasons, !REQUIRED_OPERATING_RULES.includes(rule?.ruleRef), `operating_rule_unsupported:${label}`);
    addReason(reasons, !APPROVED_STATUSES.has(rule?.status), `operating_rule_not_approved:${label}`);
    addReason(reasons, rule?.priority !== 'required', `operating_rule_priority_invalid:${label}`);
    addReason(reasons, !hasText(rule?.sourceRequirementRef), `operating_rule_source_ref_absent:${label}`);
    addReason(reasons, !isDigest(rule?.evidenceHash), `operating_rule_evidence_hash_invalid:${label}`);
    addReason(reasons, !hasText(rule?.ownerRole), `operating_rule_owner_absent:${label}`);
    addReason(reasons, hlcTuple(rule?.reviewedAtHlc) === null, `operating_rule_review_time_invalid:${label}`);
    addReason(reasons, rule?.metadataOnly !== true, `operating_rule_metadata_boundary_invalid:${label}`);
    addReason(reasons, rule?.protectedContentExcluded !== true, `operating_rule_protected_boundary_invalid:${label}`);
    addReason(
      reasons,
      hlcBefore(rule?.reviewedAtHlc, policySummary.evaluatedAtHlc),
      `operating_rule_before_policy_evaluation:${label}`,
    );
    if (REQUIRED_OPERATING_RULES.includes(rule?.ruleRef)) {
      covered.push(rule.ruleRef);
    }
  }

  const normalizedCovered = uniqueSorted(covered);
  for (const ruleRef of REQUIRED_OPERATING_RULES) {
    addReason(reasons, !normalizedCovered.includes(ruleRef), `operating_rule_missing:${ruleRef}`);
  }
  return normalizedCovered;
}

function evaluateAiNonFinalAuthorityPolicy(aiPolicy, policySummary, reasons) {
  addReason(reasons, !hasText(aiPolicy?.policyRef), 'ai_policy_ref_absent');
  addReason(reasons, !isDigest(aiPolicy?.policyHash), 'ai_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(aiPolicy?.status), 'ai_policy_not_active');
  addReason(reasons, aiPolicy?.aiOutputsLabeledAdvisory !== true, 'ai_outputs_not_labeled_advisory');
  addReason(reasons, aiPolicy?.humanDispositionRequired !== true, 'ai_human_disposition_not_required');
  addReason(reasons, aiPolicy?.metadataOnly !== true, 'ai_policy_metadata_boundary_invalid');
  addReason(reasons, aiPolicy?.protectedContentExcluded !== true, 'ai_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(aiPolicy?.evaluatedAtHlc) === null, 'ai_policy_evaluation_time_invalid');
  addReason(reasons, hlcBefore(aiPolicy?.evaluatedAtHlc, policySummary.evaluatedAtHlc), 'ai_policy_before_doctrine_policy');

  const rules = Array.isArray(aiPolicy?.regulatedActionRules) ? aiPolicy.regulatedActionRules : [];
  addReason(reasons, rules.length === 0, 'regulated_ai_action_rules_absent');

  const covered = [];
  for (const rule of rules) {
    const label = rule?.actionRef ?? 'unknown';
    addReason(reasons, !REGULATED_AI_ACTIONS.includes(rule?.actionRef), `regulated_action_unsupported:${label}`);
    addReason(reasons, rule?.aiMayAssist !== true, `regulated_action_ai_assist_boundary_invalid:${label}`);
    addReason(reasons, rule?.aiFinalAuthorityAllowed === true, `regulated_action_allows_ai_final_authority:${label}`);
    addReason(
      reasons,
      rule?.humanFinalAuthorityRequired !== true,
      `regulated_action_human_final_authority_absent:${label}`,
    );
    addReason(reasons, !isDigest(rule?.evidenceHash), `regulated_action_evidence_hash_invalid:${label}`);
    addReason(reasons, hlcTuple(rule?.reviewedAtHlc) === null, `regulated_action_review_time_invalid:${label}`);
    addReason(reasons, rule?.metadataOnly !== true, `regulated_action_metadata_boundary_invalid:${label}`);
    addReason(reasons, rule?.protectedContentExcluded !== true, `regulated_action_protected_boundary_invalid:${label}`);
    addReason(reasons, hlcBefore(rule?.reviewedAtHlc, aiPolicy?.evaluatedAtHlc), `regulated_action_before_ai_policy:${label}`);
    if (REGULATED_AI_ACTIONS.includes(rule?.actionRef)) {
      covered.push(rule.actionRef);
    }
  }

  const normalizedCovered = uniqueSorted(covered);
  for (const actionRef of REGULATED_AI_ACTIONS) {
    addReason(reasons, !normalizedCovered.includes(actionRef), `regulated_ai_action_missing:${actionRef}`);
  }
  return normalizedCovered;
}

function evaluateReceiptPrivacyPolicy(policy, policySummary, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'receipt_privacy_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'receipt_privacy_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'receipt_privacy_policy_not_active');
  addReason(reasons, policy?.hashOnlyAnchoring !== true, 'receipt_hash_only_anchor_required');
  addReason(reasons, policy?.rawSensitiveAnchoringAllowed === true, 'raw_sensitive_anchor_allowed');
  addReason(reasons, policy?.phiPiiExcluded !== true, 'receipt_phi_pii_boundary_invalid');
  addReason(reasons, policy?.sponsorConfidentialExcluded !== true, 'receipt_sponsor_confidential_boundary_invalid');
  addReason(reasons, policy?.privilegedContentExcluded !== true, 'receipt_privileged_boundary_invalid');
  addReason(reasons, policy?.sourceDocumentContentExcluded !== true, 'receipt_source_document_boundary_invalid');
  addReason(reasons, policy?.healthDebugTelemetryExcluded !== true, 'receipt_observability_boundary_invalid');
  addReason(reasons, policy?.receiptPayloadMetadataOnly !== true, 'receipt_payload_metadata_boundary_invalid');
  addReason(reasons, !isDigest(policy?.evidenceHash), 'receipt_privacy_evidence_hash_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'receipt_privacy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'receipt_privacy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'receipt_privacy_evaluation_time_invalid');
  addReason(reasons, hlcBefore(policy?.evaluatedAtHlc, policySummary.evaluatedAtHlc), 'receipt_privacy_before_doctrine_policy');
}

function evaluateVisibilityDefaults(defaults, policySummary, reasons) {
  addReason(reasons, !hasText(defaults?.policyRef), 'visibility_policy_ref_absent');
  addReason(reasons, !isDigest(defaults?.policyHash), 'visibility_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(defaults?.status), 'visibility_policy_not_active');
  addReason(
    reasons,
    !SAFE_VISIBILITY_VALUES.has(defaults?.sponsorVisibilityDefault),
    'sponsor_visibility_default_unsafe',
  );
  addReason(reasons, !SAFE_VISIBILITY_VALUES.has(defaults?.croVisibilityDefault), 'cro_visibility_default_unsafe');
  addReason(
    reasons,
    !SAFE_DIRECT_IDENTIFIER_VALUES.has(defaults?.directIdentifierVisibilityDefault),
    'direct_identifier_visibility_unsafe',
  );
  addReason(
    reasons,
    !SAFE_PARTICIPANT_LINKED_VALUES.has(defaults?.participantLinkedVisibilityDefault),
    'participant_linked_visibility_unsafe',
  );
  addReason(reasons, !SAFE_EXPORT_VALUES.has(defaults?.externalExportDefault), 'external_export_default_unsafe');
  addReason(reasons, defaults?.waiverRequiresDecisionForum !== true, 'visibility_waiver_decision_forum_missing');
  addReason(reasons, defaults?.metadataOnly !== true, 'visibility_defaults_metadata_boundary_invalid');
  addReason(reasons, defaults?.protectedContentExcluded !== true, 'visibility_defaults_protected_boundary_invalid');
  addReason(reasons, hlcTuple(defaults?.evaluatedAtHlc) === null, 'visibility_defaults_evaluation_time_invalid');
  addReason(
    reasons,
    hlcBefore(defaults?.evaluatedAtHlc, policySummary.evaluatedAtHlc),
    'visibility_defaults_before_doctrine_policy',
  );
}

function evaluateProtectionIntegrityGates(gates, policySummary, reasons) {
  addReason(reasons, !hasText(gates?.policyRef), 'protection_integrity_policy_ref_absent');
  addReason(reasons, !isDigest(gates?.policyHash), 'protection_integrity_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(gates?.status), 'protection_integrity_policy_not_active');
  addReason(reasons, gates?.participantProtectionGateActive !== true, 'participant_protection_gate_inactive');
  addReason(reasons, gates?.dataIntegrityGateActive !== true, 'data_integrity_gate_inactive');
  addReason(
    reasons,
    gates?.participantImpactRequiresHumanReview !== true,
    'participant_impact_human_review_required',
  );
  addReason(reasons, gates?.dataCorrectionRequiresAuditTrail !== true, 'data_correction_audit_trail_required');
  addReason(reasons, !isDigest(gates?.evidenceHash), 'protection_integrity_evidence_hash_invalid');
  addReason(reasons, gates?.metadataOnly !== true, 'protection_integrity_metadata_boundary_invalid');
  addReason(reasons, gates?.protectedContentExcluded !== true, 'protection_integrity_protected_boundary_invalid');
  addReason(reasons, hlcTuple(gates?.evaluatedAtHlc) === null, 'protection_integrity_evaluation_time_invalid');
  addReason(
    reasons,
    hlcBefore(gates?.evaluatedAtHlc, policySummary.evaluatedAtHlc),
    'protection_integrity_before_doctrine_policy',
  );

  const gateFamilies = sortedTextList(gates?.requiredGateFamilies);
  for (const family of REQUIRED_GATE_FAMILIES) {
    addReason(reasons, !gateFamilies.includes(family), `gate_family_missing:${family}`);
  }
  for (const family of gateFamilies) {
    addReason(reasons, !REQUIRED_GATE_FAMILIES.includes(family), `gate_family_unsupported:${family}`);
  }
  return gateFamilies.filter((family) => REQUIRED_GATE_FAMILIES.includes(family));
}

function evaluateDecisionForum(decisionForum, policySummary, reasons) {
  addReason(reasons, !hasText(decisionForum?.matterRef), 'decision_forum_matter_ref_absent');
  addReason(reasons, decisionForum?.status !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, decisionForum?.quorumMet !== true, 'decision_forum_quorum_missing');
  addReason(reasons, decisionForum?.humanGateVerified !== true, 'decision_forum_human_gate_missing');
  addReason(reasons, !isDigest(decisionForum?.decisionReceiptHash), 'decision_forum_receipt_hash_invalid');
  addReason(reasons, decisionForum?.metadataOnly !== true, 'decision_forum_metadata_boundary_invalid');
  addReason(reasons, decisionForum?.protectedContentExcluded !== true, 'decision_forum_protected_boundary_invalid');
  addReason(reasons, hlcTuple(decisionForum?.approvedAtHlc) === null, 'decision_forum_approval_time_invalid');
  addReason(
    reasons,
    hlcBefore(decisionForum?.approvedAtHlc, policySummary.evaluatedAtHlc),
    'decision_forum_before_policy_evaluation',
  );
}

function evaluateHumanReview(humanReview, decisionForum, reasons) {
  addReason(reasons, !hasText(humanReview?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(humanReview?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(humanReview?.reviewEvidenceHash), 'human_review_evidence_hash_invalid');
  addReason(reasons, humanReview?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, humanReview?.protectedContentExcluded !== true, 'human_review_protected_boundary_invalid');
  addReason(reasons, hlcTuple(humanReview?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(humanReview?.reviewedAtHlc, decisionForum?.approvedAtHlc), 'human_review_before_decision_forum');
}

function evaluateAiAssistance(aiAssistance, humanReview, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance.used === false) {
    return;
  }

  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_assistance_final_authority_forbidden');
  addReason(reasons, aiAssistance.humanReviewed !== true, 'ai_assistance_human_review_missing');
  addReason(reasons, !isDigest(aiAssistance.advisoryOutputHash), 'ai_assistance_output_hash_invalid');
  addReason(reasons, aiAssistance.metadataOnly !== true, 'ai_assistance_metadata_boundary_invalid');
  addReason(reasons, aiAssistance.protectedContentExcluded !== true, 'ai_assistance_protected_boundary_invalid');
  addReason(reasons, hlcTuple(aiAssistance.reviewedAtHlc) === null, 'ai_assistance_review_time_invalid');
  addReason(reasons, hlcBefore(humanReview?.reviewedAtHlc, aiAssistance.reviewedAtHlc), 'human_review_before_ai_review');
}

function buildControlHash(input, summaries) {
  return sha256Hex({
    activationGateIds: summaries.policySummary.activationGateIds,
    aiActionsCovered: summaries.regulatedAiActionsCovered,
    doctrineDecisionsCovered: summaries.doctrineDecisionsCovered,
    gateFamiliesCovered: summaries.gateFamiliesCovered,
    operatingRulesCovered: summaries.operatingRulesCovered,
    policyHash: input?.doctrinePolicy?.policyHash ?? null,
    policyRef: input?.doctrinePolicy?.policyRef ?? null,
    receiptPrivacyPolicyHash: input?.receiptPrivacyPolicy?.policyHash ?? null,
    schema: DOCTRINE_CONTROL_SCHEMA,
    tenantId: input?.tenantId ?? null,
    visibilityPolicyHash: input?.visibilityDefaults?.policyHash ?? null,
  });
}

function buildDoctrineControl(input, decision, summaries) {
  const controlHash = buildControlHash(input, summaries);
  return {
    schema: DOCTRINE_CONTROL_SCHEMA,
    policyRef: input?.doctrinePolicy?.policyRef ?? null,
    controlHash,
    decision,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    doctrineDecisionsCovered: summaries.doctrineDecisionsCovered,
    operatingRulesCovered: summaries.operatingRulesCovered,
    regulatedAiActionsCovered: summaries.regulatedAiActionsCovered,
    gateFamiliesCovered: summaries.gateFamiliesCovered,
    sponsorVisibilityDefault: input?.visibilityDefaults?.sponsorVisibilityDefault ?? null,
    croVisibilityDefault: input?.visibilityDefaults?.croVisibilityDefault ?? null,
    directIdentifierVisibilityDefault: input?.visibilityDefaults?.directIdentifierVisibilityDefault ?? null,
    participantLinkedVisibilityDefault: input?.visibilityDefaults?.participantLinkedVisibilityDefault ?? null,
    externalExportDefault: input?.visibilityDefaults?.externalExportDefault ?? null,
    activationGateIds: summaries.policySummary.activationGateIds,
    allowedBobEscalationIds: summaries.policySummary.allowedBobEscalationIds,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

function buildReceipt(input, doctrineControl) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'doctrine_control_policy',
    artifactVersion: input.doctrinePolicy.policyRef,
    artifactHash: doctrineControl.controlHash,
    custodyDigest: input.humanReview.reviewEvidenceHash,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sourceSystem: 'cybermedica-adjacent-qms',
    classification: 'regulated_metadata_only',
    sensitivityTags: [
      'doctrine',
      'governance',
      'ai_non_final_authority',
      'privacy_preserving_receipts',
      'metadata_only',
    ],
  });
}

export function evaluateDoctrineControlPolicy(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateDoctrinePolicy(input?.doctrinePolicy, reasons);
  const doctrineDecisionsCovered = evaluateDoctrineDecisions(input?.doctrineDecisions, policySummary, reasons);
  const operatingRulesCovered = evaluateOperatingRules(input?.operatingRules, policySummary, reasons);
  const regulatedAiActionsCovered = evaluateAiNonFinalAuthorityPolicy(
    input?.aiNonFinalAuthorityPolicy,
    policySummary,
    reasons,
  );
  evaluateReceiptPrivacyPolicy(input?.receiptPrivacyPolicy, policySummary, reasons);
  evaluateVisibilityDefaults(input?.visibilityDefaults, policySummary, reasons);
  const gateFamiliesCovered = evaluateProtectionIntegrityGates(input?.protectionIntegrityGates, policySummary, reasons);
  evaluateDecisionForum(input?.decisionForum, policySummary, reasons);
  evaluateHumanReview(input?.humanReview, input?.decisionForum, reasons);
  evaluateAiAssistance(input?.aiAssistance, input?.humanReview, reasons);

  const decision = reasons.length === 0 ? DECISION_READY : DECISION_HOLD;
  const doctrineControl = buildDoctrineControl(input, decision, {
    doctrineDecisionsCovered,
    gateFamiliesCovered,
    operatingRulesCovered,
    policySummary,
    regulatedAiActionsCovered,
  });

  return {
    decision,
    reasons,
    doctrineControl,
    receipt: decision === DECISION_READY ? buildReceipt(input, doctrineControl) : null,
  };
}

export const DOCTRINE_CONTROL_POLICY_REQUIREMENTS = Object.freeze({
  requiredActivationGates: [...REQUIRED_ACTIVATION_GATES],
  requiredDoctrineDecisions: [...REQUIRED_DOCTRINE_DECISIONS],
  requiredGateFamilies: [...REQUIRED_GATE_FAMILIES],
  requiredOperatingRules: [...REQUIRED_OPERATING_RULES],
  regulatedAiActions: [...REGULATED_AI_ACTIONS],
});
