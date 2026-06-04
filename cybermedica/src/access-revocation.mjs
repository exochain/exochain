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
const REQUIRED_PERMISSION = 'access_revocation_review';
const ACCESS_REVOCATION_SCHEMA = 'cybermedica.access_revocation.v1';

const REQUIRED_REVOCATION_TRIGGERS = Object.freeze([
  'delegation_expiration',
  'policy_violation',
  'role_change',
  'study_closure',
  'termination',
]);

const REVOCATION_ACTION_TYPES = new Set(['revoke_access', 'suspend_access']);
const ALLOWED_GRANT_PERMISSIONS = new Set(['export', 'inspect', 'metadata_read', 'read', 'write']);

const RAW_ACCESS_FIELDS = new Set([
  'directidentifier',
  'directidentifiers',
  'freeformaccessnote',
  'rawaccesscontent',
  'rawaccesslog',
  'rawauthorizationpayload',
  'rawidentitypayload',
  'rawpermissionpayload',
  'rawpolicyviolation',
  'rawrevocationcontent',
  'rawrolechange',
  'rawsourcecontent',
  'rawstudyclosurecontent',
  'revocationnotes',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_ACCESS_FIELDS = new Set([
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

function assertNoRawAccessContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAccessContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ACCESS_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw access revocation content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ACCESS_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`access revocation secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawAccessContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAccessContent(input ?? {});
  canonicalize(input ?? {});
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function sortedUniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [BigInt(hlc.physicalMs), BigInt(hlc.logical)];
}

function compareHlc(left, right) {
  if (left[0] < right[0]) {
    return -1;
  }
  if (left[0] > right[0]) {
    return 1;
  }
  if (left[1] < right[1]) {
    return -1;
  }
  if (left[1] > right[1]) {
    return 1;
  }
  return 0;
}

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) &&
    (authority.permissions.includes(REQUIRED_PERMISSION) || authority.permissions.includes('govern'));
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_access_reviewer_required');
  addReason(reasons, input?.actor?.kind === 'ai_agent' || input?.aiAssistance?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  const covered = sortedTextList(policy?.coveredTriggerTypes);
  addReason(reasons, !hasText(policy?.policyRef), 'policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'policy_hash_invalid');
  addReason(reasons, policy?.status !== 'active', 'policy_not_active');
  addReason(reasons, policy?.leastPrivilegeRequired !== true, 'policy_least_privilege_not_required');
  addReason(reasons, policy?.timeBoundRequired !== true, 'policy_time_bound_not_required');
  addReason(reasons, policy?.revocationRequired !== true, 'policy_revocation_not_required');
  addReason(reasons, policy?.auditTrailRequired !== true, 'policy_audit_trail_not_required');
  addReason(reasons, policy?.humanReviewRequired !== true, 'policy_human_review_not_required');
  addReason(reasons, policy?.metadataOnly !== true, 'policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'policy_protected_boundary_invalid');

  for (const triggerType of REQUIRED_REVOCATION_TRIGGERS) {
    addReason(reasons, !covered.includes(triggerType), `policy_missing_trigger_coverage:${triggerType}`);
  }

  return covered;
}

function evaluateSubject(input, reasons) {
  addReason(reasons, !hasText(input?.subject?.did), 'subject_did_absent');
  addReason(reasons, input?.subject?.tenantId !== input?.tenantId, 'subject_tenant_mismatch');
  addReason(reasons, sortedTextList(input?.subject?.activeRoleRefs).length === 0, 'subject_role_refs_absent');
}

function normalizedTrigger(trigger, reasons) {
  const triggerId = hasText(trigger?.triggerId) ? trigger.triggerId : 'unknown';
  const detectedAt = hlcTuple(trigger?.detectedAtHlc);
  addReason(reasons, !hasText(trigger?.triggerId), 'trigger_id_absent');
  addReason(reasons, !REQUIRED_REVOCATION_TRIGGERS.includes(trigger?.triggerType), `trigger_type_invalid:${triggerId}`);
  addReason(reasons, !isDigest(trigger?.evidenceHash), `trigger_evidence_hash_invalid:${triggerId}`);
  addReason(reasons, detectedAt === null, `trigger_detected_time_invalid:${triggerId}`);
  addReason(reasons, !hasText(trigger?.sourceSystemRef), `trigger_source_system_absent:${triggerId}`);
  addReason(reasons, trigger?.metadataOnly !== true, `trigger_metadata_boundary_invalid:${triggerId}`);
  addReason(reasons, trigger?.protectedContentExcluded !== true, `trigger_protected_boundary_invalid:${triggerId}`);

  return {
    detectedAt,
    detectedAtHlc: trigger?.detectedAtHlc ?? null,
    evidenceHash: trigger?.evidenceHash ?? null,
    triggerId,
    triggerType: trigger?.triggerType ?? null,
  };
}

function evaluateTriggers(input, effectiveAt, reasons) {
  const triggers = Array.isArray(input?.revocationTriggers) ? input.revocationTriggers.map((trigger) => normalizedTrigger(trigger, reasons)) : [];
  addReason(reasons, triggers.length === 0, 'revocation_triggers_absent');

  const triggerTypes = sortedTextList(triggers.map((trigger) => trigger.triggerType).filter((type) => REQUIRED_REVOCATION_TRIGGERS.includes(type)));
  for (const triggerType of REQUIRED_REVOCATION_TRIGGERS) {
    addReason(reasons, !triggerTypes.includes(triggerType), `trigger_missing:${triggerType}`);
  }

  for (const trigger of triggers) {
    addReason(
      reasons,
      effectiveAt !== null && trigger.detectedAt !== null && compareHlc(effectiveAt, trigger.detectedAt) < 0,
      'revocation_effective_before_trigger',
    );
  }

  return triggers.sort((left, right) => String(left.triggerType).localeCompare(String(right.triggerType)));
}

function grantHasExcessivePermission(grant) {
  return sortedTextList(grant?.permissions).some((permission) => !ALLOWED_GRANT_PERMISSIONS.has(permission));
}

function normalizedGrant(grant, input, reasons) {
  const grantId = hasText(grant?.grantId) ? grant.grantId : 'unknown';
  const issuedAt = hlcTuple(grant?.issuedAtHlc);
  const expiresAt = hlcTuple(grant?.expiresAtHlc);
  addReason(reasons, !hasText(grant?.grantId), 'grant_id_absent');
  addReason(reasons, grant?.principalDid !== input?.subject?.did, `grant_principal_mismatch:${grantId}`);
  addReason(reasons, grant?.tenantId !== input?.tenantId, `grant_tenant_mismatch:${grantId}`);
  addReason(reasons, grant?.status !== 'active', `grant_not_active:${grantId}`);
  addReason(reasons, !hasText(grant?.resourceScope), `grant_resource_scope_absent:${grantId}`);
  addReason(reasons, sortedTextList(grant?.permissions).length === 0, `grant_permissions_absent:${grantId}`);
  addReason(reasons, grantHasExcessivePermission(grant), `grant_excessive_permission:${grantId}`);
  addReason(reasons, grant?.revocable !== true, `grant_not_revocable:${grantId}`);
  addReason(reasons, grant?.timeBound !== true, `grant_not_time_bound:${grantId}`);
  addReason(reasons, grant?.leastPrivilege !== true, `grant_not_least_privilege:${grantId}`);
  addReason(reasons, issuedAt === null, `grant_issued_time_invalid:${grantId}`);
  addReason(reasons, expiresAt === null, `grant_expiry_time_invalid:${grantId}`);
  addReason(
    reasons,
    issuedAt !== null && expiresAt !== null && compareHlc(issuedAt, expiresAt) >= 0,
    `grant_time_window_invalid:${grantId}`,
  );
  addReason(reasons, !isDigest(grant?.accessPolicyHash), `grant_access_policy_hash_invalid:${grantId}`);
  addReason(reasons, !isDigest(grant?.authorityChainHash), `grant_authority_hash_invalid:${grantId}`);
  addReason(reasons, !isDigest(grant?.lastAuditHash), `grant_last_audit_hash_invalid:${grantId}`);

  return {
    authorityChainHash: grant?.authorityChainHash ?? null,
    grantId,
    permissions: sortedTextList(grant?.permissions),
    resourceScope: grant?.resourceScope ?? null,
    status: grant?.status ?? null,
  };
}

function evaluateAccessGrants(input, reasons) {
  const grants = Array.isArray(input?.accessGrants) ? input.accessGrants.map((grant) => normalizedGrant(grant, input, reasons)) : [];
  addReason(reasons, grants.length === 0, 'access_grants_absent');
  return grants.sort((left, right) => left.grantId.localeCompare(right.grantId));
}

function evaluateRevocationAction(input, effectiveAt, reasons) {
  const action = input?.revocationAction;
  addReason(reasons, !hasText(action?.actionId), 'revocation_action_id_absent');
  addReason(reasons, !REVOCATION_ACTION_TYPES.has(action?.actionType), 'revocation_action_type_invalid');
  addReason(reasons, !hasText(action?.reasonCode), 'revocation_reason_absent');
  addReason(reasons, effectiveAt === null, 'revocation_effective_time_invalid');
  addReason(reasons, action?.processedByDid !== input?.actor?.did, 'revocation_processor_actor_mismatch');
  addReason(reasons, !isDigest(action?.notificationEvidenceHash), 'revocation_notification_hash_invalid');
  addReason(reasons, !isDigest(action?.previousAuditHash), 'revocation_previous_audit_hash_invalid');
  addReason(reasons, !isDigest(action?.auditEventHash), 'revocation_audit_event_hash_invalid');
  addReason(reasons, !isDigest(action?.disclosureLogHash), 'revocation_disclosure_log_hash_invalid');
  addReason(reasons, sortedTextList(action?.affectedSystemRefs).length === 0, 'revocation_affected_systems_absent');
  addReason(reasons, action?.humanReviewed !== true, 'revocation_human_review_absent');
  addReason(reasons, action?.metadataOnly !== true, 'revocation_metadata_boundary_invalid');
  addReason(reasons, action?.protectedContentExcluded !== true, 'revocation_protected_boundary_invalid');
}

function validateInput(input, reasons) {
  assertMetadataOnly(input);
  const effectiveAt = hlcTuple(input?.revocationAction?.effectiveAtHlc);

  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.revocationPolicy, reasons);
  evaluateSubject(input, reasons);
  evaluateRevocationAction(input, effectiveAt, reasons);
  const triggers = evaluateTriggers(input, effectiveAt, reasons);
  const grants = evaluateAccessGrants(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  addReason(reasons, input?.aiAssistance?.used === true && !isDigest(input?.aiAssistance?.recommendationHash), 'ai_recommendation_hash_invalid');

  return { grants, triggers };
}

function revocationMaterial(input, triggers, grants) {
  return {
    actionType: input.revocationAction.actionType,
    affectedSystemRefs: sortedTextList(input.revocationAction.affectedSystemRefs),
    auditEventHash: input.revocationAction.auditEventHash,
    authorityChainHash: input.authority.authorityChainHash,
    disclosureLogHash: input.revocationAction.disclosureLogHash,
    effectiveAtHlc: input.revocationAction.effectiveAtHlc,
    policyHash: input.revocationPolicy.policyHash,
    policyRef: input.revocationPolicy.policyRef,
    previousAuditHash: input.revocationAction.previousAuditHash,
    revokedGrantIds: grants.map((grant) => grant.grantId).sort(),
    schema: `${ACCESS_REVOCATION_SCHEMA}.material`,
    subjectDid: input.subject.did,
    tenantId: input.tenantId,
    triggerEvidenceHashes: triggers.map((trigger) => trigger.evidenceHash).filter(isDigest).sort(),
    triggerTypes: sortedTextList(triggers.map((trigger) => trigger.triggerType).filter(hasText)),
  };
}

function buildReceipt(input, revocationHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: revocationHash,
    artifactType: 'access_revocation_decision',
    artifactVersion: `${input.revocationAction.actionId}@${input.revocationAction.actionType}`,
    classification: 'access_revocation_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.revocationAction.effectiveAtHlc,
    sensitivityTags: ['access_control', 'metadata_only', 'rule_15', 'revocation'],
    sourceSystem: 'cybermedica',
    tenantId: input.tenantId,
  });
}

function buildAccessRevocation(input, revocationHash, receipt, triggers, grants) {
  return {
    schema: ACCESS_REVOCATION_SCHEMA,
    revocationId: `cmrev_${sha256Hex({
      actionId: input.revocationAction.actionId,
      revocationHash,
      schema: `${ACCESS_REVOCATION_SCHEMA}.id`,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    revocationHash,
    tenantId: input.tenantId,
    subjectDid: input.subject.did,
    policyRef: input.revocationPolicy.policyRef,
    actionType: input.revocationAction.actionType,
    effectiveAtHlc: input.revocationAction.effectiveAtHlc,
    triggerTypes: sortedTextList(triggers.map((trigger) => trigger.triggerType).filter(hasText)),
    triggerEvidenceHashes: triggers.map((trigger) => trigger.evidenceHash).filter(isDigest).sort(),
    revokedGrantIds: grants.map((grant) => grant.grantId).sort(),
    affectedSystemRefs: sortedTextList(input.revocationAction.affectedSystemRefs),
    authorityChainHash: input.authority.authorityChainHash,
    previousAuditHash: input.revocationAction.previousAuditHash,
    auditEventHash: input.revocationAction.auditEventHash,
    disclosureLogHash: input.revocationAction.disclosureLogHash,
    noActiveProtectedAccess: true,
    receiptId: receipt.receiptId,
  };
}

export function evaluateAccessRevocation(input) {
  const reasons = [];
  const { grants, triggers } = validateInput(input, reasons);
  const uniqueReasons = sortedUniqueReasons(reasons);

  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.access_revocation_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      accessRevocation: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const material = revocationMaterial(input, triggers, grants);
  const revocationHash = sha256Hex(material);
  const receipt = buildReceipt(input, revocationHash);

  return {
    schema: 'cybermedica.access_revocation_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    accessRevocation: buildAccessRevocation(input, revocationHash, receipt, triggers, grants),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
