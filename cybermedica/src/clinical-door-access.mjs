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
const DOOR_ACCESS_SCHEMA = 'cybermedica.clinical_door_access.v1';
const REQUIRED_ADAPTER_KIND = 'server_side_gateway_node';

const REQUIRED_DOORS = Object.freeze([
  'site_profile_workspace',
  'protocol_startup_workspace',
  'evidence_vault',
  'consent_workspace',
  'safety_event_desk',
  'deviation_capa_workspace',
  'audit_inspection_workspace',
  'sponsor_diligence_workspace',
  'decision_forum_workspace',
  'deployment_admin_workspace',
]);

const REQUIRED_ACTIVATION_GATES = Object.freeze(['PTAG-016', 'PTAG-017', 'PTAG-018']);
const REQUIRED_ESCALATIONS = Object.freeze(['ESC-RUNTIME', 'ESC-OPS-SECRETS']);

const DOOR_FAMILIES = new Set([
  'data',
  'deployment_operations',
  'doctrine_governance',
  'domain_operations',
  'external_oversight',
  'ground_truth',
]);

const RAW_DOOR_FIELDS = new Set([
  'body',
  'doorbody',
  'doorcopy',
  'doorpayload',
  'doortext',
  'freeformdoor',
  'rawcontent',
  'rawdoor',
  'rawdoorcontent',
  'rawpayload',
  'rawroutepayload',
  'routebody',
  'routecontent',
  'routepayload',
  'routetext',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
]);

const SECRET_DOOR_FIELDS = new Set([
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

function assertNoRawDoorContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDoorContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_DOOR_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw clinical door content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_DOOR_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`clinical door secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawDoorContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDoorContent(input ?? {});
  canonicalize(input ?? {});
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

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function intersects(left, right) {
  const rightSet = new Set(right);
  return left.some((value) => rightSet.has(value));
}

function includesAll(values, required) {
  const valueSet = new Set(values);
  return required.every((value) => valueSet.has(value));
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, hlcTuple(input?.requestedAtHlc) === null, 'requested_time_invalid');
  addReason(reasons, !hasText(input?.requestedDoorRef), 'requested_door_absent');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function validateRegistry(input, reasons) {
  const registry = input?.doorRegistry;
  addReason(reasons, !hasText(registry?.registryRef), 'door_registry_ref_absent');
  addReason(reasons, !isDigest(registry?.registryHash), 'door_registry_hash_invalid');
  addReason(reasons, registry?.status !== 'active', 'door_registry_not_active');
  addReason(reasons, registry?.metadataOnly !== true, 'door_registry_metadata_boundary_invalid');
  addReason(reasons, registry?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(registry?.evaluatedAtHlc) === null, 'door_registry_evaluation_time_invalid');

  const requiredDoorRefs = sortedTextList(registry?.requiredDoorRefs);
  const sourceDocRefs = sortedTextList(registry?.sourceDocRefs);
  const activationGateIds = sortedTextList(registry?.activationGateIds);
  const escalationIds = sortedTextList(registry?.allowedBobEscalationIds);
  const doorRefs = sortedTextList((Array.isArray(registry?.doors) ? registry.doors : []).map((door) => door?.doorRef));

  addReason(reasons, sourceDocRefs.length === 0, 'door_source_doc_refs_absent');
  for (const requiredDoorRef of REQUIRED_DOORS) {
    addReason(reasons, !requiredDoorRefs.includes(requiredDoorRef), `registry_required_door_ref_absent:${requiredDoorRef}`);
    addReason(reasons, !doorRefs.includes(requiredDoorRef), `required_door_missing:${requiredDoorRef}`);
  }
  for (const gateId of REQUIRED_ACTIVATION_GATES) {
    addReason(reasons, !activationGateIds.includes(gateId), `activation_gate_missing:${gateId}`);
  }
  for (const escalationId of REQUIRED_ESCALATIONS) {
    addReason(reasons, !escalationIds.includes(escalationId), `bob_escalation_missing:${escalationId}`);
  }

  return {
    missingDoorRefs: REQUIRED_DOORS.filter((doorRef) => !doorRefs.includes(doorRef)),
    registeredDoorRefs: doorRefs,
  };
}

function validateTrustBoundary(input, reasons) {
  const boundary = input?.trustBoundary;
  addReason(reasons, boundary?.productionTrustState === 'verified', 'production_trust_state_must_remain_inactive');
  addReason(reasons, boundary?.rootTrustVerified === true, 'root_trust_claim_before_activation_forbidden');
  addReason(reasons, boundary?.browserAuthoritative === true, 'browser_authoritative_trust_path_forbidden');
  addReason(reasons, boundary?.selectedAdapterKind !== REQUIRED_ADAPTER_KIND, 'selected_adapter_not_server_side');
  addReason(reasons, boundary?.serverSideAdapterRequired !== true, 'server_side_adapter_requirement_absent');
  addReason(reasons, boundary?.inactiveTrustNoticeRequired !== true, 'inactive_trust_notice_absent');
  addReason(reasons, boundary?.rootSigningMaterialPresent === true, 'root_signing_material_forbidden');
  addReason(reasons, !isDigest(boundary?.boundaryEvidenceHash), 'trust_boundary_evidence_hash_invalid');
}

function normalizeDoor(door, registryEvaluatedAtHlc, reasons) {
  const doorRef = hasText(door?.doorRef) ? door.doorRef : 'unknown';
  const family = door?.family;
  const allowedRoleRefs = sortedTextList(door?.allowedRoleRefs);
  const requiredPermissionRefs = sortedTextList(door?.requiredPermissionRefs);
  const requiredActorKinds = sortedTextList(door?.requiredActorKinds);

  addReason(reasons, !hasText(door?.doorRef), 'door_ref_absent');
  addReason(reasons, !DOOR_FAMILIES.has(family), `door_family_unsupported:${doorRef}`);
  addReason(reasons, !isDigest(door?.routeHash), `door_route_hash_invalid:${doorRef}`);
  addReason(reasons, !isDigest(door?.sourceEvidenceHash), `door_source_evidence_hash_invalid:${doorRef}`);
  addReason(reasons, hlcTuple(door?.registeredAtHlc) === null, `door_registered_time_invalid:${doorRef}`);
  addReason(reasons, hlcAfter(door?.registeredAtHlc, registryEvaluatedAtHlc), `door_registered_after_registry:${doorRef}`);
  addReason(reasons, allowedRoleRefs.length === 0, `door_allowed_roles_absent:${doorRef}`);
  addReason(reasons, requiredPermissionRefs.length === 0, `door_required_permissions_absent:${doorRef}`);
  addReason(reasons, requiredActorKinds.length === 0, `door_required_actor_kinds_absent:${doorRef}`);
  addReason(reasons, door?.metadataOnly !== true, `door_metadata_boundary_invalid:${doorRef}`);
  addReason(reasons, door?.payloadsExcluded !== true, `door_payload_boundary_invalid:${doorRef}`);
  addReason(reasons, door?.protectedContentExcluded !== true, `door_protected_boundary_invalid:${doorRef}`);
  addReason(reasons, door?.productionTrustClaim === true, `door_production_trust_claim_forbidden:${doorRef}`);
  addReason(reasons, door?.serverAdapterRequired !== true, `door_server_adapter_requirement_absent:${doorRef}`);
  addReason(reasons, door?.browserAuthoritative === true, `door_browser_authoritative_forbidden:${doorRef}`);

  return {
    allowedRoleRefs,
    browserAuthoritative: door?.browserAuthoritative === true,
    consentRequired: door?.consentRequired === true,
    decisionForumRequired: door?.decisionForumRequired === true,
    doorRef,
    family: family ?? null,
    metadataOnly: door?.metadataOnly === true,
    participantLinked: door?.participantLinked === true,
    protectedContentExcluded: door?.protectedContentExcluded === true,
    requiredActorKinds,
    requiredPermissionRefs,
    routeHash: door?.routeHash ?? null,
    serverAdapterRequired: door?.serverAdapterRequired === true,
    sourceEvidenceHash: door?.sourceEvidenceHash ?? null,
  };
}

function normalizeDoors(input, reasons) {
  const doors = Array.isArray(input?.doorRegistry?.doors) ? input.doorRegistry.doors : [];
  addReason(reasons, doors.length === 0, 'clinical_doors_absent');

  const doorByRef = new Map();
  const duplicateDoorRefs = new Set();
  for (const door of doors) {
    const normalized = normalizeDoor(door, input?.doorRegistry?.evaluatedAtHlc, reasons);
    if (hasText(normalized.doorRef)) {
      if (doorByRef.has(normalized.doorRef)) {
        duplicateDoorRefs.add(normalized.doorRef);
      }
      if (!doorByRef.has(normalized.doorRef)) {
        doorByRef.set(normalized.doorRef, normalized);
      }
    }
  }
  for (const doorRef of [...duplicateDoorRefs].sort()) {
    reasons.push(`door_duplicate:${doorRef}`);
  }
  return doorByRef;
}

function actorCanAccessDoor(input, door) {
  const actorRoles = sortedTextList(input?.actor?.roleRefs);
  const actorPermissions = sortedTextList(input?.authority?.permissions);
  const actorKinds = hasText(input?.actor?.kind) ? [input.actor.kind] : [];
  return {
    actorKindAuthorized: intersects(actorKinds, door.requiredActorKinds),
    permissionAuthorized: includesAll(actorPermissions, door.requiredPermissionRefs),
    roleAuthorized: intersects(actorRoles, door.allowedRoleRefs),
  };
}

function authorizedDoorRefs(input, doorByRef) {
  return [...doorByRef.values()]
    .filter((door) => {
      const access = actorCanAccessDoor(input, door);
      return (
        access.actorKindAuthorized &&
        access.permissionAuthorized &&
        access.roleAuthorized &&
        door.metadataOnly &&
        door.protectedContentExcluded &&
        !door.browserAuthoritative
      );
    })
    .map((door) => door.doorRef)
    .sort();
}

function validateRequestedDoor(input, door, reasons) {
  if (!door) {
    addReason(reasons, hasText(input?.requestedDoorRef), `requested_door_unknown:${input?.requestedDoorRef}`);
    return {
      actorKindAuthorized: false,
      consentRequired: false,
      decisionForumRequired: false,
      doorRef: input?.requestedDoorRef ?? null,
      family: null,
      permissionAuthorized: false,
      roleAuthorized: false,
      serverAdapterRequired: false,
    };
  }

  const access = actorCanAccessDoor(input, door);
  addReason(reasons, !access.roleAuthorized, 'actor_role_not_authorized_for_requested_door');
  addReason(reasons, !access.permissionAuthorized, 'actor_permission_not_authorized_for_requested_door');
  addReason(reasons, !access.actorKindAuthorized, 'actor_kind_not_authorized_for_requested_door');

  return {
    actorKindAuthorized: access.actorKindAuthorized,
    consentRequired: door.consentRequired,
    decisionForumRequired: door.decisionForumRequired,
    doorRef: door.doorRef,
    family: door.family,
    permissionAuthorized: access.permissionAuthorized,
    roleAuthorized: access.roleAuthorized,
    serverAdapterRequired: door.serverAdapterRequired,
  };
}

function validateConsent(input, door, reasons) {
  if (!door?.consentRequired) {
    return;
  }
  const consent = input?.consentBoundary;
  addReason(reasons, consent === null || consent === undefined, `door_consent_required:${door.doorRef}`);
  addReason(reasons, consent?.status !== 'active', 'consent_not_active');
  addReason(reasons, consent?.revoked === true || consent?.status === 'revoked', 'consent_revoked');
  addReason(reasons, !hasText(consent?.consentRef), 'consent_ref_absent');
  addReason(reasons, !isDigest(consent?.evidenceHash), 'consent_evidence_hash_invalid');
}

function validateDecisionForum(input, door, reasons) {
  if (!door?.decisionForumRequired) {
    return;
  }
  const gate = input?.decisionForumGate;
  addReason(reasons, gate?.required !== true, 'decision_forum_gate_absent');
  addReason(reasons, !hasText(gate?.matterRef), 'decision_forum_matter_ref_absent');
  addReason(reasons, gate?.humanGateVerified !== true, 'decision_forum_human_gate_unverified');
  addReason(reasons, !isDigest(gate?.quorumEvidenceHash), 'decision_forum_quorum_hash_invalid');
  addReason(reasons, !isDigest(gate?.tncEvidenceHash), 'decision_forum_tnc_hash_invalid');
  addReason(reasons, gate?.kernelVerdict !== 'permit', 'decision_forum_kernel_verdict_not_permit');
  addReason(reasons, gate?.metadataOnly !== true, 'decision_forum_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(gate?.adjudicatedAtHlc) === null, 'decision_forum_time_invalid');
  addReason(reasons, hlcBefore(gate?.adjudicatedAtHlc, input?.doorRegistry?.evaluatedAtHlc), 'decision_forum_before_registry_evaluation');
  addReason(reasons, hlcAfter(gate?.adjudicatedAtHlc, input?.requestedAtHlc), 'decision_forum_after_request');
}

function validateDisclosure(input, reasons) {
  const log = input?.disclosureLog;
  addReason(reasons, !hasText(log?.disclosureRef), 'disclosure_ref_absent');
  addReason(reasons, !isDigest(log?.disclosureHash), 'disclosure_hash_invalid');
  addReason(reasons, !hasText(log?.recipientClass), 'disclosure_recipient_absent');
  addReason(reasons, !hasText(log?.purpose), 'disclosure_purpose_absent');
  addReason(reasons, log?.includesRawContent !== false, 'disclosure_raw_content_forbidden');
  addReason(reasons, hlcTuple(log?.loggedAtHlc) === null, 'disclosure_time_invalid');
  addReason(reasons, hlcBefore(log?.loggedAtHlc, input?.requestedAtHlc), 'disclosure_before_request');
}

function deniedResult(input, registryCoverage, doorDecision, authorizedRefs, reasons) {
  return {
    schema: DOOR_ACCESS_SCHEMA,
    status: 'denied',
    requestedDoorRef: input?.requestedDoorRef ?? null,
    requiredDoorRefs: [...REQUIRED_DOORS],
    registryCoverage,
    authorizedDoorRefs: [],
    suppressedDoorCount: authorizedRefs.length,
    doorDecision,
    doorAccessHash: null,
    trustState: 'inactive',
    exochainProductionClaim: false,
    canShowProductionTrustClaim: false,
    denialReasons: uniqueReasons(reasons),
    receipt: null,
  };
}

function buildDoorAccessHash(input, doorDecision, authorizedRefs, registryCoverage) {
  return sha256Hex({
    actorDid: input.actor.did,
    authorizedDoorRefs: authorizedRefs,
    boundaryEvidenceHash: input.trustBoundary.boundaryEvidenceHash,
    disclosureHash: input.disclosureLog.disclosureHash,
    doorDecision,
    registryCoverage,
    registryHash: input.doorRegistry.registryHash,
    requestedAtHlc: input.requestedAtHlc,
    requestedDoorRef: input.requestedDoorRef,
    tenantId: input.tenantId,
    trustState: 'inactive',
  });
}

function buildReceipt(input, doorAccessHash, doorDecision, authorizedRefs) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: doorAccessHash,
    artifactType: 'clinical_qms_door_access_decision',
    artifactVersion: input.requestedDoorRef,
    authorizedDoorCount: authorizedRefs.length,
    classification: 'clinical_qms_door_metadata',
    custodyDigest: sha256Hex({
      boundaryEvidenceHash: input.trustBoundary.boundaryEvidenceHash,
      disclosureHash: input.disclosureLog.disclosureHash,
      registryHash: input.doorRegistry.registryHash,
    }),
    doorFamily: doorDecision.family,
    hlcTimestamp: `${input.requestedAtHlc.physicalMs}:${input.requestedAtHlc.logical}`,
    schema: 'cybermedica.clinical_door_access_receipt.v1',
    sensitivityTags: ['metadata_only', 'clinical_qms_door', doorDecision.family],
    sourceSystem: 'cybermedica.doors_layer',
    tenantId: input.tenantId,
  });
}

export function evaluateClinicalDoorAccess(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const registryCoverage = validateRegistry(input, reasons);
  validateTrustBoundary(input, reasons);
  const doorByRef = normalizeDoors(input, reasons);
  const requestedDoor = doorByRef.get(input?.requestedDoorRef);
  const doorDecision = validateRequestedDoor(input, requestedDoor, reasons);
  validateConsent(input, requestedDoor, reasons);
  validateDecisionForum(input, requestedDoor, reasons);
  validateDisclosure(input, reasons);

  const authorizedRefs = authorizedDoorRefs(input, doorByRef);
  if (reasons.length > 0) {
    return deniedResult(input ?? {}, registryCoverage, doorDecision, authorizedRefs, reasons);
  }

  const doorAccessHash = buildDoorAccessHash(input, doorDecision, authorizedRefs, registryCoverage);
  const receipt = buildReceipt(input, doorAccessHash, doorDecision, authorizedRefs);

  return {
    schema: DOOR_ACCESS_SCHEMA,
    status: 'ready',
    requestedDoorRef: input.requestedDoorRef,
    requiredDoorRefs: [...REQUIRED_DOORS],
    registryCoverage,
    authorizedDoorRefs: authorizedRefs,
    suppressedDoorCount: doorByRef.size - authorizedRefs.length,
    doorDecision,
    doorAccessHash,
    trustState: 'inactive',
    exochainProductionClaim: false,
    canShowProductionTrustClaim: false,
    denialReasons: [],
    receipt,
  };
}
