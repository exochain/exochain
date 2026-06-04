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
const EXOCHAIN_ANCHORING_SCHEMA = 'cybermedica.exochain_anchoring.v1';
const REQUIRED_PERMISSION = 'exochain_anchor';
const CROSSCHECKED_ANCHORING_GATE_ID = 'PTAG-003';
const ACTOR_KINDS = new Set(['human', 'service_account']);
const POLICY_STATUSES = new Set(['active']);
const HUMAN_AUTHORIZATION_STATUSES = new Set(['approved']);
const CONSENT_SCOPES = new Set(['metadata_anchor', 'receipt_anchor']);
const CLASSIFICATIONS = new Set([
  'audit_metadata_only',
  'confidential_metadata_only',
  'qms_metadata_only',
  'restricted_metadata_only',
  'sponsor_confidential_metadata_only',
]);
const REQUIRED_ANCHOR_FAMILIES = [
  'audit_anchor',
  'authority_receipt',
  'consent_receipt',
  'decision_receipt',
  'evidence_receipt',
];
const FAMILY_REQUIRED_HASH_FIELDS = new Map([
  ['audit_anchor', ['auditEntryHash', 'dagNodeHash', 'dagPayloadHash']],
  ['authority_receipt', ['authorityChainHash', 'authorityReceiptHash', 'delegationAuditHash']],
  ['consent_receipt', ['consentPolicyHash', 'consentReceiptHash', 'participantCodeHash']],
  ['decision_receipt', ['decisionReceiptHash', 'humanGateHash', 'quorumHash']],
  ['evidence_receipt', ['custodyDigest', 'evidenceHash', 'receiptHash']],
]);
const EXOCHAIN_PRIMITIVE_REFS = [
  'crates/exo-authority/src/chain.rs',
  'crates/exo-consent/src/bailment.rs',
  'crates/exo-core/src/types.rs',
  'crates/exo-dag/src/dag.rs',
  'crates/exo-governance/src/audit.rs',
];
const RAW_ANCHOR_FIELDS = new Set([
  'anchorbody',
  'anchorpayload',
  'auditpayload',
  'body',
  'content',
  'dagbody',
  'dagnodepayload',
  'dagpayload',
  'decisionpayload',
  'directidentifierlist',
  'evidencepayload',
  'freetext',
  'freetextnote',
  'participantlisting',
  'payload',
  'provenancepayload',
  'rawanchor',
  'rawanchorpayload',
  'rawauditrecord',
  'rawcontent',
  'rawdecisionpayload',
  'rawevidence',
  'rawphi',
  'rawpii',
  'rawreceipt',
  'rawreceiptbody',
  'rawrecord',
  'rawsignature',
  'rawsource',
  'rawsourcedata',
  'receiptbody',
  'receiptpayload',
  'recordbody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
]);
const SECRET_ANCHOR_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstraptoken',
  'clientsecret',
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

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
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

function assertNoRawAnchoringContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAnchoringContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ANCHOR_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw anchoring content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ANCHOR_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`anchoring secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawAnchoringContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAnchoringContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlcTuple(left, right) {
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
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) < 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) > 0;
}

function hlcNotAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlcTuple(leftTuple, rightTuple) <= 0;
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function includesAll(needles, haystack) {
  const haystackSet = new Set(haystack);
  return needles.every((needle) => haystackSet.has(needle));
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function consentMatrixByRef(consentMatrix) {
  const entries = Array.isArray(consentMatrix) ? consentMatrix.filter((consent) => hasText(consent?.consentRef)) : [];
  return new Map(entries.map((consent) => [consent.consentRef, consent]));
}

function consentExpired(consent, anchorSet) {
  return hlcTuple(consent?.expiresAtHlc) === null || hlcNotAfter(consent.expiresAtHlc, anchorSet?.generatedAtHlc);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'anchor_actor_kind_invalid');
  addReason(
    reasons,
    input?.actor?.kind === 'service_account' && !hasText(input?.actor?.humanOwnerDid),
    'service_account_human_owner_absent',
  );
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'write'),
    'anchor_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateAnchorSet(input, reasons) {
  const anchorSet = input?.anchorSet;
  addReason(reasons, !hasText(anchorSet?.anchorSetRef), 'anchor_set_ref_absent');
  addReason(reasons, !hasText(anchorSet?.purpose), 'anchor_set_purpose_absent');
  addReason(reasons, hlcTuple(anchorSet?.requestedAtHlc) === null, 'anchor_requested_time_invalid');
  addReason(reasons, hlcTuple(anchorSet?.generatedAtHlc) === null, 'anchor_generated_time_invalid');
  addReason(reasons, hlcBefore(anchorSet?.generatedAtHlc, anchorSet?.requestedAtHlc), 'anchor_generated_before_request');
  addReason(reasons, anchorSet?.metadataOnly !== true, 'anchor_set_metadata_boundary_invalid');
  addReason(reasons, anchorSet?.productionTrustClaim === true, 'anchor_set_production_trust_claim_forbidden');
  addReason(reasons, anchorSet?.externalAnchorRequested === true, 'external_anchor_request_forbidden_before_activation');
}

function evaluateAnchoringPolicy(input, requiredFamilies, reasons) {
  const policy = input?.anchoringPolicy;
  const anchorSet = input?.anchorSet;
  const policyFamilies = sortedTextList(policy?.requiredAnchorFamilies);

  addReason(reasons, !hasText(policy?.policyRef), 'anchoring_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'anchoring_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'anchoring_policy_not_active');
  addReason(reasons, policy?.metadataOnly !== true, 'anchoring_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.sourcePayloadAccessible !== false, 'source_payload_access_forbidden');
  addReason(reasons, policy?.dagPayloadStored !== false, 'dag_payload_storage_forbidden_before_activation');
  addReason(reasons, policy?.crossCheckedEnabled === true, 'crosschecked_anchor_forbidden_before_activation');
  addReason(reasons, policy?.rootBackedProductionClaim === true, 'root_backed_production_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'anchoring_policy_time_invalid');
  addReason(reasons, hlcTuple(policy?.validUntilHlc) === null, 'anchoring_policy_expiry_invalid');
  addReason(reasons, hlcBefore(policy?.evaluatedAtHlc, anchorSet?.requestedAtHlc), 'anchoring_policy_before_request');
  addReason(reasons, hlcNotAfter(policy?.validUntilHlc, anchorSet?.generatedAtHlc), 'anchoring_policy_expired');
  addReason(reasons, !includesAll(REQUIRED_ANCHOR_FAMILIES, policyFamilies), 'anchoring_policy_family_coverage_incomplete');

  for (const family of REQUIRED_ANCHOR_FAMILIES) {
    addReason(reasons, !requiredFamilies.includes(family), `required_anchor_family_missing:${family}`);
  }
  for (const family of requiredFamilies) {
    addReason(reasons, !REQUIRED_ANCHOR_FAMILIES.includes(family), `anchor_family_unsupported:${family}`);
  }
}

function evaluateAdapterBoundary(adapterBoundary, reasons) {
  addReason(reasons, adapterBoundary?.productionTrustActivation === true, 'adapter_production_activation_forbidden');
  addReason(reasons, adapterBoundary?.localSimulationUsed === true, 'adapter_local_simulation_forbidden');
  addReason(reasons, adapterBoundary?.cachedOutcomeUsed === true, 'adapter_cached_outcome_forbidden');
  addReason(reasons, adapterBoundary?.overrideUsed === true, 'adapter_override_forbidden');
}

function evaluateHumanAuthorization(input, reasons) {
  const authorization = input?.humanAuthorization;
  addReason(reasons, !hasText(authorization?.reviewerDid), 'human_authorization_reviewer_absent');
  addReason(reasons, !HUMAN_AUTHORIZATION_STATUSES.has(authorization?.status), 'human_authorization_not_approved');
  addReason(reasons, !isDigest(authorization?.authorizationHash), 'human_authorization_hash_invalid');
  addReason(reasons, hlcTuple(authorization?.authorizedAtHlc) === null, 'human_authorization_time_invalid');
  addReason(reasons, hlcAfter(authorization?.authorizedAtHlc, input?.anchorSet?.generatedAtHlc), 'human_authorization_after_anchor_generation');
  addReason(reasons, authorization?.aiFinalAuthorityRejected !== true, 'human_authorization_ai_boundary_absent');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined) {
    return;
  }
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_assistance_final_authority_forbidden');
  addReason(reasons, aiAssistance.used === true && aiAssistance.reviewedByHuman !== true, 'ai_assistance_human_review_absent');
  addReason(reasons, aiAssistance.used === true && !isDigest(aiAssistance.scopeHash), 'ai_assistance_scope_hash_invalid');
}

function evaluateFamilyEvidence(anchor, reasons) {
  const requiredFields = FAMILY_REQUIRED_HASH_FIELDS.get(anchor?.family);
  if (requiredFields === undefined) {
    return;
  }
  for (const field of requiredFields) {
    addReason(
      reasons,
      !isDigest(anchor?.familyEvidence?.[field]),
      `anchor_family_evidence_hash_invalid:${anchor?.anchorRef ?? 'unknown'}:${field}`,
    );
  }
}

function evaluateParticipantConsent(anchor, input, consentByRef, reasons) {
  if (anchor?.participantLinked !== true) {
    return;
  }

  addReason(reasons, !hasText(anchor?.consentRef), `participant_consent_ref_absent:${anchor?.anchorRef ?? 'unknown'}`);
  const consent = consentByRef.get(anchor?.consentRef);
  addReason(reasons, consent === undefined, `participant_consent_absent:${anchor?.anchorRef ?? 'unknown'}`);
  addReason(
    reasons,
    consent !== undefined && consent.status !== 'active',
    `participant_consent_not_active:${anchor.anchorRef}`,
  );
  addReason(
    reasons,
    consent !== undefined && consent.revoked === true,
    `participant_consent_revoked:${anchor.anchorRef}`,
  );
  addReason(
    reasons,
    consent !== undefined && !CONSENT_SCOPES.has(consent.scope),
    `participant_consent_scope_invalid:${anchor.anchorRef}`,
  );
  addReason(
    reasons,
    consent !== undefined && !isDigest(consent.participantCodeHash),
    `participant_consent_code_hash_invalid:${anchor.anchorRef}`,
  );
  addReason(
    reasons,
    consent !== undefined && !isDigest(consent.consentReceiptHash),
    `participant_consent_receipt_hash_invalid:${anchor.anchorRef}`,
  );
  addReason(
    reasons,
    consent !== undefined && consentExpired(consent, input.anchorSet),
    `participant_consent_expired:${anchor.anchorRef}`,
  );
}

function evaluateAnchorRecord(anchor, input, consentByRef, reasons) {
  const anchorRef = anchor?.anchorRef ?? 'unknown';
  const boundary = anchor?.boundary;

  addReason(reasons, !hasText(anchor?.anchorRef), 'anchor_ref_absent');
  addReason(reasons, !REQUIRED_ANCHOR_FAMILIES.includes(anchor?.family), `anchor_family_invalid:${anchorRef}`);
  addReason(reasons, !hasText(anchor?.artifactType), `anchor_artifact_type_absent:${anchorRef}`);
  addReason(reasons, !hasText(anchor?.artifactRef), `anchor_artifact_ref_absent:${anchorRef}`);
  addReason(reasons, !isDigest(anchor?.artifactHash), `anchor_artifact_hash_invalid:${anchorRef}`);
  addReason(reasons, !isDigest(anchor?.actionHash), `anchor_action_hash_invalid:${anchorRef}`);
  addReason(reasons, !isDigest(anchor?.custodyDigest), `anchor_custody_digest_invalid:${anchorRef}`);
  addReason(reasons, !CLASSIFICATIONS.has(anchor?.classification), `anchor_classification_invalid:${anchorRef}`);
  addReason(reasons, !sortedTextList(anchor?.sensitivityTags).includes('metadata_only'), `anchor_metadata_tag_absent:${anchorRef}`);
  addReason(reasons, hlcTuple(anchor?.hlcTimestamp) === null, `anchor_hlc_invalid:${anchorRef}`);
  addReason(reasons, hlcAfter(anchor?.hlcTimestamp, input?.anchorSet?.generatedAtHlc), `anchor_hlc_after_generation:${anchorRef}`);
  addReason(reasons, !hasText(anchor?.sourceSystem), `anchor_source_system_absent:${anchorRef}`);
  addReason(reasons, boundary?.metadataOnly !== true, `anchor_metadata_boundary_invalid:${anchorRef}`);
  addReason(reasons, boundary?.rawContentExcluded !== true, `anchor_raw_content_boundary_invalid:${anchorRef}`);
  addReason(reasons, boundary?.sourcePayloadExcluded !== true, `anchor_source_payload_boundary_invalid:${anchorRef}`);
  addReason(reasons, boundary?.directIdentifiersExcluded !== true, `anchor_direct_identifier_boundary_invalid:${anchorRef}`);
  addReason(reasons, boundary?.secretMaterialExcluded !== true, `anchor_secret_boundary_invalid:${anchorRef}`);

  evaluateFamilyEvidence(anchor, reasons);
  evaluateParticipantConsent(anchor, input, consentByRef, reasons);
}

function sanitizeAnchor(anchor) {
  return {
    actionHash: anchor.actionHash,
    anchorRef: anchor.anchorRef,
    artifactHash: anchor.artifactHash,
    artifactRef: anchor.artifactRef,
    artifactType: anchor.artifactType,
    classification: anchor.classification,
    custodyDigest: anchor.custodyDigest,
    family: anchor.family,
    familyEvidenceHash: sha256Hex({
      family: anchor.family,
      familyEvidence: anchor.familyEvidence,
    }),
    hlcTimestamp: anchor.hlcTimestamp,
    participantLinked: anchor.participantLinked === true,
    sensitivityTags: sortedTextList(anchor.sensitivityTags),
  };
}

function buildAnchorPackage(input, anchors) {
  const sanitizedAnchors = anchors
    .map((anchor) => sanitizeAnchor(anchor))
    .sort((left, right) => `${left.family}:${left.anchorRef}`.localeCompare(`${right.family}:${right.anchorRef}`));
  const anchorFamilies = sortedTextList(sanitizedAnchors.map((anchor) => anchor.family));
  const packageHash = sha256Hex({
    anchorFamilies,
    anchorSet: {
      anchorSetRef: input.anchorSet.anchorSetRef,
      generatedAtHlc: input.anchorSet.generatedAtHlc,
      purpose: input.anchorSet.purpose,
    },
    anchors: sanitizedAnchors,
    humanAuthorizationHash: input.humanAuthorization.authorizationHash,
    policyHash: input.anchoringPolicy.policyHash,
    tenantId: input.tenantId,
  });

  return {
    schema: 'cybermedica.exochain_anchor_package.v1',
    packageId: `cma_${packageHash.slice(0, 32)}`,
    tenantId: input.tenantId,
    anchorSetRef: input.anchorSet.anchorSetRef,
    purpose: input.anchorSet.purpose,
    policyRef: input.anchoringPolicy.policyRef,
    policyHash: input.anchoringPolicy.policyHash,
    anchorFamilies,
    anchors: sanitizedAnchors,
    packageHash,
    metadataOnly: true,
    protectedContentAnchored: false,
    externalAnchoringActive: false,
    crossCheckedBackedClaim: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
    activationGateIds: [CROSSCHECKED_ANCHORING_GATE_ID],
    adapterBoundary: {
      decisionForumVerified: input.adapterBoundary?.decisionForumVerified === true,
      gatewayVerified: input.adapterBoundary?.gatewayVerified === true,
      nodeReceiptVerified: input.adapterBoundary?.nodeReceiptVerified === true,
      rootBundleVerified: input.adapterBoundary?.rootBundleVerified === true,
      productionTrustActivation: false,
    },
    humanAuthorizationHash: input.humanAuthorization.authorizationHash,
    custodyDigest: input.custodyDigest,
    exochainPrimitiveRefs: EXOCHAIN_PRIMITIVE_REFS,
  };
}

function buildReceipt(input, anchorPackage) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'exochain_anchor_package',
    artifactVersion: input.anchorSet.anchorSetRef,
    artifactHash: anchorPackage.packageHash,
    classification: 'restricted_metadata_only',
    hlcTimestamp: input.anchorSet.generatedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['exochain_anchor_metadata', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateExochainAnchoring(input) {
  assertMetadataOnly(input);

  const reasons = [];
  const anchors = Array.isArray(input?.anchors) ? input.anchors : [];
  const consentByRef = consentMatrixByRef(input?.participantConsentMatrix);
  const requiredFamilies = sortedTextList(anchors.map((anchor) => anchor?.family));

  evaluateTenantActorAuthority(input, reasons);
  evaluateAnchorSet(input, reasons);
  evaluateAnchoringPolicy(input, requiredFamilies, reasons);
  evaluateAdapterBoundary(input?.adapterBoundary, reasons);
  evaluateHumanAuthorization(input, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, anchors.length === 0, 'anchors_absent');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  for (const anchor of anchors) {
    evaluateAnchorRecord(anchor, input, consentByRef, reasons);
  }

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: EXOCHAIN_ANCHORING_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      anchorPackage: null,
      receipt: null,
      activationGateIds: [CROSSCHECKED_ANCHORING_GATE_ID],
    };
  }

  const anchorPackage = buildAnchorPackage(input, anchors);
  return {
    schema: EXOCHAIN_ANCHORING_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    anchorPackage,
    receipt: buildReceipt(input, anchorPackage),
  };
}
