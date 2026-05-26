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

import { canonicalize, createEvidenceReceipt, evaluateGovernedAction, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;

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

function validateProtectedContentBoundary(input) {
  canonicalize(input?.artifacts ?? []);
}

function normalizeManifestArtifacts(artifacts) {
  if (!Array.isArray(artifacts)) {
    return [];
  }
  return artifacts
    .map((artifact) => {
      if (!isDigest(artifact.artifactHash)) {
        throw new Error('artifactHash must be a non-zero lowercase 64 hex character digest');
      }
      return {
        artifactHash: artifact.artifactHash,
        artifactType: artifact.artifactType,
        artifactVersion: artifact.artifactVersion,
        classification: artifact.classification,
        controlId: artifact.controlId,
        evidenceId: artifact.evidenceId,
        tenantScopedPseudonym: artifact.tenantScopedPseudonym,
      };
    })
    .sort((left, right) => `${left.controlId}:${left.evidenceId}`.localeCompare(`${right.controlId}:${right.evidenceId}`));
}

function evaluateExportGrant(input, reasons) {
  addReason(reasons, input?.exportGrant?.status !== 'active', 'export_grant_not_active');
  addReason(reasons, input?.exportGrant?.scope !== 'sponsor_diligence_export', 'export_grant_scope_invalid');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  addReason(reasons, !Array.isArray(input?.artifacts) || input.artifacts.length === 0, 'export_artifacts_absent');
}

function buildReceipt(input, manifestId, manifestArtifacts) {
  const artifactHash = sha256Hex({
    manifestId,
    recipientTenantId: input.recipientTenantId,
    artifacts: manifestArtifacts,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'sponsor_cro_diligence_export',
    artifactVersion: `${input.recipientTenantId}@${input.manifestHlc.physicalMs}.${input.manifestHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.manifestHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['sponsor_diligence', 'metadata_only', 'quality_evidence'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function buildDiligenceExportManifest(input) {
  validateProtectedContentBoundary(input);
  const manifestArtifacts = normalizeManifestArtifacts(input?.artifacts);
  const governedDecision = evaluateGovernedAction({
    action: 'sponsor_export',
    tenantId: input?.tenantId,
    targetTenantId: input?.targetTenantId,
    actor: input?.actor,
    authority: input?.authority,
    consent: input?.consent,
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
  });
  const reasons = [...governedDecision.reasons];
  evaluateExportGrant(input, reasons);

  const denied = reasons.length > 0;
  const manifestId = `cmde_${sha256Hex({
    tenantId: input?.tenantId,
    recipientTenantId: input?.recipientTenantId,
    manifestHlc: input?.manifestHlc,
    artifacts: manifestArtifacts,
  }).slice(0, 32)}`;

  return {
    schema: 'cybermedica.diligence_export_manifest.v1',
    manifestId,
    decision: denied ? 'denied' : 'permitted',
    failClosed: denied,
    reasons: [...new Set(reasons)].sort(),
    tenantId: input?.tenantId,
    recipientTenantId: input?.recipientTenantId,
    manifestArtifacts,
    trustState: 'inactive',
    exochainProductionClaim: false,
    receipt: denied ? null : buildReceipt(input, manifestId, manifestArtifacts),
  };
}
