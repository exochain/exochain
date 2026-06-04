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

import assert from 'node:assert/strict';
import { test } from 'node:test';

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

const REQUIRED_SOURCE_FAMILIES = Object.freeze([
  'consent_source',
  'device_output',
  'ecrf_entry',
  'imaging_report',
  'lab_result',
  'participant_reported_outcome',
  'product_accountability_source',
  'query_response',
  'safety_source',
  'source_worksheet',
]);

const REQUIRED_TRACEABILITY_DOMAINS = Object.freeze([
  'alcoac_evidence',
  'attributable_capture',
  'correction_audit',
  'crf_requirement_mapping',
  'discrepancy_management',
  'export_eligibility',
  'monitor_review',
  'participant_code_boundary',
  'retention_access',
  'source_to_crf_reconciliation',
]);

async function loadSourceDataTraceability() {
  try {
    return await import('../src/source-data-traceability.mjs');
  } catch (error) {
    assert.fail(`CyberMedica source-data-traceability module must exist and load: ${error.message}`);
  }
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function sourceRecord(sourceFamily, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    sourceFamily,
    sourceRecordRef: `source-${sourceFamily.replaceAll('_', '-')}-${index + 1}`,
    participantCodeHash: hashes[(index + 1) % hashes.length],
    sourceRecordHash: hashes[index % hashes.length],
    sourceEvidenceHash: hashes[(index + 2) % hashes.length],
    capturedAtHlc: { physicalMs: 1801000000000 + index, logical: 0 },
    recordedAtHlc: { physicalMs: 1801000001000 + index, logical: 0 },
    attributableActorDid: `did:exo:source-capture-owner-${index}`,
    consentRef: 'consent-process-alpha-001',
    sourceSystemRef: 'cybermedica-source-store',
    participantIdentifiersSuppressed: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function sourceRecords() {
  return REQUIRED_SOURCE_FAMILIES.map((sourceFamily, index) => sourceRecord(sourceFamily, index));
}

function crfMapping(source, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    sourceFamily: source.sourceFamily,
    sourceRecordRef: source.sourceRecordRef,
    crfFieldRef: `crf-field-${source.sourceFamily.replaceAll('_', '-')}`,
    crfRequirementRef: `crf-req-${String(index + 1).padStart(2, '0')}`,
    sourceRecordHash: source.sourceRecordHash,
    crfValueHash: hashes[(index + 3) % hashes.length],
    mappingStatus: 'verified',
    discrepancyStatus: 'none',
    queryRef: null,
    reviewedAtHlc: { physicalMs: 1801000010000 + index, logical: 0 },
    reviewerDid: `did:exo:crf-reviewer-${index}`,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function crfMappings(records = sourceRecords()) {
  return records.map((source, index) => crfMapping(source, index));
}

function sourceTraceabilityInput(overrides = {}) {
  const records = sourceRecords();
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:source-data-owner-alpha',
      kind: 'human',
      roleRefs: ['clinical_research_coordinator', 'source_data_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_source_data_traceability', 'read'],
      authorityChainHash: DIGEST_A,
    },
    traceabilityPlan: {
      planRef: 'source-data-traceability-plan-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      studyRef: 'study-cardiac-alpha',
      activeProtocolVersionRef: 'protocol-version-cardiac-alpha-2',
      requiredSourceFamilies: REQUIRED_SOURCE_FAMILIES,
      requiredTraceabilityDomains: REQUIRED_TRACEABILITY_DOMAINS,
      crfMediaRef: 'ecrf-media-alpha',
      ecrfSystemValidationRef: 'esv-ecrf-alpha',
      sourceWorksheetTemplateHash: DIGEST_B,
      crfCompletionGuidelineHash: DIGEST_C,
      discrepancyProcedureHash: DIGEST_D,
      retentionPolicyHash: DIGEST_E,
      reviewedAtHlc: { physicalMs: 1801000000000, logical: 1 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    sourceRecords: records,
    crfMappings: crfMappings(records),
    traceabilityControls: {
      traceabilityDomainEvidence: REQUIRED_TRACEABILITY_DOMAINS.map((domainRef, index) => ({
        domainRef,
        status: 'verified',
        evidenceHash: index % 2 === 0 ? DIGEST_F : DIGEST_A,
        reviewedAtHlc: { physicalMs: 1801000020000 + index, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      })),
      openQueryCount: 0,
      openCriticalQueryCount: 0,
      unresolvedDiscrepancyCount: 0,
      correctionLedgerHash: DIGEST_B,
      allCorrectionsApproved: true,
      monitorReviewHash: DIGEST_C,
      monitorReviewComplete: true,
      participantCodeBoundaryHash: DIGEST_D,
      exportEligibilityHash: DIGEST_E,
      sourceToCrfReconciliationHash: DIGEST_F,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    review: {
      humanReviewerDid: 'did:exo:principal-investigator-alpha',
      reviewDecision: 'source_data_traceable',
      reviewedAtHlc: { physicalMs: 1801000030000, logical: 0 },
      evidenceBundleHash: DIGEST_F,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-source-data-traceability-alpha',
        workflowReceiptId: 'df-workflow-source-data-traceability-alpha',
      },
    },
    custodyDigest: DIGEST_D,
  };
  return mergeDeep(base, overrides);
}

test('source data traceability creates deterministic inactive CRF reconciliation receipts', async () => {
  const { evaluateSourceDataTraceability } = await loadSourceDataTraceability();

  const resultA = evaluateSourceDataTraceability(sourceTraceabilityInput());
  const inputB = sourceTraceabilityInput();
  inputB.traceabilityPlan.requiredSourceFamilies = [...inputB.traceabilityPlan.requiredSourceFamilies].reverse();
  inputB.traceabilityPlan.requiredTraceabilityDomains = [
    ...inputB.traceabilityPlan.requiredTraceabilityDomains,
  ].reverse();
  inputB.sourceRecords = [...inputB.sourceRecords].reverse();
  inputB.crfMappings = [...inputB.crfMappings].reverse();
  inputB.traceabilityControls.traceabilityDomainEvidence = [
    ...inputB.traceabilityControls.traceabilityDomainEvidence,
  ].reverse();
  const resultB = evaluateSourceDataTraceability(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.sourceDataTraceability.traceabilityStatus, 'traceable');
  assert.equal(resultA.sourceDataTraceability.trustState, 'inactive');
  assert.equal(resultA.sourceDataTraceability.exochainProductionClaim, false);
  assert.equal(resultA.sourceDataTraceability.sourceFamilyCoverageBasisPoints, 10000);
  assert.equal(resultA.sourceDataTraceability.crfMappingCoverageBasisPoints, 10000);
  assert.equal(resultA.sourceDataTraceability.traceabilityDomainCoverageBasisPoints, 10000);
  assert.equal(resultA.sourceDataTraceability.openQueryCount, 0);
  assert.equal(resultA.sourceDataTraceability.openCriticalQueryCount, 0);
  assert.equal(resultA.sourceDataTraceability.unresolvedDiscrepancyCount, 0);
  assert.deepEqual(resultA.sourceDataTraceability.sourceFamiliesCovered, REQUIRED_SOURCE_FAMILIES);
  assert.deepEqual(resultA.sourceDataTraceability.traceabilityDomainsCovered, REQUIRED_TRACEABILITY_DOMAINS);
  assert.equal(resultA.sourceDataTraceability.traceabilityId, resultB.sourceDataTraceability.traceabilityId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'source_data_traceability');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /participant alice|raw source|source document|crf value|medical record/iu);
});

test('source data traceability fails closed for CRF gaps discrepancies and unsafe participant boundaries', async () => {
  const { evaluateSourceDataTraceability } = await loadSourceDataTraceability();
  const baseRecords = sourceRecords();
  const result = evaluateSourceDataTraceability(
    sourceTraceabilityInput({
      actor: { did: 'did:exo:ai-source-data-reviewer-alpha', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: true,
        expired: false,
        permissions: ['read'],
        authorityChainHash: 'bad',
      },
      traceabilityPlan: {
        requiredSourceFamilies: REQUIRED_SOURCE_FAMILIES.filter((family) => family !== 'lab_result'),
        crfMediaRef: '',
        ecrfSystemValidationRef: '',
        productionTrustClaim: true,
      },
      sourceRecords: baseRecords
        .filter((record) => record.sourceFamily !== 'lab_result')
        .map((record) =>
          record.sourceFamily === 'source_worksheet'
            ? {
                ...record,
                participantIdentifiersSuppressed: false,
                recordedAtHlc: { physicalMs: 1800999999000, logical: 0 },
              }
            : record,
        ),
      crfMappings: crfMappings(baseRecords.filter((record) => record.sourceFamily !== 'lab_result')).map((mapping) =>
        mapping.sourceFamily === 'source_worksheet'
          ? {
              ...mapping,
              mappingStatus: 'pending',
              discrepancyStatus: 'open_critical',
              sourceRecordHash: DIGEST_F,
            }
          : mapping,
      ),
      traceabilityControls: {
        openQueryCount: 3,
        openCriticalQueryCount: 1,
        unresolvedDiscrepancyCount: 2,
        allCorrectionsApproved: false,
        monitorReviewComplete: false,
        sourceToCrfReconciliationHash: '',
      },
      review: {
        humanReviewerDid: '',
        reviewDecision: 'source_data_traceable',
        aiFinalAuthority: true,
        decisionForum: {
          verified: false,
          state: 'pending',
          humanGate: { verified: false },
          quorum: { status: 'not_met' },
          openChallenge: true,
        },
      },
      custodyDigest: 'not-a-digest',
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.sourceDataTraceability.traceabilityStatus, 'blocked');
  assert.equal(result.sourceDataTraceability.exochainProductionClaim, false);
  assert.equal(result.sourceDataTraceability.openCriticalQueryCount, 1);
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('source_data_traceability_authority_missing'));
  assert.ok(result.reasons.includes('authority_chain_revoked'));
  assert.ok(result.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(result.reasons.includes('required_source_family_missing:lab_result'));
  assert.ok(result.reasons.includes('source_family_record_missing:lab_result'));
  assert.ok(result.reasons.includes('crf_mapping_missing:lab_result'));
  assert.ok(result.reasons.includes('crf_media_ref_absent'));
  assert.ok(result.reasons.includes('ecrf_system_validation_ref_absent'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('source_record_participant_boundary_invalid:source_worksheet'));
  assert.ok(result.reasons.includes('source_record_recorded_before_capture:source_worksheet'));
  assert.ok(result.reasons.includes('crf_mapping_unverified:source_worksheet'));
  assert.ok(result.reasons.includes('crf_mapping_source_hash_mismatch:source_worksheet'));
  assert.ok(result.reasons.includes('critical_query_open'));
  assert.ok(result.reasons.includes('unresolved_discrepancy_present'));
  assert.ok(result.reasons.includes('corrections_not_approved'));
  assert.ok(result.reasons.includes('monitor_review_incomplete'));
  assert.ok(result.reasons.includes('source_to_crf_reconciliation_hash_invalid'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('decision_forum_not_verified'));
  assert.ok(result.reasons.includes('decision_forum_open_challenge'));
  assert.ok(result.reasons.includes('custody_digest_invalid'));
});

test('source data traceability rejects CRF mapping review before source record is recorded', async () => {
  const { evaluateSourceDataTraceability } = await loadSourceDataTraceability();
  const input = sourceTraceabilityInput();
  input.crfMappings = input.crfMappings.map((mapping) =>
    mapping.sourceFamily === 'lab_result'
      ? {
          ...mapping,
          reviewedAtHlc: { physicalMs: 1800999999000, logical: 0 },
        }
      : mapping,
  );

  const denied = evaluateSourceDataTraceability(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.sourceDataTraceability.traceabilityStatus, 'blocked');
  assert.ok(denied.reasons.includes('crf_mapping_review_before_source_recorded:lab_result'));
  assert.equal(denied.receipt, null);
});

test('source data traceability rejects raw source data CRF payloads and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateSourceDataTraceability } = await loadSourceDataTraceability();

  assert.throws(
    () =>
      evaluateSourceDataTraceability(
        sourceTraceabilityInput({
          sourceRecords: [
            {
              ...sourceRecords()[0],
              rawSourceDocumentText: 'source document states Participant Alice had a medical record event',
            },
            ...sourceRecords().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateSourceDataTraceability(
        sourceTraceabilityInput({
          crfMappings: [
            {
              ...crfMappings()[0],
              rawCrfValue: 'CRF value with direct participant detail',
            },
            ...crfMappings().slice(1),
          ],
        }),
      ),
    /raw source data content/i,
  );

  assert.throws(
    () =>
      evaluateSourceDataTraceability(
        sourceTraceabilityInput({
          traceabilityPlan: {
            apiKey: 'sk_live_source_data_secret',
          },
        }),
      ),
    /secret field/i,
  );
});
