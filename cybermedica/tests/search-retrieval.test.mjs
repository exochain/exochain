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
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_4 = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

async function loadSearchRetrieval() {
  try {
    return await import('../src/search-retrieval.mjs');
  } catch (error) {
    assert.fail(`CyberMedica search retrieval module must exist and load: ${error.message}`);
  }
}

const REQUIRED_FAMILIES = ['audits', 'capas', 'controls', 'decisions', 'documents', 'evidence', 'risks', 'sites'];

function searchInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'principal_investigator'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['search_retrieve', 'read'],
      authorityChainHash: DIGEST_A,
    },
    consent: {
      required: false,
      status: 'not_required',
      revoked: false,
      consentRef: 'metadata-search-no-participant-payload',
    },
    query: {
      queryId: 'search-quality-diligence-2026-05',
      queryHash: DIGEST_B,
      requestedAtHlc: { physicalMs: 1794000000000, logical: 0 },
      requestedFamilies: REQUIRED_FAMILIES,
      maxResults: 20,
      purpose: 'quality_system_diligence_review',
      filters: {
        siteRefs: ['site-alpha'],
        controlRefs: ['CM-QMS-CONSENT-003', 'CM-QMS-AUDIT-002'],
        protocolRefs: ['protocol-alpha'],
        lifecycleStates: ['active', 'approved', 'open', 'closed'],
      },
      searchIndex: {
        indexRef: 'cm-search-index-site-alpha-2026-05',
        indexHash: DIGEST_C,
        builtAtHlc: { physicalMs: 1793900000000, logical: 4 },
        schemaVersion: 'cybermedica.search_index.v1',
        metadataOnly: true,
        payloadsExcluded: true,
      },
    },
    accessPolicy: {
      policyRef: 'site-alpha-quality-search-policy',
      evaluatedAtHlc: { physicalMs: 1794000000000, logical: 2 },
      allowedFamilies: REQUIRED_FAMILIES,
      allowedSiteRefs: ['site-alpha'],
      allowedRoleRefs: ['quality_manager', 'principal_investigator', 'sponsor_monitor'],
      allowedSensitivityTags: ['metadata_only', 'quality_evidence', 'qms', 'sponsor_confidential_metadata'],
      allowParticipantLinked: false,
      metadataOnly: true,
      sourcePayloadAccessible: false,
      resultDisclosureRequired: true,
    },
    disclosureLog: {
      logId: 'search-disclosure-log-2026-05',
      loggedAtHlc: { physicalMs: 1794000000000, logical: 3 },
      disclosureLogHash: DIGEST_D,
      purpose: 'quality_system_diligence_review',
      recipientClass: 'site_quality_council',
      includesRawContent: false,
    },
    records: searchRecords(),
  };
}

function baseRecord(overrides) {
  return {
    tenantId: 'tenant-site-alpha',
    siteRef: 'site-alpha',
    artifactHash: DIGEST_E,
    metadataHash: DIGEST_F,
    custodyDigest: DIGEST_1,
    titleHash: DIGEST_2,
    updatedAtHlc: { physicalMs: 1793800000000, logical: 0 },
    matchedQueryHash: DIGEST_B,
    matchBasisPoints: 8000,
    sensitivityTags: ['metadata_only', 'quality_evidence', 'qms'],
    allowedRoleRefs: ['quality_manager'],
    participantLinked: false,
    lifecycleState: 'active',
    linkedControlRefs: ['CM-QMS-CONSENT-003'],
    linkedEvidenceRefs: ['evidence-alpha'],
    linkedDecisionRefs: [],
    linkedRiskRefs: [],
    linkedCapaRefs: [],
    linkedAuditRefs: [],
    linkedDocumentRefs: [],
    linkedProtocolRefs: ['protocol-alpha'],
    linkedSiteRefs: ['site-alpha'],
    boundary: {
      metadataOnly: true,
      sourcePayloadAnchored: false,
      rawContentExcluded: true,
    },
    ...overrides,
  };
}

function searchRecords() {
  return [
    baseRecord({
      recordId: 'doc-controlled-consent',
      family: 'documents',
      artifactHash: DIGEST_A,
      matchBasisPoints: 9300,
      lifecycleState: 'approved',
      linkedDocumentRefs: ['doc-consent-v3'],
    }),
    baseRecord({
      recordId: 'control-consent-readiness',
      family: 'controls',
      artifactHash: DIGEST_B,
      matchBasisPoints: 9700,
    }),
    baseRecord({
      recordId: 'evidence-consent-readiness',
      family: 'evidence',
      artifactHash: DIGEST_C,
      matchBasisPoints: 9500,
      linkedEvidenceRefs: ['evidence-consent-readiness'],
    }),
    baseRecord({
      recordId: 'risk-consent-version-use',
      family: 'risks',
      artifactHash: DIGEST_D,
      matchBasisPoints: 9100,
      linkedRiskRefs: ['risk-consent-version-use'],
    }),
    baseRecord({
      recordId: 'capa-consent-training-gap',
      family: 'capas',
      artifactHash: DIGEST_E,
      matchBasisPoints: 9000,
      linkedCapaRefs: ['capa-consent-training-gap'],
      lifecycleState: 'open',
    }),
    baseRecord({
      recordId: 'decision-consent-readiness',
      family: 'decisions',
      artifactHash: DIGEST_F,
      matchBasisPoints: 8900,
      linkedDecisionRefs: ['dfm-consent-readiness'],
      lifecycleState: 'closed',
    }),
    baseRecord({
      recordId: 'audit-consent-readiness',
      family: 'audits',
      artifactHash: DIGEST_1,
      matchBasisPoints: 8800,
      linkedAuditRefs: ['audit-consent-readiness'],
      linkedControlRefs: ['CM-QMS-AUDIT-002'],
      lifecycleState: 'closed',
    }),
    baseRecord({
      recordId: 'site-alpha-passport',
      family: 'sites',
      artifactHash: DIGEST_2,
      matchBasisPoints: 8700,
      linkedSiteRefs: ['site-alpha'],
    }),
  ];
}

test('search retrieval returns deterministic metadata-only results across required object families', async () => {
  const { evaluateSearchRetrieval } = await loadSearchRetrieval();

  const resultA = evaluateSearchRetrieval(searchInput());
  const resultB = evaluateSearchRetrieval({
    ...searchInput(),
    query: {
      ...searchInput().query,
      requestedFamilies: [...searchInput().query.requestedFamilies].reverse(),
      filters: {
        ...searchInput().query.filters,
        siteRefs: [...searchInput().query.filters.siteRefs].reverse(),
        controlRefs: [...searchInput().query.filters.controlRefs].reverse(),
        lifecycleStates: [...searchInput().query.filters.lifecycleStates].reverse(),
      },
    },
    records: [...searchInput().records].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.resultCount, 8);
  assert.equal(resultA.suppressedResultCount, 0);
  assert.equal(resultA.omittedByFilterCount, 0);
  assert.deepEqual(resultA.objectFamiliesCovered, REQUIRED_FAMILIES);
  assert.deepEqual(
    resultA.results.map((record) => record.recordId),
    [
      'control-consent-readiness',
      'evidence-consent-readiness',
      'doc-controlled-consent',
      'risk-consent-version-use',
      'capa-consent-training-gap',
      'decision-consent-readiness',
      'audit-consent-readiness',
      'site-alpha-passport',
    ],
  );
  assert.deepEqual(Object.keys(resultA.results[0]), [
    'artifactHash',
    'custodyDigest',
    'family',
    'linkedAuditRefs',
    'linkedCapaRefs',
    'linkedControlRefs',
    'linkedDecisionRefs',
    'linkedDocumentRefs',
    'linkedEvidenceRefs',
    'linkedRiskRefs',
    'linkedSiteRefs',
    'matchBasisPoints',
    'metadataHash',
    'recordId',
    'sensitivityTags',
    'siteRef',
    'updatedAtHlc',
  ]);
  assert.equal(resultA.results[0].artifactHash, DIGEST_B);
  assert.equal(resultA.exochainProductionClaim, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.resultSetHash, resultB.resultSetHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
});

test('search retrieval suppresses access-restricted candidates without leaking record identifiers', async () => {
  const { evaluateSearchRetrieval } = await loadSearchRetrieval();
  const restricted = [
    baseRecord({
      recordId: 'site-beta-audit-hidden',
      family: 'audits',
      siteRef: 'site-beta',
      matchBasisPoints: 9900,
      linkedSiteRefs: ['site-beta'],
    }),
    baseRecord({
      recordId: 'sponsor-contract-hidden',
      family: 'documents',
      sensitivityTags: ['metadata_only', 'privileged_metadata'],
      matchBasisPoints: 9800,
    }),
    baseRecord({
      recordId: 'participant-consent-hidden',
      family: 'evidence',
      participantLinked: true,
      matchBasisPoints: 9700,
    }),
  ];

  const result = evaluateSearchRetrieval({
    ...searchInput(),
    query: {
      ...searchInput().query,
      maxResults: 4,
      filters: { siteRefs: ['site-alpha'] },
    },
    records: [...restricted, ...searchInput().records],
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.resultCount, 4);
  assert.equal(result.suppressedResultCount, 3);
  assert.equal(result.suppressedBreakdown.site, 1);
  assert.equal(result.suppressedBreakdown.sensitivity, 1);
  assert.equal(result.suppressedBreakdown.participant, 1);
  assert.equal(result.suppressedRecordRefs, undefined);
  assert.deepEqual(
    result.results.map((record) => record.recordId),
    [
      'control-consent-readiness',
      'evidence-consent-readiness',
      'doc-controlled-consent',
      'risk-consent-version-use',
    ],
  );
});

test('search retrieval fails closed for unsafe authority query policy and index defects', async () => {
  const { evaluateSearchRetrieval } = await loadSearchRetrieval();

  const denied = evaluateSearchRetrieval({
    ...searchInput(),
    actor: { did: 'did:exo:ai-search-agent', kind: 'ai_agent', roleRefs: ['quality_manager'] },
    authority: { valid: true, revoked: false, expired: false, permissions: ['read'], authorityChainHash: '' },
    query: {
      ...searchInput().query,
      queryHash: '',
      requestedFamilies: ['controls', 'documents', 'unbounded_payloads'],
      maxResults: 0,
      searchIndex: {
        ...searchInput().query.searchIndex,
        metadataOnly: false,
        payloadsExcluded: false,
      },
    },
    accessPolicy: {
      ...searchInput().accessPolicy,
      allowedFamilies: ['controls'],
      allowedRoleRefs: [],
      metadataOnly: false,
      sourcePayloadAccessible: true,
    },
    disclosureLog: {
      ...searchInput().disclosureLog,
      disclosureLogHash: '',
      includesRawContent: true,
    },
    records: [
      {
        ...searchInput().records[0],
        matchedQueryHash: DIGEST_3,
        matchBasisPoints: 10001,
        boundary: {
          metadataOnly: false,
          sourcePayloadAnchored: true,
          rawContentExcluded: false,
        },
      },
    ],
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('query_hash_invalid'));
  assert.ok(denied.reasons.includes('requested_family_unsupported:unbounded_payloads'));
  assert.ok(denied.reasons.includes('requested_family_not_allowed:unbounded_payloads'));
  assert.ok(denied.reasons.includes('query_max_results_invalid'));
  assert.ok(denied.reasons.includes('search_index_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('search_index_payload_boundary_invalid'));
  assert.ok(denied.reasons.includes('access_policy_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('access_policy_payload_access_forbidden'));
  assert.ok(denied.reasons.includes('access_policy_role_refs_absent'));
  assert.ok(denied.reasons.includes('disclosure_log_hash_invalid'));
  assert.ok(denied.reasons.includes('disclosure_log_raw_content_forbidden'));
  assert.ok(denied.reasons.includes('record_match_hash_mismatch:doc-controlled-consent'));
  assert.ok(denied.reasons.includes('record_match_basis_points_invalid:doc-controlled-consent'));
  assert.ok(denied.reasons.includes('record_metadata_boundary_invalid:doc-controlled-consent'));
  assert.ok(denied.reasons.includes('record_payload_boundary_invalid:doc-controlled-consent'));
});

test('search retrieval validates HLC ordering and same-tick monotonic clocks', async () => {
  const { evaluateSearchRetrieval } = await loadSearchRetrieval();

  const sameTick = evaluateSearchRetrieval({
    ...searchInput(),
    query: {
      ...searchInput().query,
      requestedAtHlc: { physicalMs: 1794000000000, logical: 2 },
      searchIndex: {
        ...searchInput().query.searchIndex,
        builtAtHlc: { physicalMs: 1794000000000, logical: 1 },
      },
    },
    accessPolicy: {
      ...searchInput().accessPolicy,
      evaluatedAtHlc: { physicalMs: 1794000000000, logical: 2 },
    },
    disclosureLog: {
      ...searchInput().disclosureLog,
      loggedAtHlc: { physicalMs: 1794000000000, logical: 4 },
    },
  });

  assert.equal(sameTick.decision, 'permitted');

  const denied = evaluateSearchRetrieval({
    ...searchInput(),
    query: {
      ...searchInput().query,
      requestedAtHlc: { physicalMs: 1794000000000, logical: -1 },
      searchIndex: {
        ...searchInput().query.searchIndex,
        builtAtHlc: { physicalMs: 1794000000000, logical: 5 },
      },
    },
    accessPolicy: {
      ...searchInput().accessPolicy,
      evaluatedAtHlc: { physicalMs: 1793999999999, logical: 0 },
    },
    disclosureLog: {
      ...searchInput().disclosureLog,
      loggedAtHlc: { physicalMs: 1793999999998, logical: 0 },
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('query_request_time_invalid'));
  assert.ok(denied.reasons.includes('search_index_built_after_query'));
  assert.ok(denied.reasons.includes('access_policy_before_query'));
  assert.ok(denied.reasons.includes('disclosure_log_before_access_policy'));
});

test('search retrieval covers active participant consent role suppression filters and tie sorting', async () => {
  const { evaluateSearchRetrieval } = await loadSearchRetrieval();

  const result = evaluateSearchRetrieval({
    ...searchInput(),
    consent: {
      required: true,
      status: 'active',
      revoked: false,
      consentRef: 'participant-search-consent-ref',
    },
    query: {
      ...searchInput().query,
      requestedFamilies: ['controls', 'evidence'],
      maxResults: 10,
      filters: {
        siteRefs: ['site-alpha'],
        controlRefs: ['CM-QMS-CONSENT-003'],
        protocolRefs: ['protocol-alpha'],
        lifecycleStates: ['active'],
      },
    },
    accessPolicy: {
      ...searchInput().accessPolicy,
      allowedFamilies: ['controls', 'documents', 'evidence'],
      allowedSiteRefs: ['site-alpha', 'site-beta'],
      allowedRoleRefs: ['quality_manager', 'auditor'],
      allowParticipantLinked: true,
    },
    records: [
      baseRecord({
        recordId: 'z-participant-evidence',
        family: 'evidence',
        participantLinked: true,
        matchBasisPoints: 8200,
      }),
      baseRecord({
        recordId: 'a-control-tie',
        family: 'controls',
        artifactHash: DIGEST_3,
        matchBasisPoints: 8200,
      }),
      baseRecord({
        recordId: 'role-suppressed-control',
        family: 'controls',
        allowedRoleRefs: ['auditor'],
        matchBasisPoints: 9900,
      }),
      baseRecord({
        recordId: 'site-filtered-control',
        family: 'controls',
        siteRef: 'site-beta',
        linkedSiteRefs: ['site-beta'],
        matchBasisPoints: 9800,
      }),
      baseRecord({
        recordId: 'control-filtered-evidence',
        family: 'evidence',
        linkedControlRefs: ['CM-QMS-OTHER-999'],
        matchBasisPoints: 9700,
      }),
      baseRecord({
        recordId: 'protocol-filtered-evidence',
        family: 'evidence',
        linkedProtocolRefs: ['protocol-beta'],
        matchBasisPoints: 9600,
      }),
      baseRecord({
        recordId: 'lifecycle-filtered-evidence',
        family: 'evidence',
        lifecycleState: 'archived',
        matchBasisPoints: 9500,
      }),
      baseRecord({
        recordId: 'not-requested-document',
        family: 'documents',
        matchBasisPoints: 9400,
      }),
    ],
  });

  assert.equal(result.decision, 'permitted');
  assert.equal(result.suppressedBreakdown.role, 1);
  assert.equal(result.suppressedBreakdown.family, 1);
  assert.equal(result.omittedByFilterCount, 4);
  assert.deepEqual(
    result.results.map((record) => record.recordId),
    ['a-control-tie', 'z-participant-evidence'],
  );

  const metadataOnlyParticipant = evaluateSearchRetrieval({
    ...searchInput(),
    query: {
      ...searchInput().query,
      requestedFamilies: ['evidence'],
      filters: {
        siteRefs: ['site-alpha'],
        controlRefs: ['CM-QMS-CONSENT-003'],
        protocolRefs: ['protocol-alpha'],
        lifecycleStates: ['active'],
      },
    },
    accessPolicy: {
      ...searchInput().accessPolicy,
      allowedFamilies: ['evidence'],
      allowParticipantLinked: true,
    },
    records: [
      baseRecord({
        recordId: 'participant-metadata-only-evidence',
        family: 'evidence',
        participantLinked: true,
      }),
    ],
  });

  assert.equal(metadataOnlyParticipant.decision, 'permitted');
  assert.equal(metadataOnlyParticipant.resultCount, 1);
});

test('search retrieval rejects raw query result and protected source content before receipts', async () => {
  const { evaluateSearchRetrieval } = await loadSearchRetrieval();

  assert.throws(
    () =>
      evaluateSearchRetrieval({
        ...searchInput(),
        query: {
          ...searchInput().query,
          queryText: 'show participant Alice Example consent evidence',
        },
      }),
    /raw search content|protected content/i,
  );

  assert.throws(
    () =>
      evaluateSearchRetrieval({
        ...searchInput(),
        records: [
          {
            ...searchInput().records[0],
            resultSnippet: 'Participant Alice Example consent source document text',
          },
        ],
      }),
    /raw search content|protected content/i,
  );
});
