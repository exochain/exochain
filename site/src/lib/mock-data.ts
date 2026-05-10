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

// Typed mocks for the EXOCHAIN web presence v0.
// IMPORTANT: every numeric metric or live-looking value derived from this
// module is labeled `mock` in the UI. Replace this module with API calls
// against exo-gateway in v0.5+.

import type {
  Actor,
  AVC,
  AuditEntry,
  ConsentRecord,
  Incident,
  NodeRecord,
  PolicyDomain,
  Proposal,
  Revocation,
  SettlementQuote,
  SettlementReceipt,
  TrustReceipt
} from './types';

const PUBKEY_PLACEHOLDER =
  'mldsa65:8f4e…b21c (truncated for display)';
const SIG_PLACEHOLDER =
  '0xa11d…f0c2 (truncated for display)';

export const mockActors: Actor[] = [
  {
    id: 'actor_001',
    type: 'human',
    displayName: 'Mara Linn',
    organization: 'Aperture Holdings',
    publicKey: PUBKEY_PLACEHOLDER,
    createdAt: '2026-02-04T10:14:00Z',
    status: 'active'
  },
  {
    id: 'actor_002',
    type: 'organization',
    displayName: 'Aperture Holdings',
    publicKey: PUBKEY_PLACEHOLDER,
    createdAt: '2026-02-04T10:11:00Z',
    status: 'active'
  },
  {
    id: 'actor_003',
    type: 'agent',
    displayName: 'Aperture Procurement Agent',
    organization: 'Aperture Holdings',
    parentActorId: 'actor_002',
    publicKey: PUBKEY_PLACEHOLDER,
    createdAt: '2026-02-12T18:00:00Z',
    status: 'active',
    notes: 'Delegated procurement authority for indirect spend.'
  },
  {
    id: 'actor_004',
    type: 'agent',
    displayName: 'Aperture Procurement Sub-Agent',
    organization: 'Aperture Holdings',
    parentActorId: 'actor_003',
    publicKey: PUBKEY_PLACEHOLDER,
    createdAt: '2026-03-01T09:30:00Z',
    status: 'active'
  },
  {
    id: 'actor_005',
    type: 'holon',
    displayName: 'North-Atlantic Custody Holon',
    publicKey: PUBKEY_PLACEHOLDER,
    createdAt: '2026-01-22T08:00:00Z',
    status: 'active',
    notes: 'Multi-org holon for cross-jurisdictional custody verification.'
  },
  {
    id: 'actor_006',
    type: 'validator',
    displayName: 'EXO-VAL-002',
    organization: 'Northwind Operations',
    publicKey: PUBKEY_PLACEHOLDER,
    createdAt: '2026-04-12T11:11:00Z',
    status: 'active'
  },
  {
    id: 'actor_007',
    type: 'service',
    displayName: 'Custody Verifier Daemon · v0.4',
    organization: 'Aperture Holdings',
    publicKey: PUBKEY_PLACEHOLDER,
    createdAt: '2026-03-10T15:00:00Z',
    status: 'active'
  }
];

export const mockPolicyDomains: PolicyDomain[] = [
  {
    id: 'pd_001',
    name: 'aperture.procurement',
    description:
      'Indirect spend procurement. Vendor catalog and PO ceiling enforced by policy expressions.',
    ownerActorId: 'actor_002'
  },
  {
    id: 'pd_002',
    name: 'aperture.research',
    description: 'Research-only data access. No write operations permitted.',
    ownerActorId: 'actor_002'
  },
  {
    id: 'pd_003',
    name: 'holon.northatlantic.custody',
    description: 'Cross-jurisdictional custody attestation policy domain.',
    ownerActorId: 'actor_005'
  }
];

export const mockAVCs: AVC[] = [
  {
    id: 'avc_001',
    subjectActorId: 'actor_003',
    issuerActorId: 'actor_002',
    policyDomainId: 'pd_001',
    scope: {
      actions: ['procure.search', 'procure.quote', 'procure.purchase'],
      constraints: { ceiling_usd: 50000, vendor_allowlist: 'aperture-tier1' }
    },
    notBefore: '2026-02-12T18:00:00Z',
    notAfter: '2026-08-12T18:00:00Z',
    signature: { algorithm: 'ML-DSA-65', value: SIG_PLACEHOLDER },
    status: 'active'
  },
  {
    id: 'avc_002',
    subjectActorId: 'actor_004',
    issuerActorId: 'actor_003',
    parentAvcId: 'avc_001',
    policyDomainId: 'pd_001',
    scope: {
      actions: ['procure.search', 'procure.quote'],
      constraints: { ceiling_usd: 5000 }
    },
    notBefore: '2026-03-01T09:30:00Z',
    notAfter: '2026-05-30T09:30:00Z',
    signature: { algorithm: 'ML-DSA-65', value: SIG_PLACEHOLDER },
    status: 'active'
  },
  {
    id: 'avc_003',
    subjectActorId: 'actor_007',
    issuerActorId: 'actor_002',
    policyDomainId: 'pd_002',
    scope: { actions: ['research.read'] },
    notBefore: '2026-03-10T15:00:00Z',
    notAfter: '2027-03-10T15:00:00Z',
    signature: { algorithm: 'Hybrid', value: SIG_PLACEHOLDER },
    status: 'active'
  },
  {
    id: 'avc_004',
    subjectActorId: 'actor_004',
    issuerActorId: 'actor_003',
    parentAvcId: 'avc_001',
    policyDomainId: 'pd_001',
    scope: { actions: ['procure.search'] },
    notBefore: '2026-01-15T12:00:00Z',
    notAfter: '2026-04-15T12:00:00Z',
    signature: { algorithm: 'ML-DSA-65', value: SIG_PLACEHOLDER },
    status: 'expired'
  },
  {
    id: 'avc_005',
    subjectActorId: 'actor_006',
    issuerActorId: 'actor_005',
    policyDomainId: 'pd_003',
    scope: { actions: ['validate.attest', 'validate.witness'] },
    notBefore: '2026-04-12T11:11:00Z',
    notAfter: '2026-10-12T11:11:00Z',
    signature: { algorithm: 'ML-DSA-65', value: SIG_PLACEHOLDER },
    status: 'active'
  },
  {
    id: 'avc_006',
    subjectActorId: 'actor_004',
    issuerActorId: 'actor_003',
    parentAvcId: 'avc_001',
    policyDomainId: 'pd_001',
    scope: { actions: ['procure.purchase'] },
    notBefore: '2026-02-15T08:00:00Z',
    notAfter: '2026-08-15T08:00:00Z',
    signature: { algorithm: 'ML-DSA-65', value: SIG_PLACEHOLDER },
    status: 'revoked'
  }
];

export const mockConsentRecords: ConsentRecord[] = [
  {
    id: 'cr_001',
    avcId: 'avc_001',
    principalActorId: 'actor_001',
    subjectActorId: 'actor_003',
    grantedAt: '2026-02-12T17:55:00Z',
    scopeHash: 'sha3:7a2c…cc91'
  },
  {
    id: 'cr_002',
    avcId: 'avc_006',
    principalActorId: 'actor_001',
    subjectActorId: 'actor_004',
    grantedAt: '2026-02-15T07:50:00Z',
    revokedAt: '2026-04-02T14:30:00Z',
    scopeHash: 'sha3:9b14…22ee'
  }
];

export const mockTrustReceipts: TrustReceipt[] = [
  {
    id: 'tr_0001',
    avcId: 'avc_001',
    actorId: 'actor_003',
    policyHash: 'sha3:bb01…aa44',
    actionDescriptor: 'procure.search:office-furniture-batch',
    outcome: 'permitted',
    custodyHash: 'sha3:0001…aaaa',
    timestamp: '2026-02-13T09:14:22Z',
    signature: { algorithm: 'ML-DSA-65', value: SIG_PLACEHOLDER }
  },
  {
    id: 'tr_0002',
    avcId: 'avc_001',
    actorId: 'actor_003',
    policyHash: 'sha3:bb01…aa44',
    actionDescriptor: 'procure.quote:office-furniture-batch',
    outcome: 'permitted',
    custodyHash: 'sha3:0002…bbbb',
    prevHash: 'sha3:0001…aaaa',
    timestamp: '2026-02-13T09:18:01Z',
    signature: { algorithm: 'ML-DSA-65', value: SIG_PLACEHOLDER }
  },
  {
    id: 'tr_0003',
    avcId: 'avc_001',
    actorId: 'actor_003',
    policyHash: 'sha3:bb01…aa44',
    actionDescriptor: 'procure.purchase:po-2026-0234',
    outcome: 'permitted',
    custodyHash: 'sha3:0003…cccc',
    prevHash: 'sha3:0002…bbbb',
    timestamp: '2026-02-13T09:22:46Z',
    signature: { algorithm: 'ML-DSA-65', value: SIG_PLACEHOLDER }
  },
  {
    id: 'tr_0004',
    avcId: 'avc_006',
    actorId: 'actor_004',
    policyHash: 'sha3:bb01…aa44',
    actionDescriptor: 'procure.purchase:po-2026-0301',
    outcome: 'denied',
    custodyHash: 'sha3:0004…dddd',
    timestamp: '2026-04-02T14:31:10Z',
    signature: { algorithm: 'ML-DSA-65', value: SIG_PLACEHOLDER }
  }
];

export const mockSettlementQuotes: SettlementQuote[] = [
  {
    id: 'sq_0001',
    avcId: 'avc_001',
    amount: '0',
    currency: 'EXO',
    zeroFeeReason: 'launch_policy_zero',
    expiresAt: '2026-05-10T00:00:00Z'
  },
  {
    id: 'sq_0002',
    avcId: 'avc_005',
    amount: '0',
    currency: 'EXO',
    zeroFeeReason: 'launch_policy_zero',
    expiresAt: '2026-05-10T00:00:00Z'
  },
  {
    id: 'sq_0003',
    avcId: 'avc_003',
    amount: '0',
    currency: 'EXO',
    zeroFeeReason: 'humanitarian_carve_out',
    expiresAt: '2026-05-12T00:00:00Z'
  }
];

export const mockSettlementReceipts: SettlementReceipt[] = [
  {
    id: 'sr_0001',
    quoteId: 'sq_0001',
    trustReceiptId: 'tr_0003',
    amount: '0',
    currency: 'EXO',
    zeroFeeReason: 'launch_policy_zero',
    timestamp: '2026-02-13T09:22:48Z',
    signature: { algorithm: 'ML-DSA-65', value: SIG_PLACEHOLDER }
  }
];

export const mockRevocations: Revocation[] = [
  {
    id: 'rv_001',
    avcId: 'avc_006',
    cause: 'subject_request',
    initiatorActorId: 'actor_001',
    cascade: [],
    timestamp: '2026-04-02T14:30:00Z'
  }
];

export const mockNodes: NodeRecord[] = [
  {
    id: 'node_001',
    operatorOrgId: 'aperture',
    kind: 'node',
    endpoint: 'node-aperture-01.exochain.io',
    version: 'v0.4.2-alpha',
    status: 'healthy',
    lastHeight: 124803,
    region: 'us-east'
  },
  {
    id: 'node_002',
    operatorOrgId: 'northwind',
    kind: 'validator',
    endpoint: 'val-northwind-02.exochain.io',
    version: 'v0.4.2-alpha',
    status: 'healthy',
    lastHeight: 124803,
    region: 'eu-west'
  },
  {
    id: 'node_003',
    operatorOrgId: 'northwind',
    kind: 'validator',
    endpoint: 'val-northwind-03.exochain.io',
    version: 'v0.4.2-alpha',
    status: 'degraded',
    lastHeight: 124781,
    region: 'ap-south'
  },
  {
    id: 'node_004',
    operatorOrgId: 'aperture',
    kind: 'node',
    endpoint: 'node-aperture-02.exochain.io',
    version: 'v0.4.1-alpha',
    status: 'syncing',
    lastHeight: 124020,
    region: 'us-west'
  }
];

export const mockIncidents: Incident[] = [
  {
    id: 'inc_026',
    severity: 'sev3',
    title: 'Validator val-northwind-03 elevated re-attestation latency',
    status: 'mitigated',
    startedAt: '2026-05-02T18:11:00Z',
    publicSummary:
      'A regional validator showed elevated re-attestation latency. Quorum and finality were unaffected. Mitigation deployed; monitoring.'
  },
  {
    id: 'inc_025',
    severity: 'sev4',
    title: 'Docs site cache invalidation lag',
    status: 'resolved',
    startedAt: '2026-04-28T07:40:00Z',
    resolvedAt: '2026-04-28T08:02:00Z',
    publicSummary:
      'Public docs occasionally served a stale revision for ~22 minutes. No protocol impact.'
  }
];

export const mockAuditEntries: AuditEntry[] = [
  {
    id: 'au_0010',
    actorId: 'actor_001',
    scope: 'aperture',
    action: 'avc.issue',
    target: 'avc_002',
    outcome: 'success',
    timestamp: '2026-03-01T09:30:01Z'
  },
  {
    id: 'au_0011',
    actorId: 'actor_001',
    scope: 'aperture',
    action: 'avc.revoke',
    target: 'avc_006',
    outcome: 'success',
    timestamp: '2026-04-02T14:30:00Z'
  },
  {
    id: 'au_0012',
    actorId: 'actor_001',
    scope: 'aperture',
    action: 'audit.export.request',
    target: 'period:2026-Q1',
    outcome: 'success',
    timestamp: '2026-04-04T11:00:12Z'
  }
];

export const mockProposals: Proposal[] = [
  {
    id: 'gov_0007',
    title:
      'Establish parameter window for governance-subsidy ZeroFeeReason scopes',
    status: 'open',
    quorum: { needed: 7, obtained: 4 },
    openedAt: '2026-04-21T16:00:00Z'
  },
  {
    id: 'gov_0006',
    title: 'Adopt validator hardware attestation v2 schema',
    status: 'ratified',
    quorum: { needed: 7, obtained: 8 },
    openedAt: '2026-03-12T10:00:00Z'
  }
];

// Mock network metrics for the public status page. Always shown with a
// `mock` label. Wire to exo-gateway status feed in v0.5.
export const mockNetworkMetrics = {
  networkMode: 'alpha-testnet',
  validatorCount: 7,
  peerCount: 19,
  committedHeight: 124803,
  uptimeWindow: '30d',
  uptimePercent: 99.86,
  lastReleaseTag: 'v0.4.2-alpha',
  lastSeenISO: '2026-05-03T14:00:00Z'
} as const;
