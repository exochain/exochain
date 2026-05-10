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

// Frontend view types for EXOCHAIN web presence.
// These mirror the public conceptual model in SPEC.md §8.
// They are intentionally narrow — they describe what the UI renders,
// not the on-chain canonical encoding.

export type Surface = 'internet' | 'extranet' | 'intranet';

export type ActorType =
  | 'human'
  | 'organization'
  | 'agent'
  | 'holon'
  | 'service'
  | 'validator';

export type ActorStatus = 'active' | 'inactive' | 'quarantined';

export interface Actor {
  id: string;
  type: ActorType;
  displayName: string;
  publicKey?: string;
  parentActorId?: string;
  createdAt: string;
  status: ActorStatus;
  organization?: string;
  notes?: string;
}

export interface PolicyDomain {
  id: string;
  name: string;
  description: string;
  ownerActorId: string;
}

export type AvcStatus = 'active' | 'expired' | 'revoked' | 'quarantined';

export interface AVC {
  id: string;
  subjectActorId: string;
  issuerActorId: string;
  parentAvcId?: string;
  policyDomainId: string;
  scope: { actions: string[]; constraints?: Record<string, unknown> };
  notBefore: string;
  notAfter: string;
  signature: { algorithm: 'ML-DSA-65' | 'Hybrid'; value: string };
  status: AvcStatus;
}

export interface ConsentRecord {
  id: string;
  avcId: string;
  principalActorId: string;
  subjectActorId: string;
  grantedAt: string;
  revokedAt?: string;
  scopeHash: string;
}

export type TrustReceiptOutcome = 'permitted' | 'denied' | 'partial';

export interface TrustReceipt {
  id: string;
  avcId: string;
  actorId: string;
  policyHash: string;
  actionDescriptor: string;
  outcome: TrustReceiptOutcome;
  custodyHash: string;
  prevHash?: string;
  timestamp: string;
  signature: { algorithm: 'ML-DSA-65'; value: string };
}

export type ZeroFeeReason =
  | 'launch_policy_zero'
  | 'governance_subsidy'
  | 'humanitarian_carve_out';

export interface SettlementQuote {
  id: string;
  avcId: string;
  amount: '0';
  currency: 'EXO';
  zeroFeeReason: ZeroFeeReason;
  expiresAt: string;
}

export interface SettlementReceipt {
  id: string;
  quoteId: string;
  trustReceiptId: string;
  amount: '0';
  currency: 'EXO';
  zeroFeeReason: ZeroFeeReason;
  prevHash?: string;
  timestamp: string;
  signature: { algorithm: 'ML-DSA-65'; value: string };
}

export type RevocationCause =
  | 'compromise'
  | 'scope_change'
  | 'policy_violation'
  | 'subject_request'
  | 'governance_action';

export interface Revocation {
  id: string;
  avcId: string;
  cause: RevocationCause;
  initiatorActorId: string;
  cascade: string[];
  timestamp: string;
}

export type NodeKind = 'node' | 'validator';
export type NodeStatus = 'syncing' | 'healthy' | 'degraded' | 'offline';

export interface NodeRecord {
  id: string;
  operatorOrgId: string;
  kind: NodeKind;
  endpoint: string;
  version: string;
  status: NodeStatus;
  lastHeight?: number;
  region?: string;
}

export type IncidentSeverity = 'sev1' | 'sev2' | 'sev3' | 'sev4';
export type IncidentStatus = 'open' | 'mitigated' | 'resolved';

export interface Incident {
  id: string;
  severity: IncidentSeverity;
  title: string;
  status: IncidentStatus;
  startedAt: string;
  resolvedAt?: string;
  publicSummary?: string;
}

export interface AuditEntry {
  id: string;
  actorId: string;
  scope: string;
  action: string;
  target: string;
  outcome: 'success' | 'denied' | 'error';
  timestamp: string;
}

export interface Proposal {
  id: string;
  title: string;
  status: 'draft' | 'open' | 'ratified' | 'rejected';
  quorum: { needed: number; obtained: number };
  openedAt: string;
}
