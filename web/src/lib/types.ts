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

/** Core domain types mirroring the Rust backend JSON responses. */

export type DecisionStatus =
  | 'Created'
  | 'Deliberation'
  | 'Voting'
  | 'Approved'
  | 'Rejected'
  | 'Void'
  | 'Contested'
  | 'RatificationRequired'
  | 'RatificationExpired'
  | 'DegradedGovernance'

export type DecisionClass =
  | 'Operational'
  | 'Strategic'
  | 'Constitutional'
  | 'Financial'
  | 'Emergency'
  | string

export type VoteChoice = 'Approve' | 'Reject' | 'Abstain'

export type UrgencyLevel = 'critical' | 'high' | 'moderate' | 'low' | 'neutral'

export interface Decision {
  id: string
  tenantId: string
  status: DecisionStatus
  title: string
  decisionClass: DecisionClass
  author: string
  createdAt: number
  constitutionVersion: string
  votes: Vote[]
  challenges: Challenge[]
  transitionLog: Transition[]
  isTerminal: boolean
  validNextStatuses: string[]
}

export interface Vote {
  voter: string
  choice: string
  rationale?: string
  signerType: string
  timestamp: number
}

export interface Challenge {
  id: string
  grounds: string
  status: string
}

export interface Transition {
  from: string
  to: string
  actor: string
  reason?: string
  timestamp: number
}

export interface Delegation {
  id: string
  delegator: string
  delegatee: string
  scope: string
  expiresAt: number
  active: boolean
  subDelegationAllowed: boolean
  constitutionVersion: string
}

export interface AuditEntry {
  sequence: number
  eventType: string
  actor: string
  tenantId: string
  timestamp: number
  entryHash: string
  prevHash: string
}

export interface AuditIntegrity {
  chainLength: number
  verified: boolean
  headHash: string
}

export interface ConstitutionInfo {
  tenantId: string
  version: string
  hash: string
  documentCount: number
  constraints: ConstraintInfo[]
  humanGateClasses: string[]
  maxDelegationDepth: number
}

export interface ConstraintInfo {
  id: string
  description: string
  failureAction: string
}

// ── Auth & Identity types ──

export type PaceStatus = 'Unenrolled' | 'Provable' | 'Auditable' | 'Compliant' | 'Enforceable'
export type TrustTier = 'Untrusted' | 'Probationary' | 'Standard' | 'Trusted' | 'Verified'
export type AccountStatus = 'Active' | 'Suspended' | 'PendingVerification' | 'Revoked'

export interface UserProfile {
  did: string
  displayName: string
  email: string
  roles: string[]
  tenantId: string
  paceStatus: PaceStatus
  trustTier: TrustTier
  trustScore: number
  createdAt: number
  status: AccountStatus
}

export interface AgentIdentity {
  did: string
  agentName: string
  agentType: string
  ownerDid: string
  capabilities: string[]
  trustTier: TrustTier
  trustScore: number
  paceStatus: PaceStatus
  maxDecisionClass: string
  status: AccountStatus
  createdAt: number
}

export interface IdentityScore {
  did: string
  score: number
  tier: TrustTier
  factors: {
    tenureDays: number
    decisionsParticipated: number
    votesCast: number
    complianceViolations: number
    delegationDepth: number
    paceComplete: boolean
  }
  lastUpdated: number
}

export interface LoginResponse {
  token: string
  refreshToken: string
  user: UserProfile
}

export interface RegisterResponse {
  did: string
  displayName: string
  email: string
  paceStatus: PaceStatus
  token: string
  refreshToken: string
}

export interface HealthInfo {
  status: string
  decisions: number
  delegations: number
  auditEntries: number
  auditIntegrity: boolean
}

export function isTerminalStatus(status: DecisionStatus): boolean {
  return ['Approved', 'Rejected', 'Void', 'RatificationExpired'].includes(status)
}

export function statusColor(status: DecisionStatus): string {
  const colors: Record<DecisionStatus, string> = {
    Created: 'bg-gray-100 text-gray-800',
    Deliberation: 'bg-blue-100 text-blue-800',
    Voting: 'bg-yellow-100 text-yellow-800',
    Approved: 'bg-green-100 text-green-800',
    Rejected: 'bg-red-100 text-red-800',
    Void: 'bg-gray-200 text-gray-600',
    Contested: 'bg-orange-100 text-orange-800',
    RatificationRequired: 'bg-purple-100 text-purple-800',
    RatificationExpired: 'bg-red-200 text-red-900',
    DegradedGovernance: 'bg-amber-100 text-amber-800',
  }
  return colors[status] || 'bg-gray-100 text-gray-800'
}

/** Returns an urgency level classification based on decision status. */
export function urgencyLevel(status: DecisionStatus): UrgencyLevel {
  switch (status) {
    case 'Contested':
    case 'RatificationExpired':
    case 'DegradedGovernance':
      return 'critical'
    case 'Voting':
    case 'RatificationRequired':
      return 'high'
    case 'Deliberation':
      return 'moderate'
    case 'Created':
      return 'low'
    case 'Approved':
    case 'Rejected':
    case 'Void':
      return 'neutral'
    default:
      return 'neutral'
  }
}

/** Maps a DecisionStatus to its design-system dot color class. */
export function statusDotColor(status: DecisionStatus): string {
  const colors: Record<DecisionStatus, string> = {
    Created: 'bg-status-created',
    Deliberation: 'bg-status-deliberation',
    Voting: 'bg-status-voting',
    Approved: 'bg-status-approved',
    Rejected: 'bg-status-rejected',
    Void: 'bg-status-void',
    Contested: 'bg-status-contested',
    RatificationRequired: 'bg-status-ratification',
    RatificationExpired: 'bg-status-expired',
    DegradedGovernance: 'bg-status-degraded',
  }
  return colors[status] || 'bg-status-created'
}
