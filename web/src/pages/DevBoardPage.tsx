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

/** DevBoardPage — decision.forum Protocol Completeness Board
 *
 *  Every card maps to a decision.forum protocol primitive or workflow.
 *  Drives implementation of the five core protocol objects
 *  (DecisionRecord, CrosscheckReport, CustodyEvent, ClearanceCertificate,
 *   AnchorReceipt) and their supporting governance layers to 100%.
 */

import { useState, useMemo, useCallback } from 'react'
import { cn } from '../lib/utils'
import { useCouncil } from '../lib/CouncilContext'

// ─── Types ───────────────────────────────────────────────────────────────────

type EffortEstimate = 'small' | 'medium' | 'large' | 'epic'
type CardPriority = 'immediate' | 'urgent' | 'standard' | 'deferred' | 'backlog'
type BoardColumn = 'backlog' | 'triage' | 'in-progress' | 'review' | 'testing' | 'done'

interface DevCard {
  id: string
  domain: string
  domainScore: number
  title: string
  description: string
  effort: EffortEstimate
  priority: CardPriority
  tags: string[]
  blocksProduction: boolean
  column: BoardColumn
}

interface ProtocolDomain {
  id: string
  name: string
  protocolObject: string
  score: number
  color: string
  gaps: Array<{
    title: string
    description: string
    effort: EffortEstimate
    priority: CardPriority
    tags: string[]
    blocksProduction: boolean
  }>
}

// ─── decision.forum Protocol Assessment Data ────────────────────────────────
//
// Organized by protocol primitives from the decision.forum whitepaper:
//   DecisionRecord · CrosscheckReport · CustodyEvent
//   ClearanceCertificate · AnchorReceipt
// Plus supporting governance layers.

const PROTOCOL_DOMAINS: ProtocolDomain[] = [
  // ── Core Protocol Objects ──────────────────────────────────────────────

  {
    id: 'crosscheck-report', name: 'CrosscheckReport', protocolObject: 'CrosscheckReport', score: 55, color: 'bg-red-500',
    gaps: [
      { title: 'crosschecked.ai provider adapter', description: 'Build ProviderAdapter normalizing OpenAI/Anthropic/Google/xAI panel responses into CrosscheckOpinion structs with full provenance', effort: 'epic', priority: 'immediate', tags: ['crosscheck', 'integration', 'plural-intelligence'], blocksProduction: true },
      { title: 'Panel orchestration engine', description: 'Multi-model panel assembly, round-robin deliberation, synthesis extraction, and Minority Report dissent preservation', effort: 'epic', priority: 'urgent', tags: ['crosscheck', 'orchestration'], blocksProduction: true },
      { title: 'zkML proof generation for AI provenance', description: 'Generate zero-knowledge proofs that a specific model produced a specific opinion without revealing model weights', effort: 'large', priority: 'standard', tags: ['crosscheck', 'zkml', 'provenance'], blocksProduction: false },
      { title: 'Provenance compliance verification', description: 'Enforce whitepaper rule: synthetic voices MUST NOT be presented as distinct humans — verify all LLM opinions carry model provenance', effort: 'medium', priority: 'urgent', tags: ['crosscheck', 'compliance'], blocksProduction: false },
      { title: 'Devil\'s Advocate adversarial sub-process', description: 'Implement adversarial challenge mode that probes emerging consensus for weaknesses and unstated assumptions', effort: 'large', priority: 'standard', tags: ['crosscheck', 'adversarial'], blocksProduction: false },
    ],
  },
  {
    id: 'custody-chain', name: 'CustodyChain', protocolObject: 'CustodyEvent', score: 70, color: 'bg-orange-500',
    gaps: [
      { title: 'Custody chain API endpoints', description: 'GraphQL mutations for appending CustodyEvents and querying chain by decision, actor, or action type', effort: 'large', priority: 'urgent', tags: ['custody', 'api', 'graphql'], blocksProduction: true },
      { title: 'Signature verification for custody events', description: 'Verify Ed25519 detached signatures over record_hash in CustodyEvents using DID-resolved public keys', effort: 'medium', priority: 'urgent', tags: ['custody', 'crypto', 'signatures'], blocksProduction: false },
      { title: 'Real-time custody chain subscriptions', description: 'GraphQL subscriptions for live CustodyEvent stream — notify reviewers when attestations are filed', effort: 'large', priority: 'standard', tags: ['custody', 'realtime', 'subscriptions'], blocksProduction: false },
      { title: 'Custody chain visualization UI', description: 'Timeline/graph view showing chain of responsibility for each DecisionRecord with actor, role, action, and signature status', effort: 'medium', priority: 'standard', tags: ['custody', 'frontend', 'visualization'], blocksProduction: false },
    ],
  },
  {
    id: 'clearance-certificate', name: 'ClearanceCertificate', protocolObject: 'ClearanceCertificate', score: 65, color: 'bg-orange-400',
    gaps: [
      { title: 'Clearance policy engine integration', description: 'Wire ClearancePolicy evaluation into decision lifecycle — auto-evaluate after each attestation and issue certificates when thresholds met', effort: 'large', priority: 'immediate', tags: ['clearance', 'policy', 'engine'], blocksProduction: true },
      { title: 'Weighted clearance mode', description: 'Implement role-weighted voting where stewards count as 2x and custom weights per policy definition', effort: 'medium', priority: 'standard', tags: ['clearance', 'quorum', 'weights'], blocksProduction: false },
      { title: 'Clearance certificate portability', description: 'Export ClearanceCertificates as standalone verifiable JSON documents that can be validated without access to the platform', effort: 'medium', priority: 'standard', tags: ['clearance', 'portability', 'export'], blocksProduction: false },
      { title: 'Named approver enforcement', description: 'Enforce required_approvers list in ClearancePolicy — block clearance until specific DIDs have attested', effort: 'medium', priority: 'urgent', tags: ['clearance', 'approvers', 'enforcement'], blocksProduction: false },
    ],
  },
  {
    id: 'anchor-receipt', name: 'AnchorReceipt', protocolObject: 'AnchorReceipt', score: 60, color: 'bg-orange-500',
    gaps: [
      { title: 'EXOCHAIN anchor provider integration', description: 'Wire AnchorReceipt to exo-dag append_event + EventInclusionProof for production-grade immutable anchoring', effort: 'large', priority: 'immediate', tags: ['anchor', 'exochain', 'dag'], blocksProduction: true },
      { title: 'Anchor verification with Merkle proofs', description: 'Implement full inclusion proof verification against DAG store — verify receipt.inclusion_proof against live MMR/SMT state', effort: 'large', priority: 'urgent', tags: ['anchor', 'merkle', 'verification'], blocksProduction: true },
      { title: 'Third-party timestamp anchoring', description: 'Add timestamp service provider for independent temporal attestation (RFC 3161 compatible)', effort: 'medium', priority: 'standard', tags: ['anchor', 'timestamp', 'rfc3161'], blocksProduction: false },
      { title: 'Anchor verification UI badges', description: 'Visual tamper-evident badges showing anchor status: Verified/Unverified/Failed with plain-English explainers (UX-002)', effort: 'medium', priority: 'standard', tags: ['anchor', 'frontend', 'badges'], blocksProduction: false },
      { title: 'Periodic re-verification daemon', description: 'Background process that re-verifies anchor receipts on schedule and alerts on integrity failures', effort: 'medium', priority: 'deferred', tags: ['anchor', 'daemon', 'integrity'], blocksProduction: false },
    ],
  },
  {
    id: 'decision-record', name: 'DecisionRecord', protocolObject: 'DecisionRecord', score: 85, color: 'bg-blue-500',
    gaps: [
      { title: 'Canonical hashing for record_hash', description: 'Implement deterministic canonical serialization (sorted keys, excluded fields per whitepaper §Normative) for stable record_hash computation', effort: 'large', priority: 'urgent', tags: ['decision', 'hashing', 'canonical'], blocksProduction: true },
      { title: 'Decision lineage (supersedes chain)', description: 'Implement supersedes/superseded_by linkage for decision versioning and lineage tracking', effort: 'medium', priority: 'standard', tags: ['decision', 'lineage', 'versioning'], blocksProduction: false },
      { title: 'Decision lifecycle tracker UI', description: 'Visual status timeline + history for each decision showing state machine transitions with actor and timestamp (UX-010)', effort: 'medium', priority: 'standard', tags: ['decision', 'frontend', 'lifecycle'], blocksProduction: false },
    ],
  },

  // ── Supporting Governance Layers ───────────────────────────────────────

  {
    id: 'constitutional-corpus', name: 'Constitutional Corpus', protocolObject: 'Constitution', score: 75, color: 'bg-yellow-500',
    gaps: [
      { title: 'Constraint expression evaluator', description: 'Build runtime evaluation engine for constitutional ConstraintExpressions — synchronous evaluation before action completion (TNC-04)', effort: 'large', priority: 'urgent', tags: ['constitution', 'constraints', 'engine'], blocksProduction: false },
      { title: 'Constitutional amendment workflow', description: 'Full amendment lifecycle: proposal, deliberation, quorum vote, version bump, hash chain linkage', effort: 'large', priority: 'standard', tags: ['constitution', 'amendment', 'workflow'], blocksProduction: false },
      { title: 'Conflict resolution hierarchy', description: 'Enforce precedence: Articles > Bylaws > Resolutions > Charters > Policies (GOV-006)', effort: 'medium', priority: 'standard', tags: ['constitution', 'precedence', 'hierarchy'], blocksProduction: false },
      { title: 'Constitutional constraint warnings UI', description: 'Real-time inline warnings during decision creation when constraints would be violated (UX-003)', effort: 'medium', priority: 'standard', tags: ['constitution', 'frontend', 'warnings'], blocksProduction: false },
    ],
  },
  {
    id: 'authority-delegation', name: 'Authority Delegation', protocolObject: 'Delegation', score: 90, color: 'bg-green-400',
    gaps: [
      { title: 'Delegation expiry enforcement daemon', description: 'Background service that monitors delegation TTLs and auto-revokes expired delegations (TNC-05)', effort: 'medium', priority: 'standard', tags: ['delegation', 'expiry', 'daemon'], blocksProduction: false },
      { title: 'AI delegation ceiling visualization', description: 'UI showing AI agent authority boundaries, ceiling enforcement, and delegation scope cap (TNC-09)', effort: 'medium', priority: 'standard', tags: ['delegation', 'ai-ceiling', 'frontend'], blocksProduction: false },
    ],
  },
  {
    id: 'identity-sovereignty', name: 'Identity Sovereignty', protocolObject: 'PACE + DID', score: 70, color: 'bg-orange-500',
    gaps: [
      { title: 'PACE contact management API', description: 'Backend API for PACE contact CRUD, share distribution tracking, and confirmation workflow', effort: 'medium', priority: 'urgent', tags: ['identity', 'pace', 'api'], blocksProduction: false },
      { title: 'Wire PACE wizard to Shamir backend', description: 'Connect frontend PACE wizard to exo-identity::shamir::ShamirScheme for real GF(256) key sharding', effort: 'large', priority: 'urgent', tags: ['identity', 'pace', 'shamir', 'integration'], blocksProduction: true },
      { title: 'Key rotation with share re-distribution', description: 'Master key rotation that generates new shares and notifies contacts for re-distribution', effort: 'large', priority: 'standard', tags: ['identity', 'pace', 'rotation'], blocksProduction: false },
      { title: 'Trust score from governance participation', description: 'Compute identity trust scores from custody chain participation history, attestation reliability, delegation fulfillment', effort: 'large', priority: 'deferred', tags: ['identity', 'trust', 'scoring'], blocksProduction: false },
    ],
  },
  {
    id: 'challenge-protocol', name: 'Challenge Protocol', protocolObject: 'ChallengeObject', score: 80, color: 'bg-blue-400',
    gaps: [
      { title: 'Challenge resolution as new DecisionRecord', description: 'Implement challenge resolution that creates a new DecisionRecord with immutable REVERSAL linkage to original', effort: 'large', priority: 'standard', tags: ['challenge', 'reversal', 'lifecycle'], blocksProduction: false },
      { title: 'Contestation pause enforcement', description: 'When CONTESTED status set, ensure all execution is paused across API and UI until resolution', effort: 'medium', priority: 'standard', tags: ['challenge', 'enforcement', 'pause'], blocksProduction: false },
      { title: 'Challenge filing UI', description: 'Interface for filing challenges with grounds, evidence, and linked decision reference', effort: 'medium', priority: 'deferred', tags: ['challenge', 'frontend'], blocksProduction: false },
    ],
  },
  {
    id: 'emergency-governance', name: 'Emergency Governance', protocolObject: 'EmergencyAction', score: 80, color: 'bg-blue-400',
    gaps: [
      { title: 'Auto-create RATIFICATION_REQUIRED follow-up', description: 'When emergency action taken, auto-generate a new DecisionRecord requiring ratification within configurable window (TNC-10)', effort: 'large', priority: 'standard', tags: ['emergency', 'ratification', 'auto-create'], blocksProduction: false },
      { title: 'Emergency frequency monitoring', description: 'Track emergency action frequency — trigger mandatory review if >3 per quarter', effort: 'medium', priority: 'standard', tags: ['emergency', 'monitoring', 'frequency'], blocksProduction: false },
      { title: 'Succession protocol activation', description: 'Pre-defined succession for key roles with automatic activation triggers (GOV-011)', effort: 'large', priority: 'deferred', tags: ['emergency', 'succession'], blocksProduction: false },
    ],
  },
  {
    id: 'audit-integrity', name: 'Audit Integrity', protocolObject: 'AuditLog', score: 85, color: 'bg-blue-500',
    gaps: [
      { title: 'Hourly self-verification', description: 'Schedule hourly audit hash chain self-verification and emit escalation events on integrity failures (TNC-03)', effort: 'medium', priority: 'standard', tags: ['audit', 'self-verify', 'integrity'], blocksProduction: false },
      { title: 'E-discovery export workflow', description: 'Generate legally compliant e-discovery export packages with chain-of-custody documentation (LEG-010)', effort: 'large', priority: 'standard', tags: ['audit', 'ediscovery', 'legal'], blocksProduction: false },
      { title: 'Fiduciary defense package generation', description: 'Auto-generate duty-of-care evidence packages for legal defense (LEG-012)', effort: 'large', priority: 'deferred', tags: ['audit', 'fiduciary', 'legal'], blocksProduction: false },
    ],
  },
  {
    id: 'gateway-api', name: 'Gateway API', protocolObject: 'exo-gateway', score: 75, color: 'bg-yellow-500',
    gaps: [
      { title: 'CrosscheckReport GraphQL mutations', description: 'createCrosscheck, attachCrosscheckToDecision mutations with full panel orchestration', effort: 'large', priority: 'urgent', tags: ['gateway', 'graphql', 'crosscheck'], blocksProduction: false },
      { title: 'ClearanceCertificate issuance endpoint', description: 'evaluateClearance mutation that runs ClearancePolicy against CustodyChain and returns/issues certificate', effort: 'large', priority: 'urgent', tags: ['gateway', 'graphql', 'clearance'], blocksProduction: false },
      { title: 'AnchorReceipt mutation + verification query', description: 'anchorDecision mutation and verifyAnchor query for on-demand anchoring and verification', effort: 'medium', priority: 'standard', tags: ['gateway', 'graphql', 'anchor'], blocksProduction: false },
      { title: 'Real-time GraphQL subscriptions', description: 'decisionUpdated, custodyEventAppended, clearanceIssued, anchorVerified subscription handlers', effort: 'large', priority: 'standard', tags: ['gateway', 'subscriptions', 'realtime'], blocksProduction: false },
    ],
  },
  {
    id: 'zk-proof-layer', name: 'ZK Proof Layer', protocolObject: 'exo-proofs', score: 50, color: 'bg-red-500',
    gaps: [
      { title: 'Real zk-SNARK circuit integration', description: 'Replace proof stubs with Circom/Halo2 constraint system for authority chain and quorum verification proofs', effort: 'epic', priority: 'urgent', tags: ['zk', 'snark', 'circuits'], blocksProduction: true },
      { title: 'zk-STARK transparent governance proofs', description: 'Generate transparent proofs that constitutional constraints were satisfied without revealing decision content', effort: 'epic', priority: 'standard', tags: ['zk', 'stark', 'transparency'], blocksProduction: false },
      { title: 'zkML proof integration with CrosscheckReport', description: 'Wire zkml_proof field in CrosscheckReport to real zkML proof generation for AI recommendation confidence', effort: 'large', priority: 'standard', tags: ['zk', 'zkml', 'crosscheck'], blocksProduction: false },
      { title: 'Unified proof verifier', description: 'Single verification interface for SNARK, STARK, and zkML proofs with batch verification support', effort: 'large', priority: 'standard', tags: ['zk', 'verifier', 'unified'], blocksProduction: false },
      { title: 'Proof generation benchmarks', description: 'Performance test proof generation and verification under load — target <100ms verify, <2s generate', effort: 'medium', priority: 'deferred', tags: ['zk', 'perf', 'benchmarks'], blocksProduction: false },
    ],
  },
  {
    id: 'legal-compliance', name: 'Legal Compliance', protocolObject: 'exo-legal', score: 80, color: 'bg-blue-400',
    gaps: [
      { title: 'Self-authenticating business records', description: 'Implement FRE 803(6) compliant record generation with third-party timestamp anchoring (LEG-001/002/003)', effort: 'large', priority: 'standard', tags: ['legal', 'fre803', 'records'], blocksProduction: false },
      { title: 'DGCL §144 safe-harbor automation', description: 'Wire conflict disclosure workflow to automatically satisfy DGCL §144 safe-harbor requirements (LEG-005/013)', effort: 'medium', priority: 'standard', tags: ['legal', 'dgcl', 'conflict'], blocksProduction: false },
      { title: 'Attorney-client privilege compartmentalization', description: 'Data compartmentalization that protects privileged communications from e-discovery (LEG-009)', effort: 'large', priority: 'deferred', tags: ['legal', 'privilege', 'compartment'], blocksProduction: false },
    ],
  },
]

const COLUMNS: { id: BoardColumn; title: string; color: string }[] = [
  { id: 'backlog', title: 'Backlog', color: 'border-slate-300' },
  { id: 'triage', title: 'Triage', color: 'border-orange-400' },
  { id: 'in-progress', title: 'In Progress', color: 'border-blue-500' },
  { id: 'review', title: 'Review', color: 'border-violet-500' },
  { id: 'testing', title: 'Testing', color: 'border-amber-500' },
  { id: 'done', title: 'Done', color: 'border-green-500' },
]

const EFFORT_LABELS: Record<EffortEstimate, { label: string; color: string }> = {
  small: { label: 'S', color: 'bg-green-100 text-green-700' },
  medium: { label: 'M', color: 'bg-blue-100 text-blue-700' },
  large: { label: 'L', color: 'bg-orange-100 text-orange-700' },
  epic: { label: 'XL', color: 'bg-red-100 text-red-700' },
}

const PRIORITY_COLORS: Record<CardPriority, string> = {
  immediate: 'border-l-red-500',
  urgent: 'border-l-orange-500',
  standard: 'border-l-blue-500',
  deferred: 'border-l-slate-400',
  backlog: 'border-l-slate-300',
}

// ─── Generate cards from protocol assessment ────────────────────────────────

function generateCards(): DevCard[] {
  const cards: DevCard[] = []
  let idx = 0

  for (const domain of PROTOCOL_DOMAINS) {
    for (const gap of domain.gaps) {
      const column: BoardColumn =
        gap.blocksProduction ? 'triage'
        : gap.priority === 'immediate' || gap.priority === 'urgent' ? 'triage'
        : 'backlog'

      cards.push({
        id: `df-${domain.id}-${idx++}`,
        domain: domain.name,
        domainScore: domain.score,
        title: gap.title,
        description: gap.description,
        effort: gap.effort,
        priority: gap.priority,
        tags: [...gap.tags, 'decision.forum'],
        blocksProduction: gap.blocksProduction,
        column,
      })
    }
  }

  return cards
}

// ─── Component ───────────────────────────────────────────────────────────────

type ViewMode = 'board' | 'list' | 'scores'

export function DevBoardPage() {
  const [cards, setCards] = useState<DevCard[]>(() => generateCards())
  const [view, setView] = useState<ViewMode>('scores')
  const [filterDomain, setFilterDomain] = useState<string>('all')
  const [filterPriority, setFilterPriority] = useState<string>('all')
  const { openPanel } = useCouncil()

  const filteredCards = useMemo(() => {
    return cards.filter(c => {
      if (filterDomain !== 'all' && c.domain !== filterDomain) return false
      if (filterPriority !== 'all' && c.priority !== filterPriority) return false
      return true
    })
  }, [cards, filterDomain, filterPriority])

  const moveCard = useCallback((cardId: string, toColumn: BoardColumn) => {
    setCards(prev => prev.map(c => c.id === cardId ? { ...c, column: toColumn } : c))
  }, [])

  const totalGaps = cards.length
  const doneCount = cards.filter(c => c.column === 'done').length
  const blockingCount = cards.filter(c => c.blocksProduction && c.column !== 'done').length
  const overallProgress = totalGaps > 0 ? Math.round((doneCount / totalGaps) * 100) : 100

  // Group domains by category for the scores view
  const coreObjects = PROTOCOL_DOMAINS.filter(d =>
    ['crosscheck-report', 'custody-chain', 'clearance-certificate', 'anchor-receipt', 'decision-record'].includes(d.id)
  )
  const governanceLayers = PROTOCOL_DOMAINS.filter(d =>
    !['crosscheck-report', 'custody-chain', 'clearance-certificate', 'anchor-receipt', 'decision-record'].includes(d.id)
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">decision.forum Protocol Board</h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            {totalGaps} cards &middot; {doneCount} done &middot; {blockingCount} blocking production
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => openPanel('dev-completeness')}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium text-violet-600 bg-violet-50 hover:bg-violet-100 border border-violet-200 transition-colors"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
            </svg>
            Council AI
          </button>
          {/* View toggle */}
          <div className="flex rounded-lg border border-[var(--border-subtle)] overflow-hidden">
            {(['scores', 'board', 'list'] as ViewMode[]).map(v => (
              <button
                key={v}
                onClick={() => setView(v)}
                className={cn(
                  'px-3 py-1.5 text-xs font-medium capitalize transition-colors',
                  view === v
                    ? 'bg-[var(--accent-primary)] text-white'
                    : 'bg-[var(--surface-raised)] text-[var(--text-secondary)] hover:bg-[var(--surface-overlay)]'
                )}
              >
                {v}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Overall progress */}
      <div className="bg-[var(--surface-raised)] rounded-xl border border-[var(--border-subtle)] p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-semibold text-[var(--text-primary)]">Protocol Implementation</span>
          <span className="text-sm font-bold text-[var(--accent-primary)]">{overallProgress}%</span>
        </div>
        <div className="w-full h-3 bg-slate-200 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-blue-500 to-green-500 rounded-full transition-all"
            style={{ width: `${overallProgress}%` }}
          />
        </div>
      </div>

      {/* Scores view — protocol domain scorecards */}
      {view === 'scores' && (
        <div className="space-y-6">
          {/* Core Protocol Objects */}
          <div>
            <h2 className="text-sm font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
              Core Protocol Objects
            </h2>
            <div className="grid grid-cols-1 tablet:grid-cols-2 desktop:grid-cols-3 gap-4">
              {coreObjects.map(domain => (
                <DomainCard key={domain.id} domain={domain} />
              ))}
            </div>
          </div>

          {/* Supporting Governance Layers */}
          <div>
            <h2 className="text-sm font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
              Governance Layers
            </h2>
            <div className="grid grid-cols-1 tablet:grid-cols-2 desktop:grid-cols-3 gap-4">
              {governanceLayers.map(domain => (
                <DomainCard key={domain.id} domain={domain} />
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Board view — kanban */}
      {view === 'board' && (
        <>
          {/* Filters */}
          <div className="flex gap-3">
            <select
              value={filterDomain}
              onChange={e => setFilterDomain(e.target.value)}
              className="px-3 py-1.5 text-sm rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-raised)] text-[var(--text-primary)]"
            >
              <option value="all">All Protocol Domains</option>
              {PROTOCOL_DOMAINS.filter(d => d.gaps.length > 0).map(d => (
                <option key={d.id} value={d.name}>{d.name} ({d.score}%)</option>
              ))}
            </select>
            <select
              value={filterPriority}
              onChange={e => setFilterPriority(e.target.value)}
              className="px-3 py-1.5 text-sm rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-raised)] text-[var(--text-primary)]"
            >
              <option value="all">All Priorities</option>
              <option value="immediate">Immediate</option>
              <option value="urgent">Urgent</option>
              <option value="standard">Standard</option>
              <option value="deferred">Deferred</option>
            </select>
          </div>

          {/* Kanban columns */}
          <div className="flex gap-4 overflow-x-auto pb-4">
            {COLUMNS.map(col => {
              const colCards = filteredCards.filter(c => c.column === col.id)
              return (
                <div key={col.id} className="min-w-[280px] flex-shrink-0">
                  <div className={cn('rounded-t-lg border-t-2 px-3 py-2 bg-[var(--surface-raised)]', col.color)}>
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold text-[var(--text-primary)]">{col.title}</h3>
                      <span className="text-xs text-[var(--text-muted)] font-mono">{colCards.length}</span>
                    </div>
                  </div>
                  <div className="space-y-2 p-2 bg-[var(--surface-overlay)] rounded-b-lg min-h-[200px] border border-t-0 border-[var(--border-subtle)]">
                    {colCards.map(card => (
                      <DevCardComponent key={card.id} card={card} onMove={moveCard} />
                    ))}
                    {colCards.length === 0 && (
                      <div className="text-xs text-[var(--text-muted)] text-center py-8 italic">
                        No cards
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </>
      )}

      {/* List view — sortable table */}
      {view === 'list' && (
        <div className="bg-[var(--surface-raised)] rounded-xl border border-[var(--border-subtle)] overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border-subtle)] bg-[var(--surface-overlay)]">
                <th className="text-left px-4 py-2 text-xs font-semibold text-[var(--text-secondary)]">Title</th>
                <th className="text-left px-4 py-2 text-xs font-semibold text-[var(--text-secondary)]">Protocol Domain</th>
                <th className="text-left px-4 py-2 text-xs font-semibold text-[var(--text-secondary)]">Priority</th>
                <th className="text-left px-4 py-2 text-xs font-semibold text-[var(--text-secondary)]">Effort</th>
                <th className="text-left px-4 py-2 text-xs font-semibold text-[var(--text-secondary)]">Status</th>
                <th className="text-left px-4 py-2 text-xs font-semibold text-[var(--text-secondary)]">Blocks</th>
              </tr>
            </thead>
            <tbody>
              {filteredCards.map(card => (
                <tr key={card.id} className="border-b border-[var(--border-subtle)] hover:bg-[var(--surface-overlay)]">
                  <td className="px-4 py-2.5">
                    <div className="font-medium text-[var(--text-primary)]">{card.title}</div>
                    <div className="text-xs text-[var(--text-muted)] mt-0.5 truncate max-w-xs">{card.description}</div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-xs font-mono text-[var(--text-secondary)]">{card.domain}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={cn(
                      'text-xs font-medium px-2 py-0.5 rounded-full capitalize',
                      card.priority === 'immediate' ? 'bg-red-100 text-red-700'
                        : card.priority === 'urgent' ? 'bg-orange-100 text-orange-700'
                        : card.priority === 'standard' ? 'bg-blue-100 text-blue-700'
                        : 'bg-slate-100 text-slate-600'
                    )}>
                      {card.priority}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={cn('text-xs font-mono px-1.5 py-0.5 rounded', EFFORT_LABELS[card.effort].color)}>
                      {EFFORT_LABELS[card.effort].label}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-[var(--text-secondary)] capitalize">{card.column}</td>
                  <td className="px-4 py-2.5">
                    {card.blocksProduction && (
                      <span className="text-xs font-semibold text-red-600">BLOCKING</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── Domain Scorecard Component ─────────────────────────────────────────────

function DomainCard({ domain }: { domain: ProtocolDomain }) {
  return (
    <div className={cn(
      'bg-[var(--surface-raised)] rounded-xl border border-[var(--border-subtle)] p-4 transition-all hover:shadow-md',
      domain.score === 100 && 'ring-1 ring-green-300'
    )}>
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-sm font-bold text-[var(--text-primary)]">{domain.name}</h3>
        <div className={cn(
          'text-lg font-bold',
          domain.score >= 95 ? 'text-green-600'
            : domain.score >= 80 ? 'text-blue-600'
            : domain.score >= 60 ? 'text-amber-600'
            : 'text-red-600'
        )}>
          {domain.score}%
        </div>
      </div>
      <div className="text-2xs text-[var(--text-muted)] font-mono mb-3">{domain.protocolObject}</div>

      {/* Progress bar */}
      <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden mb-3">
        <div className={cn('h-full rounded-full', domain.color)} style={{ width: `${domain.score}%` }} />
      </div>

      {/* Gap list */}
      {domain.gaps.length === 0 ? (
        <div className="text-xs text-green-600 font-medium flex items-center gap-1">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          Complete — no gaps
        </div>
      ) : (
        <div className="space-y-1">
          {domain.gaps.map((gap, i) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <span className={cn(
                'w-1.5 h-1.5 rounded-full flex-shrink-0',
                gap.blocksProduction ? 'bg-red-500' : gap.priority === 'urgent' || gap.priority === 'immediate' ? 'bg-orange-500' : 'bg-slate-400'
              )} />
              <span className="text-[var(--text-secondary)] truncate flex-1">{gap.title}</span>
              <span className={cn('text-2xs font-mono px-1 rounded', EFFORT_LABELS[gap.effort].color)}>
                {EFFORT_LABELS[gap.effort].label}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Card Component ──────────────────────────────────────────────────────────

function DevCardComponent({ card, onMove }: { card: DevCard; onMove: (id: string, to: BoardColumn) => void }) {
  const [showMoveMenu, setShowMoveMenu] = useState(false)

  return (
    <div className={cn(
      'bg-[var(--surface-raised)] rounded-lg p-3 border border-[var(--border-subtle)] border-l-4 shadow-sm hover:shadow-md transition-shadow relative',
      PRIORITY_COLORS[card.priority],
    )}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="text-xs font-semibold text-[var(--text-primary)] leading-tight">{card.title}</div>
          <div className="text-2xs text-[var(--text-muted)] mt-1 line-clamp-2">{card.description}</div>
        </div>
        <div className="relative">
          <button
            onClick={() => setShowMoveMenu(!showMoveMenu)}
            className="p-1 rounded hover:bg-[var(--surface-overlay)] text-[var(--text-muted)]"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z" />
            </svg>
          </button>
          {showMoveMenu && (
            <div className="absolute right-0 mt-1 w-32 bg-white rounded-lg shadow-lg border border-slate-200 py-1 z-10">
              {COLUMNS.filter(c => c.id !== card.column).map(col => (
                <button
                  key={col.id}
                  onClick={() => { onMove(card.id, col.id); setShowMoveMenu(false) }}
                  className="block w-full text-left px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50"
                >
                  {col.title}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center gap-1.5 mt-2 flex-wrap">
        <span className="text-2xs font-mono text-[var(--text-muted)]">{card.domain}</span>
        <span className="text-[var(--text-muted)]">&middot;</span>
        <span className={cn('text-2xs font-mono px-1 rounded', EFFORT_LABELS[card.effort].color)}>
          {EFFORT_LABELS[card.effort].label}
        </span>
        {card.blocksProduction && (
          <span className="text-2xs font-bold text-red-600 bg-red-50 px-1 rounded">BLOCKS</span>
        )}
      </div>

      <div className="flex gap-1 mt-1.5 flex-wrap">
        {card.tags.slice(0, 3).map(tag => (
          <span key={tag} className="text-2xs px-1 py-0 rounded bg-slate-100 text-slate-500">{tag}</span>
        ))}
        {card.tags.length > 3 && (
          <span className="text-2xs text-[var(--text-muted)]">+{card.tags.length - 3}</span>
        )}
      </div>
    </div>
  )
}
