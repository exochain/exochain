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

/** CommandCenterPage — The governance control surface.
 *
 * A configurable grid of drag-and-droppable widgets, a kanban board for
 * human-in-the-loop workflow control, and real-time escalation triage.
 *
 * This is the erector set — interconnected challenge modules that provide
 * maximally contextualized governance intelligence.
 */

import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { GridDashboard } from '../components/grid/GridDashboard'
import { KanbanBoard, defaultGovernanceColumns, type KanbanColumnData, type KanbanCardData } from '../components/KanbanBoard'
import { cn } from '../lib/utils'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { useCouncil } from '../lib/CouncilContext'
import type { PanelDef } from '../data/defaultLayouts'
import type { Decision } from '../lib/types'

// ---------------------------------------------------------------------------
// View modes
// ---------------------------------------------------------------------------

type ViewMode = 'grid' | 'kanban' | 'split'

// Default widget configuration moved to src/data/defaultLayouts.ts (PANEL_REGISTRY)

// ---------------------------------------------------------------------------
// Widget renderers
// ---------------------------------------------------------------------------

function KpiWidget() {
  const [data, setData] = useState<{ decisions: number; delegations: number; auditEntries: number; auditIntegrity: boolean } | null>(null)

  useEffect(() => {
    api.health().then(setData).catch(() => {})
  }, [])

  if (!data) return <WidgetSkeleton />

  const kpis = [
    { label: 'Decisions', value: data.decisions, color: 'text-[var(--accent-primary)]' },
    { label: 'Delegations', value: data.delegations, color: 'text-purple-600' },
    { label: 'Audit Events', value: data.auditEntries, color: 'text-amber-600' },
    { label: 'Chain Integrity', value: data.auditIntegrity ? 'VERIFIED' : 'BROKEN', color: data.auditIntegrity ? 'text-green-600' : 'text-red-600' },
  ]

  return (
    <div className="grid grid-cols-2 tablet:grid-cols-4 gap-3">
      {kpis.map(kpi => (
        <div key={kpi.label} className="text-center p-3 rounded-lg bg-[var(--surface-overlay)]">
          <div className={cn('text-2xl font-bold', kpi.color)}>{kpi.value}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-0.5">{kpi.label}</div>
        </div>
      ))}
    </div>
  )
}

function ActiveDecisionsWidget() {
  const [decisions, setDecisions] = useState<Decision[]>([])
  const navigate = useNavigate()

  useEffect(() => {
    api.decisions.list().then(setDecisions).catch(() => {})
  }, [])

  const active = decisions.filter(d => !['Approved', 'Rejected', 'Void', 'RatificationExpired'].includes(d.status))

  return (
    <div className="space-y-2 max-h-[400px] overflow-y-auto">
      {active.length === 0 && (
        <div className="text-center text-sm text-[var(--text-muted)] py-8">No active decisions</div>
      )}
      {active.map(d => (
        <button
          key={d.id}
          onClick={() => navigate(`/decisions/${d.id}`)}
          className="w-full text-left p-3 rounded-lg bg-[var(--surface-overlay)] hover:bg-[var(--accent-muted)] transition-colors"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-sm font-medium text-[var(--text-primary)] truncate">{d.title}</span>
            <StatusPill status={d.status} />
          </div>
          <div className="flex items-center gap-3 text-2xs text-[var(--text-muted)]">
            <span>{d.decisionClass}</span>
            <span>{d.votes.length} vote{d.votes.length !== 1 ? 's' : ''}</span>
            <span>{d.challenges.length} challenge{d.challenges.length !== 1 ? 's' : ''}</span>
          </div>
        </button>
      ))}
    </div>
  )
}

function EscalationWidget() {
  // Mock escalation data — will connect to real exo-escalation backend
  const escalations = [
    { id: 'E-001', severity: 'critical', title: 'Audit gap detected in sequence 47→49', age: '2m ago' },
    { id: 'E-002', severity: 'warning', title: 'Delegation cascade: 8 new delegations in 1h', age: '15m ago' },
    { id: 'E-003', severity: 'info', title: '3 consent grants expiring within 24h', age: '1h ago' },
  ]

  const severityColors: Record<string, string> = {
    critical: 'bg-red-500',
    warning: 'bg-amber-500',
    elevated: 'bg-orange-500',
    info: 'bg-blue-400',
  }

  return (
    <div className="space-y-2">
      {escalations.map(e => (
        <div key={e.id} className="flex items-start gap-2 p-2 rounded-lg bg-[var(--surface-overlay)]">
          <span className={cn('w-2 h-2 rounded-full mt-1.5 flex-shrink-0', severityColors[e.severity] || 'bg-slate-400')} />
          <div className="min-w-0 flex-1">
            <div className="text-xs font-medium text-[var(--text-primary)] leading-tight">{e.title}</div>
            <div className="text-2xs text-[var(--text-muted)] mt-0.5">{e.id} &middot; {e.age}</div>
          </div>
        </div>
      ))}
    </div>
  )
}

function TrustScoreWidget() {
  const { user } = useAuth()
  if (!user) return <WidgetSkeleton />

  const tierColors: Record<string, string> = {
    Verified: 'text-green-600 bg-green-100',
    Trusted: 'text-blue-600 bg-blue-100',
    Standard: 'text-slate-600 bg-slate-100',
    Probationary: 'text-amber-600 bg-amber-100',
    Untrusted: 'text-red-600 bg-red-100',
  }

  return (
    <div className="flex flex-col items-center gap-2 py-2">
      <div className="text-3xl font-bold text-[var(--accent-primary)]">{user.trustScore}</div>
      <span className={cn('rounded-full px-2 py-0.5 text-xs font-semibold', tierColors[user.trustTier] || 'bg-slate-100 text-slate-600')}>
        {user.trustTier}
      </span>
      <div className="text-2xs text-[var(--text-muted)] mt-1">PACE: {user.paceStatus}</div>
    </div>
  )
}

function AuditChainWidget() {
  const [integrity, setIntegrity] = useState<{ verified: boolean; chainLength: number; headHash: string } | null>(null)

  useEffect(() => {
    api.audit.verify().then(setIntegrity).catch(() => {})
  }, [])

  if (!integrity) return <WidgetSkeleton />

  return (
    <div className="flex flex-col items-center gap-2 py-2">
      <div className={cn(
        'w-12 h-12 rounded-full flex items-center justify-center',
        integrity.verified ? 'bg-green-100' : 'bg-red-100',
      )}>
        <svg className={cn('w-6 h-6', integrity.verified ? 'text-green-600' : 'text-red-600')} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          {integrity.verified ? (
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          ) : (
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.07 16.5c-.77.833.192 2.5 1.732 2.5z" />
          )}
        </svg>
      </div>
      <div className="text-sm font-semibold text-[var(--text-primary)]">
        {integrity.verified ? 'Chain Verified' : 'INTEGRITY BREACH'}
      </div>
      <div className="text-2xs text-[var(--text-muted)]">{integrity.chainLength} events</div>
      <div className="text-2xs text-[var(--text-muted)] font-mono truncate max-w-full px-2" title={integrity.headHash}>
        HEAD: {integrity.headHash.substring(0, 12)}...
      </div>
    </div>
  )
}

function DelegationWidget() {
  const [count, setCount] = useState(0)

  useEffect(() => {
    api.delegations.list().then(d => setCount(d.length)).catch(() => {})
  }, [])

  return (
    <div className="flex flex-col items-center gap-2 py-2">
      <div className="text-3xl font-bold text-purple-600">{count}</div>
      <div className="text-sm text-[var(--text-secondary)]">Active Delegations</div>
      <div className="text-2xs text-[var(--text-muted)]">Authority chains monitored</div>
    </div>
  )
}

function AgentWidget() {
  const [agents, setAgents] = useState<{ did: string; agentName: string; agentType: string; trustScore: number; paceStatus: string }[]>([])

  useEffect(() => {
    api.agents.list().then(setAgents).catch(() => {})
  }, [])

  return (
    <div className="space-y-2">
      {agents.length === 0 && <div className="text-sm text-[var(--text-muted)] text-center py-4">No agents enrolled</div>}
      {agents.map(a => (
        <div key={a.did} className="flex items-center gap-3 p-2 rounded-lg bg-[var(--surface-overlay)]">
          <div className="w-8 h-8 rounded-lg bg-purple-100 flex items-center justify-center">
            <svg className="w-4 h-4 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium text-[var(--text-primary)] truncate">{a.agentName}</div>
            <div className="text-2xs text-[var(--text-muted)]">{a.agentType} &middot; Score {a.trustScore} &middot; {a.paceStatus}</div>
          </div>
        </div>
      ))}
    </div>
  )
}

function CouncilTicketsWidget() {
  const { tickets, openPanel, openTicketCount } = useCouncil()

  const TAG_COLORS: Record<string, string> = {
    help: 'bg-blue-100 text-blue-700',
    feature: 'bg-purple-100 text-purple-700',
    bug: 'bg-red-100 text-red-700',
    question: 'bg-cyan-100 text-cyan-700',
    feedback: 'bg-slate-100 text-slate-600',
    escalation: 'bg-orange-100 text-orange-700',
    proposal: 'bg-violet-100 text-violet-700',
    triage: 'bg-amber-100 text-amber-700',
    implementation: 'bg-emerald-100 text-emerald-700',
    'test-plan': 'bg-green-100 text-green-700',
    security: 'bg-red-200 text-red-800',
    governance: 'bg-indigo-100 text-indigo-700',
    config: 'bg-gray-100 text-gray-600',
  }

  const recentTickets = tickets.slice(-6)

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-violet-500 health-pulse" />
          <span className="text-xs font-semibold text-violet-600">{openTicketCount} OPEN TICKETS</span>
        </div>
        <button
          onClick={() => openPanel('general')}
          className="text-2xs text-[var(--accent-primary)] hover:underline"
        >
          + New
        </button>
      </div>
      {recentTickets.length === 0 ? (
        <div className="text-center py-4">
          <div className="text-sm text-[var(--text-muted)]">No tickets yet</div>
          <button
            onClick={() => openPanel('general')}
            className="mt-2 text-xs text-[var(--accent-primary)] hover:underline"
          >
            Start a conversation to create tickets
          </button>
        </div>
      ) : (
        recentTickets.map(ticket => (
          <div key={ticket.id} className="flex items-start gap-2 p-2 rounded-lg bg-[var(--surface-overlay)]">
            <span className={cn(
              'w-2 h-2 rounded-full mt-1.5 flex-shrink-0',
              ticket.priority === 'immediate' ? 'bg-red-500' :
              ticket.priority === 'urgent' ? 'bg-orange-500' :
              ticket.priority === 'standard' ? 'bg-blue-500' : 'bg-slate-400',
            )} />
            <div className="min-w-0 flex-1">
              <div className="text-xs font-medium text-[var(--text-primary)] leading-tight truncate">{ticket.title}</div>
              <div className="text-2xs text-[var(--text-muted)] mt-0.5">{ticket.status} &middot; {ticket.sourceModule}</div>
              <div className="flex gap-1 mt-1 flex-wrap">
                {ticket.tags.slice(0, 3).map(tag => (
                  <span key={tag} className={cn('rounded-full px-1.5 py-0 text-2xs', TAG_COLORS[tag] || 'bg-slate-100 text-slate-600')}>
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  )
}

function CgrKernelWidget() {
  // CGR Kernel status — hardcoded for now, will connect to kernel API
  const invariants = [
    { id: 'INV-001', name: 'NO_SELF_MODIFY', status: 'active' },
    { id: 'INV-002', name: 'NO_SELF_GRANT', status: 'active' },
    { id: 'INV-003', name: 'CONSENT_FIRST', status: 'active' },
    { id: 'INV-005', name: 'ALIGN_FLOOR', status: 'active' },
    { id: 'INV-007', name: 'HUMAN_OVERRIDE', status: 'active' },
    { id: 'INV-008', name: 'KERNEL_IMMUT', status: 'active' },
  ]

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2 mb-2">
        <span className="w-2 h-2 rounded-full bg-green-500 health-pulse" />
        <span className="text-xs font-semibold text-green-600">JUDICIAL BRANCH ACTIVE</span>
      </div>
      {invariants.map(inv => (
        <div key={inv.id} className="flex items-center gap-2 text-2xs">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
          <span className="font-mono text-[var(--text-muted)]">{inv.id}</span>
          <span className="text-[var(--text-secondary)]">{inv.name}</span>
        </div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function WidgetSkeleton() {
  return (
    <div className="animate-pulse space-y-3 py-2">
      <div className="h-4 bg-[var(--surface-overlay)] rounded w-3/4" />
      <div className="h-4 bg-[var(--surface-overlay)] rounded w-1/2" />
      <div className="h-4 bg-[var(--surface-overlay)] rounded w-5/6" />
    </div>
  )
}

function StatusPill({ status }: { status: string }) {
  const colors: Record<string, string> = {
    Created: 'bg-slate-100 text-slate-700',
    Deliberation: 'bg-blue-100 text-blue-700',
    Voting: 'bg-yellow-100 text-yellow-800',
    Approved: 'bg-green-100 text-green-800',
    Rejected: 'bg-red-100 text-red-700',
    Contested: 'bg-orange-100 text-orange-700',
  }
  return (
    <span className={cn('rounded-full px-2 py-0.5 text-2xs font-medium', colors[status] || 'bg-slate-100 text-slate-600')}>
      {status}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Widget renderer map
// ---------------------------------------------------------------------------

// Widget rendering moved inline to GridDashboard renderPanel prop below

// ---------------------------------------------------------------------------
// Mock kanban data
// ---------------------------------------------------------------------------

function buildKanbanData(decisions: Decision[], councilTickets?: import('../lib/council').CouncilTicket[]): KanbanColumnData[] {
  const cols = defaultGovernanceColumns()

  // Inject council tickets into kanban columns
  if (councilTickets) {
    councilTickets.forEach(ticket => {
      const card: KanbanCardData = {
        id: ticket.id,
        title: ticket.title,
        description: ticket.description.slice(0, 100),
        tags: ticket.tags.map(t => ({
          label: t,
          color: t === 'bug' ? '#EF4444' : t === 'feature' ? '#8B5CF6' : t === 'security' ? '#DC2626' : t === 'escalation' ? '#F97316' : '#6366F1',
        })),
        priority: ticket.priority,
        assignee: ticket.author,
        linkedTriageId: ticket.id,
        createdAt: ticket.createdAt,
        metadata: { source: 'council-ai', module: ticket.sourceModule },
      }

      switch (ticket.status) {
        case 'open': cols.find(c => c.id === 'backlog')?.cards.push(card); break
        case 'council-triage': cols.find(c => c.id === 'triage')?.cards.push(card); break
        case 'human-review': cols.find(c => c.id === 'review')?.cards.push(card); break
        case 'council-advised': cols.find(c => c.id === 'deliberation')?.cards.push(card); break
        case 'implementation': case 'testing': cols.find(c => c.id === 'voting')?.cards.push(card); break
        case 'resolved': cols.find(c => c.id === 'resolved')?.cards.push(card); break
        case 'dismissed': cols.find(c => c.id === 'archived')?.cards.push(card); break
        default: cols.find(c => c.id === 'backlog')?.cards.push(card); break
      }
    })
  }

  decisions.forEach(d => {
    const card: KanbanCardData = {
      id: d.id,
      title: d.title,
      description: `${d.decisionClass} decision by ${d.author}`,
      tags: [
        { label: d.decisionClass, color: '#2563EB' },
        { label: `${d.votes.length} votes`, color: '#7C3AED' },
      ],
      priority: d.status === 'Contested' ? 'immediate'
        : d.status === 'Voting' ? 'urgent'
        : d.status === 'Deliberation' ? 'standard'
        : 'deferred',
      assignee: d.author,
      linkedDecisionId: d.id,
      createdAt: d.createdAt,
    }

    switch (d.status) {
      case 'Created': cols.find(c => c.id === 'backlog')?.cards.push(card); break
      case 'Deliberation': cols.find(c => c.id === 'deliberation')?.cards.push(card); break
      case 'Voting': cols.find(c => c.id === 'voting')?.cards.push(card); break
      case 'Contested': cols.find(c => c.id === 'triage')?.cards.push(card); break
      case 'Approved': case 'Rejected': cols.find(c => c.id === 'resolved')?.cards.push(card); break
      case 'Void': case 'RatificationExpired': cols.find(c => c.id === 'archived')?.cards.push(card); break
      default: cols.find(c => c.id === 'review')?.cards.push(card); break
    }
  })

  return cols
}

// ---------------------------------------------------------------------------
// CommandCenterPage
// ---------------------------------------------------------------------------

export function CommandCenterPage() {
  const [viewMode, setViewMode] = useState<ViewMode>('split')
  const [kanbanCols, setKanbanCols] = useState<KanbanColumnData[]>(defaultGovernanceColumns())
  const navigate = useNavigate()
  const { tickets: councilTickets } = useCouncil()

  // Load decisions + council tickets for kanban
  useEffect(() => {
    api.decisions.list()
      .then(decisions => setKanbanCols(buildKanbanData(decisions, councilTickets)))
      .catch(() => setKanbanCols(buildKanbanData([], councilTickets)))
  }, [councilTickets])

  const handleCardMove = useCallback((cardId: string, fromCol: string, toCol: string, _newIndex: number) => {
    console.log(`Card ${cardId} moved from ${fromCol} to ${toCol}`)
    // In production, this would trigger a decision status transition via the API
  }, [])

  const handleCardClick = useCallback((card: KanbanCardData) => {
    if (card.linkedDecisionId) {
      navigate(`/decisions/${card.linkedDecisionId}`)
    }
  }, [navigate])

  return (
    <div className="space-y-6">
      {/* Page header with view mode toggle */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">Command Center</h1>
          <p className="text-sm text-[var(--text-secondary)] mt-0.5">
            Governance control surface — drag, drop, and interconnect
          </p>
        </div>

        {/* View mode toggle */}
        <div className="flex items-center gap-1 bg-[var(--surface-overlay)] rounded-lg p-0.5">
          {(['grid', 'kanban', 'split'] as ViewMode[]).map(mode => (
            <button
              key={mode}
              onClick={() => setViewMode(mode)}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-medium transition-colors',
                viewMode === mode
                  ? 'bg-[var(--surface-widget)] text-[var(--accent-primary)] shadow-sm'
                  : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]',
              )}
            >
              {mode === 'grid' ? 'Widgets' : mode === 'kanban' ? 'Kanban' : 'Split View'}
            </button>
          ))}
        </div>
      </div>

      {/* 24-Column Grid Dashboard */}
      {(viewMode === 'grid' || viewMode === 'split') && (
        <section aria-label="Widget grid">
          <GridDashboard
            renderPanel={(panelDef: PanelDef) => {
              // Map panel registry to existing widget renderers
              switch (panelDef.id) {
                case 'kpi-overview': return <KpiWidget />
                case 'active-decisions': return <ActiveDecisionsWidget />
                case 'escalation-feed': return <EscalationWidget />
                case 'trust-scores': return <TrustScoreWidget />
                case 'audit-chain': return <AuditChainWidget />
                case 'delegation-map': return <DelegationWidget />
                case 'agent-status': return <AgentWidget />
                case 'cgr-kernel': return <CgrKernelWidget />
                case 'council-tickets': return <CouncilTicketsWidget />
                default: return <div className="text-sm text-[var(--text-muted)]">Widget: {panelDef.id}</div>
              }
            }}
          />
        </section>
      )}

      {/* Kanban Board */}
      {(viewMode === 'kanban' || viewMode === 'split') && (
        <section aria-label="Governance kanban">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-lg font-semibold text-[var(--text-primary)]">Governance Workflow</h2>
            <div className="text-xs text-[var(--text-muted)]">
              {kanbanCols.reduce((sum, c) => sum + c.cards.length, 0)} cards across {kanbanCols.length} columns
            </div>
          </div>
          <KanbanBoard
            columns={kanbanCols}
            onCardMove={handleCardMove}
            onCardClick={handleCardClick}
          />
        </section>
      )}
    </div>
  )
}
