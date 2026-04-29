/** feedbackStore.ts — Zustand store for mandated reporter feedback system.
 *
 * Every widget has a "Report Issue" capability. Reports are filed as
 * structured issues that get triaged by agent teams, tracked through
 * resolution, and surfaced on the Council Tickets board.
 *
 * This is the "mandated reporter" pattern: any widget can flag a problem,
 * and the system MUST acknowledge, triage, and resolve it. No report
 * gets silently dropped.
 */

import { create } from 'zustand'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type IssueSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type IssueCategory = 'bug' | 'ux' | 'data' | 'performance' | 'security' | 'feature' | 'question'
export type IssueStatus = 'open' | 'triaged' | 'assigned' | 'in-progress' | 'resolved' | 'dismissed'

export interface FeedbackIssue {
  id: string
  /** Widget that filed the report */
  sourceWidgetId: string
  sourceModuleType: string
  /** Reporter */
  title: string
  description: string
  severity: IssueSeverity
  category: IssueCategory
  status: IssueStatus
  /** Auto-captured context */
  widgetState?: Record<string, unknown>
  browserInfo?: string
  /** Agent assignment */
  assignedAgentTeam?: string
  assignedAgentId?: string
  /** Resolution */
  resolution?: string
  resolvedAt?: number
  /** Timestamps */
  createdAt: number
  updatedAt: number
}

// ---------------------------------------------------------------------------
// localStorage
// ---------------------------------------------------------------------------

const LS_KEY = 'exo_feedback_issues'

function loadIssues(): FeedbackIssue[] {
  try {
    return JSON.parse(localStorage.getItem(LS_KEY) || '[]')
  } catch {
    return []
  }
}

function persistIssues(issues: FeedbackIssue[]) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(issues))
  } catch { /* degrade gracefully */ }
}

// ---------------------------------------------------------------------------
// Server persistence
// ---------------------------------------------------------------------------

async function submitToServer(issue: FeedbackIssue) {
  try {
    await fetch('/api/v1/feedback-issues', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${localStorage.getItem('df_token')}`,
        'x-exo-auth-observed-at-ms': String(issue.updatedAt),
      },
      body: JSON.stringify(issue),
    })
  } catch { /* best-effort */ }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

interface FeedbackState {
  issues: FeedbackIssue[]
  /** Currently open reporter slideout */
  reporterOpen: boolean
  reporterWidgetId: string | null
  reporterModuleType: string | null

  // Actions
  openReporter: (widgetId: string, moduleType: string) => void
  closeReporter: () => void
  fileIssue: (input: {
    title: string
    description: string
    severity: IssueSeverity
    category: IssueCategory
    widgetState?: Record<string, unknown>
  }) => FeedbackIssue
  updateIssueStatus: (id: string, status: IssueStatus, resolution?: string) => void
  dismissIssue: (id: string, reason: string) => void

  // Computed
  openIssueCount: () => number
  issuesForWidget: (widgetId: string) => FeedbackIssue[]
}

export const useFeedbackStore = create<FeedbackState>((set, get) => ({
  issues: loadIssues(),
  reporterOpen: false,
  reporterWidgetId: null,
  reporterModuleType: null,

  openReporter: (widgetId, moduleType) => {
    set({ reporterOpen: true, reporterWidgetId: widgetId, reporterModuleType: moduleType })
  },

  closeReporter: () => {
    set({ reporterOpen: false, reporterWidgetId: null, reporterModuleType: null })
  },

  fileIssue: (input) => {
    const { reporterWidgetId, reporterModuleType, issues } = get()
    const now = Date.now()
    const issue: FeedbackIssue = {
      id: `fb-${now}-${Math.random().toString(36).slice(2, 8)}`,
      sourceWidgetId: reporterWidgetId || 'unknown',
      sourceModuleType: reporterModuleType || 'unknown',
      title: input.title,
      description: input.description,
      severity: input.severity,
      category: input.category,
      status: 'open',
      widgetState: input.widgetState,
      browserInfo: navigator.userAgent,
      createdAt: now,
      updatedAt: now,
    }
    const next = [issue, ...issues]
    set({ issues: next, reporterOpen: false, reporterWidgetId: null, reporterModuleType: null })
    persistIssues(next)
    submitToServer(issue)
    return issue
  },

  updateIssueStatus: (id, status, resolution) => {
    const { issues } = get()
    const now = Date.now()
    const next = issues.map(i =>
      i.id === id ? { ...i, status, resolution, updatedAt: now, ...(status === 'resolved' ? { resolvedAt: now } : {}) } : i
    )
    set({ issues: next })
    persistIssues(next)
  },

  dismissIssue: (id, reason) => {
    const { issues } = get()
    const now = Date.now()
    const next = issues.map(i =>
      i.id === id ? { ...i, status: 'dismissed' as IssueStatus, resolution: reason, updatedAt: now } : i
    )
    set({ issues: next })
    persistIssues(next)
  },

  openIssueCount: () => {
    return get().issues.filter(i => !['resolved', 'dismissed'].includes(i.status)).length
  },

  issuesForWidget: (widgetId) => {
    return get().issues.filter(i => i.sourceWidgetId === widgetId)
  },
}))
