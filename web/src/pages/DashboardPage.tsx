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

import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { DecisionCard } from '../components/DecisionCard'
import { useDecisions } from '../hooks/useDecisions'
import { isTerminalStatus } from '../lib/types'
import type { Decision, DecisionStatus } from '../lib/types'

/* ── Filter definitions ── */
type FilterKey = 'all' | 'active' | DecisionStatus

interface FilterDef {
  label: string
  value: FilterKey
}

const STATUS_FILTERS: FilterDef[] = [
  { label: 'All', value: 'all' },
  { label: 'Active', value: 'active' },
  { label: 'Voting', value: 'Voting' },
  { label: 'Deliberation', value: 'Deliberation' },
  { label: 'Approved', value: 'Approved' },
  { label: 'Rejected', value: 'Rejected' },
  { label: 'Created', value: 'Created' },
  { label: 'Contested', value: 'Contested' },
]

/* ── Sort definitions ── */
type SortKey = 'date' | 'status' | 'class'

const SORT_OPTIONS: { label: string; value: SortKey }[] = [
  { label: 'Date', value: 'date' },
  { label: 'Status', value: 'status' },
  { label: 'Class', value: 'class' },
]

const STATUS_ORDER: Record<string, number> = {
  Voting: 0,
  Contested: 1,
  DegradedGovernance: 2,
  RatificationRequired: 3,
  Deliberation: 4,
  Created: 5,
  Approved: 6,
  Rejected: 7,
  Void: 8,
  RatificationExpired: 9,
}

function sortDecisions(decisions: Decision[], key: SortKey): Decision[] {
  const sorted = [...decisions]
  switch (key) {
    case 'date':
      return sorted.sort((a, b) => b.createdAt - a.createdAt)
    case 'status':
      return sorted.sort(
        (a, b) => (STATUS_ORDER[a.status] ?? 99) - (STATUS_ORDER[b.status] ?? 99)
      )
    case 'class':
      return sorted.sort((a, b) => a.decisionClass.localeCompare(b.decisionClass))
    default:
      return sorted
  }
}

function filterDecisions(decisions: Decision[], filter: FilterKey): Decision[] {
  if (filter === 'all') return decisions
  if (filter === 'active') return decisions.filter((d) => !isTerminalStatus(d.status))
  return decisions.filter((d) => d.status === filter)
}

/* ── Loading skeleton ── */
function SkeletonCard() {
  return (
    <div className="border border-slate-200 rounded-lg p-4 bg-white animate-pulse" aria-hidden="true">
      <div className="flex items-start gap-3">
        <div className="w-3 h-3 rounded-full bg-slate-200 mt-1" />
        <div className="flex-1 space-y-2">
          <div className="h-5 bg-slate-200 rounded w-3/4" />
          <div className="h-3 bg-slate-100 rounded w-1/2" />
        </div>
        <div className="h-9 w-28 bg-slate-200 rounded-md" />
      </div>
    </div>
  )
}

/* ── Stat card ── */
function StatCard({
  label,
  count,
  accent,
}: {
  label: string
  count: number
  accent: string
}) {
  return (
    <div className="border border-slate-200 rounded-lg bg-white p-4 text-center">
      <p className={`text-2xl font-bold ${accent}`}>{count}</p>
      <p className="text-sm text-slate-500 mt-0.5">{label}</p>
    </div>
  )
}

/**
 * Command View — executive's primary governance dashboard.
 *
 * Structure: KPI stats -> filter/sort bar -> decision brief list -> quick actions.
 * Mobile-first responsive layout. WCAG 2.2 AA compliant.
 */
export function DashboardPage() {
  const { decisions, loading, error, refresh } = useDecisions()
  const [filter, setFilter] = useState<FilterKey>('all')
  const [sort, setSort] = useState<SortKey>('date')

  const processed = useMemo(
    () => sortDecisions(filterDecisions(decisions, filter), sort),
    [decisions, filter, sort]
  )

  /* ── Stats ── */
  const stats = useMemo(
    () => ({
      total: decisions.length,
      pendingAction: decisions.filter((d) => !isTerminalStatus(d.status)).length,
      inVoting: decisions.filter((d) => d.status === 'Voting').length,
      approved: decisions.filter((d) => d.status === 'Approved').length,
    }),
    [decisions]
  )

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
      <header>
        <h1 className="text-2xl font-bold text-slate-900">Command View</h1>
        <p className="text-sm text-slate-500 mt-1">Active governance decisions</p>
      </header>

      {/* ── KPI Stats Row ── */}
      <section
        aria-label="Decision statistics"
        className="grid grid-cols-2 sm:grid-cols-4 gap-3"
      >
        <StatCard label="Total Decisions" count={stats.total} accent="text-slate-700" />
        <StatCard label="Pending Action" count={stats.pendingAction} accent="text-blue-600" />
        <StatCard label="In Voting" count={stats.inVoting} accent="text-yellow-600" />
        <StatCard label="Approved" count={stats.approved} accent="text-green-600" />
      </section>

      {/* ── Filter / Sort Bar ── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        {/* Status filters */}
        <nav aria-label="Filter decisions by status">
          <ul className="flex flex-nowrap gap-1.5 overflow-x-auto pb-1 -mb-1 sm:flex-wrap sm:overflow-visible sm:pb-0 sm:mb-0">
            {STATUS_FILTERS.map((f) => (
              <li key={f.value} className="flex-shrink-0">
                <button
                  onClick={() => setFilter(f.value)}
                  aria-pressed={filter === f.value}
                  className={`px-3 py-1.5 rounded-full text-sm font-medium transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-1 ${
                    filter === f.value
                      ? 'bg-slate-900 text-white'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {f.label}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        {/* Sort toggle */}
        <div className="flex items-center gap-1.5" role="group" aria-label="Sort decisions">
          <span className="text-xs text-slate-500 font-medium uppercase tracking-wide mr-1">
            Sort
          </span>
          {SORT_OPTIONS.map((s) => (
            <button
              key={s.value}
              onClick={() => setSort(s.value)}
              aria-pressed={sort === s.value}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-1 ${
                sort === s.value
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Error state ── */}
      {error && (
        <div
          className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700"
          role="alert"
        >
          <p className="font-medium">Failed to load decisions</p>
          <p className="mt-1">{error}</p>
          <button
            onClick={refresh}
            className="mt-2 text-sm font-medium text-red-800 underline hover:no-underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
          >
            Try again
          </button>
        </div>
      )}

      {/* ── Decision List ── */}
      {loading ? (
        <div className="space-y-3" role="status" aria-live="polite" aria-label="Loading decisions">
          <span className="sr-only">Loading decisions...</span>
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : processed.length === 0 ? (
        <div className="text-center py-16">
          <svg
            className="mx-auto h-12 w-12 text-slate-300"
            fill="none"
            viewBox="0 0 24 24"
            strokeWidth={1}
            stroke="currentColor"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m6.75 12H9.75m3 0h-3m0 0v3m0-3v-3m-3.375 7.5h7.5a2.25 2.25 0 002.25-2.25V6.75a2.25 2.25 0 00-2.25-2.25H6.75A2.25 2.25 0 004.5 6.75v10.5a2.25 2.25 0 002.25 2.25z"
            />
          </svg>
          <h3 className="mt-3 text-sm font-medium text-slate-900">No decisions found</h3>
          <p className="mt-1 text-sm text-slate-500">
            {filter !== 'all'
              ? `No decisions match the "${filter}" filter.`
              : 'Get started by creating your first decision.'}
          </p>
          {filter !== 'all' && (
            <button
              onClick={() => setFilter('all')}
              className="mt-3 text-sm font-medium text-blue-600 hover:text-blue-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              Clear filter
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-3" role="feed" aria-label="Decision list">
          {processed.map((decision) => (
            <DecisionCard key={decision.id} decision={decision} />
          ))}
        </div>
      )}

      {/* ── Connected Applications ── */}
      <section aria-label="Connected applications">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
          Connected Applications
        </h2>
        <div className="border border-slate-200 rounded-lg bg-white p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="inline-block w-2.5 h-2.5 rounded-full bg-green-500" aria-label="Connected" />
              <div>
                <p className="text-sm font-semibold text-slate-900">LiveSafe.ai</p>
                <p className="text-xs text-slate-500">Patient-sovereign health identity</p>
              </div>
            </div>
            <Link
              to="/applications/livesafe"
              className="text-sm font-medium text-blue-600 hover:text-blue-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              View Status
            </Link>
          </div>
        </div>
      </section>

      {/* ── Floating "New Decision" button ── */}
      <Link
        to="/decisions/new"
        className="fixed bottom-6 right-6 z-30 inline-flex items-center gap-2 px-5 py-3 rounded-full bg-blue-600 text-white text-sm font-semibold shadow-lg hover:bg-blue-700 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 md:bottom-8 md:right-8"
        aria-label="Create new decision"
      >
        <svg
          className="w-5 h-5"
          fill="none"
          viewBox="0 0 24 24"
          strokeWidth={2}
          stroke="currentColor"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
        </svg>
        <span className="hidden sm:inline">New Decision</span>
      </Link>
    </div>
  )
}
