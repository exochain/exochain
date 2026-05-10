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

import { Link } from 'react-router-dom'
import { cn } from '../lib/utils'
import { statusColor, isTerminalStatus } from '../lib/types'
import type { Decision, DecisionStatus, DecisionClass } from '../lib/types'

interface DecisionCardProps {
  decision: Decision
}

/* ── Status dot colors (solid dots, not badges) ── */
const STATUS_DOT_COLOR: Record<DecisionStatus, string> = {
  Created: 'bg-slate-400',
  Deliberation: 'bg-blue-500',
  Voting: 'bg-yellow-500',
  Approved: 'bg-green-500',
  Rejected: 'bg-red-500',
  Void: 'bg-gray-500',
  Contested: 'bg-orange-500',
  RatificationRequired: 'bg-purple-500',
  RatificationExpired: 'bg-red-800',
  DegradedGovernance: 'bg-amber-600',
}

/* ── Decision class badge colors ── */
const CLASS_BADGE: Record<string, string> = {
  Operational: 'bg-slate-100 text-slate-700',
  Strategic: 'bg-indigo-100 text-indigo-700',
  Constitutional: 'bg-purple-100 text-purple-700',
  Financial: 'bg-emerald-100 text-emerald-700',
  Emergency: 'bg-red-100 text-red-700',
}

function classBadgeColor(dc: DecisionClass): string {
  return CLASS_BADGE[dc] || 'bg-slate-100 text-slate-700'
}

/* ── Date formatting ── */
function formatDate(ts: number): string {
  if (ts < 1e12) return `HLC: ${ts}`
  const date = new Date(ts)
  const now = Date.now()
  const diffMs = now - ts
  const diffMin = Math.floor(diffMs / 60_000)
  const diffHr = Math.floor(diffMs / 3_600_000)
  const diffDay = Math.floor(diffMs / 86_400_000)
  if (diffMin < 1) return 'just now'
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHr < 24) return `${diffHr}h ago`
  if (diffDay < 7) return `${diffDay}d ago`
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

/* ── DID shortening ── */
function shortenDid(did: string): string {
  return did.replace(/^did:exo:/, '')
}

/* ── Primary action logic ── */
function primaryAction(decision: Decision): { label: string; variant: string } | null {
  if (decision.isTerminal) return null
  switch (decision.status) {
    case 'Created':
      return { label: 'Begin Deliberation', variant: 'bg-blue-600 hover:bg-blue-700 text-white' }
    case 'Deliberation':
      return { label: 'Advance to Voting', variant: 'bg-yellow-600 hover:bg-yellow-700 text-white' }
    case 'Voting':
      return { label: 'Cast Vote', variant: 'bg-green-600 hover:bg-green-700 text-white' }
    case 'Contested':
      return { label: 'Review Challenge', variant: 'bg-orange-600 hover:bg-orange-700 text-white' }
    case 'RatificationRequired':
      return { label: 'Ratify', variant: 'bg-purple-600 hover:bg-purple-700 text-white' }
    case 'DegradedGovernance':
      return { label: 'Resolve', variant: 'bg-amber-600 hover:bg-amber-700 text-white' }
    default:
      return null
  }
}

/**
 * Intelligence Brief Card — executive-grade decision summary.
 *
 * Desktop: horizontal row layout (status dot | title+metadata | action).
 * Mobile: stacked card (status+title top, metadata middle, full-width action bottom).
 *
 * WCAG 2.2 AA: proper ARIA labels, keyboard navigation, semantic HTML.
 */
export function DecisionCard({ decision }: DecisionCardProps) {
  const terminal = isTerminalStatus(decision.status)
  const action = primaryAction(decision)

  const approveCount = decision.votes.filter((v) => v.choice === 'Approve').length
  const rejectCount = decision.votes.filter((v) => v.choice === 'Reject').length
  const abstainCount = decision.votes.filter((v) => v.choice === 'Abstain').length
  const totalVotes = decision.votes.length
  const showVoteBar = decision.status === 'Voting' && totalVotes > 0

  return (
    <article
      className={cn(
        'group relative border rounded-lg bg-white hover:shadow-md transition-shadow',
        'focus-within:ring-2 focus-within:ring-blue-500 focus-within:ring-offset-2',
        terminal ? 'border-slate-200 opacity-80' : 'border-slate-200'
      )}
      aria-labelledby={`decision-title-${decision.id}`}
      aria-describedby={`decision-meta-${decision.id}`}
    >
      <Link
        to={`/decisions/${decision.id}`}
        className="absolute inset-0 z-10 focus:outline-none"
        aria-label={`View decision: ${decision.title}`}
        tabIndex={0}
      >
        <span className="sr-only">Open decision details</span>
      </Link>

      {/* ── Desktop: horizontal row | Mobile: stacked ── */}
      <div className="p-4 flex flex-col md:flex-row md:items-center md:gap-4">

        {/* Left: Status dot + Title block */}
        <div className="flex items-start gap-3 flex-1 min-w-0">
          {/* Status dot */}
          <div className="flex-shrink-0 pt-1" aria-hidden="true">
            <span
              className={cn(
                'block w-3 h-3 rounded-full',
                STATUS_DOT_COLOR[decision.status] || 'bg-gray-400',
                !terminal && 'ring-2 ring-offset-2',
                !terminal && (STATUS_DOT_COLOR[decision.status] || 'ring-gray-400').replace('bg-', 'ring-')
              )}
            />
          </div>

          <div className="flex-1 min-w-0">
            {/* Title row */}
            <div className="flex items-center gap-2 flex-wrap">
              <h3
                id={`decision-title-${decision.id}`}
                className="text-base font-semibold text-slate-900 truncate max-w-md"
                title={decision.title}
              >
                {decision.title}
              </h3>

              {/* Status badge */}
              <span
                className={cn(
                  'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium whitespace-nowrap',
                  statusColor(decision.status)
                )}
                role="status"
                aria-label={`Status: ${decision.status}${terminal ? ' (final)' : ''}`}
              >
                {decision.status.replace(/([A-Z])/g, ' $1').trim()}
              </span>

              {/* Decision class badge */}
              <span
                className={cn(
                  'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium whitespace-nowrap',
                  classBadgeColor(decision.decisionClass)
                )}
                aria-label={`Class: ${decision.decisionClass}`}
              >
                {decision.decisionClass}
              </span>
            </div>

            {/* Metadata row */}
            <div
              id={`decision-meta-${decision.id}`}
              className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-slate-500"
            >
              <span aria-label={`Author: ${shortenDid(decision.author)}`}>
                <svg className="inline-block w-3.5 h-3.5 mr-0.5 -mt-0.5 text-slate-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0" />
                </svg>
                {shortenDid(decision.author)}
              </span>
              <span aria-label={`Created: ${formatDate(decision.createdAt)}`}>
                {formatDate(decision.createdAt)}
              </span>

              {/* Transition count badge */}
              {decision.transitionLog.length > 0 && (
                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-100 text-xs text-slate-600">
                  {decision.transitionLog.length} transition{decision.transitionLog.length !== 1 ? 's' : ''}
                </span>
              )}

              {/* Vote count badge */}
              {totalVotes > 0 && (
                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-100 text-xs text-slate-600">
                  {totalVotes} vote{totalVotes !== 1 ? 's' : ''}
                </span>
              )}

              {/* Challenge indicator */}
              {decision.challenges.length > 0 && (
                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-orange-100 text-xs text-orange-700 font-medium" role="alert">
                  {decision.challenges.length} challenge{decision.challenges.length !== 1 ? 's' : ''}
                </span>
              )}
            </div>

            {/* Vote progress bar */}
            {showVoteBar && (
              <div className="mt-2" role="meter" aria-label="Vote progress" aria-valuenow={totalVotes} aria-valuemin={0}>
                <div className="flex h-2 w-full max-w-xs rounded-full overflow-hidden bg-slate-100">
                  {approveCount > 0 && (
                    <div
                      className="bg-green-500 transition-all"
                      style={{ width: `${(approveCount / totalVotes) * 100}%` }}
                      title={`${approveCount} approve`}
                    />
                  )}
                  {rejectCount > 0 && (
                    <div
                      className="bg-red-500 transition-all"
                      style={{ width: `${(rejectCount / totalVotes) * 100}%` }}
                      title={`${rejectCount} reject`}
                    />
                  )}
                  {abstainCount > 0 && (
                    <div
                      className="bg-slate-400 transition-all"
                      style={{ width: `${(abstainCount / totalVotes) * 100}%` }}
                      title={`${abstainCount} abstain`}
                    />
                  )}
                </div>
                <div className="mt-0.5 flex gap-3 text-xs text-slate-500">
                  <span className="text-green-600">{approveCount} approve</span>
                  <span className="text-red-600">{rejectCount} reject</span>
                  {abstainCount > 0 && <span className="text-slate-500">{abstainCount} abstain</span>}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right: Action area */}
        <div className="mt-3 md:mt-0 md:flex-shrink-0">
          {action ? (
            <Link
              to={`/decisions/${decision.id}`}
              className={cn(
                'relative z-20 inline-flex items-center justify-center px-4 py-2 rounded-md text-sm font-medium transition-colors',
                'w-full md:w-auto',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-blue-500',
                action.variant
              )}
              aria-label={`${action.label} for ${decision.title}`}
            >
              {action.label}
            </Link>
          ) : (
            <span className="inline-flex items-center px-3 py-1.5 text-sm font-medium text-slate-400">
              Finalized
            </span>
          )}
        </div>
      </div>
    </article>
  )
}
