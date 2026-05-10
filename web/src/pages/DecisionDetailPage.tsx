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

import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { StatusBadge } from '../components/StatusBadge'
import { AiRecommendationCard } from '../components/AiRecommendationCard'
import { useDecision } from '../hooks/useDecisions'
import { api } from '../lib/api'
import type { DecisionStatus, Vote } from '../lib/types'
import { cn } from '../lib/utils'

/** Format a DID for display: "did:exo:alice" -> "alice" */
function formatDid(did: string): string {
  return did.replace(/^did:exo:/, '')
}

/** Format epoch timestamp to readable date */
function formatDate(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

/** Map decision status to OODA phase index */
function oodaPhaseIndex(status: DecisionStatus): number {
  switch (status) {
    case 'Created':
      return 0
    case 'Deliberation':
      return 1
    case 'Voting':
    case 'RatificationRequired':
      return 2
    case 'Approved':
    case 'Rejected':
    case 'Void':
    case 'RatificationExpired':
    case 'Contested':
    case 'DegradedGovernance':
      return 3
    default:
      return 0
  }
}

const OODA_PHASES = [
  { key: 'observe', label: 'Observe', description: 'Evidence gathering' },
  { key: 'orient', label: 'Orient', description: 'Analysis & cross-checks' },
  { key: 'decide', label: 'Decide', description: 'Commitment' },
  { key: 'act', label: 'Act', description: 'Outcome' },
] as const

/**
 * Decision Dossier — comprehensive intelligence dossier for a single decision.
 */
export function DecisionDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { decision, loading, error, refresh } = useDecision(id || '')
  const [voteChoice, setVoteChoice] = useState<string>('')
  const [voteRationale, setVoteRationale] = useState('')
  const [submittingVote, setSubmittingVote] = useState(false)
  const [advancingTo, setAdvancingTo] = useState<string | null>(null)
  const [tallySubmitting, setTallySubmitting] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  if (loading) {
    return (
      <div className="text-center py-12 text-slate-500" role="status" aria-label="Loading decision">
        <div className="inline-block w-6 h-6 border-2 border-slate-300 border-t-blue-600 rounded-full animate-spin mb-3" aria-hidden="true" />
        <p>Loading decision dossier...</p>
      </div>
    )
  }

  if (error || !decision) {
    return (
      <div className="text-center py-12">
        <p className="text-slate-500 mb-4">{error || 'Decision not found.'}</p>
        <Link to="/" className="text-blue-600 hover:underline focus-visible:outline-2 focus-visible:outline-blue-600">
          Back to Command View
        </Link>
      </div>
    )
  }

  const currentOodaIdx = oodaPhaseIndex(decision.status)

  // Vote tallies
  const approveCount = decision.votes.filter((v) => v.choice === 'Approve').length
  const rejectCount = decision.votes.filter((v) => v.choice === 'Reject').length
  const abstainCount = decision.votes.filter((v) => v.choice === 'Abstain').length
  const totalVotes = decision.votes.length

  const handleVote = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!voteChoice) return
    setSubmittingVote(true)
    setActionError(null)
    try {
      await api.decisions.vote(decision.id, 'did:exo:alice', voteChoice, voteRationale || undefined)
      setVoteChoice('')
      setVoteRationale('')
      refresh()
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to cast vote')
    } finally {
      setSubmittingVote(false)
    }
  }

  const handleAdvance = async (newStatus: string) => {
    setAdvancingTo(newStatus)
    setActionError(null)
    try {
      await api.decisions.advance(decision.id, newStatus, 'did:exo:alice')
      refresh()
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to advance decision')
    } finally {
      setAdvancingTo(null)
    }
  }

  const handleTally = async () => {
    setTallySubmitting(true)
    setActionError(null)
    try {
      await api.decisions.tally(decision.id, 'did:exo:alice')
      refresh()
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to tally votes')
    } finally {
      setTallySubmitting(false)
    }
  }

  return (
    <div className="space-y-8">
      {/* Back link */}
      <Link
        to="/"
        className="inline-flex items-center gap-1 text-sm text-blue-600 hover:text-blue-800 hover:underline focus-visible:outline-2 focus-visible:outline-blue-600"
        aria-label="Back to Command View"
      >
        <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
          <path fillRule="evenodd" d="M17 10a.75.75 0 01-.75.75H5.612l4.158 3.96a.75.75 0 11-1.04 1.08l-5.5-5.25a.75.75 0 010-1.08l5.5-5.25a.75.75 0 111.04 1.08L5.612 9.25H16.25A.75.75 0 0117 10z" clipRule="evenodd" />
        </svg>
        Back to Command View
      </Link>

      {/* OODA Lifecycle Rail */}
      <section aria-label="OODA decision lifecycle">
        <h2 className="sr-only">Decision Lifecycle</h2>
        <div className="bg-white border border-slate-200 rounded-xl p-4 sm:p-6">
          <nav aria-label="OODA lifecycle phases">
            <ol className="flex items-center justify-between gap-0">
              {OODA_PHASES.map((phase, idx) => {
                const isComplete = idx < currentOodaIdx
                const isCurrent = idx === currentOodaIdx
                const isFuture = idx > currentOodaIdx
                return (
                  <li key={phase.key} className="flex items-center flex-1 last:flex-initial">
                    <div className="flex flex-col items-center text-center min-w-0">
                      <div
                        className={cn(
                          'w-10 h-10 sm:w-12 sm:h-12 rounded-full flex items-center justify-center text-sm font-bold border-2 transition-colors',
                          isComplete && 'bg-blue-600 border-blue-600 text-white',
                          isCurrent && 'bg-blue-100 border-blue-600 text-blue-700',
                          isFuture && 'bg-slate-100 border-slate-300 text-slate-400'
                        )}
                        aria-current={isCurrent ? 'step' : undefined}
                      >
                        {isComplete ? (
                          <svg className="w-5 h-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                            <path fillRule="evenodd" d="M16.704 4.153a.75.75 0 01.143 1.052l-8 10.5a.75.75 0 01-1.127.075l-4.5-4.5a.75.75 0 011.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 011.05-.143z" clipRule="evenodd" />
                          </svg>
                        ) : (
                          idx + 1
                        )}
                      </div>
                      <span className={cn(
                        'mt-2 text-xs sm:text-sm font-medium',
                        isComplete && 'text-blue-700',
                        isCurrent && 'text-blue-700',
                        isFuture && 'text-slate-400'
                      )}>
                        {phase.label}
                      </span>
                      <span className="hidden sm:block text-xs text-slate-400 mt-0.5">
                        {phase.description}
                      </span>
                    </div>
                    {idx < OODA_PHASES.length - 1 && (
                      <div
                        className={cn(
                          'flex-1 h-0.5 mx-2 sm:mx-4 mt-[-1.5rem] sm:mt-[-2rem]',
                          isComplete ? 'bg-blue-600' : 'bg-slate-200'
                        )}
                        aria-hidden="true"
                      />
                    )}
                  </li>
                )
              })}
            </ol>
          </nav>
        </div>
      </section>

      {/* Intelligence Brief */}
      <section aria-labelledby="intel-brief-heading" className="bg-white border border-slate-200 rounded-xl p-6">
        <h2 id="intel-brief-heading" className="sr-only">Intelligence Brief</h2>
        <div className="space-y-4">
          <div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 mb-3">{decision.title}</h1>
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge status={decision.status} />
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-700">
                {decision.decisionClass}
              </span>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-slate-500">
            <span>
              <span className="font-medium text-slate-700">{formatDid(decision.author)}</span>
            </span>
            <span aria-label="Created date">{formatDate(decision.createdAt)}</span>
            <span className="text-xs">Constitution v{decision.constitutionVersion}</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
            <div className="border border-slate-200 rounded-lg p-3">
              <p className="text-xs text-slate-400 uppercase tracking-wide">ID</p>
              <p className="text-sm font-mono text-slate-600 truncate" title={decision.id}>{decision.id}</p>
            </div>
            <div className="border border-slate-200 rounded-lg p-3">
              <p className="text-xs text-slate-400 uppercase tracking-wide">Tenant</p>
              <p className="text-sm font-mono text-slate-600 truncate">{decision.tenantId}</p>
            </div>
            <div className="border border-slate-200 rounded-lg p-3">
              <p className="text-xs text-slate-400 uppercase tracking-wide">Votes</p>
              <p className="text-sm font-semibold text-slate-700">{totalVotes}</p>
            </div>
            <div className="border border-slate-200 rounded-lg p-3">
              <p className="text-xs text-slate-400 uppercase tracking-wide">Challenges</p>
              <p className="text-sm font-semibold text-slate-700">{decision.challenges.length}</p>
            </div>
          </div>
        </div>
      </section>

      {/* Stakeholder & Voting Panel */}
      {(totalVotes > 0 || decision.status === 'Voting') && (
        <section aria-labelledby="voting-heading" className="bg-white border border-slate-200 rounded-xl p-6">
          <h2 id="voting-heading" className="text-lg font-semibold text-slate-900 mb-4">Stakeholder Votes</h2>

          {/* Vote summary bar */}
          {totalVotes > 0 && (
            <div className="mb-6">
              <div className="flex items-center gap-3 text-sm text-slate-600 mb-2">
                <span className="flex items-center gap-1">
                  <span className="w-3 h-3 rounded-sm bg-green-500" aria-hidden="true" />
                  Approve: {approveCount}
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-3 h-3 rounded-sm bg-red-500" aria-hidden="true" />
                  Reject: {rejectCount}
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-3 h-3 rounded-sm bg-slate-400" aria-hidden="true" />
                  Abstain: {abstainCount}
                </span>
              </div>
              <div
                className="flex h-3 rounded-full overflow-hidden bg-slate-100"
                role="img"
                aria-label={`Vote progress: ${approveCount} approve, ${rejectCount} reject, ${abstainCount} abstain out of ${totalVotes} total`}
              >
                {approveCount > 0 && (
                  <div
                    className="bg-green-500 transition-all"
                    style={{ width: `${(approveCount / totalVotes) * 100}%` }}
                  />
                )}
                {rejectCount > 0 && (
                  <div
                    className="bg-red-500 transition-all"
                    style={{ width: `${(rejectCount / totalVotes) * 100}%` }}
                  />
                )}
                {abstainCount > 0 && (
                  <div
                    className="bg-slate-400 transition-all"
                    style={{ width: `${(abstainCount / totalVotes) * 100}%` }}
                  />
                )}
              </div>
              <p className="text-xs text-slate-400 mt-1">
                {totalVotes} vote{totalVotes !== 1 ? 's' : ''} cast
              </p>
            </div>
          )}

          {/* Individual vote cards */}
          {totalVotes > 0 && (
            <div className="space-y-3 mb-6">
              {decision.votes.map((vote: Vote, idx: number) => (
                <div key={idx} className="border border-slate-200 rounded-lg p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-slate-800">{formatDid(vote.voter)}</span>
                        <span className={cn(
                          'inline-flex px-2 py-0.5 rounded-full text-xs font-medium',
                          vote.choice === 'Approve' && 'bg-green-100 text-green-800',
                          vote.choice === 'Reject' && 'bg-red-100 text-red-800',
                          vote.choice === 'Abstain' && 'bg-slate-100 text-slate-600'
                        )}>
                          {vote.choice}
                        </span>
                        <span className={cn(
                          'inline-flex px-2 py-0.5 rounded-full text-xs font-medium',
                          vote.signerType === 'Human' ? 'bg-blue-100 text-blue-700' : 'bg-purple-100 text-purple-700'
                        )}>
                          {vote.signerType}
                        </span>
                      </div>
                      {vote.rationale && (
                        <p className="text-sm text-slate-600 mt-2 italic">"{vote.rationale}"</p>
                      )}
                    </div>
                    <time className="text-xs text-slate-400 whitespace-nowrap" dateTime={new Date(vote.timestamp).toISOString()}>
                      {formatDate(vote.timestamp)}
                    </time>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Vote action form */}
          {decision.status === 'Voting' && (
            <form onSubmit={handleVote} className="border-t border-slate-200 pt-4">
              <h3 className="text-sm font-semibold text-slate-700 mb-3">Cast Your Vote</h3>
              <div className="flex flex-wrap gap-2 mb-3" role="radiogroup" aria-label="Vote choice">
                {(['Approve', 'Reject', 'Abstain'] as const).map((choice) => (
                  <label
                    key={choice}
                    className={cn(
                      'inline-flex items-center px-4 py-2 rounded-lg border-2 text-sm font-medium cursor-pointer transition-colors focus-within:ring-2 focus-within:ring-blue-500',
                      voteChoice === choice
                        ? choice === 'Approve' ? 'border-green-500 bg-green-50 text-green-800'
                          : choice === 'Reject' ? 'border-red-500 bg-red-50 text-red-800'
                          : 'border-slate-500 bg-slate-50 text-slate-800'
                        : 'border-slate-200 bg-white text-slate-600 hover:border-slate-400'
                    )}
                  >
                    <input
                      type="radio"
                      name="voteChoice"
                      value={choice}
                      checked={voteChoice === choice}
                      onChange={(e) => setVoteChoice(e.target.value)}
                      className="sr-only"
                    />
                    {choice}
                  </label>
                ))}
              </div>
              <div className="mb-3">
                <label htmlFor="vote-rationale" className="block text-xs text-slate-500 mb-1">
                  Rationale (optional)
                </label>
                <input
                  id="vote-rationale"
                  type="text"
                  value={voteRationale}
                  onChange={(e) => setVoteRationale(e.target.value)}
                  placeholder="Provide reasoning for your vote"
                  className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
              <button
                type="submit"
                disabled={!voteChoice || submittingVote}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:bg-slate-300 disabled:cursor-not-allowed focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 transition-colors"
              >
                {submittingVote ? 'Submitting...' : 'Submit Vote'}
              </button>
            </form>
          )}
        </section>
      )}

      {/* Challenge Panel */}
      {decision.challenges.length > 0 && (
        <section aria-labelledby="challenges-heading">
          <h2 id="challenges-heading" className="text-lg font-semibold text-slate-900 mb-3">Challenges</h2>
          <div className="space-y-3">
            {decision.challenges.map((ch) => (
              <div
                key={ch.id}
                className="border border-orange-300 bg-orange-50 rounded-xl p-4"
                role="alert"
              >
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-orange-500 mt-0.5 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                    <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                  </svg>
                  <div className="flex-1">
                    <p className="font-medium text-orange-800">{ch.grounds}</p>
                    <p className="text-xs text-orange-600 mt-1">
                      Status: <span className="font-medium">{ch.status}</span>
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* AI Recommendation — shown during Deliberation */}
      {decision.status === 'Deliberation' && (
        <section aria-label="AI recommendation">
          <h2 className="text-lg font-semibold text-slate-900 mb-3">AI Analysis</h2>
          <AiRecommendationCard
            recommendation="Based on historical governance data, this budget allocation aligns with organizational priorities and falls within established financial thresholds."
            confidence={0.87}
            modelVersion="governance-llm-v2"
            proofVerified={true}
            onHumanReview={() => alert('Human review acknowledged')}
          />
        </section>
      )}

      {/* Narrative Timeline */}
      {decision.transitionLog && decision.transitionLog.length > 0 && (
        <section aria-labelledby="timeline-heading" className="bg-white border border-slate-200 rounded-xl p-6">
          <h2 id="timeline-heading" className="text-lg font-semibold text-slate-900 mb-4">Narrative Timeline</h2>
          <div className="relative">
            {/* Vertical connecting line */}
            <div className="absolute left-4 top-2 bottom-2 w-0.5 bg-slate-200" aria-hidden="true" />

            <ol className="space-y-4" aria-label="Decision transition timeline">
              {decision.transitionLog.map((t, idx) => (
                <li key={idx} className="relative pl-10">
                  {/* Timeline dot */}
                  <div
                    className={cn(
                      'absolute left-2.5 top-1.5 w-3 h-3 rounded-full border-2 border-white',
                      idx === decision.transitionLog.length - 1 ? 'bg-blue-600' : 'bg-slate-400'
                    )}
                    aria-hidden="true"
                  />
                  <div className="border border-slate-200 rounded-lg p-3">
                    <div className="flex items-start justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2 text-sm">
                        <span className="inline-flex px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-500">
                          {t.from}
                        </span>
                        <svg className="w-4 h-4 text-slate-400" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                          <path fillRule="evenodd" d="M3 10a.75.75 0 01.75-.75h10.638L10.23 5.29a.75.75 0 111.04-1.08l5.5 5.25a.75.75 0 010 1.08l-5.5 5.25a.75.75 0 11-1.04-1.08l4.158-3.96H3.75A.75.75 0 013 10z" clipRule="evenodd" />
                        </svg>
                        <span className="inline-flex px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                          {t.to}
                        </span>
                      </div>
                      <time className="text-xs text-slate-400" dateTime={new Date(t.timestamp).toISOString()}>
                        {formatDate(t.timestamp)}
                      </time>
                    </div>
                    <div className="mt-1 text-xs text-slate-500">
                      by <span className="font-medium text-slate-700">{formatDid(t.actor)}</span>
                      {t.reason && <span className="ml-1">— {t.reason}</span>}
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </section>
      )}

      {/* Error display */}
      {actionError && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-800" role="alert">
          {actionError}
        </div>
      )}

      {/* Actions Bar */}
      {(!decision.isTerminal && decision.validNextStatuses.length > 0) || decision.status === 'Voting' ? (
        <section
          aria-label="Decision actions"
          className="bg-white border border-slate-200 rounded-xl p-4 sm:p-6 sticky bottom-0 sm:static z-10 shadow-lg sm:shadow-none"
        >
          <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">Actions</h2>
          <div className="flex flex-wrap gap-2">
            {decision.validNextStatuses.map((s) => (
              <button
                key={s}
                onClick={() => handleAdvance(s)}
                disabled={advancingTo !== null}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:bg-slate-300 disabled:cursor-not-allowed focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 transition-colors"
              >
                {advancingTo === s ? 'Advancing...' : `Advance to ${s}`}
              </button>
            ))}
            {decision.status === 'Voting' && (
              <button
                onClick={handleTally}
                disabled={tallySubmitting}
                className="px-4 py-2 bg-purple-600 text-white rounded-lg text-sm font-medium hover:bg-purple-700 disabled:bg-slate-300 disabled:cursor-not-allowed focus-visible:ring-2 focus-visible:ring-purple-500 focus-visible:ring-offset-2 transition-colors"
              >
                {tallySubmitting ? 'Tallying...' : 'Tally Votes'}
              </button>
            )}
          </div>
        </section>
      ) : null}
    </div>
  )
}
