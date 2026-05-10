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

import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../lib/auth'
import { api } from '../lib/api'
import { cn } from '../lib/utils'
import type { IdentityScore, PaceStatus } from '../lib/types'

const PACE_STEPS: { key: string; label: string; status: PaceStatus }[] = [
  { key: 'P', label: 'Provable', status: 'Provable' },
  { key: 'A', label: 'Auditable', status: 'Auditable' },
  { key: 'C', label: 'Compliant', status: 'Compliant' },
  { key: 'E', label: 'Enforceable', status: 'Enforceable' },
]

const PACE_ORDER: PaceStatus[] = ['Unenrolled', 'Provable', 'Auditable', 'Compliant', 'Enforceable']

function paceIndex(status: PaceStatus): number {
  return PACE_ORDER.indexOf(status)
}

function tierColor(tier: string): string {
  switch (tier) {
    case 'Verified': return 'bg-green-100 text-green-800'
    case 'Trusted': return 'bg-blue-100 text-blue-800'
    case 'Standard': return 'bg-slate-100 text-slate-700'
    case 'Probationary': return 'bg-amber-100 text-amber-800'
    case 'Untrusted': return 'bg-red-100 text-red-800'
    default: return 'bg-slate-100 text-slate-700'
  }
}

function scoreTier(score: number): { tier: string; color: string } {
  if (score >= 900) return { tier: 'Verified', color: 'text-green-600' }
  if (score >= 700) return { tier: 'Trusted', color: 'text-blue-600' }
  if (score >= 500) return { tier: 'Standard', color: 'text-slate-600' }
  if (score >= 300) return { tier: 'Probationary', color: 'text-amber-600' }
  return { tier: 'Untrusted', color: 'text-red-600' }
}

export function IdentityPage() {
  const { user } = useAuth()
  const [identityScore, setIdentityScore] = useState<IdentityScore | null>(null)
  const [loading, setLoading] = useState(true)
  const [copied, setCopied] = useState(false)

  const fetchScore = useCallback(async () => {
    if (!user) return
    try {
      const score = await api.identity.score(user.did)
      setIdentityScore(score)
    } catch {
      // Score endpoint may not be available yet
    } finally {
      setLoading(false)
    }
  }, [user])

  useEffect(() => {
    fetchScore()
  }, [fetchScore])

  function copyDid() {
    if (!user) return
    navigator.clipboard.writeText(user.did).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  if (!user) return null

  const currentPaceIdx = paceIndex(user.paceStatus)
  const score = identityScore?.score ?? user.trustScore
  const tier = scoreTier(score)
  const isFullyEnrolled = user.paceStatus === 'Enforceable'

  return (
    <div className="space-y-6 max-w-4xl">
      <h1 className="text-2xl font-bold text-slate-900">Governance Identity</h1>

      {/* Identity Card */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
        <div className="flex flex-col tablet:flex-row tablet:items-start tablet:justify-between gap-4">
          <div className="space-y-2">
            <h2 className="text-lg font-semibold text-slate-900">{user.displayName}</h2>
            <p className="text-sm text-slate-500">{user.email}</p>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">DID:</span>
              <code className="font-mono text-xs text-slate-600 bg-slate-50 px-2 py-0.5 rounded">
                {user.did.length > 32 ? `${user.did.slice(0, 16)}...${user.did.slice(-8)}` : user.did}
              </code>
              <button
                onClick={copyDid}
                className="text-xs text-blue-600 hover:text-blue-700 focus-visible:outline-2 focus-visible:outline-blue-600"
                aria-label="Copy DID to clipboard"
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {user.roles.map(role => (
              <span
                key={role}
                className="inline-flex items-center rounded-full bg-blue-50 px-2.5 py-0.5 text-xs font-medium text-blue-700"
              >
                {role}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* PACE Status */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
        <h2 className="text-base font-semibold text-slate-900 mb-4">PACE Status</h2>
        <div className="flex items-center justify-center gap-3 tablet:gap-6">
          {PACE_STEPS.map((step, i) => {
            const stepIdx = i + 1 // PACE_ORDER index (skip 'Unenrolled')
            const completed = currentPaceIdx >= stepIdx
            const current = currentPaceIdx === stepIdx
            return (
              <div key={step.key} className="flex items-center">
                <div className="flex flex-col items-center">
                  <div
                    className={cn(
                      'w-12 h-12 rounded-full flex items-center justify-center text-sm font-bold border-2 transition-colors',
                      completed
                        ? 'border-blue-600 bg-blue-600 text-white'
                        : current
                          ? 'border-blue-400 bg-blue-50 text-blue-600'
                          : 'border-slate-300 bg-slate-50 text-slate-400'
                    )}
                    aria-label={`${step.label}: ${completed ? 'completed' : current ? 'current' : 'pending'}`}
                  >
                    {step.key}
                  </div>
                  <span className={cn(
                    'mt-1.5 text-xs font-medium',
                    completed ? 'text-blue-600' : 'text-slate-400'
                  )}>
                    {step.label}
                  </span>
                </div>
                {i < PACE_STEPS.length - 1 && (
                  <div
                    className={cn(
                      'w-8 tablet:w-12 h-0.5 mb-5 mx-1',
                      currentPaceIdx > stepIdx ? 'bg-blue-600' : 'bg-slate-300'
                    )}
                    aria-hidden="true"
                  />
                )}
              </div>
            )
          })}
        </div>

        {!isFullyEnrolled && (
          <div className="mt-6 text-center space-y-3">
            <Link
              to="/identity/pace"
              className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-emerald-600 to-blue-600 px-6 py-2.5 text-sm font-semibold text-white hover:from-emerald-700 hover:to-blue-700 shadow-md hover:shadow-lg transition-all"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Begin PACE Enrollment Wizard
            </Link>
            <p className="text-xs text-slate-500">
              Set up Shamir's Secret Sharing with 4+ trusted contacts to secure your key
            </p>
          </div>
        )}
      </div>

      {/* Trust Score */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
        <h2 className="text-base font-semibold text-slate-900 mb-4">Trust Score</h2>
        <div className="flex flex-col tablet:flex-row tablet:items-center gap-6">
          <div className="text-center">
            <div className={cn('text-5xl font-bold', tier.color)}>
              {score}
            </div>
            <span className={cn(
              'mt-2 inline-block rounded-full px-3 py-0.5 text-xs font-semibold',
              tierColor(tier.tier)
            )}>
              {tier.tier}
            </span>
          </div>

          {/* Score bar */}
          <div className="flex-1">
            <div className="w-full bg-slate-100 rounded-full h-3">
              <div
                className={cn(
                  'h-3 rounded-full transition-all',
                  score >= 900 ? 'bg-green-500'
                    : score >= 700 ? 'bg-blue-500'
                    : score >= 500 ? 'bg-slate-500'
                    : score >= 300 ? 'bg-amber-500'
                    : 'bg-red-500'
                )}
                style={{ width: `${Math.min(100, (score / 1000) * 100)}%` }}
                role="progressbar"
                aria-valuenow={score}
                aria-valuemin={0}
                aria-valuemax={1000}
                aria-label={`Trust score: ${score} out of 1000`}
              />
            </div>
            <div className="flex justify-between mt-1 text-2xs text-slate-400">
              <span>0</span>
              <span>1000</span>
            </div>
          </div>
        </div>
      </div>

      {/* Score Factors */}
      {identityScore && (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-4">Score Factors</h2>
          <div className="grid grid-cols-2 tablet:grid-cols-4 gap-4">
            <FactorCard label="Tenure" value={`${identityScore.factors.tenureDays} days`} />
            <FactorCard label="Decisions" value={String(identityScore.factors.decisionsParticipated)} />
            <FactorCard label="Votes Cast" value={String(identityScore.factors.votesCast)} />
            <FactorCard
              label="Violations"
              value={String(identityScore.factors.complianceViolations)}
              warn={identityScore.factors.complianceViolations > 0}
            />
          </div>
        </div>
      )}

      {loading && !identityScore && (
        <div className="text-sm text-slate-400 text-center py-4">Loading identity data...</div>
      )}
    </div>
  )
}

function FactorCard({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="bg-slate-50 rounded-lg p-4 text-center">
      <div className={cn('text-xl font-bold', warn ? 'text-red-600' : 'text-slate-900')}>
        {value}
      </div>
      <div className="mt-1 text-xs text-slate-500">{label}</div>
    </div>
  )
}
