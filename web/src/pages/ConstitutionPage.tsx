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

import { useState, useEffect } from 'react'
import type { ConstitutionInfo } from '../lib/types'
import { api } from '../lib/api'
import { cn } from '../lib/utils'

/** Truncate hash for display */
function truncateHash(hash: string): string {
  if (hash.length <= 12) return hash
  return `${hash.slice(0, 8)}...${hash.slice(-4)}`
}

/** Failure action badge color */
function failureActionColor(action: string): string {
  const lower = action.toLowerCase()
  if (lower === 'block') return 'bg-red-100 text-red-800 border-red-200'
  if (lower === 'warn') return 'bg-yellow-100 text-yellow-800 border-yellow-200'
  if (lower === 'escalate') return 'bg-orange-100 text-orange-800 border-orange-200'
  return 'bg-slate-100 text-slate-600 border-slate-200'
}

/**
 * Constitution Page — governance framework and constraints.
 */
export function ConstitutionPage() {
  const [constitution, setConstitution] = useState<ConstitutionInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.constitution
      .get()
      .then(setConstitution)
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load constitution'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="text-center py-12 text-slate-500" role="status" aria-label="Loading constitution">
        <div className="inline-block w-6 h-6 border-2 border-slate-300 border-t-blue-600 rounded-full animate-spin mb-3" aria-hidden="true" />
        <p>Loading constitution...</p>
      </div>
    )
  }

  if (error || !constitution) {
    return (
      <div className="text-center py-12">
        <p className="text-slate-500">{error || 'Constitution not found.'}</p>
      </div>
    )
  }

  return (
    <div>
      {/* Page header */}
      <div className="mb-8">
        <h1 className="text-xl sm:text-2xl font-bold text-slate-900">Constitution</h1>
        <p className="text-sm text-slate-500 mt-1">Governance framework and constraints</p>
      </div>

      {/* Overview Card */}
      <section
        aria-labelledby="overview-heading"
        className="bg-white border border-slate-200 rounded-xl p-6 mb-8"
      >
        <h2 id="overview-heading" className="text-lg font-semibold text-slate-900 mb-4">Framework Overview</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="border border-slate-200 rounded-lg p-4">
            <p className="text-xs text-slate-400 uppercase tracking-wide">Tenant</p>
            <p className="text-sm font-medium text-slate-900 mt-1">{constitution.tenantId}</p>
          </div>
          <div className="border border-slate-200 rounded-lg p-4">
            <p className="text-xs text-slate-400 uppercase tracking-wide">Version</p>
            <p className="text-2xl font-bold text-slate-900 mt-1">v{constitution.version}</p>
          </div>
          <div className="border border-slate-200 rounded-lg p-4">
            <p className="text-xs text-slate-400 uppercase tracking-wide">Document Hash</p>
            <p
              className="text-sm font-mono text-slate-600 mt-1"
              title={constitution.hash}
            >
              {truncateHash(constitution.hash)}
            </p>
          </div>
          <div className="border border-slate-200 rounded-lg p-4">
            <p className="text-xs text-slate-400 uppercase tracking-wide">Documents</p>
            <p className="text-2xl font-bold text-slate-900 mt-1">{constitution.documentCount}</p>
          </div>
        </div>
      </section>

      {/* Human Gate Classes */}
      <section
        aria-labelledby="human-gate-heading"
        className="bg-white border border-slate-200 rounded-xl p-6 mb-8"
      >
        <h2 id="human-gate-heading" className="text-lg font-semibold text-slate-900 mb-2">Human Gate Classes</h2>
        <p className="text-sm text-slate-500 mb-4">Decision classes requiring mandatory human approval</p>
        {constitution.humanGateClasses.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {constitution.humanGateClasses.map((cls) => (
              <span
                key={cls}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-50 border border-blue-200 text-blue-800 text-sm font-medium"
              >
                <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                  <path d="M10 8a3 3 0 100-6 3 3 0 000 6zM3.465 14.493a1.23 1.23 0 00.41 1.412A9.957 9.957 0 0010 18c2.31 0 4.438-.784 6.131-2.1.43-.333.604-.903.408-1.41a7.002 7.002 0 00-13.074.003z" />
                </svg>
                {cls}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-sm text-slate-400 italic">No human gate classes defined.</p>
        )}
      </section>

      {/* Delegation Limits */}
      <section
        aria-labelledby="delegation-limits-heading"
        className="bg-white border border-slate-200 rounded-xl p-6 mb-8"
      >
        <h2 id="delegation-limits-heading" className="text-lg font-semibold text-slate-900 mb-2">Delegation Limits</h2>
        <p className="text-sm text-slate-500 mb-4">Maximum depth of delegation chains</p>
        <div className="flex items-center gap-4">
          <div className="w-16 h-16 rounded-xl bg-purple-50 border border-purple-200 flex items-center justify-center">
            <span className="text-2xl font-bold text-purple-700">{constitution.maxDelegationDepth}</span>
          </div>
          <div>
            <p className="text-sm font-medium text-slate-900">Maximum Delegation Depth</p>
            <p className="text-xs text-slate-500">
              Delegation chains cannot exceed {constitution.maxDelegationDepth} level{constitution.maxDelegationDepth !== 1 ? 's' : ''} deep
            </p>
          </div>
        </div>
      </section>

      {/* Constraints Section */}
      <section aria-labelledby="constraints-heading" className="bg-white border border-slate-200 rounded-xl p-6">
        <h2 id="constraints-heading" className="text-lg font-semibold text-slate-900 mb-2">Active Constraints</h2>
        <p className="text-sm text-slate-500 mb-4">Rules enforced by the governance framework</p>
        {constitution.constraints.length > 0 ? (
          <div className="space-y-3">
            {constitution.constraints.map((constraint) => (
              <div
                key={constraint.id}
                className="border border-slate-200 rounded-lg p-4 hover:border-slate-300 transition-colors"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-mono font-medium text-slate-700">{constraint.id}</span>
                      <span className={cn(
                        'inline-flex px-2 py-0.5 rounded-full text-xs font-medium border',
                        failureActionColor(constraint.failureAction)
                      )}>
                        {constraint.failureAction}
                      </span>
                    </div>
                    <p className="text-sm text-slate-600 mt-1">{constraint.description}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-slate-400 italic">No constraints defined.</p>
        )}
      </section>
    </div>
  )
}
