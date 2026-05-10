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

import { useState, useEffect, useMemo } from 'react'
import type { Delegation } from '../lib/types'
import { api } from '../lib/api'
import { cn } from '../lib/utils'

/** Format a DID for display: "did:exo:alice" -> "alice" */
function formatDid(did: string): string {
  return did.replace(/^did:exo:/, '')
}

/** Format epoch timestamp to readable date */
function formatDate(ts: number): string {
  return new Date(ts).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

/**
 * Authority Map — delegation chain visualization.
 */
export function DelegationsPage() {
  const [delegations, setDelegations] = useState<Delegation[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.delegations
      .list()
      .then(setDelegations)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  // Group delegations by delegator for hierarchy display
  const groupedByDelegator = useMemo(() => {
    const groups = new Map<string, Delegation[]>()
    for (const d of delegations) {
      const key = d.delegator
      if (!groups.has(key)) groups.set(key, [])
      groups.get(key)!.push(d)
    }
    return groups
  }, [delegations])

  // Build chain structure: identify roots (delegators who are not delegatees of others)
  const allDelegatees = useMemo(() => new Set(delegations.map((d) => d.delegatee)), [delegations])
  const rootDelegators = useMemo(() => {
    const roots: string[] = []
    for (const delegator of groupedByDelegator.keys()) {
      if (!allDelegatees.has(delegator)) {
        roots.push(delegator)
      }
    }
    // If no roots found (circular), just use all delegators
    return roots.length > 0 ? roots : Array.from(groupedByDelegator.keys())
  }, [groupedByDelegator, allDelegatees])

  /** Render delegation cards for a given delegator, recursively */
  function renderDelegationTree(delegator: string, depth: number, visited: Set<string>): React.ReactNode {
    if (visited.has(delegator)) return null
    visited.add(delegator)
    const children = groupedByDelegator.get(delegator)
    if (!children) return null

    return children.map((d) => (
      <div key={d.id} className={cn('relative', depth > 0 && 'ml-6 sm:ml-10')}>
        {/* Connecting line */}
        {depth > 0 && (
          <div className="absolute left-[-1rem] sm:left-[-1.5rem] top-0 bottom-0 flex items-start" aria-hidden="true">
            <div className="w-0.5 h-full bg-slate-200" />
            <div className="absolute top-6 left-0 w-4 sm:w-6 h-0.5 bg-slate-200" />
          </div>
        )}

        {/* Delegation card */}
        <div
          className={cn(
            'border rounded-xl p-4 mb-3 transition-colors',
            d.active
              ? 'border-slate-200 bg-white hover:border-blue-300'
              : 'border-slate-100 bg-slate-50 opacity-70'
          )}
        >
          {/* Header: delegator -> delegatee */}
          <div className="flex items-center gap-2 flex-wrap mb-3">
            <span className="inline-flex items-center px-2.5 py-1 rounded-lg bg-blue-50 text-blue-800 text-sm font-medium">
              {formatDid(d.delegator)}
            </span>
            <svg className="w-5 h-5 text-slate-400 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path fillRule="evenodd" d="M3 10a.75.75 0 01.75-.75h10.638L10.23 5.29a.75.75 0 111.04-1.08l5.5 5.25a.75.75 0 010 1.08l-5.5 5.25a.75.75 0 11-1.04-1.08l4.158-3.96H3.75A.75.75 0 013 10z" clipRule="evenodd" />
            </svg>
            <span className="inline-flex items-center px-2.5 py-1 rounded-lg bg-green-50 text-green-800 text-sm font-medium">
              {formatDid(d.delegatee)}
            </span>
            <span
              className={cn(
                'inline-flex px-2 py-0.5 rounded-full text-xs font-medium ml-auto',
                d.active ? 'bg-green-100 text-green-800' : 'bg-slate-100 text-slate-500'
              )}
            >
              {d.active ? 'Active' : 'Expired'}
            </span>
          </div>

          {/* Details grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wide">Scope</p>
              <div className="flex flex-wrap gap-1 mt-1">
                {d.scope.split(',').map((s) => (
                  <span key={s.trim()} className="inline-flex px-2 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-700">
                    {s.trim()}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wide">Sub-delegation</p>
              <span className={cn(
                'inline-flex px-2 py-0.5 rounded-full text-xs font-medium mt-1',
                d.subDelegationAllowed ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
              )}>
                {d.subDelegationAllowed ? 'Allowed' : 'Not Allowed'}
              </span>
            </div>
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wide">Constitution</p>
              <p className="text-sm text-slate-700 mt-1">v{d.constitutionVersion}</p>
            </div>
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wide">Expires</p>
              <p className="text-sm text-slate-700 mt-1">{formatDate(d.expiresAt)}</p>
            </div>
          </div>
        </div>

        {/* Recurse into delegatee's delegations */}
        {renderDelegationTree(d.delegatee, depth + 1, visited)}
      </div>
    ))
  }

  return (
    <div>
      {/* Page header */}
      <div className="mb-8">
        <h1 className="text-xl sm:text-2xl font-bold text-slate-900">Authority Map</h1>
        <p className="text-sm text-slate-500 mt-1">Delegation chain visualization</p>
      </div>

      {loading ? (
        <div className="text-center py-12 text-slate-500" role="status" aria-label="Loading delegations">
          <div className="inline-block w-6 h-6 border-2 border-slate-300 border-t-blue-600 rounded-full animate-spin mb-3" aria-hidden="true" />
          <p>Loading authority map...</p>
        </div>
      ) : delegations.length === 0 ? (
        <div className="text-center py-12 text-slate-400">
          <p>No delegations found.</p>
        </div>
      ) : (
        <>
          {/* Summary stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
            <div className="bg-white border border-slate-200 rounded-xl p-4">
              <p className="text-xs text-slate-400 uppercase tracking-wide">Total Delegations</p>
              <p className="text-2xl font-bold text-slate-900 mt-1">{delegations.length}</p>
            </div>
            <div className="bg-white border border-slate-200 rounded-xl p-4">
              <p className="text-xs text-slate-400 uppercase tracking-wide">Active</p>
              <p className="text-2xl font-bold text-green-600 mt-1">{delegations.filter((d) => d.active).length}</p>
            </div>
            <div className="bg-white border border-slate-200 rounded-xl p-4">
              <p className="text-xs text-slate-400 uppercase tracking-wide">Expired</p>
              <p className="text-2xl font-bold text-slate-400 mt-1">{delegations.filter((d) => !d.active).length}</p>
            </div>
            <div className="bg-white border border-slate-200 rounded-xl p-4">
              <p className="text-xs text-slate-400 uppercase tracking-wide">Delegators</p>
              <p className="text-2xl font-bold text-slate-900 mt-1">{groupedByDelegator.size}</p>
            </div>
          </div>

          {/* Desktop: Tree visualization */}
          <div className="hidden sm:block" aria-label="Delegation hierarchy tree">
            {rootDelegators.map((root) => (
              <div key={root} className="mb-6">
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-2 h-2 rounded-full bg-blue-600" aria-hidden="true" />
                  <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wide">
                    Root: {formatDid(root)}
                  </h2>
                </div>
                {renderDelegationTree(root, 0, new Set())}
              </div>
            ))}
          </div>

          {/* Mobile: Flat list with indentation */}
          <div className="sm:hidden" aria-label="Delegation list">
            {rootDelegators.map((root) => (
              <div key={root} className="mb-4">
                <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wide mb-2">
                  {formatDid(root)}
                </h2>
                {renderDelegationTree(root, 0, new Set())}
              </div>
            ))}
          </div>
        </>
      )}

      <p className="mt-6 text-xs text-slate-400">
        TNC-05: Delegations expire immediately at their deadline with no grace period.
        TNC-09: AI agents are subject to delegation ceiling restrictions.
      </p>
    </div>
  )
}
