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
import type { AuditEntry, AuditIntegrity } from '../lib/types'
import { api } from '../lib/api'
import { cn } from '../lib/utils'

/** Format a DID for display */
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

/** Truncate hash for display */
function truncateHash(hash: string): string {
  if (hash.length <= 12) return hash
  return `${hash.slice(0, 8)}...${hash.slice(-4)}`
}

/** Event type color mapping */
function eventTypeColor(eventType: string): string {
  if (eventType.includes('Created')) return 'bg-slate-100 text-slate-700'
  if (eventType.includes('Advanced')) return 'bg-blue-100 text-blue-700'
  if (eventType.includes('Vote')) return 'bg-yellow-100 text-yellow-700'
  if (eventType.includes('Challenge')) return 'bg-orange-100 text-orange-700'
  if (eventType.includes('Delegation')) return 'bg-purple-100 text-purple-700'
  if (eventType.includes('Tally')) return 'bg-green-100 text-green-700'
  return 'bg-slate-100 text-slate-600'
}

/** All known event types for filter */
const EVENT_TYPES = [
  'All',
  'DecisionCreated',
  'DecisionAdvanced',
  'VoteCast',
  'VoteTallied',
  'ChallengeRaised',
  'DelegationCreated',
  'DelegationRevoked',
]

/**
 * Audit Ledger — tamper-evident governance record.
 */
export function AuditTrailPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [integrity, setIntegrity] = useState<AuditIntegrity | null>(null)
  const [loading, setLoading] = useState(true)
  const [filterType, setFilterType] = useState('All')

  useEffect(() => {
    Promise.all([api.audit.trail(), api.audit.verify()])
      .then(([trail, verify]) => {
        setEntries(trail)
        setIntegrity(verify)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const filteredEntries = useMemo(() => {
    if (filterType === 'All') return entries
    return entries.filter((e) => e.eventType === filterType)
  }, [entries, filterType])

  return (
    <div>
      {/* Page header */}
      <div className="mb-8">
        <h1 className="text-xl sm:text-2xl font-bold text-slate-900">Audit Ledger</h1>
        <p className="text-sm text-slate-500 mt-1">Tamper-evident governance record</p>
      </div>

      {loading ? (
        <div className="text-center py-12 text-slate-500" role="status" aria-label="Loading audit ledger">
          <div className="inline-block w-6 h-6 border-2 border-slate-300 border-t-blue-600 rounded-full animate-spin mb-3" aria-hidden="true" />
          <p>Loading audit ledger...</p>
        </div>
      ) : (
        <>
          {/* Chain Status Card */}
          {integrity && (
            <div
              className={cn(
                'border rounded-xl p-6 mb-8',
                integrity.verified
                  ? 'border-green-200 bg-gradient-to-r from-green-50 to-white'
                  : 'border-red-200 bg-gradient-to-r from-red-50 to-white'
              )}
              role="status"
              aria-label={`Chain integrity ${integrity.verified ? 'verified' : 'failed'}`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div
                    className={cn(
                      'w-12 h-12 rounded-full flex items-center justify-center',
                      integrity.verified ? 'bg-green-100' : 'bg-red-100'
                    )}
                  >
                    {integrity.verified ? (
                      <svg className="w-6 h-6 text-green-600" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clipRule="evenodd" />
                      </svg>
                    ) : (
                      <svg className="w-6 h-6 text-red-600" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clipRule="evenodd" />
                      </svg>
                    )}
                  </div>
                  <div>
                    <h2 className={cn(
                      'text-lg font-bold',
                      integrity.verified ? 'text-green-800' : 'text-red-800'
                    )}>
                      {integrity.verified ? 'Chain Integrity Verified' : 'Chain Integrity FAILED'}
                    </h2>
                    <p className="text-sm text-slate-500">
                      Hash chain is {integrity.verified ? 'valid and tamper-free' : 'broken or tampered'}
                    </p>
                  </div>
                </div>
                <div className="flex gap-6">
                  <div>
                    <p className="text-xs text-slate-400 uppercase tracking-wide">Chain Length</p>
                    <p className="text-2xl font-bold text-slate-900">{integrity.chainLength}</p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-400 uppercase tracking-wide">Head Hash</p>
                    <p
                      className="text-sm font-mono text-slate-600 mt-1"
                      title={integrity.headHash}
                    >
                      {truncateHash(integrity.headHash)}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Filter bar */}
          <div className="mb-6">
            <label htmlFor="event-type-filter" className="block text-xs text-slate-500 uppercase tracking-wide mb-2">
              Filter by Event Type
            </label>
            <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Event type filter">
              {EVENT_TYPES.map((type) => (
                <button
                  key={type}
                  onClick={() => setFilterType(type)}
                  className={cn(
                    'px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-1',
                    filterType === type
                      ? 'border-blue-500 bg-blue-50 text-blue-700'
                      : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300'
                  )}
                  role="radio"
                  aria-checked={filterType === type}
                >
                  {type === 'All' ? 'All Events' : type.replace(/([A-Z])/g, ' $1').trim()}
                </button>
              ))}
            </div>
          </div>

          {/* Event Feed */}
          <div className="space-y-0" aria-label="Audit event feed">
            {filteredEntries.length === 0 ? (
              <div className="text-center py-8 text-slate-400">
                No entries match the selected filter.
              </div>
            ) : (
              <div className="relative">
                {/* Connecting line */}
                <div className="absolute left-5 top-4 bottom-4 w-0.5 bg-slate-200" aria-hidden="true" />

                <ol className="space-y-3">
                  {filteredEntries.map((entry) => (
                    <li key={entry.sequence} className="relative pl-12">
                      {/* Chain link dot */}
                      <div
                        className="absolute left-3.5 top-4 w-3 h-3 rounded-full bg-white border-2 border-slate-300"
                        aria-hidden="true"
                      />

                      <div className="bg-white border border-slate-200 rounded-xl p-4 hover:border-slate-300 transition-colors">
                        <div className="flex items-start justify-between gap-3 flex-wrap">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-mono text-slate-400">#{entry.sequence}</span>
                            <span className={cn(
                              'inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium',
                              eventTypeColor(entry.eventType)
                            )}>
                              {entry.eventType.replace(/([A-Z])/g, ' $1').trim()}
                            </span>
                          </div>
                          <time
                            className="text-xs text-slate-400"
                            dateTime={new Date(entry.timestamp).toISOString()}
                          >
                            {formatDate(entry.timestamp)}
                          </time>
                        </div>

                        <div className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-2 text-sm">
                          <div>
                            <span className="text-xs text-slate-400">Actor: </span>
                            <span className="font-medium text-slate-700">{formatDid(entry.actor)}</span>
                          </div>
                          <div>
                            <span className="text-xs text-slate-400">Tenant: </span>
                            <span className="text-slate-600">{entry.tenantId}</span>
                          </div>
                        </div>

                        {/* Hash chain visualization */}
                        <div className="mt-3 flex flex-col sm:flex-row sm:items-center gap-2 text-xs">
                          <div className="flex items-center gap-1">
                            <span className="text-slate-400">Hash:</span>
                            <code
                              className="font-mono bg-slate-50 px-1.5 py-0.5 rounded text-slate-600"
                              title={entry.entryHash}
                            >
                              {truncateHash(entry.entryHash)}
                            </code>
                          </div>
                          <svg className="hidden sm:block w-4 h-4 text-slate-300 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                            <path fillRule="evenodd" d="M14.77 4.21a.75.75 0 01.02 1.06l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 011.08-1.04L10 8.168l3.71-3.938a.75.75 0 011.06-.02z" clipRule="evenodd" />
                          </svg>
                          <div className="flex items-center gap-1">
                            <span className="text-slate-400">Prev:</span>
                            <code
                              className="font-mono bg-slate-50 px-1.5 py-0.5 rounded text-slate-600"
                              title={entry.prevHash}
                            >
                              {truncateHash(entry.prevHash)}
                            </code>
                          </div>
                        </div>
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        </>
      )}

      <p className="mt-6 text-xs text-slate-400">
        TNC-03: Audit log is a continuous hash chain with hourly self-verification.
        Each entry hash = H(sequence || prev_hash || event_hash || type || actor || timestamp).
      </p>
    </div>
  )
}
