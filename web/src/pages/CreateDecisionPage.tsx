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
import { useNavigate, Link } from 'react-router-dom'
import { ConstraintWarning } from '../components/ConstraintWarning'
import { api } from '../lib/api'
import { cn } from '../lib/utils'

const DECISION_CLASSES = [
  { value: 'Operational', description: 'Day-to-day operational decisions' },
  { value: 'Strategic', description: 'Long-term strategic direction' },
  { value: 'Constitutional', description: 'Changes to governance framework' },
  { value: 'Financial', description: 'Budget and financial commitments' },
  { value: 'Emergency', description: 'Time-critical emergency actions' },
]

/**
 * New Decision — initiate a governance decision.
 * Real-time constraint warnings (UX-003).
 * Conflict disclosure workflow (UX-009).
 */
export function CreateDecisionPage() {
  const navigate = useNavigate()
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [decisionClass, setDecisionClass] = useState('Operational')
  const [conflictDisclosed, setConflictDisclosed] = useState(false)
  const [hasConflict, setHasConflict] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Real-time constraint evaluation
  const constraints = []
  if (decisionClass === 'Constitutional') {
    constraints.push({
      id: 'TNC-02',
      message: 'Constitutional decisions require human gate approval. AI agents cannot approve this decision class.',
      severity: 'warn' as const,
    })
  }
  if (decisionClass === 'Strategic' || decisionClass === 'Constitutional') {
    constraints.push({
      id: 'C-002',
      message: `Minimum quorum of 2 required for ${decisionClass} decisions.`,
      severity: 'info' as const,
    })
  }
  if (hasConflict && !conflictDisclosed) {
    constraints.push({
      id: 'TNC-06',
      message: 'Conflict of interest must be disclosed before participation. Decision creation is blocked.',
      severity: 'block' as const,
    })
  }

  const isBlocked = constraints.some((c) => c.severity === 'block')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (isBlocked) return
    setSubmitting(true)
    setError(null)
    try {
      const created = await api.decisions.create({
        title,
        body,
        decisionClass,
        author: 'did:exo:alice',
      })
      navigate(`/decisions/${created.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create decision')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="max-w-2xl">
      {/* Page header */}
      <div className="mb-8">
        <Link
          to="/"
          className="inline-flex items-center gap-1 text-sm text-blue-600 hover:text-blue-800 hover:underline focus-visible:outline-2 focus-visible:outline-blue-600 mb-4"
          aria-label="Back to Command View"
        >
          <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
            <path fillRule="evenodd" d="M17 10a.75.75 0 01-.75.75H5.612l4.158 3.96a.75.75 0 11-1.04 1.08l-5.5-5.25a.75.75 0 010-1.08l5.5-5.25a.75.75 0 111.04 1.08L5.612 9.25H16.25A.75.75 0 0117 10z" clipRule="evenodd" />
          </svg>
          Back to Command View
        </Link>
        <h1 className="text-xl sm:text-2xl font-bold text-slate-900">New Decision</h1>
        <p className="text-sm text-slate-500 mt-1">Initiate a governance decision</p>
      </div>

      {error && (
        <div className="mb-6 p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-800" role="alert">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Title */}
        <div>
          <label htmlFor="title" className="block text-sm font-medium text-slate-700 mb-1">
            Decision Title
          </label>
          <input
            id="title"
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            required
            className="w-full px-3 py-2.5 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder:text-slate-400"
            placeholder="Enter decision title"
          />
        </div>

        {/* Decision Class — visual pills */}
        <fieldset>
          <legend className="block text-sm font-medium text-slate-700 mb-2">
            Decision Class
          </legend>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2" role="radiogroup" aria-label="Decision class selection">
            {DECISION_CLASSES.map((cls) => (
              <label
                key={cls.value}
                className={cn(
                  'flex items-start gap-3 p-3 rounded-lg border-2 cursor-pointer transition-colors focus-within:ring-2 focus-within:ring-blue-500',
                  decisionClass === cls.value
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-slate-200 bg-white hover:border-slate-300'
                )}
              >
                <input
                  type="radio"
                  name="decisionClass"
                  value={cls.value}
                  checked={decisionClass === cls.value}
                  onChange={(e) => setDecisionClass(e.target.value)}
                  className="sr-only"
                />
                <div className={cn(
                  'mt-0.5 w-4 h-4 rounded-full border-2 flex items-center justify-center flex-shrink-0',
                  decisionClass === cls.value
                    ? 'border-blue-600 bg-blue-600'
                    : 'border-slate-300'
                )}>
                  {decisionClass === cls.value && (
                    <div className="w-1.5 h-1.5 rounded-full bg-white" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <span className={cn(
                    'text-sm font-medium',
                    decisionClass === cls.value ? 'text-blue-800' : 'text-slate-700'
                  )}>
                    {cls.value}
                  </span>
                  <p className="text-xs text-slate-500 mt-0.5">{cls.description}</p>
                </div>
              </label>
            ))}
          </div>
        </fieldset>

        {/* Description */}
        <div>
          <label htmlFor="body" className="block text-sm font-medium text-slate-700 mb-1">
            Description
          </label>
          <textarea
            id="body"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            required
            rows={6}
            className="w-full px-3 py-2.5 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder:text-slate-400"
            placeholder="Describe the decision, its rationale, and expected impact"
          />
        </div>

        {/* Conflict disclosure workflow (UX-009) */}
        <fieldset className="border border-slate-200 rounded-lg p-4">
          <legend className="text-sm font-medium text-slate-700 px-1">Conflict Disclosure (TNC-06)</legend>
          <div className="space-y-3 mt-2">
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input
                type="checkbox"
                checked={hasConflict}
                onChange={(e) => setHasConflict(e.target.checked)}
                className="w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-slate-700">I have a potential conflict of interest related to this decision</span>
            </label>
            {hasConflict && (
              <label className="flex items-center gap-2 text-sm ml-6 cursor-pointer">
                <input
                  type="checkbox"
                  checked={conflictDisclosed}
                  onChange={(e) => setConflictDisclosed(e.target.checked)}
                  className="w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-slate-700">I hereby disclose my conflict and understand it will be recorded</span>
              </label>
            )}
          </div>
        </fieldset>

        {/* Real-time constraint warnings (UX-003) */}
        {constraints.length > 0 && (
          <div className="space-y-2" aria-label="Constitutional constraint warnings" role="region">
            {constraints.map((c) => (
              <ConstraintWarning key={c.id} constraintId={c.id} message={c.message} severity={c.severity} />
            ))}
          </div>
        )}

        <button
          type="submit"
          disabled={isBlocked || !title || !body || submitting}
          className="w-full px-4 py-3 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:bg-slate-300 disabled:cursor-not-allowed focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 transition-colors"
        >
          {submitting ? 'Creating...' : isBlocked ? 'Blocked by Constraint' : 'Create Decision'}
        </button>
      </form>
    </div>
  )
}
