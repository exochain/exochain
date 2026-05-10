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

/** FeedbackReporter — Mandated reporter issue filing slideout.
 *
 * When a user (or an AI agent) identifies an issue through any widget,
 * this slideout captures a structured report. Reports are:
 *
 * 1. Persisted to localStorage immediately
 * 2. Submitted to the server for agent team triage
 * 3. Tracked through resolution on the Council Tickets board
 * 4. NEVER silently dropped — the mandated reporter pattern guarantees
 *    every report gets acknowledged
 *
 * The form auto-captures widget context (which widget, what module type)
 * and browser info. The user provides title, description, severity, and
 * category.
 */

import { useState, useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { cn } from '../../lib/utils'
import { useFeedbackStore, type IssueSeverity, type IssueCategory } from '../../stores/feedbackStore'
import { PANEL_REGISTRY } from '../../data/defaultLayouts'

const SEVERITIES: { value: IssueSeverity; label: string; color: string }[] = [
  { value: 'critical', label: 'Critical',   color: 'bg-red-500' },
  { value: 'high',     label: 'High',       color: 'bg-orange-500' },
  { value: 'medium',   label: 'Medium',     color: 'bg-amber-500' },
  { value: 'low',      label: 'Low',        color: 'bg-blue-500' },
  { value: 'info',     label: 'Info',       color: 'bg-slate-400' },
]

const CATEGORIES: { value: IssueCategory; label: string; icon: string }[] = [
  { value: 'bug',         label: 'Bug',         icon: '🐛' },
  { value: 'ux',          label: 'UX Issue',    icon: '🎨' },
  { value: 'data',        label: 'Data Error',  icon: '📊' },
  { value: 'performance', label: 'Performance', icon: '⚡' },
  { value: 'security',    label: 'Security',    icon: '🔒' },
  { value: 'feature',     label: 'Feature Req', icon: '💡' },
  { value: 'question',    label: 'Question',    icon: '❓' },
]

export function FeedbackReporter() {
  const { reporterOpen, reporterWidgetId, reporterModuleType, closeReporter, fileIssue } = useFeedbackStore()
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState<IssueSeverity>('medium')
  const [category, setCategory] = useState<IssueCategory>('bug')
  const [submitting, setSubmitting] = useState(false)
  const [submitted, setSubmitted] = useState(false)
  const titleRef = useRef<HTMLInputElement>(null)

  const widgetDef = PANEL_REGISTRY.find(p => p.id === reporterWidgetId)

  // Auto-focus title on open
  useEffect(() => {
    if (reporterOpen) {
      setTitle('')
      setDescription('')
      setSeverity('medium')
      setCategory('bug')
      setSubmitted(false)
      setTimeout(() => titleRef.current?.focus(), 100)
    }
  }, [reporterOpen])

  // Close on Escape
  useEffect(() => {
    if (!reporterOpen) return
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') closeReporter()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [reporterOpen, closeReporter])

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!title.trim()) return
    setSubmitting(true)
    const issue = fileIssue({
      title: title.trim(),
      description: description.trim(),
      severity,
      category,
    })
    setSubmitting(false)
    setSubmitted(true)
    // Auto-close after showing confirmation
    setTimeout(() => {
      setSubmitted(false)
      closeReporter()
    }, 2000)
    // Log for visibility
    console.log('[MandatedReporter] Issue filed:', issue.id, issue.title)
  }

  if (!reporterOpen) return null

  return createPortal(
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/30 z-50"
        onClick={closeReporter}
        aria-hidden="true"
      />

      {/* Slideout */}
      <div className="fixed right-0 top-0 bottom-0 w-full max-w-md bg-[var(--surface-raised,#fff)] border-l border-[var(--border-subtle)] shadow-2xl z-50 flex flex-col animate-slide-in-right">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)] bg-amber-50">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-amber-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <h2 className="text-sm font-bold text-amber-900">Report Issue</h2>
              <p className="text-2xs text-amber-700">Mandated Reporter &mdash; all reports are tracked</p>
            </div>
          </div>
          <button onClick={closeReporter} className="p-1.5 rounded-md hover:bg-amber-100" aria-label="Close">
            <svg className="w-4 h-4 text-amber-700" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Source widget badge */}
        {widgetDef && (
          <div className="px-4 py-2 bg-[var(--surface-overlay)] border-b border-[var(--border-subtle)] flex items-center gap-2">
            <span className="text-2xs text-[var(--text-muted)]">Source:</span>
            <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-2xs font-medium bg-[var(--accent-muted,#DBEAFE)] text-[var(--accent-primary,#2563EB)]">
              {widgetDef.title}
            </span>
            <span className="text-2xs text-[var(--text-muted)]">{reporterModuleType} module</span>
          </div>
        )}

        {/* Success state */}
        {submitted ? (
          <div className="flex-1 flex items-center justify-center p-8">
            <div className="text-center">
              <div className="w-16 h-16 rounded-full bg-green-100 flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h3 className="text-lg font-bold text-[var(--text-primary)]">Issue Reported</h3>
              <p className="text-sm text-[var(--text-secondary)] mt-1">
                Your report has been filed and will be triaged by the agent team.
              </p>
            </div>
          </div>
        ) : (
          /* Form */
          <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-4 space-y-4">
            {/* Title */}
            <div>
              <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">Issue Title *</label>
              <input
                ref={titleRef}
                type="text"
                value={title}
                onChange={e => setTitle(e.target.value)}
                placeholder="Brief description of the issue"
                maxLength={120}
                required
                className="w-full px-3 py-2 text-sm border border-[var(--border-subtle)] rounded-lg bg-[var(--surface-base)] focus:outline-none focus:ring-2 focus:ring-amber-400"
              />
            </div>

            {/* Severity */}
            <div>
              <label className="block text-xs font-semibold text-[var(--text-primary)] mb-2">Severity</label>
              <div className="flex gap-1.5">
                {SEVERITIES.map(s => (
                  <button
                    key={s.value}
                    type="button"
                    onClick={() => setSeverity(s.value)}
                    className={cn(
                      'flex items-center gap-1 px-2.5 py-1.5 rounded-md text-2xs font-medium border transition-colors',
                      severity === s.value
                        ? 'border-amber-400 bg-amber-50 text-amber-900 shadow-sm'
                        : 'border-[var(--border-subtle)] text-[var(--text-secondary)] hover:bg-[var(--surface-overlay)]'
                    )}
                  >
                    <span className={cn('w-2 h-2 rounded-full', s.color)} />
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Category */}
            <div>
              <label className="block text-xs font-semibold text-[var(--text-primary)] mb-2">Category</label>
              <div className="grid grid-cols-4 gap-1.5">
                {CATEGORIES.map(c => (
                  <button
                    key={c.value}
                    type="button"
                    onClick={() => setCategory(c.value)}
                    className={cn(
                      'flex flex-col items-center gap-0.5 px-2 py-2 rounded-lg text-2xs font-medium border transition-colors',
                      category === c.value
                        ? 'border-amber-400 bg-amber-50 text-amber-900 shadow-sm'
                        : 'border-[var(--border-subtle)] text-[var(--text-secondary)] hover:bg-[var(--surface-overlay)]'
                    )}
                  >
                    <span className="text-base">{c.icon}</span>
                    <span>{c.label}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Description */}
            <div>
              <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">Details</label>
              <textarea
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder="What happened? What did you expect? Steps to reproduce..."
                rows={5}
                className="w-full px-3 py-2 text-sm border border-[var(--border-subtle)] rounded-lg bg-[var(--surface-base)] focus:outline-none focus:ring-2 focus:ring-amber-400 resize-none"
              />
            </div>

            {/* Auto-captured context */}
            <div className="bg-[var(--surface-overlay)] rounded-lg p-3">
              <div className="text-2xs font-semibold text-[var(--text-muted)] mb-1.5">AUTO-CAPTURED CONTEXT</div>
              <div className="grid grid-cols-2 gap-1 text-2xs text-[var(--text-secondary)]">
                <span>Widget:</span><span className="font-mono">{reporterWidgetId}</span>
                <span>Module:</span><span className="font-mono">{reporterModuleType}</span>
                <span>Timestamp:</span><span className="font-mono">{new Date().toISOString()}</span>
              </div>
            </div>

            {/* Submit */}
            <div className="flex items-center gap-3 pt-2">
              <button
                type="submit"
                disabled={!title.trim() || submitting}
                className={cn(
                  'flex-1 px-4 py-2.5 rounded-lg text-sm font-semibold transition-colors',
                  'bg-amber-500 text-white hover:bg-amber-600 disabled:opacity-50 disabled:cursor-not-allowed',
                )}
              >
                {submitting ? 'Filing...' : 'File Report'}
              </button>
              <button
                type="button"
                onClick={closeReporter}
                className="px-4 py-2.5 rounded-lg text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--surface-overlay)] border border-[var(--border-subtle)]"
              >
                Cancel
              </button>
            </div>

            {/* Mandated reporter notice */}
            <p className="text-center text-2xs text-[var(--text-muted)] pb-2">
              All reports are tracked through resolution. No report is silently dropped.
            </p>
          </form>
        )}
      </div>
    </>,
    document.body,
  )
}
