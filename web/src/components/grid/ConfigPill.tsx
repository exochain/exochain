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

/** ConfigPill — Per-widget configuration button.
 *
 * Every panel gets a gear icon that opens a dropdown with:
 * - AI Help (opens Council AI with widget context)
 * - Report Issue (mandated reporter — opens feedback slideout)
 * - Resize options (edit mode only)
 * - Hide panel (edit mode only)
 *
 * This is the integration point between the grid, the AI council,
 * and the mandated reporter feedback system.
 */

import { useState, useRef, useEffect } from 'react'
import { cn } from '../../lib/utils'
import { useCouncil } from '../../lib/CouncilContext'
import { useFeedbackStore } from '../../stores/feedbackStore'
import { useLayoutTemplateStore } from '../../stores/layoutTemplateStore'
import type { PanelDef } from '../../data/defaultLayouts'

interface ConfigPillProps {
  panel: PanelDef
  editMode: boolean
}

export function ConfigPill({ panel, editMode }: ConfigPillProps) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const { openPanel } = useCouncil()
  const openReporter = useFeedbackStore(s => s.openReporter)
  const toggleVisibility = useLayoutTemplateStore(s => s.togglePanelVisibility)
  const issuesForWidget = useFeedbackStore(s => s.issuesForWidget)
  const widgetIssues = issuesForWidget(panel.id)
  const openIssues = widgetIssues.filter(i => !['resolved', 'dismissed'].includes(i.status))

  // Close on outside click
  useEffect(() => {
    if (!open) return
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [open])

  // Close on Escape
  useEffect(() => {
    if (!open) return
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [open])

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={(e) => { e.stopPropagation(); setOpen(!open) }}
        onPointerDown={(e) => e.stopPropagation()}
        className={cn(
          'p-1 rounded-md transition-colors',
          'hover:bg-[var(--surface-overlay,#F1F5F9)] text-[var(--text-muted,#94A3B8)]',
          'hover:text-[var(--text-primary,#0F172A)]',
          open && 'bg-[var(--surface-overlay)] text-[var(--text-primary)]',
        )}
        aria-label={`Configure ${panel.title}`}
        aria-expanded={open}
        aria-haspopup="true"
        title="Widget settings"
      >
        {/* Gear icon */}
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
        {/* Issue badge */}
        {openIssues.length > 0 && (
          <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-red-500 text-white text-[8px] font-bold flex items-center justify-center">
            {openIssues.length}
          </span>
        )}
      </button>

      {open && (
        <div
          className="absolute right-0 top-full mt-1 w-52 bg-[var(--surface-raised,#fff)] border border-[var(--border-subtle,#E2E8F0)] rounded-lg shadow-lg z-50 py-1 overflow-hidden"
          onPointerDown={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="px-3 py-1.5 border-b border-[var(--border-subtle)]">
            <div className="text-2xs font-semibold text-[var(--text-muted)] uppercase tracking-wider">{panel.title}</div>
          </div>

          {/* AI Help */}
          <button
            onClick={() => { setOpen(false); openPanel(panel.moduleType, panel.id) }}
            className="flex items-center gap-2 w-full text-left px-3 py-2 text-xs hover:bg-violet-50 hover:text-violet-700 transition-colors"
          >
            <svg className="w-3.5 h-3.5 text-violet-500" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
            </svg>
            <span>AI Help</span>
            <kbd className="ml-auto text-2xs text-[var(--text-muted)] bg-[var(--surface-overlay)] px-1 rounded font-mono">^J</kbd>
          </button>

          {/* Report Issue (Mandated Reporter) */}
          <button
            onClick={() => { setOpen(false); openReporter(panel.id, panel.moduleType) }}
            className="flex items-center gap-2 w-full text-left px-3 py-2 text-xs hover:bg-amber-50 hover:text-amber-700 transition-colors"
          >
            <svg className="w-3.5 h-3.5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span>Report Issue</span>
            {openIssues.length > 0 && (
              <span className="ml-auto inline-flex items-center justify-center min-w-[1.25rem] h-4 rounded-full bg-red-100 text-red-700 text-2xs font-bold px-1">
                {openIssues.length}
              </span>
            )}
          </button>

          {/* View open issues for this widget */}
          {openIssues.length > 0 && (
            <div className="border-t border-[var(--border-subtle)] mt-1 pt-1">
              <div className="px-3 py-1 text-2xs font-semibold text-[var(--text-muted)] uppercase">Open Issues</div>
              {openIssues.slice(0, 3).map(issue => (
                <div key={issue.id} className="flex items-center gap-2 px-3 py-1.5 text-2xs">
                  <span className={cn(
                    'w-1.5 h-1.5 rounded-full flex-shrink-0',
                    issue.severity === 'critical' ? 'bg-red-500' :
                    issue.severity === 'high' ? 'bg-orange-500' :
                    issue.severity === 'medium' ? 'bg-amber-500' : 'bg-blue-400'
                  )} />
                  <span className="truncate text-[var(--text-secondary)]">{issue.title}</span>
                </div>
              ))}
            </div>
          )}

          {/* Edit mode actions */}
          {editMode && (
            <div className="border-t border-[var(--border-subtle)] mt-1 pt-1">
              <button
                onClick={() => { setOpen(false); toggleVisibility(panel.id) }}
                className="flex items-center gap-2 w-full text-left px-3 py-2 text-xs hover:bg-red-50 hover:text-red-600 transition-colors"
              >
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.542 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                </svg>
                <span>Hide Panel</span>
              </button>
            </div>
          )}

          {/* Module tags */}
          {panel.tags.length > 0 && (
            <div className="border-t border-[var(--border-subtle)] mt-1 px-3 py-2 flex gap-1 flex-wrap">
              {panel.tags.map(tag => (
                <span key={tag} className="inline-flex items-center rounded-full px-1.5 py-0.5 text-2xs bg-[var(--surface-overlay)] text-[var(--text-muted)]">
                  {tag}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
