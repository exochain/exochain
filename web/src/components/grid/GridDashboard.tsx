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

/** GridDashboard — 24-column configurable grid with template management.
 *
 * The full-featured grid layout system:
 * - 24-column react-grid-layout with vertical compaction
 * - Drag-and-drop repositioning (edit mode only)
 * - Panel resize via SE handle (edit mode only)
 * - Panel show/hide toggles
 * - Named layout templates (built-in + user-created) with full CRUD
 * - Per-panel config pill with AI help, mandated reporter feedback
 * - Dual persistence: localStorage (immediate) + server (fire-and-forget)
 */

import { useState, useMemo, useCallback, type ReactNode } from 'react'
import RGL from 'react-grid-layout'
import 'react-grid-layout/css/styles.css'

const GridLayout = RGL as unknown as React.ComponentType<{
  layout: LayoutItem[]
  cols: number
  rowHeight: number
  width: number
  margin: [number, number]
  containerPadding: [number, number]
  compactType: 'vertical' | 'horizontal' | null
  isDraggable: boolean
  isResizable: boolean
  draggableHandle: string
  resizeHandles: string[]
  onLayoutChange: (layout: LayoutItem[]) => void
  useCSSTransforms: boolean
  children: React.ReactNode
}>
import { cn } from '../../lib/utils'
import { useLayoutTemplateStore } from '../../stores/layoutTemplateStore'
import { useFeedbackStore } from '../../stores/feedbackStore'
import { GRID_COLS, GRID_ROW_HEIGHT, GRID_MARGIN, GRID_CONTAINER_PADDING, PANEL_REGISTRY, type PanelDef, type LayoutItem } from '../../data/defaultLayouts'
import { ConfigPill } from './ConfigPill'
import { TemplateSaveDialog, DeleteConfirmDialog } from './TemplateSaveDialog'
import { FeedbackReporter } from './FeedbackReporter'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface GridDashboardProps {
  /** Map of panel ID to React component to render */
  renderPanel: (panelDef: PanelDef) => ReactNode
  /** Grid container width in pixels. Default: auto-measured. */
  width?: number
  className?: string
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function GridDashboard({ renderPanel, width: fixedWidth, className }: GridDashboardProps) {
  const {
    templates,
    activeTemplateId,
    editMode,
    selectTemplate,
    setEditMode,
    updateDraftLayout,
    togglePanelVisibility,
    saveTemplate,
    saveAsTemplate,
    renameTemplate,
    deleteTemplate,
    getActiveTemplate,
    getEffectiveLayout,
    getEffectiveHiddenPanels,
  } = useLayoutTemplateStore()

  const openIssueCount = useFeedbackStore(s => s.openIssueCount)

  const [saveDialogOpen, setSaveDialogOpen] = useState(false)
  const [renameDialogOpen, setRenameDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [containerWidth, setContainerWidth] = useState(1200)

  // Measure container width
  const containerRef = useCallback((node: HTMLDivElement | null) => {
    if (!node) return
    const observer = new ResizeObserver(entries => {
      for (const entry of entries) {
        setContainerWidth(entry.contentRect.width)
      }
    })
    observer.observe(node)
    return () => observer.disconnect()
  }, [])

  const effectiveLayout = getEffectiveLayout()
  const hiddenPanels = new Set(getEffectiveHiddenPanels())
  const activeTemplate = getActiveTemplate()

  // In edit mode, show all panels (hidden ones with overlay). In normal mode, filter hidden.
  const visibleLayout = useMemo(() => {
    if (editMode) return effectiveLayout
    return effectiveLayout.filter(item => !hiddenPanels.has(item.i))
  }, [editMode, effectiveLayout, hiddenPanels])

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleLayoutChange = useCallback((newLayout: any) => {
    if (editMode) {
      updateDraftLayout(newLayout as LayoutItem[])
    }
  }, [editMode, updateDraftLayout])

  const gridWidth = fixedWidth || containerWidth

  return (
    <div ref={containerRef} className={cn('grid-dashboard', className)}>
      {/* ── Toolbar ────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          {/* Template selector */}
          <div className="flex items-center gap-1.5">
            <label className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider">Layout:</label>
            <select
              value={activeTemplateId}
              onChange={e => selectTemplate(e.target.value)}
              disabled={editMode}
              className={cn(
                'text-sm font-medium px-2 py-1 rounded-md border border-[var(--border-subtle)] bg-[var(--surface-base)]',
                'focus:outline-none focus:ring-2 focus:ring-[var(--accent-primary)]',
                editMode && 'opacity-50 cursor-not-allowed',
              )}
            >
              {templates.map(t => (
                <option key={t.id} value={t.id}>
                  {t.name}{t.isBuiltIn ? '' : ' (custom)'}
                </option>
              ))}
            </select>
          </div>

          {/* Edit mode toggle */}
          {!editMode ? (
            <button
              onClick={() => setEditMode(true)}
              className="flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium border border-[var(--border-subtle)] hover:bg-[var(--surface-overlay)] transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
              </svg>
              Edit Layout
            </button>
          ) : (
            <div className="flex items-center gap-1.5">
              {/* Save (only if current template is user-created) */}
              {!activeTemplate.isBuiltIn && (
                <button
                  onClick={saveTemplate}
                  className="px-2.5 py-1 rounded-md text-xs font-semibold bg-[var(--accent-primary)] text-white hover:bg-[var(--accent-hover)] transition-colors"
                >
                  Save
                </button>
              )}

              {/* Save As */}
              <button
                onClick={() => setSaveDialogOpen(true)}
                className="px-2.5 py-1 rounded-md text-xs font-medium border border-[var(--accent-primary)] text-[var(--accent-primary)] hover:bg-[var(--accent-primary)]/10 transition-colors"
              >
                Save As...
              </button>

              {/* Discard */}
              <button
                onClick={() => setEditMode(false)}
                className="px-2.5 py-1 rounded-md text-xs font-medium text-[var(--text-secondary)] hover:bg-[var(--surface-overlay)] transition-colors"
              >
                Discard
              </button>

              {/* Rename (user templates only) */}
              {!activeTemplate.isBuiltIn && (
                <button
                  onClick={() => setRenameDialogOpen(true)}
                  className="p-1 rounded-md text-[var(--text-muted)] hover:bg-[var(--surface-overlay)] hover:text-[var(--text-primary)] transition-colors"
                  title="Rename template"
                >
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                  </svg>
                </button>
              )}

              {/* Delete (user templates only) */}
              {!activeTemplate.isBuiltIn && (
                <button
                  onClick={() => setDeleteDialogOpen(true)}
                  className="p-1 rounded-md text-[var(--text-muted)] hover:bg-red-50 hover:text-red-600 transition-colors"
                  title="Delete template"
                >
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              )}
            </div>
          )}
        </div>

        {/* Right side: issue counter + edit mode indicator */}
        <div className="flex items-center gap-2">
          {openIssueCount() > 0 && (
            <span className="flex items-center gap-1 text-2xs text-amber-700 bg-amber-50 rounded-full px-2 py-0.5">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              {openIssueCount()} open issues
            </span>
          )}

          {editMode && (
            <span className="flex items-center gap-1 text-2xs font-semibold text-violet-700 bg-violet-50 rounded-full px-2.5 py-1">
              <span className="w-2 h-2 rounded-full bg-violet-500 health-pulse" />
              EDITING
            </span>
          )}
        </div>
      </div>

      {/* ── Hidden panels toggle bar (edit mode) ───────────────── */}
      {editMode && hiddenPanels.size > 0 && (
        <div className="mb-3 p-2.5 rounded-lg border border-dashed border-[var(--border-subtle)] bg-[var(--surface-overlay)]">
          <div className="text-2xs font-semibold text-[var(--text-muted)] mb-1.5 uppercase tracking-wider">
            Hidden Panels ({hiddenPanels.size})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {Array.from(hiddenPanels).map(panelId => {
              const def = PANEL_REGISTRY.find(p => p.id === panelId)
              return (
                <button
                  key={panelId}
                  onClick={() => togglePanelVisibility(panelId)}
                  className="flex items-center gap-1 px-2 py-1 rounded-md text-2xs font-medium border border-[var(--border-subtle)] hover:bg-[var(--surface-raised)] hover:border-[var(--accent-primary)] transition-colors"
                >
                  <svg className="w-3 h-3 text-[var(--text-muted)]" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  </svg>
                  {def?.title || panelId}
                </button>
              )
            })}
          </div>
        </div>
      )}

      {/* ── Grid ───────────────────────────────────────────────── */}
      <GridLayout
        layout={visibleLayout}
        cols={GRID_COLS}
        rowHeight={GRID_ROW_HEIGHT}
        width={gridWidth}
        margin={GRID_MARGIN}
        containerPadding={GRID_CONTAINER_PADDING}
        compactType="vertical"
        isDraggable={editMode}
        isResizable={editMode}
        draggableHandle=".panel-drag-handle"
        resizeHandles={['se']}
        onLayoutChange={handleLayoutChange}
        useCSSTransforms
      >
        {visibleLayout.map(item => {
          const panelDef = PANEL_REGISTRY.find(p => p.id === item.i)
          if (!panelDef) return <div key={item.i} />

          const isHidden = hiddenPanels.has(item.i)

          return (
            <div
              key={item.i}
              className={cn(
                'grid-panel group',
                isHidden && editMode && 'opacity-40 border-dashed',
              )}
            >
              <div className={cn(
                'h-full flex flex-col bg-[var(--surface-widget,#fff)] border border-[var(--border-widget,#CBD5E1)] overflow-hidden',
                'transition-shadow duration-200',
                'hover:shadow-[var(--shadow-widget-hover)]',
                'shadow-[var(--shadow-widget)]',
                isHidden && editMode && 'border-dashed border-orange-300 bg-orange-50/30',
              )}
              style={{ borderRadius: 'var(--radius-widget, 12px)' }}
              >
                {/* Panel header */}
                <div className="flex items-center justify-between px-3 py-2 border-b border-[var(--border-subtle,#E2E8F0)]">
                  <div className="flex items-center gap-2 min-w-0">
                    {/* Drag handle (edit mode only) */}
                    {editMode && (
                      <div className="panel-drag-handle cursor-grab active:cursor-grabbing">
                        <svg className="w-4 h-4 text-[var(--text-muted,#94A3B8)]" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
                          <circle cx="4" cy="3" r="1.5" /><circle cx="12" cy="3" r="1.5" />
                          <circle cx="4" cy="8" r="1.5" /><circle cx="12" cy="8" r="1.5" />
                          <circle cx="4" cy="13" r="1.5" /><circle cx="12" cy="13" r="1.5" />
                        </svg>
                      </div>
                    )}

                    <h3 className="text-sm font-semibold text-[var(--text-primary,#0F172A)] truncate">
                      {panelDef.title}
                    </h3>

                    {/* Module type badge */}
                    <span className="hidden tablet:inline-flex items-center rounded-full px-1.5 py-0.5 text-2xs font-medium bg-[var(--accent-muted,#DBEAFE)] text-[var(--accent-primary,#2563EB)]">
                      {panelDef.moduleType}
                    </span>

                    {/* Hidden indicator */}
                    {isHidden && editMode && (
                      <span className="inline-flex items-center rounded-full px-1.5 py-0.5 text-2xs font-medium bg-orange-100 text-orange-700">
                        hidden
                      </span>
                    )}
                  </div>

                  {/* Config pill — always visible */}
                  <div className="flex items-center gap-0.5">
                    <ConfigPill panel={panelDef} editMode={editMode} />

                    {/* Unhide button for hidden panels in edit mode */}
                    {isHidden && editMode && (
                      <button
                        onClick={() => togglePanelVisibility(panelDef.id)}
                        className="p-1 rounded-md text-orange-600 hover:bg-orange-100"
                        title="Show panel"
                      >
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                          <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                        </svg>
                      </button>
                    )}
                  </div>
                </div>

                {/* Panel content */}
                <div className="flex-1 overflow-auto p-3">
                  {renderPanel(panelDef)}
                </div>
              </div>
            </div>
          )
        })}
      </GridLayout>

      {/* ── Dialogs ────────────────────────────────────────────── */}
      <TemplateSaveDialog
        open={saveDialogOpen}
        onClose={() => setSaveDialogOpen(false)}
        onSave={(name) => saveAsTemplate(name)}
        title="Save Layout As"
        placeholder="My custom layout"
      />

      <TemplateSaveDialog
        open={renameDialogOpen}
        onClose={() => setRenameDialogOpen(false)}
        onSave={(name) => renameTemplate(activeTemplateId, name)}
        title="Rename Template"
        initialValue={activeTemplate.name}
        submitLabel="Rename"
      />

      <DeleteConfirmDialog
        open={deleteDialogOpen}
        templateName={activeTemplate.name}
        onClose={() => setDeleteDialogOpen(false)}
        onConfirm={() => deleteTemplate(activeTemplateId)}
      />

      {/* ── Mandated Reporter Slideout ─────────────────────────── */}
      <FeedbackReporter />
    </div>
  )
}

export default GridDashboard
