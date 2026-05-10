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

/** WidgetGrid — Drag-and-drop grid layout for governance widgets.
 *
 * An erector set of challenge modules interconnected through a
 * responsive, sortable grid. Each widget is a self-contained
 * multimodal container that can be resized, collapsed, maximized,
 * and re-ordered via drag and drop.
 */

import { useState, useCallback, type ReactNode } from 'react'
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from '@dnd-kit/core'
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  rectSortingStrategy,
} from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import { cn } from '../lib/utils'
import { WidgetAIButton } from './WidgetAIButton'

// ---------------------------------------------------------------------------
// Widget configuration
// ---------------------------------------------------------------------------

export type WidgetSize = '1x1' | '2x1' | '1x2' | '2x2' | '3x1' | '3x2' | 'full'

export interface WidgetConfig {
  id: string
  title: string
  size: WidgetSize
  collapsible: boolean
  removable: boolean
  /** Module type for interconnection */
  moduleType: string
  /** Tags for filtering */
  tags: string[]
}

interface WidgetGridProps {
  widgets: WidgetConfig[]
  onReorder: (widgets: WidgetConfig[]) => void
  onRemove?: (id: string) => void
  onResize?: (id: string, size: WidgetSize) => void
  renderWidget: (config: WidgetConfig) => ReactNode
  className?: string
}

// ---------------------------------------------------------------------------
// Size to grid classes
// ---------------------------------------------------------------------------

function sizeClasses(size: WidgetSize): string {
  switch (size) {
    case '1x1': return 'col-span-1 row-span-1'
    case '2x1': return 'col-span-2 row-span-1'
    case '1x2': return 'col-span-1 row-span-2'
    case '2x2': return 'col-span-2 row-span-2'
    case '3x1': return 'col-span-3 row-span-1'
    case '3x2': return 'col-span-3 row-span-2'
    case 'full': return 'col-span-full row-span-1'
    default: return 'col-span-1 row-span-1'
  }
}

// ---------------------------------------------------------------------------
// SortableWidget — individual drag-and-drop container
// ---------------------------------------------------------------------------

interface SortableWidgetProps {
  config: WidgetConfig
  onRemove?: (id: string) => void
  onResize?: (id: string, size: WidgetSize) => void
  children: ReactNode
}

function SortableWidget({ config, onRemove, onResize, children }: SortableWidgetProps) {
  const [collapsed, setCollapsed] = useState(false)
  const [maximized, setMaximized] = useState(false)
  const [showSizeMenu, setShowSizeMenu] = useState(false)

  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id: config.id })

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
  }

  const sizes: WidgetSize[] = ['1x1', '2x1', '1x2', '2x2', '3x1', 'full']

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={cn(
        sizeClasses(maximized ? 'full' : config.size),
        'group relative',
        isDragging && 'z-50 opacity-75',
        maximized && 'fixed inset-4 z-50 !col-span-1 !row-span-1',
      )}
    >
      <div
        className={cn(
          'h-full flex flex-col bg-[var(--surface-widget,#fff)] border border-[var(--border-widget,#CBD5E1)]',
          'transition-shadow duration-200',
          'hover:shadow-[var(--shadow-widget-hover)]',
          isDragging ? 'shadow-[var(--shadow-overlay)]' : 'shadow-[var(--shadow-widget)]',
        )}
        style={{ borderRadius: 'var(--radius-widget, 12px)' }}
      >
        {/* Widget header — drag handle */}
        <div
          className="flex items-center justify-between px-3 py-2 border-b border-[var(--border-subtle,#E2E8F0)] cursor-grab active:cursor-grabbing select-none"
          {...attributes}
          {...listeners}
        >
          <div className="flex items-center gap-2 min-w-0">
            {/* Drag grip icon */}
            <svg className="w-4 h-4 text-[var(--text-muted,#94A3B8)] flex-shrink-0" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
              <circle cx="4" cy="3" r="1.5" /><circle cx="12" cy="3" r="1.5" />
              <circle cx="4" cy="8" r="1.5" /><circle cx="12" cy="8" r="1.5" />
              <circle cx="4" cy="13" r="1.5" /><circle cx="12" cy="13" r="1.5" />
            </svg>
            <h3 className="text-sm font-semibold text-[var(--text-primary,#0F172A)] truncate">
              {config.title}
            </h3>
            {/* Module type badge */}
            <span className="hidden tablet:inline-flex items-center rounded-full px-1.5 py-0.5 text-2xs font-medium bg-[var(--accent-muted,#DBEAFE)] text-[var(--accent-primary,#2563EB)]">
              {config.moduleType}
            </span>
          </div>

          {/* Widget controls */}
          <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
            {/* AI assistant button */}
            <WidgetAIButton
              moduleType={config.moduleType}
              widgetId={config.id}
              compact
            />

            {config.collapsible && (
              <button
                onClick={(e) => { e.stopPropagation(); setCollapsed(!collapsed) }}
                className="p-1 rounded hover:bg-[var(--surface-overlay,#F1F5F9)]"
                aria-label={collapsed ? 'Expand widget' : 'Collapse widget'}
                onPointerDown={(e) => e.stopPropagation()}
              >
                <svg className="w-3.5 h-3.5 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                    d={collapsed ? 'M19 9l-7 7-7-7' : 'M5 15l7-7 7 7'} />
                </svg>
              </button>
            )}

            {/* Resize */}
            <div className="relative">
              <button
                onClick={(e) => { e.stopPropagation(); setShowSizeMenu(!showSizeMenu) }}
                className="p-1 rounded hover:bg-[var(--surface-overlay,#F1F5F9)]"
                aria-label="Resize widget"
                onPointerDown={(e) => e.stopPropagation()}
              >
                <svg className="w-3.5 h-3.5 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                    d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
                </svg>
              </button>
              {showSizeMenu && (
                <div className="absolute right-0 top-full mt-1 bg-[var(--surface-raised)] border border-[var(--border-subtle)] rounded-lg shadow-lg z-50 py-1 min-w-[100px]"
                  onPointerDown={(e) => e.stopPropagation()}>
                  {sizes.map(s => (
                    <button key={s}
                      onClick={(e) => { e.stopPropagation(); onResize?.(config.id, s); setShowSizeMenu(false) }}
                      className={cn(
                        'block w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--surface-overlay)]',
                        config.size === s && 'font-bold text-[var(--accent-primary)]'
                      )}>
                      {s}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Maximize */}
            <button
              onClick={(e) => { e.stopPropagation(); setMaximized(!maximized) }}
              className="p-1 rounded hover:bg-[var(--surface-overlay,#F1F5F9)]"
              aria-label={maximized ? 'Restore widget' : 'Maximize widget'}
              onPointerDown={(e) => e.stopPropagation()}
            >
              <svg className="w-3.5 h-3.5 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d={maximized ? 'M9 9V4.5M9 9H4.5M9 9L3.75 3.75M9 15v4.5M9 15H4.5M9 15l-5.25 5.25M15 9h4.5M15 9V4.5M15 9l5.25-5.25M15 15h4.5M15 15v4.5m0-4.5l5.25 5.25' : 'M3.75 3.75v4.5m0-4.5h4.5m-4.5 0L9 9M3.75 20.25v-4.5m0 4.5h4.5m-4.5 0L9 15M20.25 3.75h-4.5m4.5 0v4.5m0-4.5L15 9m5.25 11.25h-4.5m4.5 0v-4.5m0 4.5L15 15'} />
              </svg>
            </button>

            {config.removable && (
              <button
                onClick={(e) => { e.stopPropagation(); onRemove?.(config.id) }}
                className="p-1 rounded hover:bg-red-50 hover:text-red-500"
                aria-label="Remove widget"
                onPointerDown={(e) => e.stopPropagation()}
              >
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}
          </div>
        </div>

        {/* Widget body */}
        <div className={cn(
          'flex-1 overflow-auto transition-all',
          collapsed ? 'max-h-0 overflow-hidden' : 'p-3',
        )}>
          {!collapsed && children}
        </div>

        {/* Tag footer */}
        {config.tags.length > 0 && !collapsed && (
          <div className="flex items-center gap-1 px-3 py-1.5 border-t border-[var(--border-subtle,#E2E8F0)]">
            {config.tags.map(tag => (
              <span key={tag} className="inline-flex items-center rounded-full px-2 py-0.5 text-2xs font-medium bg-[var(--surface-overlay)] text-[var(--text-secondary)]">
                {tag}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Maximized backdrop */}
      {maximized && (
        <div className="fixed inset-0 bg-black/40 -z-10" onClick={() => setMaximized(false)} />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// WidgetGrid — the container
// ---------------------------------------------------------------------------

export function WidgetGrid({ widgets, onReorder, onRemove, onResize, renderWidget, className }: WidgetGridProps) {
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 8 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  )

  const handleDragEnd = useCallback((event: DragEndEvent) => {
    const { active, over } = event
    if (over && active.id !== over.id) {
      const oldIndex = widgets.findIndex(w => w.id === active.id)
      const newIndex = widgets.findIndex(w => w.id === over.id)
      onReorder(arrayMove(widgets, oldIndex, newIndex))
    }
  }, [widgets, onReorder])

  return (
    <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
      <SortableContext items={widgets.map(w => w.id)} strategy={rectSortingStrategy}>
        <div className={cn(
          'grid grid-cols-1 tablet:grid-cols-2 desktop:grid-cols-3 gap-4 auto-rows-[minmax(200px,auto)]',
          className,
        )}>
          {widgets.map(config => (
            <SortableWidget
              key={config.id}
              config={config}
              onRemove={onRemove}
              onResize={onResize}
            >
              {renderWidget(config)}
            </SortableWidget>
          ))}
        </div>
      </SortableContext>
    </DndContext>
  )
}

export default WidgetGrid
