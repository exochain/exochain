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

/** KanbanBoard — Human-in-the-loop governance workflow control.
 *
 * A deck of tagged cards flowing through governance stages.
 * Drag cards between columns. Each card is an event — a decision,
 * a triage item, an escalation, a challenge module.
 *
 * Columns map to governance workflow: Backlog → Triage → In Review →
 * Deliberation → Voting → Resolved → Archived
 */

import { useState, useCallback, type ReactNode } from 'react'
import {
  DndContext,
  closestCorners,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragOverEvent,
  DragOverlay,
  type DragStartEvent,
} from '@dnd-kit/core'
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import { cn } from '../lib/utils'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CardTag {
  label: string
  color: string
}

export type CardPriority = 'immediate' | 'urgent' | 'standard' | 'deferred' | 'backlog'

export interface KanbanCardData {
  id: string
  title: string
  description?: string
  tags: CardTag[]
  priority: CardPriority
  assignee?: string
  linkedDecisionId?: string
  linkedTriageId?: string
  dueAt?: number
  createdAt: number
  metadata?: Record<string, string>
}

export interface KanbanColumnData {
  id: string
  title: string
  color: string
  wipLimit?: number
  cards: KanbanCardData[]
}

interface KanbanBoardProps {
  columns: KanbanColumnData[]
  onCardMove: (cardId: string, fromCol: string, toCol: string, newIndex: number) => void
  onCardClick?: (card: KanbanCardData, columnId: string) => void
  renderCardExtra?: (card: KanbanCardData) => ReactNode
  className?: string
}

// ---------------------------------------------------------------------------
// Priority styles
// ---------------------------------------------------------------------------

const priorityStyles: Record<CardPriority, { border: string; dot: string; label: string }> = {
  immediate: { border: 'border-l-4 border-l-red-500', dot: 'bg-red-500', label: 'IMM' },
  urgent: { border: 'border-l-4 border-l-orange-500', dot: 'bg-orange-500', label: 'URG' },
  standard: { border: 'border-l-4 border-l-blue-400', dot: 'bg-blue-400', label: 'STD' },
  deferred: { border: 'border-l-4 border-l-slate-400', dot: 'bg-slate-400', label: 'DEF' },
  backlog: { border: 'border-l-4 border-l-slate-300', dot: 'bg-slate-300', label: 'BKL' },
}

// ---------------------------------------------------------------------------
// Sortable Card
// ---------------------------------------------------------------------------

function SortableCard({
  card,
  columnId,
  onClick,
  renderExtra,
}: {
  card: KanbanCardData
  columnId: string
  onClick?: (card: KanbanCardData, columnId: string) => void
  renderExtra?: (card: KanbanCardData) => ReactNode
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: card.id,
    data: { columnId },
  })

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
  }

  const ps = priorityStyles[card.priority]

  return (
    <div
      ref={setNodeRef}
      style={style}
      {...attributes}
      {...listeners}
      className={cn(
        'bg-[var(--surface-widget,#fff)] rounded-md shadow-[var(--shadow-card)] p-2.5 cursor-grab active:cursor-grabbing',
        'hover:shadow-[var(--shadow-widget)] transition-shadow',
        ps.border,
        isDragging && 'opacity-40',
      )}
      onClick={() => onClick?.(card, columnId)}
      role="button"
      aria-label={`Card: ${card.title}`}
    >
      {/* Title + Priority */}
      <div className="flex items-start justify-between gap-2 mb-1">
        <h4 className="text-sm font-medium text-[var(--text-primary)] leading-tight line-clamp-2">
          {card.title}
        </h4>
        <span className={cn('flex-shrink-0 w-2 h-2 rounded-full mt-1', ps.dot)} title={card.priority} />
      </div>

      {/* Description preview */}
      {card.description && (
        <p className="text-2xs text-[var(--text-secondary)] line-clamp-2 mb-2">
          {card.description}
        </p>
      )}

      {/* Tags */}
      {card.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-1.5">
          {card.tags.map((tag, i) => (
            <span
              key={i}
              className="inline-flex items-center rounded-full px-1.5 py-0.5 text-2xs font-medium"
              style={{ backgroundColor: tag.color + '20', color: tag.color }}
            >
              {tag.label}
            </span>
          ))}
        </div>
      )}

      {/* Footer: assignee + due date */}
      <div className="flex items-center justify-between text-2xs text-[var(--text-muted)]">
        {card.assignee ? (
          <div className="flex items-center gap-1">
            <div className="w-4 h-4 rounded-full bg-[var(--accent-muted)] flex items-center justify-center text-2xs font-bold text-[var(--accent-primary)]">
              {card.assignee.charAt(0).toUpperCase()}
            </div>
            <span className="truncate max-w-[80px]">{card.assignee}</span>
          </div>
        ) : (
          <span className="text-[var(--text-muted)]">Unassigned</span>
        )}
        {card.dueAt && (
          <span className={cn(
            card.dueAt < Date.now() ? 'text-[var(--urgency-critical)] font-semibold' : ''
          )}>
            {new Date(card.dueAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
          </span>
        )}
      </div>

      {/* Extension point for custom rendering */}
      {renderExtra?.(card)}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Card overlay (shown while dragging)
// ---------------------------------------------------------------------------

function CardOverlay({ card }: { card: KanbanCardData }) {
  const ps = priorityStyles[card.priority]
  return (
    <div className={cn(
      'bg-[var(--surface-widget,#fff)] rounded-md shadow-[var(--shadow-overlay)] p-2.5',
      ps.border,
      'rotate-2 scale-105',
    )}>
      <h4 className="text-sm font-medium text-[var(--text-primary)]">{card.title}</h4>
      <div className="flex flex-wrap gap-1 mt-1">
        {card.tags.map((tag, i) => (
          <span key={i} className="inline-flex items-center rounded-full px-1.5 py-0.5 text-2xs font-medium"
            style={{ backgroundColor: tag.color + '20', color: tag.color }}>
            {tag.label}
          </span>
        ))}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Column
// ---------------------------------------------------------------------------

function Column({
  column,
  onCardClick,
  renderCardExtra,
}: {
  column: KanbanColumnData
  onCardClick?: (card: KanbanCardData, columnId: string) => void
  renderCardExtra?: (card: KanbanCardData) => ReactNode
}) {
  const isOverWip = column.wipLimit != null && column.cards.length > column.wipLimit
  const isAtWip = column.wipLimit != null && column.cards.length === column.wipLimit

  return (
    <div className="flex flex-col min-w-[260px] max-w-[320px] flex-shrink-0">
      {/* Column header */}
      <div
        className="flex items-center justify-between px-3 py-2 rounded-t-lg"
        style={{ backgroundColor: column.color }}
      >
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">
            {column.title}
          </h3>
          <span className={cn(
            'inline-flex items-center justify-center min-w-[20px] h-5 rounded-full text-2xs font-bold px-1',
            isOverWip ? 'bg-red-500 text-white'
              : isAtWip ? 'bg-amber-500 text-white'
                : 'bg-[var(--surface-overlay)] text-[var(--text-secondary)]',
          )}>
            {column.cards.length}
            {column.wipLimit != null && `/${column.wipLimit}`}
          </span>
        </div>
      </div>

      {/* Card list */}
      <SortableContext items={column.cards.map(c => c.id)} strategy={verticalListSortingStrategy}>
        <div className={cn(
          'flex-1 space-y-2 p-2 min-h-[100px] rounded-b-lg border border-t-0',
          'border-[var(--border-subtle)]',
          isOverWip && 'bg-red-50/50',
        )}
          style={{ backgroundColor: column.color + '40' }}
        >
          {column.cards.map(card => (
            <SortableCard
              key={card.id}
              card={card}
              columnId={column.id}
              onClick={onCardClick}
              renderExtra={renderCardExtra}
            />
          ))}

          {column.cards.length === 0 && (
            <div className="flex items-center justify-center h-20 text-xs text-[var(--text-muted)] italic">
              Drop cards here
            </div>
          )}
        </div>
      </SortableContext>
    </div>
  )
}

// ---------------------------------------------------------------------------
// KanbanBoard
// ---------------------------------------------------------------------------

export function KanbanBoard({ columns: initialColumns, onCardMove, onCardClick, renderCardExtra, className }: KanbanBoardProps) {
  const [columns, setColumns] = useState(initialColumns)
  const [activeCard, setActiveCard] = useState<KanbanCardData | null>(null)

  // Update columns when props change
  if (initialColumns !== columns && JSON.stringify(initialColumns) !== JSON.stringify(columns)) {
    setColumns(initialColumns)
  }

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  )

  const findColumn = useCallback((cardId: string) => {
    return columns.find(col => col.cards.some(c => c.id === cardId))
  }, [columns])

  const handleDragStart = useCallback((event: DragStartEvent) => {
    const col = findColumn(event.active.id as string)
    const card = col?.cards.find(c => c.id === event.active.id)
    setActiveCard(card || null)
  }, [findColumn])

  const handleDragOver = useCallback((event: DragOverEvent) => {
    const { active, over } = event
    if (!over) return

    const activeCol = findColumn(active.id as string)
    const overCol = findColumn(over.id as string) || columns.find(c => c.id === over.id)

    if (!activeCol || !overCol || activeCol.id === overCol.id) return

    setColumns(prev => {
      const activeCards = [...prev.find(c => c.id === activeCol.id)!.cards]
      const overCards = [...prev.find(c => c.id === overCol.id)!.cards]

      const activeIndex = activeCards.findIndex(c => c.id === active.id)
      const [movedCard] = activeCards.splice(activeIndex, 1)

      const overIndex = overCards.findIndex(c => c.id === over.id)
      overCards.splice(overIndex >= 0 ? overIndex : overCards.length, 0, movedCard)

      return prev.map(col => {
        if (col.id === activeCol.id) return { ...col, cards: activeCards }
        if (col.id === overCol.id) return { ...col, cards: overCards }
        return col
      })
    })
  }, [columns, findColumn])

  const handleDragEnd = useCallback((event: DragEndEvent) => {
    const { active, over } = event
    setActiveCard(null)

    if (!over) return

    const overCol = findColumn(over.id as string) || columns.find(c => c.id === over.id)
    if (!overCol) return

    const overIndex = overCol.cards.findIndex(c => c.id === active.id)
    const activeData = active.data.current as { columnId?: string } | undefined
    const fromCol = activeData?.columnId || ''

    if (fromCol !== overCol.id || overIndex >= 0) {
      onCardMove(active.id as string, fromCol, overCol.id, Math.max(0, overIndex))
    }
  }, [columns, findColumn, onCardMove])

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCorners}
      onDragStart={handleDragStart}
      onDragOver={handleDragOver}
      onDragEnd={handleDragEnd}
    >
      <div className={cn(
        'flex gap-4 overflow-x-auto pb-4 min-h-[400px]',
        className,
      )}>
        {columns.map(col => (
          <Column
            key={col.id}
            column={col}
            onCardClick={onCardClick}
            renderCardExtra={renderCardExtra}
          />
        ))}
      </div>

      <DragOverlay>
        {activeCard && <CardOverlay card={activeCard} />}
      </DragOverlay>
    </DndContext>
  )
}

/** Create default governance kanban columns. */
export function defaultGovernanceColumns(): KanbanColumnData[] {
  return [
    { id: 'backlog', title: 'Backlog', color: 'var(--kanban-backlog, #F1F5F9)', cards: [] },
    { id: 'triage', title: 'Triage', color: 'var(--kanban-triage, #FEF3C7)', wipLimit: 8, cards: [] },
    { id: 'review', title: 'In Review', color: 'var(--kanban-review, #DBEAFE)', wipLimit: 5, cards: [] },
    { id: 'deliberation', title: 'Deliberation', color: 'var(--kanban-review, #DBEAFE)', wipLimit: 5, cards: [] },
    { id: 'voting', title: 'Voting', color: 'var(--kanban-voting, #FDE68A)', wipLimit: 3, cards: [] },
    { id: 'resolved', title: 'Resolved', color: 'var(--kanban-resolved, #D1FAE5)', cards: [] },
    { id: 'archived', title: 'Archived', color: 'var(--kanban-archived, #F3F4F6)', cards: [] },
  ]
}

export default KanbanBoard
