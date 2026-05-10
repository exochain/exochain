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

/** defaultLayouts.ts — Built-in layout templates and widget registry.
 *
 * Every panel in the system is registered here with its default position
 * on the 24-column grid. Built-in templates are immutable — users can
 * "Save As" from them but never overwrite.
 */

// ---------------------------------------------------------------------------
// Layout item type (matches react-grid-layout's Layout interface)
// ---------------------------------------------------------------------------

export interface LayoutItem {
  i: string
  x: number
  y: number
  w: number
  h: number
  minW?: number
  minH?: number
  maxW?: number
  maxH?: number
  static?: boolean
  isDraggable?: boolean
  isResizable?: boolean
}

// ---------------------------------------------------------------------------
// Grid constants
// ---------------------------------------------------------------------------

export const GRID_COLS = 24
export const GRID_ROW_HEIGHT = 56
export const GRID_MARGIN: [number, number] = [10, 10]
export const GRID_CONTAINER_PADDING: [number, number] = [10, 10]

// ---------------------------------------------------------------------------
// Widget panel registry
// ---------------------------------------------------------------------------

export interface PanelDef {
  id: string
  title: string
  moduleType: string
  helpTopicId: string
  tags: string[]
  /** Minimum width in grid columns */
  minW: number
  /** Minimum height in grid rows */
  minH: number
}

export const PANEL_REGISTRY: PanelDef[] = [
  { id: 'kpi-overview',      title: 'Governance KPIs',       moduleType: 'metrics',    helpTopicId: 'kpi-overview',      tags: ['overview', 'real-time'],     minW: 6,  minH: 2 },
  { id: 'active-decisions',  title: 'Active Decisions',      moduleType: 'decisions',  helpTopicId: 'active-decisions',  tags: ['workflow', 'voting'],        minW: 6,  minH: 4 },
  { id: 'escalation-feed',   title: 'Escalation Feed',       moduleType: 'escalation', helpTopicId: 'escalation-feed',   tags: ['alerts', 'triage'],          minW: 4,  minH: 3 },
  { id: 'trust-scores',      title: 'Trust Score Monitor',   moduleType: 'identity',   helpTopicId: 'trust-scores',      tags: ['pace', 'scoring'],           minW: 4,  minH: 2 },
  { id: 'audit-chain',       title: 'Audit Chain Health',    moduleType: 'audit',      helpTopicId: 'audit-chain',       tags: ['integrity', 'forensic'],     minW: 4,  minH: 2 },
  { id: 'delegation-map',    title: 'Authority Map',         moduleType: 'delegation', helpTopicId: 'delegation-map',    tags: ['authority', 'chain'],        minW: 4,  minH: 2 },
  { id: 'agent-status',      title: 'Agent Registry',        moduleType: 'agents',     helpTopicId: 'agent-status',      tags: ['holon', 'ai'],               minW: 6,  minH: 3 },
  { id: 'cgr-kernel',        title: 'CGR Kernel Status',     moduleType: 'kernel',     helpTopicId: 'cgr-kernel',        tags: ['invariants', 'judicial'],    minW: 4,  minH: 2 },
  { id: 'council-tickets',   title: 'Council Tickets',       moduleType: 'council',    helpTopicId: 'council-tickets',   tags: ['tickets', 'triage'],         minW: 6,  minH: 3 },
]

// ---------------------------------------------------------------------------
// Layout template type
// ---------------------------------------------------------------------------

export interface LayoutTemplate {
  id: string
  name: string
  layout: LayoutItem[]
  hiddenPanels: string[]
  isBuiltIn: boolean
  createdAt: number
  updatedAt: number
}

// ---------------------------------------------------------------------------
// Built-in templates
// ---------------------------------------------------------------------------

const DEFAULT_LAYOUT: LayoutItem[] = [
  { i: 'kpi-overview',      x: 0,  y: 0,  w: 16, h: 3,  minW: 6,  minH: 2 },
  { i: 'active-decisions',  x: 16, y: 0,  w: 8,  h: 6,  minW: 6,  minH: 4 },
  { i: 'escalation-feed',   x: 0,  y: 3,  w: 8,  h: 5,  minW: 4,  minH: 3 },
  { i: 'trust-scores',      x: 8,  y: 3,  w: 4,  h: 3,  minW: 4,  minH: 2 },
  { i: 'audit-chain',       x: 12, y: 3,  w: 4,  h: 3,  minW: 4,  minH: 2 },
  { i: 'delegation-map',    x: 8,  y: 6,  w: 4,  h: 3,  minW: 4,  minH: 2 },
  { i: 'agent-status',      x: 12, y: 6,  w: 12, h: 4,  minW: 6,  minH: 3 },
  { i: 'cgr-kernel',        x: 0,  y: 8,  w: 8,  h: 3,  minW: 4,  minH: 2 },
  { i: 'council-tickets',   x: 0,  y: 11, w: 12, h: 4,  minW: 6,  minH: 3 },
]

const COMPACT_LAYOUT: LayoutItem[] = [
  { i: 'kpi-overview',      x: 0,  y: 0,  w: 12, h: 3,  minW: 6,  minH: 2 },
  { i: 'active-decisions',  x: 12, y: 0,  w: 12, h: 5,  minW: 6,  minH: 4 },
  { i: 'escalation-feed',   x: 0,  y: 3,  w: 6,  h: 4,  minW: 4,  minH: 3 },
  { i: 'trust-scores',      x: 6,  y: 3,  w: 6,  h: 3,  minW: 4,  minH: 2 },
  { i: 'audit-chain',       x: 0,  y: 7,  w: 6,  h: 3,  minW: 4,  minH: 2 },
  { i: 'delegation-map',    x: 6,  y: 6,  w: 6,  h: 3,  minW: 4,  minH: 2 },
  { i: 'agent-status',      x: 12, y: 5,  w: 12, h: 4,  minW: 6,  minH: 3 },
  { i: 'cgr-kernel',        x: 0,  y: 10, w: 6,  h: 3,  minW: 4,  minH: 2 },
  { i: 'council-tickets',   x: 6,  y: 9,  w: 12, h: 4,  minW: 6,  minH: 3 },
]

const MINIMAL_LAYOUT: LayoutItem[] = [
  { i: 'kpi-overview',      x: 0,  y: 0,  w: 24, h: 3,  minW: 6,  minH: 2 },
  { i: 'active-decisions',  x: 0,  y: 3,  w: 12, h: 6,  minW: 6,  minH: 4 },
  { i: 'council-tickets',   x: 12, y: 3,  w: 12, h: 6,  minW: 6,  minH: 3 },
]

const FULL_OVERVIEW_LAYOUT: LayoutItem[] = [
  { i: 'kpi-overview',      x: 0,  y: 0,  w: 24, h: 3,  minW: 6,  minH: 2 },
  { i: 'active-decisions',  x: 0,  y: 3,  w: 8,  h: 6,  minW: 6,  minH: 4 },
  { i: 'escalation-feed',   x: 8,  y: 3,  w: 8,  h: 6,  minW: 4,  minH: 3 },
  { i: 'council-tickets',   x: 16, y: 3,  w: 8,  h: 6,  minW: 6,  minH: 3 },
  { i: 'trust-scores',      x: 0,  y: 9,  w: 6,  h: 3,  minW: 4,  minH: 2 },
  { i: 'audit-chain',       x: 6,  y: 9,  w: 6,  h: 3,  minW: 4,  minH: 2 },
  { i: 'delegation-map',    x: 12, y: 9,  w: 6,  h: 3,  minW: 4,  minH: 2 },
  { i: 'cgr-kernel',        x: 18, y: 9,  w: 6,  h: 3,  minW: 4,  minH: 2 },
  { i: 'agent-status',      x: 0,  y: 12, w: 24, h: 4,  minW: 6,  minH: 3 },
]

export const BUILTIN_TEMPLATES: LayoutTemplate[] = [
  { id: 'builtin-default',       name: 'Default',       layout: DEFAULT_LAYOUT,       hiddenPanels: [],                                                      isBuiltIn: true, createdAt: 0, updatedAt: 0 },
  { id: 'builtin-compact',       name: 'Compact',       layout: COMPACT_LAYOUT,       hiddenPanels: [],                                                      isBuiltIn: true, createdAt: 0, updatedAt: 0 },
  { id: 'builtin-minimal',       name: 'Minimal',       layout: MINIMAL_LAYOUT,       hiddenPanels: ['escalation-feed', 'trust-scores', 'audit-chain', 'delegation-map', 'agent-status', 'cgr-kernel'], isBuiltIn: true, createdAt: 0, updatedAt: 0 },
  { id: 'builtin-full-overview', name: 'Full Overview', layout: FULL_OVERVIEW_LAYOUT,  hiddenPanels: [],                                                      isBuiltIn: true, createdAt: 0, updatedAt: 0 },
]

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** Merge a saved layout with the current panel registry.
 *  If new panels were added to PANEL_REGISTRY since the layout was saved,
 *  they get appended at the bottom with default sizing.
 */
export function mergeLayoutWithDefaults(saved: LayoutItem[], defaults: LayoutItem[]): LayoutItem[] {
  const savedIds = new Set(saved.map(l => l.i))
  const maxY = saved.reduce((m, l) => Math.max(m, l.y + l.h), 0)
  const missing = defaults.filter(d => !savedIds.has(d.i))
  let nextY = maxY
  const appended = missing.map((d, idx) => {
    const item = { ...d, x: (idx * 8) % 24, y: nextY }
    if ((idx * 8) % 24 + d.w > 24) nextY += d.h
    return item
  })
  return [...saved, ...appended]
}
