/** layoutTemplateStore.ts — Zustand store for grid layout templates.
 *
 * Manages: template CRUD, edit mode with draft state, dual persistence
 * (localStorage immediate + server fire-and-forget), and forward-compatible
 * layout merging when new panels are added to the registry.
 */

import { create } from 'zustand'
import type { LayoutItem } from '../data/defaultLayouts'
import {
  BUILTIN_TEMPLATES,
  BUILTIN_TEMPLATES as builtins,
  mergeLayoutWithDefaults,
  type LayoutTemplate,
} from '../data/defaultLayouts'

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------

const LS_TEMPLATES_KEY = 'exo_layout_templates'
const LS_ACTIVE_KEY = 'exo_active_template_id'

function loadLocal(): { templates: LayoutTemplate[]; activeId: string } {
  try {
    const raw = localStorage.getItem(LS_TEMPLATES_KEY)
    const saved: LayoutTemplate[] = raw ? JSON.parse(raw) : []
    const activeId = localStorage.getItem(LS_ACTIVE_KEY) || 'builtin-default'
    // Merge built-ins (always authoritative) with user templates
    const userTemplates = saved.filter(t => !t.isBuiltIn)
    return { templates: [...builtins, ...userTemplates], activeId }
  } catch {
    return { templates: [...builtins], activeId: 'builtin-default' }
  }
}

function persistLocal(templates: LayoutTemplate[], activeId: string) {
  try {
    // Only persist user templates — built-ins are embedded in code
    const user = templates.filter(t => !t.isBuiltIn)
    localStorage.setItem(LS_TEMPLATES_KEY, JSON.stringify(user))
    localStorage.setItem(LS_ACTIVE_KEY, activeId)
  } catch { /* quota exceeded — degrade gracefully */ }
}

// ---------------------------------------------------------------------------
// Server persistence (fire-and-forget)
// ---------------------------------------------------------------------------

async function saveToServer(template: LayoutTemplate) {
  try {
    await fetch('/api/v1/layout-templates', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${localStorage.getItem('df_token')}`,
        'x-exo-auth-observed-at-ms': String(template.updatedAt),
      },
      body: JSON.stringify({
        id: template.id,
        name: template.name,
        layout: JSON.stringify(template.layout),
        hiddenPanels: template.hiddenPanels,
        isBuiltIn: template.isBuiltIn,
        createdAt: template.createdAt,
        updatedAt: template.updatedAt,
      }),
    })
  } catch { /* server sync is best-effort */ }
}

async function deleteFromServer(id: string) {
  try {
    const observedAt = Date.now()
    await fetch(`/api/v1/layout-templates/${id}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${localStorage.getItem('df_token')}`,
        'x-exo-auth-observed-at-ms': String(observedAt),
      },
    })
  } catch { /* best-effort */ }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

interface LayoutTemplateState {
  templates: LayoutTemplate[]
  activeTemplateId: string
  editMode: boolean
  draftLayout: LayoutItem[] | null
  draftHiddenPanels: string[] | null

  // Actions
  selectTemplate: (id: string) => void
  setEditMode: (on: boolean) => void
  updateDraftLayout: (layout: LayoutItem[]) => void
  togglePanelVisibility: (panelId: string) => void
  saveTemplate: () => void
  saveAsTemplate: (name: string) => string
  renameTemplate: (id: string, name: string) => void
  deleteTemplate: (id: string) => void
  duplicateTemplate: (id: string, newName: string) => string

  // Computed
  getActiveTemplate: () => LayoutTemplate
  getEffectiveLayout: () => LayoutItem[]
  getEffectiveHiddenPanels: () => string[]
}

const initial = loadLocal()

export const useLayoutTemplateStore = create<LayoutTemplateState>((set, get) => ({
  templates: initial.templates,
  activeTemplateId: initial.activeId,
  editMode: false,
  draftLayout: null,
  draftHiddenPanels: null,

  // ── Select template ──────────────────────────────────────────
  selectTemplate: (id) => {
    if (get().editMode) return // blocked while editing
    set({ activeTemplateId: id })
    persistLocal(get().templates, id)
  },

  // ── Edit mode ────────────────────────────────────────────────
  setEditMode: (on) => {
    if (on) {
      const active = get().getActiveTemplate()
      const defaultLayout = BUILTIN_TEMPLATES[0].layout
      set({
        editMode: true,
        draftLayout: mergeLayoutWithDefaults([...active.layout], defaultLayout),
        draftHiddenPanels: [...active.hiddenPanels],
      })
    } else {
      // Discard draft
      set({ editMode: false, draftLayout: null, draftHiddenPanels: null })
    }
  },

  // ── Draft mutations (edit mode only) ─────────────────────────
  updateDraftLayout: (layout) => {
    if (!get().editMode) return
    set({ draftLayout: layout })
  },

  togglePanelVisibility: (panelId) => {
    if (!get().editMode) return
    const current = get().draftHiddenPanels || []
    const next = current.includes(panelId)
      ? current.filter(id => id !== panelId)
      : [...current, panelId]
    set({ draftHiddenPanels: next })
  },

  // ── Save (overwrite current user template) ───────────────────
  saveTemplate: () => {
    const { activeTemplateId, draftLayout, draftHiddenPanels, templates } = get()
    const active = templates.find(t => t.id === activeTemplateId)
    if (!active || active.isBuiltIn || !draftLayout || !draftHiddenPanels) return

    const now = Date.now()
    const updated: LayoutTemplate = {
      ...active,
      layout: draftLayout,
      hiddenPanels: draftHiddenPanels,
      updatedAt: now,
    }
    const next = templates.map(t => t.id === active.id ? updated : t)
    set({ templates: next, editMode: false, draftLayout: null, draftHiddenPanels: null })
    persistLocal(next, activeTemplateId)
    saveToServer(updated)
  },

  // ── Save As (create new template from draft) ─────────────────
  saveAsTemplate: (name) => {
    const { draftLayout, draftHiddenPanels, templates } = get()
    if (!draftLayout || !draftHiddenPanels) return ''

    const now = Date.now()
    const id = `user-${now}-${Math.random().toString(36).slice(2, 8)}`
    const newTemplate: LayoutTemplate = {
      id,
      name,
      layout: draftLayout,
      hiddenPanels: draftHiddenPanels,
      isBuiltIn: false,
      createdAt: now,
      updatedAt: now,
    }
    const next = [...templates, newTemplate]
    set({
      templates: next,
      activeTemplateId: id,
      editMode: false,
      draftLayout: null,
      draftHiddenPanels: null,
    })
    persistLocal(next, id)
    saveToServer(newTemplate)
    return id
  },

  // ── Rename ───────────────────────────────────────────────────
  renameTemplate: (id, name) => {
    const { templates } = get()
    const t = templates.find(t => t.id === id)
    if (!t || t.isBuiltIn) return
    const updated = { ...t, name, updatedAt: Date.now() }
    const next = templates.map(x => x.id === id ? updated : x)
    set({ templates: next })
    persistLocal(next, get().activeTemplateId)
    saveToServer(updated)
  },

  // ── Delete ───────────────────────────────────────────────────
  deleteTemplate: (id) => {
    const { templates, activeTemplateId } = get()
    const t = templates.find(t => t.id === id)
    if (!t || t.isBuiltIn) return
    const next = templates.filter(t => t.id !== id)
    const newActive = activeTemplateId === id ? 'builtin-default' : activeTemplateId
    set({ templates: next, activeTemplateId: newActive })
    persistLocal(next, newActive)
    deleteFromServer(id)
  },

  // ── Duplicate ────────────────────────────────────────────────
  duplicateTemplate: (id, newName) => {
    const { templates } = get()
    const source = templates.find(t => t.id === id)
    if (!source) return ''
    const now = Date.now()
    const newId = `user-${now}-${Math.random().toString(36).slice(2, 8)}`
    const dup: LayoutTemplate = {
      ...source,
      id: newId,
      name: newName,
      isBuiltIn: false,
      createdAt: now,
      updatedAt: now,
    }
    const next = [...templates, dup]
    set({ templates: next, activeTemplateId: newId })
    persistLocal(next, newId)
    saveToServer(dup)
    return newId
  },

  // ── Computed ─────────────────────────────────────────────────
  getActiveTemplate: () => {
    const { templates, activeTemplateId } = get()
    return templates.find(t => t.id === activeTemplateId) || templates[0]
  },

  getEffectiveLayout: () => {
    const { editMode, draftLayout } = get()
    if (editMode && draftLayout) return draftLayout
    const defaultLayout = BUILTIN_TEMPLATES[0].layout
    return mergeLayoutWithDefaults(get().getActiveTemplate().layout, defaultLayout)
  },

  getEffectiveHiddenPanels: () => {
    const { editMode, draftHiddenPanels } = get()
    if (editMode && draftHiddenPanels) return draftHiddenPanels
    return get().getActiveTemplate().hiddenPanels
  },
}))
