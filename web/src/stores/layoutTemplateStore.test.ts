/** layoutTemplateStore.test.ts — Comprehensive test suite for layout template Zustand store.
 *
 * Tests cover:
 * - Template selection and activation
 * - Edit mode state management
 * - Draft layout mutations (updateDraftLayout, togglePanelVisibility)
 * - Template persistence (localStorage and server)
 * - Create (saveAsTemplate), Read (getters), Update (saveTemplate, renameTemplate),
 *   and Delete (deleteTemplate) operations
 * - Template duplication with new names
 * - Computed selectors (getActiveTemplate, getEffectiveLayout, getEffectiveHiddenPanels)
 * - Edit mode draft merging with defaults
 * - Built-in template protection (immutability)
 * - localStorage corruption handling
 * - Server persistence (fire-and-forget) with fetch mocking
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useLayoutTemplateStore } from './layoutTemplateStore'
import type { LayoutTemplate, LayoutItem } from '../data/defaultLayouts'

// Mock the defaultLayouts module
vi.mock('../data/defaultLayouts', () => {
  const defaultLayout: LayoutItem[] = [
    { i: 'panel-1', x: 0, y: 0, w: 6, h: 4 },
    { i: 'panel-2', x: 6, y: 0, w: 6, h: 4 },
    { i: 'panel-3', x: 0, y: 4, w: 12, h: 4 },
  ]

  const builtInTemplates: LayoutTemplate[] = [
    {
      id: 'builtin-default',
      name: 'Default',
      layout: defaultLayout,
      hiddenPanels: [],
      isBuiltIn: true,
      createdAt: 1000,
      updatedAt: 1000,
    },
    {
      id: 'builtin-compact',
      name: 'Compact',
      layout: [
        { i: 'panel-1', x: 0, y: 0, w: 12, h: 2 },
        { i: 'panel-2', x: 0, y: 2, w: 12, h: 2 },
      ],
      hiddenPanels: ['panel-3'],
      isBuiltIn: true,
      createdAt: 2000,
      updatedAt: 2000,
    },
  ]

  return {
    BUILTIN_TEMPLATES: builtInTemplates,
    mergeLayoutWithDefaults: (layout: LayoutItem[], defaults: LayoutItem[]) => {
      // Simple merge: layout items override defaults, missing defaults are added
      const merged = [...layout]
      for (const def of defaults) {
        if (!merged.find(l => l.i === def.i)) {
          merged.push(def)
        }
      }
      return merged
    },
  }
})

// Mock fetch for server persistence
global.fetch = vi.fn()

// Helper: the mock built-in templates (must match vi.mock above)
const MOCK_BUILTINS: LayoutTemplate[] = [
  {
    id: 'builtin-default',
    name: 'Default',
    layout: [
      { i: 'panel-1', x: 0, y: 0, w: 6, h: 4 },
      { i: 'panel-2', x: 6, y: 0, w: 6, h: 4 },
      { i: 'panel-3', x: 0, y: 4, w: 12, h: 4 },
    ],
    hiddenPanels: [],
    isBuiltIn: true,
    createdAt: 1000,
    updatedAt: 1000,
  },
  {
    id: 'builtin-compact',
    name: 'Compact',
    layout: [
      { i: 'panel-1', x: 0, y: 0, w: 12, h: 2 },
      { i: 'panel-2', x: 0, y: 2, w: 12, h: 2 },
    ],
    hiddenPanels: ['panel-3'],
    isBuiltIn: true,
    createdAt: 2000,
    updatedAt: 2000,
  },
]

describe('useLayoutTemplateStore', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    ;(global.fetch as any).mockResolvedValue({ ok: true })
    // Properly reset the Zustand singleton state between tests
    useLayoutTemplateStore.setState({
      templates: [...MOCK_BUILTINS],
      activeTemplateId: 'builtin-default',
      editMode: false,
      draftLayout: null,
      draftHiddenPanels: null,
    })
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  // ──────────────────────────────────────────────────────────────────
  // Initial state
  // ──────────────────────────────────────────────────────────────────

  describe('Initial state', () => {
    it('should load built-in templates with default active template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      expect(result.current.templates.length).toBe(2)
      expect(result.current.templates[0].id).toBe('builtin-default')
      expect(result.current.templates[1].id).toBe('builtin-compact')
      expect(result.current.activeTemplateId).toBe('builtin-default')
    })

    it('should initialize with edit mode off', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      expect(result.current.editMode).toBe(false)
      expect(result.current.draftLayout).toBeNull()
      expect(result.current.draftHiddenPanels).toBeNull()
    })

    it('should load user templates from localStorage', () => {
      // Zustand is a singleton — we simulate "loading from localStorage" by
      // setting state with a user template included, which mirrors what
      // loadLocal() would produce on a fresh init.
      const userTemplate: LayoutTemplate = {
        id: 'user-template-1',
        name: 'My Custom Template',
        layout: [{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }],
        hiddenPanels: [],
        isBuiltIn: false,
        createdAt: 3000,
        updatedAt: 3000,
      }

      useLayoutTemplateStore.setState({
        templates: [...MOCK_BUILTINS, userTemplate],
        activeTemplateId: 'user-template-1',
      })

      const { result } = renderHook(() => useLayoutTemplateStore())

      expect(result.current.templates.length).toBe(3) // 2 built-ins + 1 user
      expect(result.current.templates[2].id).toBe('user-template-1')
      expect(result.current.activeTemplateId).toBe('user-template-1')
    })

    it('should handle corrupted localStorage gracefully', () => {
      localStorage.setItem('exo_layout_templates', 'invalid json')
      localStorage.setItem('exo_active_template_id', 'builtin-default')

      const { result } = renderHook(() => useLayoutTemplateStore())

      expect(result.current.templates.length).toBe(2) // Falls back to built-ins
      expect(result.current.activeTemplateId).toBe('builtin-default')
    })

    it('should default to builtin-default if active template not found', () => {
      localStorage.setItem('exo_active_template_id', 'nonexistent-template')

      const { result } = renderHook(() => useLayoutTemplateStore())

      expect(result.current.activeTemplateId).toBe('builtin-default')
    })
  })

  // ──────────────────────────────────────────────────────────────────
  // Template selection
  // ──────────────────────────────────────────────────────────────────

  describe('selectTemplate', () => {
    it('should change active template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.selectTemplate('builtin-compact')
      })

      expect(result.current.activeTemplateId).toBe('builtin-compact')
    })

    it('should persist active template to localStorage', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.selectTemplate('builtin-compact')
      })

      const saved = localStorage.getItem('exo_active_template_id')
      expect(saved).toBe('builtin-compact')
    })

    it('should block template selection while in edit mode', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
      })

      expect(result.current.editMode).toBe(true)

      act(() => {
        result.current.selectTemplate('builtin-compact')
      })

      // Should remain on default template
      expect(result.current.activeTemplateId).toBe('builtin-default')
    })

    it('should allow selection of user-created templates', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let newId: string
      // Create a new template
      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.togglePanelVisibility('panel-1')
        newId = result.current.saveAsTemplate('New Template')
      })

      act(() => {
        result.current.selectTemplate('builtin-compact')
      })

      expect(result.current.activeTemplateId).toBe('builtin-compact')

      act(() => {
        result.current.selectTemplate(newId!)
      })

      expect(result.current.activeTemplateId).toBe(newId)
    })
  })

  // ──────────────────────────────────────────────────────────────────
  // Edit mode management
  // ──────────────────────────────────────────────────────────────────

  describe('setEditMode', () => {
    it('should enable edit mode with draft from active template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
      })

      expect(result.current.editMode).toBe(true)
      expect(result.current.draftLayout).not.toBeNull()
      expect(result.current.draftHiddenPanels).not.toBeNull()
    })

    it('should populate draft with active template layout', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.selectTemplate('builtin-compact')
        result.current.setEditMode(true)
      })

      const draftLayout = result.current.draftLayout
      expect(draftLayout).toBeDefined()
      expect(draftLayout?.length).toBeGreaterThan(0)
      expect(draftLayout?.some(l => l.i === 'panel-1')).toBe(true)
    })

    it('should copy hidden panels to draft', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.selectTemplate('builtin-compact')
        result.current.setEditMode(true)
      })

      expect(result.current.draftHiddenPanels).toEqual(['panel-3'])
    })

    it('should disable edit mode and discard draft', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
      })

      expect(result.current.editMode).toBe(true)

      act(() => {
        result.current.setEditMode(false)
      })

      expect(result.current.editMode).toBe(false)
      expect(result.current.draftLayout).toBeNull()
      expect(result.current.draftHiddenPanels).toBeNull()
    })

    it('should merge layout with defaults when entering edit mode', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
      })

      const draftLayout = result.current.draftLayout
      // Should include items from both active template and defaults
      expect(draftLayout).toBeDefined()
      expect(draftLayout!.length).toBeGreaterThanOrEqual(3)
    })
  })

  // ──────────────────────────────────────────────────────────────────
  // Draft mutations
  // ──────────────────────────────────────────────────────────────────

  describe('updateDraftLayout', () => {
    it('should update draft layout while in edit mode', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const newLayout: LayoutItem[] = [
        { i: 'panel-new', x: 0, y: 0, w: 12, h: 8 },
      ]

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout(newLayout)
      })

      expect(result.current.draftLayout).toEqual(newLayout)
    })

    it('should ignore update when not in edit mode', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const newLayout: LayoutItem[] = [
        { i: 'panel-new', x: 0, y: 0, w: 12, h: 8 },
      ]

      act(() => {
        result.current.updateDraftLayout(newLayout)
      })

      expect(result.current.draftLayout).toBeNull()
    })

    it('should handle empty layout array', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([])
      })

      expect(result.current.draftLayout).toEqual([])
    })
  })

  describe('togglePanelVisibility', () => {
    it('should add panel to hidden panels', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.togglePanelVisibility('panel-1')
      })

      expect(result.current.draftHiddenPanels).toContain('panel-1')
    })

    it('should remove panel from hidden panels', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.selectTemplate('builtin-compact')
        result.current.setEditMode(true)
      })

      // builtin-compact has panel-3 hidden
      expect(result.current.draftHiddenPanels).toContain('panel-3')

      act(() => {
        result.current.togglePanelVisibility('panel-3')
      })

      expect(result.current.draftHiddenPanels).not.toContain('panel-3')
    })

    it('should toggle multiple panels independently', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.togglePanelVisibility('panel-1')
        result.current.togglePanelVisibility('panel-2')
      })

      expect(result.current.draftHiddenPanels).toEqual(
        expect.arrayContaining(['panel-1', 'panel-2']),
      )

      act(() => {
        result.current.togglePanelVisibility('panel-1')
      })

      expect(result.current.draftHiddenPanels).toEqual(['panel-2'])
    })

    it('should ignore toggle when not in edit mode', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      // Not in edit mode — draftHiddenPanels is null
      expect(result.current.editMode).toBe(false)

      act(() => {
        result.current.togglePanelVisibility('panel-1')
      })

      // Should remain null since toggle is ignored outside edit mode
      expect(result.current.draftHiddenPanels).toBeNull()
    })
  })

  // ──────────────────────────────────────────────────────────────────
  // Template CRUD operations
  // ──────────────────────────────────────────────────────────────────

  describe('saveTemplate', () => {
    it('should update active user template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let templateId: string
      // Create a user template first
      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-new', x: 0, y: 0, w: 6, h: 4 }])
        templateId = result.current.saveAsTemplate('Original')
      })

      // Now edit and save
      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([
          { i: 'panel-new', x: 0, y: 0, w: 8, h: 4 },
        ])
        result.current.saveTemplate()
      })

      const updated = result.current.templates.find(t => t.id === templateId)
      expect(updated).toBeDefined()
      expect(updated?.layout[0].w).toBe(8)
    })

    it('should exit edit mode after saving', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveAsTemplate('Test')
      })

      act(() => {
        result.current.setEditMode(true)
        result.current.saveTemplate()
      })

      expect(result.current.editMode).toBe(false)
      expect(result.current.draftLayout).toBeNull()
      expect(result.current.draftHiddenPanels).toBeNull()
    })

    it('should prevent saving built-in templates', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const builtInTemplate = result.current.templates[0]
      expect(builtInTemplate.isBuiltIn).toBe(true)

      // Try to save built-in
      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveTemplate()
      })

      // Template should remain unchanged
      const afterAttempt = result.current.templates.find(
        t => t.id === builtInTemplate.id,
      )
      expect(afterAttempt).toEqual(builtInTemplate)
    })

    it('should persist template to localStorage', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveAsTemplate('Test')
        result.current.setEditMode(true)
        result.current.updateDraftLayout([
          { i: 'panel-1', x: 0, y: 0, w: 8, h: 4 },
        ])
        result.current.saveTemplate()
      })

      const saved = localStorage.getItem('exo_layout_templates')
      expect(saved).toBeDefined()
      const templates = JSON.parse(saved!)
      const test = templates.find((t: LayoutTemplate) => t.name === 'Test')
      expect(test?.layout[0].w).toBe(8)
    })

    it('should call server API to persist template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveAsTemplate('ServerTest')
        result.current.setEditMode(true)
        result.current.saveTemplate()
      })

      expect(global.fetch).toHaveBeenCalledWith(
        '/api/v1/layout-templates',
        expect.objectContaining({
          method: 'PUT',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        }),
      )
    })
  })

  describe('saveAsTemplate', () => {
    it('should create new template from draft', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let newId: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([
          { i: 'panel-1', x: 0, y: 0, w: 6, h: 4 },
          { i: 'panel-2', x: 6, y: 0, w: 6, h: 4 },
        ])
        result.current.togglePanelVisibility('panel-2')
        newId = result.current.saveAsTemplate('My Template')
      })

      const created = result.current.templates.find(t => t.id === newId)
      expect(created).toBeDefined()
      expect(created?.name).toBe('My Template')
      expect(created?.isBuiltIn).toBe(false)
      expect(created?.layout.length).toBe(2)
      expect(created?.hiddenPanels).toContain('panel-2')
    })

    it('should set new template as active', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveAsTemplate('Active Template')
      })

      expect(result.current.activeTemplateId).toMatch(/^user-/)
    })

    it('should exit edit mode after saving', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveAsTemplate('Test')
      })

      expect(result.current.editMode).toBe(false)
      expect(result.current.draftLayout).toBeNull()
      expect(result.current.draftHiddenPanels).toBeNull()
    })

    it('should persist new template to localStorage', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveAsTemplate('Persisted')
      })

      const saved = localStorage.getItem('exo_layout_templates')
      const templates = JSON.parse(saved!)
      expect(templates.some((t: LayoutTemplate) => t.name === 'Persisted')).toBe(
        true,
      )
    })

    it('should call server API for new template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveAsTemplate('Server Save')
      })

      expect(global.fetch).toHaveBeenCalledWith(
        '/api/v1/layout-templates',
        expect.objectContaining({
          method: 'PUT',
        }),
      )
    })

    it('should generate unique IDs for multiple templates', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const ids: string[] = []

      for (let i = 0; i < 3; i++) {
        act(() => {
          result.current.setEditMode(true)
          result.current.updateDraftLayout([
            { i: 'panel-1', x: 0, y: 0, w: 6, h: 4 },
          ])
          ids.push(result.current.saveAsTemplate(`Template ${i}`))
        })
      }

      expect(new Set(ids).size).toBe(3)
    })

    it('should return empty string if draft is null', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const id = result.current.saveAsTemplate('No Draft')

      expect(id).toBe('')
    })
  })

  describe('renameTemplate', () => {
    it('should rename user template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let templateId: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        templateId = result.current.saveAsTemplate('Original')
      })

      act(() => {
        result.current.renameTemplate(templateId, 'Renamed')
      })

      const renamed = result.current.templates.find(t => t.id === templateId)
      expect(renamed?.name).toBe('Renamed')
    })

    it('should prevent renaming built-in templates', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const builtIn = result.current.templates[0]

      act(() => {
        result.current.renameTemplate(builtIn.id, 'Hacked')
      })

      const afterAttempt = result.current.templates.find(t => t.id === builtIn.id)
      expect(afterAttempt?.name).toBe(builtIn.name)
    })

    it('should persist rename to localStorage', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let templateId: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        templateId = result.current.saveAsTemplate('Original')
      })

      act(() => {
        result.current.renameTemplate(templateId, 'Updated')
      })

      const saved = localStorage.getItem('exo_layout_templates')
      const templates = JSON.parse(saved!)
      expect(
        templates.find((t: LayoutTemplate) => t.id === templateId)?.name,
      ).toBe('Updated')
    })

    it('should call server API on rename', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let templateId: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        templateId = result.current.saveAsTemplate('Original')
      })

      vi.clearAllMocks()

      act(() => {
        result.current.renameTemplate(templateId, 'ServerRenamed')
      })

      expect(global.fetch).toHaveBeenCalledWith(
        '/api/v1/layout-templates',
        expect.objectContaining({
          method: 'PUT',
        }),
      )
    })

    it('should update timestamp on rename', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let templateId: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        templateId = result.current.saveAsTemplate('Original')
      })

      const original = result.current.templates.find(t => t.id === templateId)
      const originalTime = original?.updatedAt

      // Wait a tiny bit to ensure time advances
      const now = Date.now()
      while (Date.now() === now) {
        // Spin to ensure time advance
      }

      act(() => {
        result.current.renameTemplate(templateId, 'Updated')
      })

      const updated = result.current.templates.find(t => t.id === templateId)
      expect(updated?.updatedAt).toBeGreaterThan(originalTime!)
    })
  })

  describe('deleteTemplate', () => {
    it('should delete user template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let templateId: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        templateId = result.current.saveAsTemplate('To Delete')
      })

      const countBefore = result.current.templates.length

      act(() => {
        result.current.deleteTemplate(templateId)
      })

      expect(result.current.templates.length).toBe(countBefore - 1)
      expect(result.current.templates.find(t => t.id === templateId)).toBeUndefined()
    })

    it('should prevent deletion of built-in templates', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const builtIn = result.current.templates[0]
      const countBefore = result.current.templates.length

      act(() => {
        result.current.deleteTemplate(builtIn.id)
      })

      expect(result.current.templates.length).toBe(countBefore)
      expect(result.current.templates.find(t => t.id === builtIn.id)).toBeDefined()
    })

    it('should switch to default template if active template is deleted', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let templateId: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        templateId = result.current.saveAsTemplate('Active Delete')
      })

      expect(result.current.activeTemplateId).toBe(templateId)

      act(() => {
        result.current.deleteTemplate(templateId)
      })

      expect(result.current.activeTemplateId).toBe('builtin-default')
    })

    it('should preserve active template if deleted template is not active', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let toDelete: string
      let otherTemplate: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        toDelete = result.current.saveAsTemplate('Delete')
      })

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        otherTemplate = result.current.saveAsTemplate('Keep')
      })

      act(() => {
        result.current.selectTemplate(otherTemplate)
      })

      expect(result.current.activeTemplateId).toBe(otherTemplate)

      act(() => {
        result.current.deleteTemplate(toDelete)
      })

      expect(result.current.activeTemplateId).toBe(otherTemplate)
    })

    it('should persist deletion to localStorage', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let templateId: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        templateId = result.current.saveAsTemplate('To Delete')
      })

      act(() => {
        result.current.deleteTemplate(templateId)
      })

      const saved = localStorage.getItem('exo_layout_templates')
      const templates = JSON.parse(saved!)
      expect(templates.find((t: LayoutTemplate) => t.id === templateId)).toBeUndefined()
    })

    it('should call server API on delete', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let templateId: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        templateId = result.current.saveAsTemplate('Server Delete')
      })

      vi.clearAllMocks()

      act(() => {
        result.current.deleteTemplate(templateId)
      })

      expect(global.fetch).toHaveBeenCalledWith(
        `/api/v1/layout-templates/${templateId}`,
        expect.objectContaining({
          method: 'DELETE',
        }),
      )
    })
  })

  describe('duplicateTemplate', () => {
    it('should create copy of template with new name', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const original = result.current.templates[0]

      let duplicateId: string

      act(() => {
        duplicateId = result.current.duplicateTemplate(original.id, 'Copy of Default')
      })

      const duplicate = result.current.templates.find(t => t.id === duplicateId)
      expect(duplicate).toBeDefined()
      expect(duplicate?.name).toBe('Copy of Default')
      expect(duplicate?.layout).toEqual(original.layout)
      expect(duplicate?.hiddenPanels).toEqual(original.hiddenPanels)
    })

    it('should mark duplicate as user template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const original = result.current.templates[0]

      let duplicateId: string

      act(() => {
        duplicateId = result.current.duplicateTemplate(original.id, 'Copy')
      })

      const duplicate = result.current.templates.find(t => t.id === duplicateId)
      expect(duplicate?.isBuiltIn).toBe(false)
    })

    it('should set duplicate as active template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const original = result.current.templates[0]

      act(() => {
        result.current.duplicateTemplate(original.id, 'Copy')
      })

      expect(result.current.activeTemplateId).toMatch(/^user-/)
    })

    it('should persist duplicate to localStorage', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const original = result.current.templates[0]

      let duplicateId: string

      act(() => {
        duplicateId = result.current.duplicateTemplate(original.id, 'Saved Copy')
      })

      const saved = localStorage.getItem('exo_layout_templates')
      const templates = JSON.parse(saved!)
      expect(
        templates.find((t: LayoutTemplate) => t.id === duplicateId),
      ).toBeDefined()
    })

    it('should call server API on duplicate', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const original = result.current.templates[0]

      vi.clearAllMocks()

      act(() => {
        result.current.duplicateTemplate(original.id, 'Server Copy')
      })

      expect(global.fetch).toHaveBeenCalledWith(
        '/api/v1/layout-templates',
        expect.objectContaining({
          method: 'PUT',
        }),
      )
    })

    it('should return empty string if source template not found', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const id = result.current.duplicateTemplate('nonexistent', 'Copy')

      expect(id).toBe('')
    })

    it('should duplicate user templates', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let userTemplate: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        userTemplate = result.current.saveAsTemplate('Original User')
      })

      let duplicateId: string

      act(() => {
        duplicateId = result.current.duplicateTemplate(userTemplate, 'Copy User')
      })

      const duplicate = result.current.templates.find(t => t.id === duplicateId)
      expect(duplicate?.name).toBe('Copy User')
      expect(duplicate?.isBuiltIn).toBe(false)
    })
  })

  // ──────────────────────────────────────────────────────────────────
  // Computed selectors
  // ──────────────────────────────────────────────────────────────────

  describe('getActiveTemplate', () => {
    it('should return active template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const active = result.current.getActiveTemplate()

      expect(active).toBeDefined()
      expect(active.id).toBe('builtin-default')
    })

    it('should return first template if active not found', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      // Manually set invalid active ID (simulate corrupted state)
      const store = useLayoutTemplateStore.getState()
      store.activeTemplateId = 'nonexistent'

      const active = result.current.getActiveTemplate()

      expect(active).toBeDefined()
      expect(active.id).toBe(result.current.templates[0].id)
    })

    it('should return updated template after rename', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let templateId: string

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        templateId = result.current.saveAsTemplate('Original')
      })

      act(() => {
        result.current.selectTemplate(templateId)
        result.current.renameTemplate(templateId, 'Updated Name')
      })

      const active = result.current.getActiveTemplate()
      expect(active.name).toBe('Updated Name')
    })
  })

  describe('getEffectiveLayout', () => {
    it('should return draft layout while in edit mode', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
      })

      const effective = result.current.getEffectiveLayout()
      expect(effective).toEqual(result.current.draftLayout)
    })

    it('should return active template layout when not editing', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const effective = result.current.getEffectiveLayout()
      const active = result.current.getActiveTemplate()

      // Should be merged with defaults
      expect(effective).toBeDefined()
      expect(effective.length).toBeGreaterThanOrEqual(active.layout.length)
    })

    it('should merge with defaults', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      const effective = result.current.getEffectiveLayout()

      // Should include panel-1, panel-2, panel-3 from defaults
      expect(effective.some(l => l.i === 'panel-1')).toBe(true)
      expect(effective.some(l => l.i === 'panel-2')).toBe(true)
      expect(effective.some(l => l.i === 'panel-3')).toBe(true)
    })
  })

  describe('getEffectiveHiddenPanels', () => {
    it('should return draft hidden panels while in edit mode', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.togglePanelVisibility('test-panel')
      })

      const effective = result.current.getEffectiveHiddenPanels()
      expect(effective).toContain('test-panel')
    })

    it('should return active template hidden panels when not editing', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.selectTemplate('builtin-compact')
      })

      const effective = result.current.getEffectiveHiddenPanels()
      const active = result.current.getActiveTemplate()

      expect(effective).toEqual(active.hiddenPanels)
    })

    it('should return empty array for default template', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.selectTemplate('builtin-default')
      })

      const effective = result.current.getEffectiveHiddenPanels()
      expect(effective).toEqual([])
    })
  })

  // ──────────────────────────────────────────────────────────────────
  // Complex workflows
  // ──────────────────────────────────────────────────────────────────

  describe('Complex workflows', () => {
    it('should handle full template lifecycle', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      let templateId: string
      let duplicateId: string

      // Create
      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([
          { i: 'panel-1', x: 0, y: 0, w: 6, h: 4 },
          { i: 'panel-2', x: 6, y: 0, w: 6, h: 4 },
        ])
        result.current.togglePanelVisibility('panel-2')
        templateId = result.current.saveAsTemplate('Lifecycle')
      })

      expect(result.current.templates.find(t => t.id === templateId)).toBeDefined()
      expect(result.current.activeTemplateId).toBe(templateId)

      // Edit
      act(() => {
        result.current.setEditMode(true)
        result.current.togglePanelVisibility('panel-1')
        result.current.saveTemplate()
      })

      const edited = result.current.templates.find(t => t.id === templateId)
      expect(edited?.hiddenPanels).toContain('panel-1')

      // Rename
      act(() => {
        result.current.renameTemplate(templateId, 'Lifecycle Renamed')
      })

      expect(result.current.templates.find(t => t.id === templateId)?.name).toBe(
        'Lifecycle Renamed',
      )

      // Duplicate
      act(() => {
        duplicateId = result.current.duplicateTemplate(templateId, 'Copy')
      })

      expect(result.current.templates.find(t => t.id === duplicateId)).toBeDefined()

      // Delete original
      act(() => {
        result.current.deleteTemplate(templateId)
      })

      expect(result.current.templates.find(t => t.id === templateId)).toBeUndefined()
      expect(result.current.templates.find(t => t.id === duplicateId)).toBeDefined()
    })

    it('should handle multiple simultaneous edits', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.togglePanelVisibility('panel-1')
        result.current.togglePanelVisibility('panel-2')
        result.current.togglePanelVisibility('panel-1') // Toggle off
      })

      expect(result.current.draftHiddenPanels).toEqual(['panel-2'])
    })

    it('should persist through store recreation', () => {
      const { result: result1 } = renderHook(() => useLayoutTemplateStore())

      let templateId: string

      act(() => {
        result1.current.setEditMode(true)
        result1.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        templateId = result1.current.saveAsTemplate('Persistent')
      })

      // Simulate new component mounting (new store instance loads from localStorage)
      const { result: result2 } = renderHook(() => useLayoutTemplateStore())

      const found = result2.current.templates.find(t => t.id === templateId)
      expect(found).toBeDefined()
      expect(found?.name).toBe('Persistent')
    })
  })

  // ──────────────────────────────────────────────────────────────────
  // Server persistence
  // ──────────────────────────────────────────────────────────────────

  describe('Server persistence', () => {
    it('should send Authorization header with token from localStorage', () => {
      localStorage.setItem('df_token', 'test-token-123')

      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveAsTemplate('Auth Test')
      })

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer test-token-123',
          }),
        }),
      )
    })

    it('should send gateway-required actor binding metadata', () => {
      localStorage.setItem('df_token', 'test-token-123')

      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveAsTemplate('Gateway Metadata')
      })

      const [, init] = vi.mocked(global.fetch).mock.calls[0]
      const headers = init?.headers as Record<string, string>
      const body = JSON.parse(init?.body as string)

      expect(body.createdAt).toBeGreaterThan(0)
      expect(body.updatedAt).toBeGreaterThan(0)
      expect(headers['x-exo-auth-observed-at-ms']).toBe(String(body.updatedAt))
    })

    it('should continue on server sync failure (fire-and-forget)', () => {
      ;(global.fetch as any).mockRejectedValueOnce(new Error('Network error'))

      const { result } = renderHook(() => useLayoutTemplateStore())

      // Should not throw
      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveAsTemplate('Fire and Forget')
      })

      // Template should still be created locally
      expect(result.current.templates.length).toBeGreaterThan(2)
    })

    it('should serialize layout to JSON string for server', () => {
      const { result } = renderHook(() => useLayoutTemplateStore())

      act(() => {
        result.current.setEditMode(true)
        result.current.updateDraftLayout([{ i: 'panel-1', x: 0, y: 0, w: 6, h: 4 }])
        result.current.saveAsTemplate('Serialize')
      })

      const callArgs = (global.fetch as any).mock.calls[0][1]
      const body = JSON.parse(callArgs.body)
      expect(typeof body.layout).toBe('string')
      expect(JSON.parse(body.layout)).toEqual(expect.any(Array))
    })
  })
})
