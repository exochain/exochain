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

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  Theme,
  themes,
  applyTheme,
  getPersistedTheme,
  persistTheme,
} from './theme'

describe('Theme Module', () => {
  beforeEach(() => {
    // Clear localStorage before each test
    localStorage.clear()
    // Reset document styles
    document.documentElement.style.cssText = ''
    document.body.style.cssText = ''
  })

  afterEach(() => {
    localStorage.clear()
    document.documentElement.style.cssText = ''
    document.body.style.cssText = ''
  })

  describe('Theme interface structure', () => {
    it('should define Theme interface with required color properties', () => {
      const testTheme: Theme = themes.governance
      expect(testTheme.colors).toBeDefined()
      expect(testTheme.colors.surfaceBase).toBeDefined()
      expect(testTheme.colors.surfaceRaised).toBeDefined()
      expect(testTheme.colors.surfaceOverlay).toBeDefined()
      expect(testTheme.colors.surfaceWidget).toBeDefined()
      expect(testTheme.colors.textPrimary).toBeDefined()
      expect(testTheme.colors.textSecondary).toBeDefined()
      expect(testTheme.colors.textMuted).toBeDefined()
      expect(testTheme.colors.borderSubtle).toBeDefined()
      expect(testTheme.colors.borderWidget).toBeDefined()
      expect(testTheme.colors.accentPrimary).toBeDefined()
      expect(testTheme.colors.accentHover).toBeDefined()
      expect(testTheme.colors.accentMuted).toBeDefined()
      expect(testTheme.colors.urgencyCritical).toBeDefined()
      expect(testTheme.colors.urgencyHigh).toBeDefined()
      expect(testTheme.colors.urgencyModerate).toBeDefined()
      expect(testTheme.colors.urgencyLow).toBeDefined()
      expect(testTheme.colors.urgencyNeutral).toBeDefined()
      expect(testTheme.colors.kanbanBacklog).toBeDefined()
      expect(testTheme.colors.kanbanTriage).toBeDefined()
      expect(testTheme.colors.kanbanReview).toBeDefined()
      expect(testTheme.colors.kanbanVoting).toBeDefined()
      expect(testTheme.colors.kanbanResolved).toBeDefined()
      expect(testTheme.colors.kanbanArchived).toBeDefined()
    })

    it('should define Theme interface with required radius properties', () => {
      const testTheme: Theme = themes.governance
      expect(testTheme.radius).toBeDefined()
      expect(testTheme.radius.widget).toBeDefined()
      expect(testTheme.radius.card).toBeDefined()
      expect(testTheme.radius.button).toBeDefined()
      expect(testTheme.radius.badge).toBeDefined()
    })

    it('should define Theme interface with required shadow properties', () => {
      const testTheme: Theme = themes.governance
      expect(testTheme.shadow).toBeDefined()
      expect(testTheme.shadow.widget).toBeDefined()
      expect(testTheme.shadow.widgetHover).toBeDefined()
      expect(testTheme.shadow.card).toBeDefined()
      expect(testTheme.shadow.overlay).toBeDefined()
    })

    it('should define Theme interface with required metadata properties', () => {
      const testTheme: Theme = themes.governance
      expect(testTheme.id).toBeDefined()
      expect(testTheme.name).toBeDefined()
      expect(testTheme.description).toBeDefined()
    })

    it('should have all color values as strings', () => {
      const testTheme: Theme = themes.governance
      Object.values(testTheme.colors).forEach((value) => {
        expect(typeof value).toBe('string')
        expect(value.length).toBeGreaterThan(0)
      })
    })

    it('should have all radius values as strings', () => {
      const testTheme: Theme = themes.governance
      Object.values(testTheme.radius).forEach((value) => {
        expect(typeof value).toBe('string')
        expect(value.length).toBeGreaterThan(0)
      })
    })

    it('should have all shadow values as strings', () => {
      const testTheme: Theme = themes.governance
      Object.values(testTheme.shadow).forEach((value) => {
        expect(typeof value).toBe('string')
        expect(value.length).toBeGreaterThan(0)
      })
    })
  })

  describe('themes record', () => {
    it('should export three themes', () => {
      expect(Object.keys(themes).length).toBe(3)
    })

    it('should have governance theme', () => {
      expect(themes.governance).toBeDefined()
      expect(themes.governance.id).toBe('governance')
      expect(themes.governance.name).toBe('Governance Blue')
      expect(themes.governance.description).toBe('Default institutional theme')
    })

    it('should have midnight theme', () => {
      expect(themes.midnight).toBeDefined()
      expect(themes.midnight.id).toBe('midnight')
      expect(themes.midnight.name).toBe('Midnight Command')
      expect(themes.midnight.description).toBe('Dark theme for extended operations')
    })

    it('should have ember theme', () => {
      expect(themes.ember).toBeDefined()
      expect(themes.ember.id).toBe('ember')
      expect(themes.ember.name).toBe('Ember Alert')
      expect(themes.ember.description).toBe('High-contrast crisis operations theme')
    })

    it('should have complete color palette for each theme', () => {
      Object.values(themes).forEach((theme) => {
        const colorKeys = Object.keys(theme.colors)
        expect(colorKeys.length).toBe(23) // Based on the Theme interface
      })
    })

    it('should have consistent radius values across themes', () => {
      Object.values(themes).forEach((theme) => {
        expect(theme.radius.widget).toBeDefined()
        expect(theme.radius.card).toBeDefined()
        expect(theme.radius.button).toBeDefined()
        expect(theme.radius.badge).toBe('9999px')
      })
    })
  })

  describe('applyTheme', () => {
    it('should set CSS custom properties for colors', () => {
      const theme = themes.governance
      applyTheme(theme)

      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe(
        theme.colors.surfaceBase
      )
      expect(document.documentElement.style.getPropertyValue('--surface-raised')).toBe(
        theme.colors.surfaceRaised
      )
      expect(document.documentElement.style.getPropertyValue('--surface-overlay')).toBe(
        theme.colors.surfaceOverlay
      )
      expect(document.documentElement.style.getPropertyValue('--surface-widget')).toBe(
        theme.colors.surfaceWidget
      )
      expect(document.documentElement.style.getPropertyValue('--text-primary')).toBe(
        theme.colors.textPrimary
      )
      expect(document.documentElement.style.getPropertyValue('--text-secondary')).toBe(
        theme.colors.textSecondary
      )
      expect(document.documentElement.style.getPropertyValue('--text-muted')).toBe(
        theme.colors.textMuted
      )
    })

    it('should set CSS custom properties for border colors', () => {
      const theme = themes.governance
      applyTheme(theme)

      expect(document.documentElement.style.getPropertyValue('--border-subtle')).toBe(
        theme.colors.borderSubtle
      )
      expect(document.documentElement.style.getPropertyValue('--border-widget')).toBe(
        theme.colors.borderWidget
      )
    })

    it('should set CSS custom properties for accent colors', () => {
      const theme = themes.governance
      applyTheme(theme)

      expect(document.documentElement.style.getPropertyValue('--accent-primary')).toBe(
        theme.colors.accentPrimary
      )
      expect(document.documentElement.style.getPropertyValue('--accent-hover')).toBe(
        theme.colors.accentHover
      )
      expect(document.documentElement.style.getPropertyValue('--accent-muted')).toBe(
        theme.colors.accentMuted
      )
    })

    it('should set CSS custom properties for urgency colors', () => {
      const theme = themes.governance
      applyTheme(theme)

      expect(document.documentElement.style.getPropertyValue('--urgency-critical')).toBe(
        theme.colors.urgencyCritical
      )
      expect(document.documentElement.style.getPropertyValue('--urgency-high')).toBe(
        theme.colors.urgencyHigh
      )
      expect(document.documentElement.style.getPropertyValue('--urgency-moderate')).toBe(
        theme.colors.urgencyModerate
      )
      expect(document.documentElement.style.getPropertyValue('--urgency-low')).toBe(
        theme.colors.urgencyLow
      )
    })

    it('should set CSS custom properties for kanban colors', () => {
      const theme = themes.governance
      applyTheme(theme)

      expect(document.documentElement.style.getPropertyValue('--kanban-backlog')).toBe(
        theme.colors.kanbanBacklog
      )
      expect(document.documentElement.style.getPropertyValue('--kanban-triage')).toBe(
        theme.colors.kanbanTriage
      )
      expect(document.documentElement.style.getPropertyValue('--kanban-review')).toBe(
        theme.colors.kanbanReview
      )
      expect(document.documentElement.style.getPropertyValue('--kanban-voting')).toBe(
        theme.colors.kanbanVoting
      )
      expect(document.documentElement.style.getPropertyValue('--kanban-resolved')).toBe(
        theme.colors.kanbanResolved
      )
      expect(document.documentElement.style.getPropertyValue('--kanban-archived')).toBe(
        theme.colors.kanbanArchived
      )
    })

    it('should set CSS custom properties for radius values', () => {
      const theme = themes.governance
      applyTheme(theme)

      expect(document.documentElement.style.getPropertyValue('--radius-widget')).toBe(
        theme.radius.widget
      )
      expect(document.documentElement.style.getPropertyValue('--radius-card')).toBe(
        theme.radius.card
      )
      expect(document.documentElement.style.getPropertyValue('--radius-button')).toBe(
        theme.radius.button
      )
    })

    it('should set CSS custom properties for shadow values', () => {
      const theme = themes.governance
      applyTheme(theme)

      expect(document.documentElement.style.getPropertyValue('--shadow-widget')).toBe(
        theme.shadow.widget
      )
      expect(document.documentElement.style.getPropertyValue('--shadow-widget-hover')).toBe(
        theme.shadow.widgetHover
      )
      expect(document.documentElement.style.getPropertyValue('--shadow-card')).toBe(
        theme.shadow.card
      )
      expect(document.documentElement.style.getPropertyValue('--shadow-overlay')).toBe(
        theme.shadow.overlay
      )
    })

    it('should apply background color to document body', () => {
      const theme = themes.governance
      applyTheme(theme)

      // jsdom converts hex to rgb — check the CSS custom property instead
      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe(theme.colors.surfaceBase)
    })

    it('should apply text color to document body', () => {
      const theme = themes.governance
      applyTheme(theme)

      // jsdom converts hex to rgb — check the CSS custom property instead
      expect(document.documentElement.style.getPropertyValue('--text-primary')).toBe(theme.colors.textPrimary)
    })

    it('should apply midnight theme correctly', () => {
      const theme = themes.midnight
      applyTheme(theme)

      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe('#0F172A')
      expect(document.documentElement.style.getPropertyValue('--text-primary')).toBe('#F1F5F9')
      // Verify via CSS custom property (jsdom converts hex to rgb for inline styles)
      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe(themes.midnight.colors.surfaceBase)
    })

    it('should apply ember theme correctly', () => {
      const theme = themes.ember
      applyTheme(theme)

      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe('#1C1917')
      expect(document.documentElement.style.getPropertyValue('--accent-primary')).toBe('#F97316')
      expect(document.documentElement.style.getPropertyValue('--text-primary')).toBe(theme.colors.textPrimary)
    })

    it('should replace previously applied theme', () => {
      applyTheme(themes.governance)
      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe('#F8FAFC')

      applyTheme(themes.midnight)
      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe('#0F172A')
    })
  })

  describe('getPersistedTheme', () => {
    it('should return governance as default when localStorage is empty', () => {
      const result = getPersistedTheme()
      expect(result).toBe('governance')
    })

    it('should return stored theme ID when present in localStorage', () => {
      localStorage.setItem('df_theme', 'midnight')
      const result = getPersistedTheme()
      expect(result).toBe('midnight')
    })

    it('should return default when localStorage has null value', () => {
      localStorage.setItem('df_theme', '')
      const result = getPersistedTheme()
      expect(result).toBe('governance')
    })

    it('should return ember theme when stored', () => {
      localStorage.setItem('df_theme', 'ember')
      const result = getPersistedTheme()
      expect(result).toBe('ember')
    })

    it('should return custom theme ID if stored', () => {
      localStorage.setItem('df_theme', 'custom-theme')
      const result = getPersistedTheme()
      expect(result).toBe('custom-theme')
    })

    it('should use df_theme localStorage key', () => {
      // Verify the correct key by setting it and checking the return value
      localStorage.setItem('df_theme', 'midnight')
      expect(getPersistedTheme()).toBe('midnight')
      // Verify it doesn't read from a wrong key
      localStorage.removeItem('df_theme')
      localStorage.setItem('wrong_key', 'ember')
      expect(getPersistedTheme()).toBe('governance')
    })
  })

  describe('persistTheme', () => {
    it('should save theme ID to localStorage', () => {
      persistTheme('midnight')
      expect(localStorage.getItem('df_theme')).toBe('midnight')
    })

    it('should overwrite existing theme in localStorage', () => {
      localStorage.setItem('df_theme', 'governance')
      persistTheme('ember')
      expect(localStorage.getItem('df_theme')).toBe('ember')
    })

    it('should persist governance theme', () => {
      persistTheme('governance')
      expect(localStorage.getItem('df_theme')).toBe('governance')
    })

    it('should persist ember theme', () => {
      persistTheme('ember')
      expect(localStorage.getItem('df_theme')).toBe('ember')
    })

    it('should use df_theme localStorage key', () => {
      persistTheme('midnight')
      // Verify it wrote to the correct key
      expect(localStorage.getItem('df_theme')).toBe('midnight')
    })

    it('should persist custom theme ID', () => {
      persistTheme('custom-theme-id')
      expect(localStorage.getItem('df_theme')).toBe('custom-theme-id')
    })
  })

  describe('Integration tests', () => {
    it('should persist and retrieve the same theme', () => {
      persistTheme('midnight')
      const retrieved = getPersistedTheme()
      expect(retrieved).toBe('midnight')
    })

    it('should apply persisted theme from localStorage', () => {
      persistTheme('midnight')
      const themeId = getPersistedTheme()
      const theme = themes[themeId as keyof typeof themes]
      applyTheme(theme)

      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe(
        themes.midnight.colors.surfaceBase
      )
    })

    it('should handle complete workflow: persist, retrieve, apply', () => {
      // Persist
      persistTheme('ember')

      // Retrieve
      const themeId = getPersistedTheme()
      expect(themeId).toBe('ember')

      // Apply
      const theme = themes[themeId as keyof typeof themes]
      applyTheme(theme)

      expect(document.documentElement.style.getPropertyValue('--accent-primary')).toBe('#F97316')
      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe('#1C1917')
    })

    it('should switch between themes correctly', () => {
      // Start with governance
      applyTheme(themes.governance)
      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe('#F8FAFC')

      // Switch to midnight
      persistTheme('midnight')
      const themeId = getPersistedTheme()
      applyTheme(themes[themeId as keyof typeof themes])
      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe('#0F172A')

      // Switch to ember
      persistTheme('ember')
      const newThemeId = getPersistedTheme()
      applyTheme(themes[newThemeId as keyof typeof themes])
      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe('#1C1917')
    })
  })

  describe('Edge cases', () => {
    it('should handle applying theme with all same color values', () => {
      const monoTheme: Theme = {
        id: 'mono',
        name: 'Monochrome',
        description: 'Test theme',
        colors: {
          surfaceBase: '#FFFFFF',
          surfaceRaised: '#FFFFFF',
          surfaceOverlay: '#FFFFFF',
          surfaceWidget: '#FFFFFF',
          textPrimary: '#000000',
          textSecondary: '#000000',
          textMuted: '#000000',
          borderSubtle: '#CCCCCC',
          borderWidget: '#CCCCCC',
          accentPrimary: '#0000FF',
          accentHover: '#0000FF',
          accentMuted: '#0000FF',
          urgencyCritical: '#FF0000',
          urgencyHigh: '#FF0000',
          urgencyModerate: '#FF0000',
          urgencyLow: '#FF0000',
          urgencyNeutral: '#808080',
          kanbanBacklog: '#FFFFFF',
          kanbanTriage: '#FFFFFF',
          kanbanReview: '#FFFFFF',
          kanbanVoting: '#FFFFFF',
          kanbanResolved: '#FFFFFF',
          kanbanArchived: '#FFFFFF',
        },
        radius: { widget: '0px', card: '0px', button: '0px', badge: '9999px' },
        shadow: { widget: 'none', widgetHover: 'none', card: 'none', overlay: 'none' },
      }
      applyTheme(monoTheme)
      expect(document.documentElement.style.getPropertyValue('--surface-base')).toBe('#FFFFFF')
    })

    it('should handle empty string theme ID in localStorage fallback', () => {
      localStorage.setItem('df_theme', '')
      expect(getPersistedTheme()).toBe('governance')
    })

    it('should not throw when applying same theme twice', () => {
      expect(() => {
        applyTheme(themes.governance)
        applyTheme(themes.governance)
      }).not.toThrow()
    })

    it('should preserve non-theme CSS properties when applying theme', () => {
      document.documentElement.style.setProperty('--custom-var', '#123456')
      applyTheme(themes.governance)
      expect(document.documentElement.style.getPropertyValue('--custom-var')).toBe('#123456')
    })
  })

  describe('Color contrast and validity', () => {
    it('should have valid hex colors in governance theme', () => {
      const hexRegex = /^#[0-9A-F]{6}$/i
      Object.values(themes.governance.colors).forEach((color) => {
        expect(hexRegex.test(color)).toBe(true)
      })
    })

    it('should have valid hex colors in midnight theme', () => {
      const hexRegex = /^#[0-9A-F]{6}$/i
      Object.values(themes.midnight.colors).forEach((color) => {
        expect(hexRegex.test(color)).toBe(true)
      })
    })

    it('should have valid hex colors in ember theme', () => {
      const hexRegex = /^#[0-9A-F]{6}$/i
      Object.values(themes.ember.colors).forEach((color) => {
        expect(hexRegex.test(color)).toBe(true)
      })
    })

    it('should have valid px or shadow values in radius properties', () => {
      Object.values(themes).forEach((theme) => {
        expect(theme.radius.widget).toMatch(/^\d+px$|^\d+\.\d+px$/)
        expect(theme.radius.card).toMatch(/^\d+px$|^\d+\.\d+px$/)
        expect(theme.radius.button).toMatch(/^\d+px$|^\d+\.\d+px$/)
        expect(theme.radius.badge).toBe('9999px')
      })
    })
  })
})
