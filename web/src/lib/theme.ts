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

/** Skinnable theme engine for decision.forum.
 *
 * Themes define a complete color palette, typography, spacing, and
 * border-radius system. The active theme is applied via CSS custom
 * properties on :root, allowing instant skin changes without re-render.
 */

export interface Theme {
  id: string
  name: string
  description: string
  colors: {
    surfaceBase: string
    surfaceRaised: string
    surfaceOverlay: string
    surfaceWidget: string
    textPrimary: string
    textSecondary: string
    textMuted: string
    borderSubtle: string
    borderWidget: string
    accentPrimary: string
    accentHover: string
    accentMuted: string
    urgencyCritical: string
    urgencyHigh: string
    urgencyModerate: string
    urgencyLow: string
    urgencyNeutral: string
    kanbanBacklog: string
    kanbanTriage: string
    kanbanReview: string
    kanbanVoting: string
    kanbanResolved: string
    kanbanArchived: string
  }
  radius: {
    widget: string
    card: string
    button: string
    badge: string
  }
  shadow: {
    widget: string
    widgetHover: string
    card: string
    overlay: string
  }
}

export const themes: Record<string, Theme> = {
  governance: {
    id: 'governance',
    name: 'Governance Blue',
    description: 'Default institutional theme',
    colors: {
      surfaceBase: '#F8FAFC',
      surfaceRaised: '#FFFFFF',
      surfaceOverlay: '#F1F5F9',
      surfaceWidget: '#FFFFFF',
      textPrimary: '#0F172A',
      textSecondary: '#64748B',
      textMuted: '#94A3B8',
      borderSubtle: '#E2E8F0',
      borderWidget: '#CBD5E1',
      accentPrimary: '#2563EB',
      accentHover: '#1D4ED8',
      accentMuted: '#DBEAFE',
      urgencyCritical: '#DC2626',
      urgencyHigh: '#EA580C',
      urgencyModerate: '#CA8A04',
      urgencyLow: '#16A34A',
      urgencyNeutral: '#6B7280',
      kanbanBacklog: '#F1F5F9',
      kanbanTriage: '#FEF3C7',
      kanbanReview: '#DBEAFE',
      kanbanVoting: '#FDE68A',
      kanbanResolved: '#D1FAE5',
      kanbanArchived: '#F3F4F6',
    },
    radius: { widget: '12px', card: '8px', button: '6px', badge: '9999px' },
    shadow: {
      widget: '0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.06)',
      widgetHover: '0 4px 12px rgba(0,0,0,0.1), 0 2px 4px rgba(0,0,0,0.06)',
      card: '0 1px 2px rgba(0,0,0,0.05)',
      overlay: '0 10px 25px rgba(0,0,0,0.15)',
    },
  },
  midnight: {
    id: 'midnight',
    name: 'Midnight Command',
    description: 'Dark theme for extended operations',
    colors: {
      surfaceBase: '#0F172A',
      surfaceRaised: '#1E293B',
      surfaceOverlay: '#334155',
      surfaceWidget: '#1E293B',
      textPrimary: '#F1F5F9',
      textSecondary: '#94A3B8',
      textMuted: '#64748B',
      borderSubtle: '#334155',
      borderWidget: '#475569',
      accentPrimary: '#60A5FA',
      accentHover: '#93C5FD',
      accentMuted: '#1E3A5F',
      urgencyCritical: '#F87171',
      urgencyHigh: '#FB923C',
      urgencyModerate: '#FACC15',
      urgencyLow: '#4ADE80',
      urgencyNeutral: '#9CA3AF',
      kanbanBacklog: '#1E293B',
      kanbanTriage: '#422006',
      kanbanReview: '#172554',
      kanbanVoting: '#422006',
      kanbanResolved: '#052E16',
      kanbanArchived: '#1F2937',
    },
    radius: { widget: '12px', card: '8px', button: '6px', badge: '9999px' },
    shadow: {
      widget: '0 1px 3px rgba(0,0,0,0.3), 0 1px 2px rgba(0,0,0,0.2)',
      widgetHover: '0 4px 12px rgba(0,0,0,0.4), 0 2px 4px rgba(0,0,0,0.2)',
      card: '0 1px 2px rgba(0,0,0,0.2)',
      overlay: '0 10px 25px rgba(0,0,0,0.5)',
    },
  },
  ember: {
    id: 'ember',
    name: 'Ember Alert',
    description: 'High-contrast crisis operations theme',
    colors: {
      surfaceBase: '#1C1917',
      surfaceRaised: '#292524',
      surfaceOverlay: '#44403C',
      surfaceWidget: '#292524',
      textPrimary: '#FAFAF9',
      textSecondary: '#A8A29E',
      textMuted: '#78716C',
      borderSubtle: '#44403C',
      borderWidget: '#57534E',
      accentPrimary: '#F97316',
      accentHover: '#FB923C',
      accentMuted: '#431407',
      urgencyCritical: '#EF4444',
      urgencyHigh: '#F97316',
      urgencyModerate: '#EAB308',
      urgencyLow: '#22C55E',
      urgencyNeutral: '#A8A29E',
      kanbanBacklog: '#292524',
      kanbanTriage: '#451A03',
      kanbanReview: '#431407',
      kanbanVoting: '#422006',
      kanbanResolved: '#052E16',
      kanbanArchived: '#1C1917',
    },
    radius: { widget: '8px', card: '6px', button: '4px', badge: '9999px' },
    shadow: {
      widget: '0 1px 3px rgba(0,0,0,0.4), 0 0 0 1px rgba(249,115,22,0.1)',
      widgetHover: '0 4px 12px rgba(0,0,0,0.5), 0 0 0 1px rgba(249,115,22,0.2)',
      card: '0 1px 2px rgba(0,0,0,0.3)',
      overlay: '0 10px 25px rgba(0,0,0,0.6)',
    },
  },
}

/** Apply a theme by setting CSS custom properties on :root. */
export function applyTheme(theme: Theme): void {
  const root = document.documentElement
  const { colors, radius, shadow } = theme

  root.style.setProperty('--surface-base', colors.surfaceBase)
  root.style.setProperty('--surface-raised', colors.surfaceRaised)
  root.style.setProperty('--surface-overlay', colors.surfaceOverlay)
  root.style.setProperty('--surface-widget', colors.surfaceWidget)
  root.style.setProperty('--text-primary', colors.textPrimary)
  root.style.setProperty('--text-secondary', colors.textSecondary)
  root.style.setProperty('--text-muted', colors.textMuted)
  root.style.setProperty('--border-subtle', colors.borderSubtle)
  root.style.setProperty('--border-widget', colors.borderWidget)
  root.style.setProperty('--accent-primary', colors.accentPrimary)
  root.style.setProperty('--accent-hover', colors.accentHover)
  root.style.setProperty('--accent-muted', colors.accentMuted)
  root.style.setProperty('--urgency-critical', colors.urgencyCritical)
  root.style.setProperty('--urgency-high', colors.urgencyHigh)
  root.style.setProperty('--urgency-moderate', colors.urgencyModerate)
  root.style.setProperty('--urgency-low', colors.urgencyLow)
  root.style.setProperty('--kanban-backlog', colors.kanbanBacklog)
  root.style.setProperty('--kanban-triage', colors.kanbanTriage)
  root.style.setProperty('--kanban-review', colors.kanbanReview)
  root.style.setProperty('--kanban-voting', colors.kanbanVoting)
  root.style.setProperty('--kanban-resolved', colors.kanbanResolved)
  root.style.setProperty('--kanban-archived', colors.kanbanArchived)
  root.style.setProperty('--radius-widget', radius.widget)
  root.style.setProperty('--radius-card', radius.card)
  root.style.setProperty('--radius-button', radius.button)
  root.style.setProperty('--shadow-widget', shadow.widget)
  root.style.setProperty('--shadow-widget-hover', shadow.widgetHover)
  root.style.setProperty('--shadow-card', shadow.card)
  root.style.setProperty('--shadow-overlay', shadow.overlay)

  // Apply body background
  document.body.style.backgroundColor = colors.surfaceBase
  document.body.style.color = colors.textPrimary
}

/** Get persisted theme or default. */
export function getPersistedTheme(): string {
  return localStorage.getItem('df_theme') || 'governance'
}

/** Persist theme selection. */
export function persistTheme(themeId: string): void {
  localStorage.setItem('df_theme', themeId)
}
