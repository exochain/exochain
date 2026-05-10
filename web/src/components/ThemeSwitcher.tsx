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

/** ThemeSwitcher — skin selector for the governance interface. */

import { useState, useEffect } from 'react'
import { themes, applyTheme, getPersistedTheme, persistTheme } from '../lib/theme'
import { cn } from '../lib/utils'

export function ThemeSwitcher() {
  const [activeId, setActiveId] = useState(getPersistedTheme)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    const theme = themes[activeId] || themes.governance
    applyTheme(theme)
  }, [activeId])

  const switchTheme = (id: string) => {
    setActiveId(id)
    persistTheme(id)
    setOpen(false)
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="p-1.5 rounded-md hover:bg-[var(--surface-overlay)] transition-colors"
        aria-label="Switch theme"
        title="Switch theme"
      >
        <svg className="w-4 h-4 text-[var(--text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01" />
        </svg>
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full mt-1 bg-[var(--surface-raised)] border border-[var(--border-subtle)] rounded-lg shadow-[var(--shadow-overlay)] z-50 py-1 min-w-[200px]">
            <div className="px-3 py-1.5 text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider">
              Theme
            </div>
            {Object.values(themes).map(theme => (
              <button
                key={theme.id}
                onClick={() => switchTheme(theme.id)}
                className={cn(
                  'flex items-center gap-3 w-full px-3 py-2 text-sm hover:bg-[var(--surface-overlay)] transition-colors',
                  activeId === theme.id && 'bg-[var(--accent-muted)]',
                )}
              >
                {/* Color preview swatch */}
                <div className="flex gap-0.5 flex-shrink-0">
                  <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: theme.colors.accentPrimary }} />
                  <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: theme.colors.surfaceBase }} />
                  <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: theme.colors.textPrimary }} />
                </div>
                <div className="text-left">
                  <div className={cn(
                    'font-medium',
                    activeId === theme.id ? 'text-[var(--accent-primary)]' : 'text-[var(--text-primary)]',
                  )}>
                    {theme.name}
                  </div>
                  <div className="text-2xs text-[var(--text-muted)]">{theme.description}</div>
                </div>
                {activeId === theme.id && (
                  <svg className="w-4 h-4 text-[var(--accent-primary)] ml-auto flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                )}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
