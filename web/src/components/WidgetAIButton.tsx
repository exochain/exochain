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

/** WidgetAIButton — Per-widget AI assistant trigger.
 *
 *  Every module gets an integrated agentic conversational elicitation
 *  button that opens the Council AI panel with the widget's module
 *  context pre-loaded.
 */

import { useCouncil } from '../lib/CouncilContext'
import { cn } from '../lib/utils'

interface WidgetAIButtonProps {
  moduleType: string
  widgetId: string
  className?: string
  compact?: boolean
}

export function WidgetAIButton({ moduleType, widgetId, className, compact = false }: WidgetAIButtonProps) {
  const { openPanel } = useCouncil()

  return (
    <button
      onClick={(e) => {
        e.stopPropagation()
        openPanel(moduleType, widgetId)
      }}
      onPointerDown={(e) => e.stopPropagation()}
      className={cn(
        'inline-flex items-center gap-1 rounded-lg transition-all',
        compact
          ? 'p-1 hover:bg-violet-50 hover:text-violet-600'
          : 'px-2 py-1 text-2xs font-medium bg-gradient-to-r from-violet-500/10 to-blue-500/10 hover:from-violet-500/20 hover:to-blue-500/20 text-violet-600 border border-violet-200/50',
        className,
      )}
      aria-label={`Open AI assistant for ${moduleType} module`}
      title={`Ask Council AI about ${moduleType}`}
    >
      <svg className={cn(compact ? 'w-3.5 h-3.5' : 'w-3 h-3')} viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
      </svg>
      {!compact && <span>AI</span>}
    </button>
  )
}
