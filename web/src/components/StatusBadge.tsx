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

import { cn } from '../lib/utils'
import { statusColor, isTerminalStatus, type DecisionStatus } from '../lib/types'

interface StatusBadgeProps {
  status: DecisionStatus
  showVerification?: boolean
}

/**
 * Tamper-evident status badge (UX-002).
 * Shows visual verification status with accessible labels.
 */
export function StatusBadge({ status, showVerification = true }: StatusBadgeProps) {
  const terminal = isTerminalStatus(status)

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium',
        statusColor(status)
      )}
      role="status"
      aria-label={`Decision status: ${status}${terminal ? ' (final)' : ''}`}
    >
      {showVerification && (
        <span
          className={cn('w-2 h-2 rounded-full', terminal ? 'bg-current opacity-60' : 'bg-current animate-pulse')}
          aria-hidden="true"
        />
      )}
      {status.replace(/([A-Z])/g, ' $1').trim()}
      {terminal && (
        <svg className="w-3 h-3" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clipRule="evenodd" />
        </svg>
      )}
    </span>
  )
}
