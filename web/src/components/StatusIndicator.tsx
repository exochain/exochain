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
import type { DecisionStatus } from '../lib/types'
import { statusDotColor } from '../lib/types'

interface StatusIndicatorProps {
  status: DecisionStatus
  size?: 'sm' | 'md' | 'lg'
}

const sizeClasses: Record<string, { dot: string; text: string }> = {
  sm: { dot: 'w-2 h-2', text: 'text-xs' },
  md: { dot: 'w-2.5 h-2.5', text: 'text-sm' },
  lg: { dot: 'w-3 h-3', text: 'text-base' },
}

const statusLabels: Record<DecisionStatus, string> = {
  Created: 'Created',
  Deliberation: 'Deliberation',
  Voting: 'Voting',
  Approved: 'Approved',
  Rejected: 'Rejected',
  Void: 'Void',
  Contested: 'Contested',
  RatificationRequired: 'Ratification Required',
  RatificationExpired: 'Ratification Expired',
  DegradedGovernance: 'Degraded Governance',
}

export function StatusIndicator({ status, size = 'md' }: StatusIndicatorProps) {
  const classes = sizeClasses[size]
  const dotColor = statusDotColor(status)
  const label = statusLabels[status] || status

  return (
    <span className="inline-flex items-center gap-1.5" role="status" aria-label={`Status: ${label}`}>
      <span
        className={cn('inline-block rounded-full', classes.dot, dotColor)}
        aria-hidden="true"
      />
      <span className={cn(classes.text, 'font-medium text-text-gov-primary')}>
        {label}
      </span>
    </span>
  )
}
