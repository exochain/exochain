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

interface AmbientStatusBarProps {
  pendingCount: number
  overdueCount: number
  votingCount: number
  healthOk: boolean
  chainVerified: boolean
  chainLength: number
  mode: 'sidebar' | 'topbar' | 'badges'
}

export function AmbientStatusBar({
  pendingCount,
  overdueCount,
  votingCount,
  healthOk,
  chainVerified,
  chainLength,
  mode,
}: AmbientStatusBarProps) {
  if (mode === 'badges') {
    return (
      <div className="flex items-center gap-2" role="status" aria-label="Governance status badges">
        {pendingCount > 0 && (
          <span className="inline-flex items-center justify-center min-w-[1.25rem] h-5 rounded-full bg-urgency-moderate text-white text-2xs font-bold px-1" aria-label={`${pendingCount} pending`}>
            {pendingCount}
          </span>
        )}
        {overdueCount > 0 && (
          <span className="inline-flex items-center justify-center min-w-[1.25rem] h-5 rounded-full bg-urgency-critical text-white text-2xs font-bold px-1" aria-label={`${overdueCount} overdue`}>
            {overdueCount}
          </span>
        )}
        {votingCount > 0 && (
          <span className="inline-flex items-center justify-center min-w-[1.25rem] h-5 rounded-full bg-status-voting text-white text-2xs font-bold px-1" aria-label={`${votingCount} voting`}>
            {votingCount}
          </span>
        )}
      </div>
    )
  }

  if (mode === 'topbar') {
    return (
      <div
        className="flex items-center gap-4 px-4 py-2 bg-surface-raised border-b border-border-subtle text-sm"
        role="status"
        aria-label="Governance ambient status"
      >
        <StatusItem label="Pending" count={pendingCount} color="text-urgency-moderate" />
        <StatusItem label="Overdue" count={overdueCount} color="text-urgency-critical" />
        <StatusItem label="Voting" count={votingCount} color="text-status-voting" />
        <HealthDot ok={healthOk} />
        <ChainBadge verified={chainVerified} length={chainLength} />
      </div>
    )
  }

  // sidebar mode
  return (
    <div
      className="space-y-3 px-4 py-3"
      role="status"
      aria-label="Governance ambient status"
    >
      <h2 className="text-xs font-semibold uppercase tracking-wider text-text-gov-secondary">
        Ambient Status
      </h2>
      <div className="space-y-2">
        <SidebarRow label="Pending" count={pendingCount} color="text-urgency-moderate" bgColor="bg-yellow-50" />
        <SidebarRow label="Overdue" count={overdueCount} color="text-urgency-critical" bgColor="bg-red-50" />
        <SidebarRow label="Voting" count={votingCount} color="text-status-voting" bgColor="bg-yellow-50" />
        <div className="flex items-center justify-between py-1.5 px-2 rounded-md bg-surface-overlay">
          <span className="text-sm text-text-gov-secondary">Health</span>
          <HealthDot ok={healthOk} />
        </div>
        <div className="flex items-center justify-between py-1.5 px-2 rounded-md bg-surface-overlay">
          <span className="text-sm text-text-gov-secondary">Chain</span>
          <ChainBadge verified={chainVerified} length={chainLength} />
        </div>
      </div>
    </div>
  )
}

function StatusItem({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="text-text-gov-secondary">{label}:</span>
      <span className={cn('font-semibold', color)}>{count}</span>
    </span>
  )
}

function SidebarRow({ label, count, color, bgColor }: { label: string; count: number; color: string; bgColor: string }) {
  return (
    <div className={cn('flex items-center justify-between py-1.5 px-2 rounded-md', bgColor)}>
      <span className="text-sm text-text-gov-secondary">{label}</span>
      <span className={cn('text-lg font-bold', color)}>{count}</span>
    </div>
  )
}

function HealthDot({ ok }: { ok: boolean }) {
  return (
    <span className="inline-flex items-center gap-1" aria-label={ok ? 'System healthy' : 'System unhealthy'}>
      <span
        className={cn(
          'inline-block w-2.5 h-2.5 rounded-full',
          ok ? 'bg-urgency-low health-pulse' : 'bg-urgency-critical'
        )}
        aria-hidden="true"
      />
      <span className="text-sm font-medium">{ok ? 'OK' : 'Error'}</span>
    </span>
  )
}

function ChainBadge({ verified, length }: { verified: boolean; length: number }) {
  return (
    <span className="inline-flex items-center gap-1" aria-label={`Chain ${verified ? 'verified' : 'unverified'}, length ${length}`}>
      <span className={cn('text-sm', verified ? 'text-urgency-low' : 'text-urgency-critical')}>
        {verified ? '\u2713' : '\u2717'}
      </span>
      <span className="text-sm font-medium">{length}</span>
    </span>
  )
}
