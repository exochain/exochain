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

/**
 * APE Dashboard — Personalized post-onboarding dashboard that wraps the
 * grid system with the user's board of directors context.
 *
 * Reads onboarding data from localStorage (set during OnboardPage flow)
 * and displays the board roster alongside the main grid dashboard.
 */

import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { CommandCenterPage } from '../CommandCenterPage'
import { cn } from '../../lib/utils'

interface BoardMember {
  id: string
  title: string
  shortTitle: string
  icon: string
  description: string
  capabilities: string[]
  decisionClass: string
}

interface OnboardingData {
  displayName: string
  email: string
  boardName: string
  governanceStyle: string
  boardMembers: BoardMember[]
  createdAt: string
}

const STATUS_LABELS: Record<string, { label: string; color: string }> = {
  idle: { label: 'Idle', color: 'text-slate-400' },
  deliberating: { label: 'Deliberating', color: 'text-amber-400' },
  executing: { label: 'Executing', color: 'text-blue-400' },
  monitoring: { label: 'Monitoring', color: 'text-emerald-400' },
}

const GOVERNANCE_LABELS: Record<string, string> = {
  consensus: 'Consensus',
  majority: 'Majority Rule',
  executive: 'Executive Authority',
}

// Simulated agent activity for demo
function randomStatus(): string {
  const options = ['idle', 'deliberating', 'executing', 'monitoring']
  return options[Math.floor(Math.random() * options.length)]
}

export function APEDashboardPage() {
  const [onboarding, setOnboarding] = useState<OnboardingData | null>(null)
  const [boardCollapsed, setBoardCollapsed] = useState(false)
  const [memberStatuses, setMemberStatuses] = useState<Record<string, string>>({})

  useEffect(() => {
    const raw = localStorage.getItem('ape_onboarding')
    if (raw) {
      try {
        const data = JSON.parse(raw) as OnboardingData
        setOnboarding(data)
        // Initialize random statuses
        const statuses: Record<string, string> = {}
        data.boardMembers.forEach(m => { statuses[m.id] = randomStatus() })
        setMemberStatuses(statuses)
      } catch { /* ignore parse errors */ }
    }
  }, [])

  // Cycle agent statuses periodically for demo
  useEffect(() => {
    if (!onboarding) return
    const interval = setInterval(() => {
      setMemberStatuses(prev => {
        const next = { ...prev }
        // Randomly update 1-2 members
        const members = onboarding.boardMembers
        const idx = Math.floor(Math.random() * members.length)
        next[members[idx].id] = randomStatus()
        return next
      })
    }, 5000)
    return () => clearInterval(interval)
  }, [onboarding])

  // No onboarding data — show redirect
  if (!onboarding) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-100">
        <div className="text-center">
          <div className="text-4xl mb-4">{'\u{1F680}'}</div>
          <h2 className="text-xl font-bold text-slate-800 mb-2">No Board Configured</h2>
          <p className="text-sm text-slate-500 mb-6">
            Complete onboarding to set up your board of directors.
          </p>
          <Link
            to="/APE"
            className="px-6 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-500"
          >
            Start Onboarding
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[var(--surface-base,#f1f5f9)] flex">
      {/* Board sidebar */}
      <div
        className={cn(
          'flex-shrink-0 bg-white border-r border-slate-200 transition-all duration-300 overflow-hidden',
          boardCollapsed ? 'w-12' : 'w-64'
        )}
      >
        {/* Collapse toggle */}
        <button
          onClick={() => setBoardCollapsed(!boardCollapsed)}
          className="w-full p-3 text-left text-xs text-slate-400 hover:text-slate-600 hover:bg-slate-50 border-b border-slate-100"
          title={boardCollapsed ? 'Expand board' : 'Collapse board'}
        >
          {boardCollapsed ? '\u{25B6}' : '\u{25C0}'}
          {!boardCollapsed && <span className="ml-2 font-medium text-slate-600">Board</span>}
        </button>

        {!boardCollapsed && (
          <div className="p-4">
            {/* Board header */}
            <div className="mb-4">
              <h3 className="text-sm font-bold text-slate-800 truncate">
                {onboarding.boardName}
              </h3>
              <div className="flex items-center gap-1.5 mt-1">
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                <span className="text-xs text-slate-500">
                  {GOVERNANCE_LABELS[onboarding.governanceStyle] || onboarding.governanceStyle}
                </span>
              </div>
            </div>

            {/* Board members */}
            <div className="space-y-1">
              {onboarding.boardMembers.map(member => {
                const status = memberStatuses[member.id] || 'idle'
                const statusInfo = STATUS_LABELS[status] || STATUS_LABELS.idle
                return (
                  <div
                    key={member.id}
                    className="flex items-center gap-2 p-2 rounded-lg hover:bg-slate-50 cursor-default group"
                    title={`${member.title} — ${member.description}`}
                  >
                    <span className="text-lg">{member.icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold text-slate-700 truncate">
                        {member.shortTitle}
                      </div>
                      <div className={cn('text-2xs', statusInfo.color)}>
                        {statusInfo.label}
                      </div>
                    </div>
                    <span
                      className={cn(
                        'w-1.5 h-1.5 rounded-full flex-shrink-0',
                        status === 'executing' ? 'bg-blue-400 animate-pulse' :
                        status === 'deliberating' ? 'bg-amber-400 animate-pulse' :
                        status === 'monitoring' ? 'bg-emerald-400' :
                        'bg-slate-300'
                      )}
                    />
                  </div>
                )
              })}
            </div>

            {/* Board stats */}
            <div className="mt-6 pt-4 border-t border-slate-100">
              <div className="grid grid-cols-2 gap-3">
                <Stat label="Members" value={String(onboarding.boardMembers.length)} />
                <Stat label="Active" value={String(
                  Object.values(memberStatuses).filter(s => s !== 'idle').length
                )} />
                <Stat label="Decisions" value="0" />
                <Stat label="Uptime" value={getUptime(onboarding.createdAt)} />
              </div>
            </div>

            {/* Quick actions */}
            <div className="mt-4 space-y-1.5">
              <Link
                to="/decisions/new"
                className="block w-full text-center px-3 py-1.5 bg-blue-600 text-white text-xs font-medium rounded-lg hover:bg-blue-500 transition-colors"
              >
                + New Decision
              </Link>
              <Link
                to="/agents"
                className="block w-full text-center px-3 py-1.5 text-slate-600 text-xs font-medium rounded-lg hover:bg-slate-100 transition-colors border border-slate-200"
              >
                Manage Agents
              </Link>
            </div>
          </div>
        )}
      </div>

      {/* Main dashboard area */}
      <div className="flex-1 min-w-0 overflow-auto">
        {/* APE header */}
        <div className="bg-white border-b border-slate-200 px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-xl font-bold text-slate-900">
                {onboarding.displayName}'s Command Center
              </h1>
              <p className="text-xs text-slate-500 mt-0.5">
                Autonomous Portfolio Engine &mdash; {onboarding.boardMembers.length} board members active
              </p>
            </div>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5 text-xs text-emerald-600 font-medium bg-emerald-50 px-2.5 py-1 rounded-full">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                Board Online
              </span>
            </div>
          </div>
        </div>

        {/* Full command center with grid dashboard + kanban */}
        <div className="p-6">
          <CommandCenterPage />
        </div>
      </div>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="text-center">
      <div className="text-lg font-bold text-slate-800">{value}</div>
      <div className="text-2xs text-slate-500">{label}</div>
    </div>
  )
}

function getUptime(createdAt: string): string {
  const ms = Date.now() - new Date(createdAt).getTime()
  const mins = Math.floor(ms / 60000)
  if (mins < 60) return `${mins}m`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h`
  return `${Math.floor(hours / 24)}d`
}
