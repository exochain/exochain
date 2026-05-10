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

import { useState, useEffect, useCallback, type FormEvent } from 'react'
import { api } from '../lib/api'
import { cn } from '../lib/utils'
import type { AgentIdentity, PaceStatus } from '../lib/types'

const AGENT_TYPE_LABELS: Record<string, string> = {
  autonomous: 'Autonomous',
  copilot: 'Copilot',
  tool: 'Tool',
  holon: 'Holon',
}

const AGENT_TYPE_ICONS: Record<string, string> = {
  autonomous: '\u{1F916}',
  copilot: '\u{1F9D1}\u200D\u2708\uFE0F',
  tool: '\u{1F527}',
  holon: '\u{1F517}',
}

const CAPABILITIES = ['CreateDecision', 'CastVote', 'AdvanceDecision', 'GrantDelegation']
const DECISION_CLASSES = ['Operational', 'Strategic', 'Constitutional', 'Financial', 'Emergency']

const PACE_ORDER: PaceStatus[] = ['Unenrolled', 'Provable', 'Auditable', 'Compliant', 'Enforceable']

function paceIndex(status: PaceStatus): number {
  return PACE_ORDER.indexOf(status)
}

function tierBarColor(score: number): string {
  if (score >= 900) return 'bg-green-500'
  if (score >= 700) return 'bg-blue-500'
  if (score >= 500) return 'bg-slate-500'
  if (score >= 300) return 'bg-amber-500'
  return 'bg-red-500'
}

function tierBadge(tier: string): string {
  switch (tier) {
    case 'Verified': return 'bg-green-100 text-green-800'
    case 'Trusted': return 'bg-blue-100 text-blue-800'
    case 'Standard': return 'bg-slate-100 text-slate-700'
    case 'Probationary': return 'bg-amber-100 text-amber-800'
    case 'Untrusted': return 'bg-red-100 text-red-800'
    default: return 'bg-slate-100 text-slate-700'
  }
}

export function AgentsPage() {
  const [agents, setAgents] = useState<AgentIdentity[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)

  const fetchAgents = useCallback(async () => {
    try {
      const list = await api.agents.list()
      setAgents(list)
    } catch {
      // May fail if no agents yet
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchAgents()
  }, [fetchAgents])

  function handleEnrolled() {
    setShowModal(false)
    fetchAgents()
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex flex-col tablet:flex-row tablet:items-center tablet:justify-between gap-4">
        <h1 className="text-2xl font-bold text-slate-900">
          Agent Registry &mdash; Identity &amp; Governance
        </h1>
        <button
          onClick={() => setShowModal(true)}
          className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
        >
          Enroll New Agent
        </button>
      </div>

      {loading && (
        <div className="text-sm text-slate-400 text-center py-8">Loading agents...</div>
      )}

      {!loading && agents.length === 0 && (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-8 text-center">
          <p className="text-slate-500 text-sm">No agents enrolled yet.</p>
          <button
            onClick={() => setShowModal(true)}
            className="mt-4 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
          >
            Enroll Your First Agent
          </button>
        </div>
      )}

      {/* Agent cards */}
      <div className="grid gap-4 tablet:grid-cols-2">
        {agents.map(agent => (
          <AgentCard key={agent.did} agent={agent} />
        ))}
      </div>

      {/* Enrollment modal */}
      {showModal && (
        <EnrollModal onClose={() => setShowModal(false)} onSuccess={handleEnrolled} />
      )}
    </div>
  )
}

function AgentCard({ agent }: { agent: AgentIdentity }) {
  const pIdx = paceIndex(agent.paceStatus)

  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-lg" aria-hidden="true">
              {AGENT_TYPE_ICONS[agent.agentType] || '\u{1F916}'}
            </span>
            <h3 className="text-base font-semibold text-slate-900">{agent.agentName}</h3>
          </div>
          <span className={cn(
            'mt-1 inline-block rounded-full px-2 py-0.5 text-2xs font-medium',
            'bg-slate-100 text-slate-600'
          )}>
            {AGENT_TYPE_LABELS[agent.agentType] || agent.agentType}
          </span>
        </div>
        <span className={cn(
          'rounded-full px-2 py-0.5 text-2xs font-semibold',
          tierBadge(agent.trustTier)
        )}>
          {agent.trustTier}
        </span>
      </div>

      {/* DID */}
      <div>
        <span className="text-2xs text-slate-400">DID: </span>
        <code className="font-mono text-2xs text-slate-500">
          {agent.did.length > 36 ? `${agent.did.slice(0, 18)}...${agent.did.slice(-8)}` : agent.did}
        </code>
      </div>

      {/* Trust score bar */}
      <div>
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs text-slate-500">Trust Score</span>
          <span className="text-xs font-semibold text-slate-700">{agent.trustScore}/1000</span>
        </div>
        <div className="w-full bg-slate-100 rounded-full h-2">
          <div
            className={cn('h-2 rounded-full transition-all', tierBarColor(agent.trustScore))}
            style={{ width: `${Math.min(100, (agent.trustScore / 1000) * 100)}%` }}
            role="progressbar"
            aria-valuenow={agent.trustScore}
            aria-valuemin={0}
            aria-valuemax={1000}
            aria-label={`Trust score: ${agent.trustScore}`}
          />
        </div>
      </div>

      {/* PACE dots */}
      <div>
        <span className="text-xs text-slate-500 block mb-1">PACE Status</span>
        <div className="flex items-center gap-1.5">
          {['P', 'A', 'C', 'E'].map((letter, i) => (
            <div
              key={letter}
              className={cn(
                'w-6 h-6 rounded-full flex items-center justify-center text-2xs font-bold',
                pIdx >= i + 1
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-200 text-slate-400'
              )}
              aria-label={`${letter}: ${pIdx >= i + 1 ? 'complete' : 'incomplete'}`}
            >
              {letter}
            </div>
          ))}
        </div>
      </div>

      {/* Capabilities */}
      <div>
        <span className="text-xs text-slate-500 block mb-1">Capabilities</span>
        <div className="flex flex-wrap gap-1">
          {agent.capabilities.map(cap => (
            <span
              key={cap}
              className="inline-flex items-center rounded bg-slate-100 px-1.5 py-0.5 text-2xs font-medium text-slate-600"
            >
              {cap}
            </span>
          ))}
        </div>
      </div>

      {/* Max decision class */}
      <div className="text-xs text-slate-500">
        Max Decision Class: <span className="font-medium text-slate-700">{agent.maxDecisionClass}</span>
      </div>
    </div>
  )
}

function EnrollModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [agentName, setAgentName] = useState('')
  const [agentType, setAgentType] = useState('autonomous')
  const [capabilities, setCapabilities] = useState<string[]>([])
  const [maxDecisionClass, setMaxDecisionClass] = useState('Operational')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  function toggleCapability(cap: string) {
    setCapabilities(prev =>
      prev.includes(cap) ? prev.filter(c => c !== cap) : [...prev, cap]
    )
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!agentName.trim()) {
      setError('Agent name is required')
      return
    }
    setError('')
    setSubmitting(true)
    try {
      await api.agents.enroll({
        agentName: agentName.trim(),
        agentType,
        capabilities,
        maxDecisionClass,
      })
      onSuccess()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Enrollment failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal */}
      <div
        className="relative bg-white rounded-xl shadow-lg border border-slate-200 p-6 w-full max-w-md mx-4"
        role="dialog"
        aria-modal="true"
        aria-labelledby="enroll-title"
      >
        <h2 id="enroll-title" className="text-lg font-semibold text-slate-900 mb-4">
          Enroll New Agent
        </h2>

        {error && (
          <div
            className="mb-4 rounded-lg bg-red-50 border border-red-200 p-3 text-sm text-red-700"
            role="alert"
          >
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} noValidate>
          <div className="space-y-4">
            <div>
              <label htmlFor="agent-name" className="block text-sm font-medium text-slate-700 mb-1">
                Agent Name
              </label>
              <input
                id="agent-name"
                type="text"
                required
                value={agentName}
                onChange={e => setAgentName(e.target.value)}
                className="block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="My Agent"
              />
            </div>

            <div>
              <label htmlFor="agent-type" className="block text-sm font-medium text-slate-700 mb-1">
                Agent Type
              </label>
              <select
                id="agent-type"
                value={agentType}
                onChange={e => setAgentType(e.target.value)}
                className="block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              >
                {Object.entries(AGENT_TYPE_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
            </div>

            <fieldset>
              <legend className="block text-sm font-medium text-slate-700 mb-2">
                Capabilities
              </legend>
              <div className="space-y-2">
                {CAPABILITIES.map(cap => (
                  <label key={cap} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={capabilities.includes(cap)}
                      onChange={() => toggleCapability(cap)}
                      className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="text-sm text-slate-700">{cap}</span>
                  </label>
                ))}
              </div>
            </fieldset>

            <div>
              <label htmlFor="max-class" className="block text-sm font-medium text-slate-700 mb-1">
                Max Decision Class
              </label>
              <select
                id="max-class"
                value={maxDecisionClass}
                onChange={e => setMaxDecisionClass(e.target.value)}
                className="block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              >
                {DECISION_CLASSES.map(dc => (
                  <option key={dc} value={dc}>{dc}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="mt-6 flex gap-3 justify-end">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? 'Enrolling...' : 'Enroll Agent'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
