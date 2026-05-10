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

/* ── Mock data ── */
const MOCK_METRICS = {
  identities: 1_247,
  scans: 3_891,
  consents: 8_432,
  receipts: 24_106,
}

const MOCK_HEARTBEAT = '2026-03-15T14:32:09Z'
const MOCK_GATEWAY_URL = 'https://exo-gateway.livesafe.ai:8080'

interface IntegrationPoint {
  name: string
  description: string
  status: 'connected' | 'pending' | 'degraded'
  lastEvent: string
  eventCount: number
}

const INTEGRATION_POINTS: IntegrationPoint[] = [
  {
    name: 'Identity / DID',
    description: 'Patient DID anchoring to EXOCHAIN custody spine. Verifiable credentials issuance and revocation.',
    status: 'connected',
    lastEvent: '2026-03-15T14:31:44Z',
    eventCount: 1_247,
  },
  {
    name: 'PACE / VSS',
    description: 'Trustee key sharding ceremonies via Shamir Secret Sharing. 3-of-4 threshold reconstruction.',
    status: 'connected',
    lastEvent: '2026-03-15T14:28:12Z',
    eventCount: 312,
  },
  {
    name: 'Audit Trail',
    description: 'SHA256-chained audit receipts anchored to EXOCHAIN DAG. Tamper-evident event logging.',
    status: 'connected',
    lastEvent: '2026-03-15T14:32:01Z',
    eventCount: 24_106,
  },
  {
    name: 'Emergency Scan',
    description: 'QR/NFC emergency card scanning with consent-gated provider access to patient records.',
    status: 'connected',
    lastEvent: '2026-03-15T13:47:33Z',
    eventCount: 3_891,
  },
  {
    name: 'Provider Consent',
    description: 'Granular consent management for provider access. Time-bounded, scope-limited authorization.',
    status: 'pending',
    lastEvent: '2026-03-15T12:15:09Z',
    eventCount: 8_432,
  },
]

const IDENTITY_DIMENSIONS = [
  { name: 'Biometric', value: 92, color: 'bg-blue-500' },
  { name: 'Behavioral', value: 78, color: 'bg-emerald-500' },
  { name: 'Credential', value: 95, color: 'bg-violet-500' },
  { name: 'Social', value: 64, color: 'bg-amber-500' },
  { name: 'Temporal', value: 88, color: 'bg-rose-500' },
  { name: 'Contextual', value: 71, color: 'bg-cyan-500' },
]

const TRUSTEES = [
  { label: 'Trustee A', shard: 'S1' },
  { label: 'Trustee B', shard: 'S2' },
  { label: 'Trustee C', shard: 'S3' },
  { label: 'Trustee D', shard: 'S4' },
]

/* ── Status helpers ── */
function StatusDot({ status }: { status: 'connected' | 'pending' | 'degraded' }) {
  return (
    <span
      className={cn(
        'inline-block w-2.5 h-2.5 rounded-full flex-shrink-0',
        status === 'connected' && 'bg-green-500',
        status === 'pending' && 'bg-amber-500',
        status === 'degraded' && 'bg-red-500',
      )}
      aria-label={`Status: ${status}`}
    />
  )
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/* ── Stat card ── */
function MetricCard({
  label,
  count,
  accent,
  icon,
}: {
  label: string
  count: number
  accent: string
  icon: string
}) {
  return (
    <div className="border border-border-subtle rounded-lg bg-surface-raised p-4 text-center">
      <div className="flex items-center justify-center mb-2">
        <svg className={cn('w-5 h-5', accent)} fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
        </svg>
      </div>
      <p className={cn('text-2xl font-bold', accent)}>{count.toLocaleString()}</p>
      <p className="text-sm text-text-gov-secondary mt-0.5">{label}</p>
    </div>
  )
}

/* ── Integration point card ── */
function IntegrationCard({ point }: { point: IntegrationPoint }) {
  return (
    <div className="border border-border-subtle rounded-lg bg-surface-raised p-4">
      <div className="flex items-center gap-2 mb-2">
        <StatusDot status={point.status} />
        <h3 className="text-sm font-semibold text-text-gov-primary">{point.name}</h3>
        <span className={cn(
          'ml-auto text-2xs font-medium uppercase tracking-wide px-2 py-0.5 rounded-full',
          point.status === 'connected' && 'bg-green-100 text-green-800',
          point.status === 'pending' && 'bg-amber-100 text-amber-800',
          point.status === 'degraded' && 'bg-red-100 text-red-800',
        )}>
          {point.status}
        </span>
      </div>
      <p className="text-xs text-text-gov-secondary mb-3">{point.description}</p>
      <div className="flex items-center justify-between text-xs text-text-gov-secondary">
        <span>Last event: {formatTimestamp(point.lastEvent)}</span>
        <span className="font-medium text-text-gov-primary">{point.eventCount.toLocaleString()} events</span>
      </div>
    </div>
  )
}

/* ── Main page ── */
export function LiveSafePage() {
  return (
    <div className="space-y-8">
      {/* ── Header ── */}
      <header className="flex items-center gap-3">
        <StatusDot status="connected" />
        <div>
          <h1 className="text-2xl font-bold text-text-gov-primary">LiveSafe.ai Integration</h1>
          <p className="text-sm text-text-gov-secondary mt-0.5">
            Patient-sovereign health identity system — EXOCHAIN integration status
          </p>
        </div>
      </header>

      {/* ── Connection Status ── */}
      <section aria-label="Connection status">
        <div className="border border-border-subtle rounded-lg bg-surface-raised p-4">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-text-gov-secondary mb-3">
            Connection Status
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <p className="text-xs text-text-gov-secondary">Status</p>
              <p className="flex items-center gap-2 text-sm font-medium text-text-gov-primary mt-0.5">
                <StatusDot status="connected" />
                Connected
              </p>
            </div>
            <div>
              <p className="text-xs text-text-gov-secondary">Gateway URL</p>
              <p className="text-sm font-mono text-text-gov-primary mt-0.5 truncate">{MOCK_GATEWAY_URL}</p>
            </div>
            <div>
              <p className="text-xs text-text-gov-secondary">Last Heartbeat</p>
              <p className="text-sm font-medium text-text-gov-primary mt-0.5">{formatTimestamp(MOCK_HEARTBEAT)}</p>
            </div>
          </div>
        </div>
      </section>

      {/* ── Integration Metrics ── */}
      <section aria-label="Integration metrics">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-text-gov-secondary mb-3">
          Integration Metrics
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <MetricCard
            label="Identities Anchored"
            count={MOCK_METRICS.identities}
            accent="text-blue-600"
            icon="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"
          />
          <MetricCard
            label="Scans Anchored"
            count={MOCK_METRICS.scans}
            accent="text-emerald-600"
            icon="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"
          />
          <MetricCard
            label="Consents Anchored"
            count={MOCK_METRICS.consents}
            accent="text-violet-600"
            icon="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
          />
          <MetricCard
            label="Audit Receipts"
            count={MOCK_METRICS.receipts}
            accent="text-amber-600"
            icon="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
          />
        </div>
      </section>

      {/* ── Integration Points ── */}
      <section aria-label="Integration points">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-text-gov-secondary mb-3">
          Integration Points
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {INTEGRATION_POINTS.map((point) => (
            <IntegrationCard key={point.name} point={point} />
          ))}
        </div>
      </section>

      {/* ── 0dentity Scoring ── */}
      <section aria-label="0dentity scoring system">
        <div className="border border-border-subtle rounded-lg bg-surface-raised p-5">
          <h2 className="text-sm font-semibold text-text-gov-primary mb-1">
            0dentity&#8482; Scoring System
          </h2>
          <p className="text-xs text-text-gov-secondary mb-4">
            Six-dimensional identity confidence scoring. Each dimension is independently assessed
            and combined into a composite trust vector anchored to the EXOCHAIN identity graph.
          </p>
          <div className="space-y-2">
            {IDENTITY_DIMENSIONS.map((dim) => (
              <div key={dim.name} className="flex items-center gap-3">
                <span className="text-xs font-medium text-text-gov-secondary w-20 text-right flex-shrink-0">
                  {dim.name}
                </span>
                <div className="flex-1 h-4 bg-surface-overlay rounded-full overflow-hidden">
                  <div
                    className={cn('h-full rounded-full transition-all', dim.color)}
                    style={{ width: `${dim.value}%` }}
                  />
                </div>
                <span className="text-xs font-bold text-text-gov-primary w-8">{dim.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── PACE Architecture ── */}
      <section aria-label="PACE trust network">
        <div className="border border-border-subtle rounded-lg bg-surface-raised p-5">
          <h2 className="text-sm font-semibold text-text-gov-primary mb-1">
            PACE Trust Network
          </h2>
          <p className="text-xs text-text-gov-secondary mb-4">
            1:4 trustee key sharding model using Shamir&apos;s Secret Sharing.
            Any 3-of-4 trustees can reconstruct the patient&apos;s custody key.
          </p>
          <div className="flex flex-col items-center gap-3">
            {/* Subscriber */}
            <div className="border border-blue-300 bg-blue-50 rounded-lg px-4 py-2 text-center">
              <p className="text-xs font-semibold text-blue-800">Subscriber</p>
              <p className="text-2xs text-blue-600">Master Key (K)</p>
            </div>
            {/* Arrow down */}
            <div className="text-text-gov-secondary text-sm">
              <span aria-hidden="true">Shamir SSS (3-of-4 threshold)</span>
            </div>
            {/* Trustees */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 w-full max-w-lg">
              {TRUSTEES.map((t) => (
                <div
                  key={t.label}
                  className="border border-emerald-300 bg-emerald-50 rounded-lg px-3 py-2 text-center"
                >
                  <p className="text-xs font-semibold text-emerald-800">{t.label}</p>
                  <p className="text-2xs text-emerald-600 font-mono">{t.shard}</p>
                </div>
              ))}
            </div>
            <p className="text-2xs text-text-gov-secondary text-center max-w-md">
              Each trustee holds one shard. Reconstruction requires 3 of 4 shards.
              No single trustee can access the patient&apos;s identity independently.
            </p>
          </div>
        </div>
      </section>

      {/* ── System Architecture ── */}
      <section aria-label="System architecture">
        <div className="border border-border-subtle rounded-lg bg-surface-raised p-5">
          <h2 className="text-sm font-semibold text-text-gov-primary mb-3">
            System Architecture
          </h2>
          <div className="font-mono text-xs text-text-gov-secondary space-y-1 bg-surface-overlay rounded-lg p-4">
            <div className="text-blue-600 font-semibold">LiveSafe.ai (Patient Sovereignty)</div>
            <div className="pl-4 text-text-gov-secondary">&#x2193; GraphQL</div>
            <div className="pl-4 text-emerald-600 font-semibold">EXOCHAIN Gateway (exo-gateway :8080)</div>
            <div className="pl-8 text-text-gov-secondary">&#x2193;</div>
            <div className="pl-8 text-violet-600 font-semibold">decision.forum Protocol Layer</div>
            <div className="pl-12 text-text-gov-secondary">&#x2193;</div>
            <div className="pl-12 text-amber-600 font-semibold">EXOCHAIN Custody Spine (DAG + BFT + Identity)</div>
          </div>
        </div>
      </section>
    </div>
  )
}
