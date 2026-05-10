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

import { Section, Eyebrow, H1, H2, Lede } from '@/components/ui/Section';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { KPI } from '@/components/ui/KPI';
import { Pill } from '@/components/ui/Pill';
import { StatusPill } from '@/components/ui/StatusPill';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { mockIncidents, mockNetworkMetrics } from '@/lib/mock-data';
import { fmtDate } from '@/lib/format';
import type { Incident } from '@/lib/types';

export const metadata = { title: 'Status' };

const incidentCols: Column<Incident>[] = [
  { key: 'severity', header: 'Severity', render: (r) => <Pill tone={r.severity === 'sev1' ? 'alert' : r.severity === 'sev2' ? 'signal' : 'roadmap'}>{r.severity.toUpperCase()}</Pill> },
  { key: 'title', header: 'Incident' },
  { key: 'status', header: 'Status', render: (r) => <StatusPill status={r.status} /> },
  { key: 'startedAt', header: 'Started', render: (r) => <span className="font-mono text-xs">{fmtDate(r.startedAt)}</span> },
  { key: 'resolvedAt', header: 'Resolved', render: (r) => <span className="font-mono text-xs">{r.resolvedAt ? fmtDate(r.resolvedAt) : '—'}</span> }
];

export default function Page() {
  const m = mockNetworkMetrics;
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Status</Eyebrow>
        <H1 className="mt-3">EXOCHAIN public status.</H1>
        <Lede className="mt-5 max-w-prose">
          Network mode and recent incident history. Numeric metrics on this
          page are sourced from the gateway when available; until the live
          status feed is wired they are labeled <em>mock</em>.
        </Lede>
        <div className="mt-4 flex flex-wrap gap-2">
          <Pill tone="signal">alpha</Pill>
          <Pill tone="custody">network: {m.networkMode}</Pill>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Network</H2>
        <div className="mt-5 grid grid-cols-2 md:grid-cols-4 gap-3">
          <KPI label="Validators" value={m.validatorCount} mock />
          <KPI label="Peers" value={m.peerCount} mock />
          <KPI label="Committed height" value={m.committedHeight.toLocaleString()} mock />
          <KPI label={`Uptime · ${m.uptimeWindow}`} value={`${m.uptimePercent}%`} mock />
        </div>
        <p className="mt-4 text-xs text-ink/60 dark:text-vellum-soft/60">
          Last seen <span className="font-mono">{fmtDate(m.lastSeenISO)}</span>.
          Last release <span className="font-mono">{m.lastReleaseTag}</span>.
        </p>
      </Section>

      <Section className="py-8">
        <H2>Service health</H2>
        <div className="mt-5 grid md:grid-cols-3 gap-5">
          {[
            { name: 'Gateway · public', status: 'healthy' as const },
            { name: 'Node API · public', status: 'healthy' as const },
            { name: 'Public docs', status: 'healthy' as const }
          ].map((s) => (
            <Card key={s.name}>
              <CardHeader title={s.name} right={<StatusPill status={s.status} />} />
              <CardBody>
                <p className="text-sm">
                  Synthetic checks every 60s. <Pill tone="mock">mock</Pill>
                </p>
              </CardBody>
            </Card>
          ))}
        </div>
      </Section>

      <Section className="py-8">
        <H2>Recent incidents</H2>
        <div className="mt-5">
          <DataTable
            columns={incidentCols}
            rows={mockIncidents}
            empty="No incidents to report."
          />
        </div>
      </Section>
    </>
  );
}
