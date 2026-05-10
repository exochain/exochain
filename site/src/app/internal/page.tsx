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

import Link from 'next/link';
import { IntPageHead } from '@/components/content/IntPageHead';
import { KPI } from '@/components/ui/KPI';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Pill } from '@/components/ui/Pill';
import { StatusPill } from '@/components/ui/StatusPill';
import { mockIncidents, mockNetworkMetrics, mockProposals } from '@/lib/mock-data';
import { fmtDate } from '@/lib/format';

export const metadata = { title: 'Operations' };

export default function Page() {
  const m = mockNetworkMetrics;
  const open = mockIncidents.filter(i => i.status !== 'resolved');
  return (
    <div className="space-y-8">
      <IntPageHead
        eyebrow="Intranet · operations"
        title="EXOCHAIN operations"
        lede="Network, incidents, governance, and pricing-policy summary."
        pills={
          <>
            <Pill tone="alert">redaction-on by default</Pill>
            <Pill tone="custody">launch_policy_zero · all active prices = 0</Pill>
          </>
        }
      />
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KPI label="Validators" value={m.validatorCount} mock />
        <KPI label="Peers" value={m.peerCount} mock />
        <KPI label="Open incidents" value={open.length} mock />
        <KPI label="Open proposals" value={mockProposals.filter(p => p.status === 'open').length} mock />
      </div>

      <div className="grid lg:grid-cols-2 gap-5">
        <Card>
          <CardHeader title="Open incidents" right={<Link href="/internal/incidents" className="text-xs underline">All incidents</Link>} />
          <CardBody>
            <ul className="text-sm divide-y hairline">
              {open.length === 0 ? <li className="py-3 text-ink/60">None.</li> : open.map(i => (
                <li key={i.id} className="py-3 flex items-start justify-between gap-3">
                  <div>
                    <div className="font-mono text-xs">{i.id}</div>
                    <div>{i.title}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Pill tone={i.severity === 'sev1' ? 'alert' : i.severity === 'sev2' ? 'signal' : 'roadmap'}>{i.severity.toUpperCase()}</Pill>
                    <StatusPill status={i.status} />
                  </div>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Governance proposals" right={<Link href="/internal/governance" className="text-xs underline">All</Link>} />
          <CardBody>
            <ul className="text-sm divide-y hairline">
              {mockProposals.map(p => (
                <li key={p.id} className="py-3 flex items-center justify-between gap-3">
                  <div>
                    <div className="font-mono text-xs">{p.id}</div>
                    <div>{p.title}</div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono">{p.quorum.obtained}/{p.quorum.needed} quorum</span>
                    <StatusPill status={p.status} />
                  </div>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader title="Pricing policy summary" right={<Link href="/internal/pricing-policy" className="text-xs underline">Manage</Link>} />
        <CardBody className="text-sm">
          Active pricing: every fee = <span className="font-mono">0 EXO</span> with{' '}
          <span className="font-mono">ZeroFeeReason: launch_policy_zero</span>.{' '}
          Last reviewed <span className="font-mono">{fmtDate('2026-04-30T10:00:00Z')}</span>.
        </CardBody>
      </Card>
    </div>
  );
}
