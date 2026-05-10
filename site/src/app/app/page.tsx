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
import { Eyebrow, H1, Lede, H2 } from '@/components/ui/Section';
import { KPI } from '@/components/ui/KPI';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { ZeroPriceBanner } from '@/components/ui/ZeroPriceBanner';
import { mockAVCs, mockActors, mockTrustReceipts, mockSettlementQuotes } from '@/lib/mock-data';
import { fmtDate } from '@/lib/format';
import { StatusPill } from '@/components/ui/StatusPill';

export const metadata = { title: 'Dashboard' };

export default function Page() {
  const activeAVCs = mockAVCs.filter((a) => a.status === 'active').length;
  const recentReceipts = mockTrustReceipts.slice(-3).reverse();
  return (
    <div className="space-y-8">
      <div>
        <Eyebrow>Extranet · dashboard</Eyebrow>
        <H1 className="mt-3 text-3xl">Aperture Holdings</H1>
        <Lede className="mt-2">All counts below come from the extranet mock dataset for v0.</Lede>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KPI label="Active AVCs" value={activeAVCs} mock />
        <KPI label="Active actors" value={mockActors.length} mock />
        <KPI label="Recent trust receipts" value={mockTrustReceipts.length} mock />
        <KPI label="Settlement quotes (zero)" value={mockSettlementQuotes.length} mock />
      </div>
      <ZeroPriceBanner />
      <div className="grid lg:grid-cols-2 gap-5">
        <Card>
          <CardHeader title="Recent activity" right={<Link href="/app/trust-receipts" className="text-xs underline">View all</Link>} />
          <CardBody>
            <ul className="text-sm divide-y hairline">
              {recentReceipts.map((r) => (
                <li key={r.id} className="py-3 flex items-center justify-between gap-3">
                  <div>
                    <div className="font-mono text-xs">{r.id}</div>
                    <div>{r.actionDescriptor}</div>
                  </div>
                  <div className="flex items-center gap-3">
                    <StatusPill status={r.outcome} />
                    <span className="font-mono text-xs">{fmtDate(r.timestamp)}</span>
                  </div>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Things to do" />
          <CardBody>
            <ul className="text-sm space-y-2">
              <li><Link href="/app/avcs/issue" className="underline">Issue an AVC</Link></li>
              <li><Link href="/app/avcs/validate" className="underline">Validate an AVC</Link></li>
              <li><Link href="/app/api-keys" className="underline">Create an API key</Link></li>
              <li><Link href="/app/audit-exports" className="underline">Request an audit export</Link></li>
              <li><Link href="/app/security-requests" className="underline">Submit a security report</Link></li>
            </ul>
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
