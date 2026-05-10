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
import { mockNetworkMetrics } from '@/lib/mock-data';
import { fmtNum } from '@/lib/format';

export const metadata = { title: 'Network' };

export default function Page() {
  const m = mockNetworkMetrics;
  return (
    <>
      <IntPageHead
        eyebrow="Intranet · network"
        title="Network operations"
        lede="Gateway, validators, mesh, replication."
      />
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KPI label="Validators" value={m.validatorCount} mock />
        <KPI label="Peers" value={m.peerCount} mock />
        <KPI label="Committed height" value={fmtNum(m.committedHeight)} mock />
        <KPI label="Mode" value={m.networkMode} mock />
      </div>
      <div className="grid md:grid-cols-2 gap-5 mt-6">
        <Card>
          <CardHeader title="Drilldowns" />
          <CardBody>
            <ul className="text-sm space-y-1.5">
              <li><Link href="/internal/nodes" className="underline">Node health</Link></li>
              <li><Link href="/internal/validators" className="underline">Validator registry</Link></li>
            </ul>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Recent block production" />
          <CardBody className="text-sm font-mono space-y-1">
            <div>height {fmtNum(m.committedHeight)}     · validator val-northwind-02</div>
            <div>height {fmtNum(m.committedHeight - 1)} · validator val-northwind-02</div>
            <div>height {fmtNum(m.committedHeight - 2)} · validator val-northwind-04</div>
            <div>height {fmtNum(m.committedHeight - 3)} · validator val-aperture-01</div>
          </CardBody>
        </Card>
      </div>
    </>
  );
}
