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

import { AppPageHead } from '@/components/content/AppPageHead';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Pill } from '@/components/ui/Pill';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { StatusPill } from '@/components/ui/StatusPill';
import { mockNodes } from '@/lib/mock-data';
import { fmtNum } from '@/lib/format';
import type { NodeRecord } from '@/lib/types';

export const metadata = { title: 'Validators' };

const cols: Column<NodeRecord>[] = [
  { key: 'id', header: 'Validator', render: (r) => <span className="font-mono text-xs">{r.id}</span> },
  { key: 'endpoint', header: 'Endpoint', render: (r) => <span className="font-mono text-xs">{r.endpoint}</span> },
  { key: 'version', header: 'Version', render: (r) => <span className="font-mono text-xs">{r.version}</span> },
  { key: 'region', header: 'Region' },
  { key: 'status', header: 'Status', render: (r) => <StatusPill status={r.status} /> },
  { key: 'lastHeight', header: 'Last height', render: (r) => <span className="font-mono text-xs">{r.lastHeight ? fmtNum(r.lastHeight) : '—'}</span> }
];

export default function Page() {
  return (
    <>
      <AppPageHead
        eyebrow="Extranet · operate"
        title="Validators"
        lede="Hardware attestation, key registration, observation period, and ongoing validator telemetry."
        pills={<Pill tone="mock">mock telemetry</Pill>}
      />
      <div className="grid lg:grid-cols-[1fr_1.4fr] gap-6">
        <Card>
          <CardHeader title="Onboard a validator" />
          <CardBody className="text-sm space-y-3">
            <ol className="list-decimal pl-5 space-y-1.5">
              <li>Upload hardware attestation evidence.</li>
              <li>Register signing key (HSM strongly recommended).</li>
              <li>Begin observation period.</li>
              <li>Apply for quorum membership.</li>
            </ol>
            <button className="border hairline rounded-sm px-3 py-2 bg-ink text-vellum-soft">
              Begin onboarding (placeholder)
            </button>
          </CardBody>
        </Card>
        <DataTable columns={cols} rows={mockNodes.filter(n => n.kind === 'validator')} />
      </div>
    </>
  );
}
