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
import { DataTable, type Column } from '@/components/ui/DataTable';
import { StatusPill } from '@/components/ui/StatusPill';
import { Pill } from '@/components/ui/Pill';
import { mockNodes } from '@/lib/mock-data';
import { fmtNum } from '@/lib/format';
import type { NodeRecord } from '@/lib/types';

export const metadata = { title: 'Nodes' };

const cols: Column<NodeRecord>[] = [
  { key: 'id', header: 'Node', render: (r) => <span className="font-mono text-xs">{r.id}</span> },
  { key: 'kind', header: 'Kind', render: (r) => <Pill tone="custody">{r.kind}</Pill> },
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
        title="Nodes"
        lede="Node operator surface. Validators have additional onboarding."
        pills={<Pill tone="mock">mock telemetry</Pill>}
      />
      <DataTable columns={cols} rows={mockNodes.filter(n => n.kind === 'node')} />
    </>
  );
}
