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

import { IntPageHead, StepUpRequired } from '@/components/content/IntPageHead';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { mockAuditEntries } from '@/lib/mock-data';
import { fmtDate } from '@/lib/format';
import type { AuditEntry } from '@/lib/types';

export const metadata = { title: 'Audit export queue' };

const cols: Column<AuditEntry>[] = [
  { key: 'id', header: 'Entry', render: (r) => <span className="font-mono text-xs">{r.id}</span> },
  { key: 'actorId', header: 'Actor', render: (r) => <span className="font-mono text-xs">{r.actorId}</span> },
  { key: 'scope', header: 'Scope' },
  { key: 'action', header: 'Action' },
  { key: 'target', header: 'Target', render: (r) => <span className="font-mono text-xs">{r.target}</span> },
  { key: 'outcome', header: 'Outcome' },
  { key: 'timestamp', header: 'When', render: (r) => <span className="font-mono text-xs">{fmtDate(r.timestamp)}</span> }
];

export default function Page() {
  return (
    <>
      <IntPageHead
        eyebrow="Intranet · audit"
        title="Audit export queue"
        lede="Pending packets, signing state, delivery state."
        pills={<StepUpRequired />}
      />
      <DataTable columns={cols} rows={mockAuditEntries} />
    </>
  );
}
