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
import { mockTrustReceipts } from '@/lib/mock-data';
import { fmtDate, shorten } from '@/lib/format';
import type { TrustReceipt } from '@/lib/types';

export const metadata = { title: 'Trust Receipts' };

const cols: Column<TrustReceipt>[] = [
  { key: 'id', header: 'Receipt', render: (r) => <span className="font-mono text-xs">{r.id}</span> },
  { key: 'avcId', header: 'AVC', render: (r) => <span className="font-mono text-xs">{r.avcId}</span> },
  { key: 'actorId', header: 'Actor', render: (r) => <span className="font-mono text-xs">{r.actorId}</span> },
  { key: 'actionDescriptor', header: 'Action' },
  { key: 'outcome', header: 'Outcome', render: (r) => <StatusPill status={r.outcome} /> },
  { key: 'custodyHash', header: 'Custody', render: (r) => <span className="font-mono text-xs">{shorten(r.custodyHash, 14)}</span> },
  { key: 'prevHash', header: 'Prev', render: (r) => <span className="font-mono text-xs">{shorten(r.prevHash, 14)}</span> },
  { key: 'timestamp', header: 'When', render: (r) => <span className="font-mono text-xs">{fmtDate(r.timestamp)}</span> }
];

export default function Page() {
  return (
    <>
      <AppPageHead
        eyebrow="Extranet · trust receipts"
        title="Trust receipts"
        lede="Hash-chained, signed records of authorized actions. Drill into a receipt for its full custody trail."
      />
      <DataTable columns={cols} rows={mockTrustReceipts} />
    </>
  );
}
