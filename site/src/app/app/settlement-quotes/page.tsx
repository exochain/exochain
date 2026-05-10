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
import { ZeroPriceBanner } from '@/components/ui/ZeroPriceBanner';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { Pill } from '@/components/ui/Pill';
import { mockSettlementQuotes } from '@/lib/mock-data';
import { fmtDate } from '@/lib/format';
import type { SettlementQuote } from '@/lib/types';

export const metadata = { title: 'Settlement quotes' };

const cols: Column<SettlementQuote>[] = [
  { key: 'id', header: 'Quote', render: (r) => <span className="font-mono text-xs">{r.id}</span> },
  { key: 'avcId', header: 'AVC', render: (r) => <span className="font-mono text-xs">{r.avcId}</span> },
  { key: 'amount', header: 'Amount', render: (r) => <span className="font-mono">{r.amount} {r.currency}</span> },
  { key: 'zeroFeeReason', header: 'ZeroFeeReason', render: (r) => <Pill tone="custody">{r.zeroFeeReason}</Pill> },
  { key: 'expiresAt', header: 'Expires', render: (r) => <span className="font-mono text-xs">{fmtDate(r.expiresAt)}</span> }
];

export default function Page() {
  return (
    <>
      <AppPageHead
        eyebrow="Extranet · settlement"
        title="Settlement quotes"
        lede="Quotes generated against trust receipts. Under the launch policy every quote returns 0 EXO."
      />
      <ZeroPriceBanner />
      <div className="mt-6">
        <DataTable columns={cols} rows={mockSettlementQuotes} />
      </div>
    </>
  );
}
