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

import { IntPageHead, QuorumRequired } from '@/components/content/IntPageHead';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { StatusPill } from '@/components/ui/StatusPill';
import { mockProposals } from '@/lib/mock-data';
import { fmtDate } from '@/lib/format';
import type { Proposal } from '@/lib/types';

export const metadata = { title: 'Governance' };

const cols: Column<Proposal>[] = [
  { key: 'id', header: 'Proposal', render: (r) => <span className="font-mono text-xs">{r.id}</span> },
  { key: 'title', header: 'Title' },
  { key: 'status', header: 'Status', render: (r) => <StatusPill status={r.status} /> },
  { key: 'quorum', header: 'Quorum', render: (r) => <span className="font-mono text-xs">{r.quorum.obtained}/{r.quorum.needed}</span> },
  { key: 'openedAt', header: 'Opened', render: (r) => <span className="font-mono text-xs">{fmtDate(r.openedAt)}</span> }
];

export default function Page() {
  return (
    <>
      <IntPageHead
        eyebrow="Intranet · governance"
        title="Governance controls"
        lede="Open proposals, quorum status, ratification."
        pills={<QuorumRequired />}
      />
      <DataTable columns={cols} rows={mockProposals} />
    </>
  );
}
