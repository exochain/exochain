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

import { IntPageHead } from '@/components/content/IntPageHead';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { Pill } from '@/components/ui/Pill';
import { StatusPill } from '@/components/ui/StatusPill';
import { mockActors } from '@/lib/mock-data';
import { fmtDate } from '@/lib/format';
import type { Actor } from '@/lib/types';

export const metadata = { title: 'Actor registry' };

const cols: Column<Actor>[] = [
  { key: 'id', header: 'Actor', render: (r) => <span className="font-mono text-xs">{r.id}</span> },
  { key: 'type', header: 'Type', render: (r) => <Pill tone="custody">{r.type}</Pill> },
  { key: 'displayName', header: 'Display name' },
  { key: 'organization', header: 'Org' },
  { key: 'createdAt', header: 'Registered', render: (r) => <span className="font-mono text-xs">{fmtDate(r.createdAt)}</span> },
  { key: 'status', header: 'Status', render: (r) => <StatusPill status={r.status} /> }
];

export default function Page() {
  return (
    <>
      <IntPageHead
        eyebrow="Intranet · actors"
        title="Actor registry"
        lede="Read-only with quarantine action. Quarantine cascades through derivative AVCs."
        pills={<Pill tone="alert">quarantine writes audit + step-up</Pill>}
      />
      <DataTable columns={cols} rows={mockActors} />
    </>
  );
}
