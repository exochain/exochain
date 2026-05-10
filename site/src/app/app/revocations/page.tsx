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

import { AppPageHead, AuditNote } from '@/components/content/AppPageHead';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { Pill } from '@/components/ui/Pill';
import { mockRevocations } from '@/lib/mock-data';
import { fmtDate } from '@/lib/format';
import type { Revocation } from '@/lib/types';

export const metadata = { title: 'Revocations' };

const cols: Column<Revocation>[] = [
  { key: 'id', header: 'Revocation', render: (r) => <span className="font-mono text-xs">{r.id}</span> },
  { key: 'avcId', header: 'AVC', render: (r) => <span className="font-mono text-xs">{r.avcId}</span> },
  { key: 'cause', header: 'Cause', render: (r) => <Pill tone="signal">{r.cause}</Pill> },
  { key: 'initiatorActorId', header: 'Initiated by', render: (r) => <span className="font-mono text-xs">{r.initiatorActorId}</span> },
  { key: 'cascade', header: 'Cascade', render: (r) => <span className="font-mono text-xs">{r.cascade.length} child(ren)</span> },
  { key: 'timestamp', header: 'When', render: (r) => <span className="font-mono text-xs">{fmtDate(r.timestamp)}</span> }
];

export default function Page() {
  return (
    <>
      <AppPageHead
        eyebrow="Extranet · revocations"
        title="Revocations"
        lede="Each revocation cascades through the credential graph. Step-up auth required to commit a revocation in v0.5+."
      />
      <DataTable columns={cols} rows={mockRevocations} empty="No revocations recorded." />
      <AuditNote>Submitting a revocation writes to the audit log and broadcasts a revocation event.</AuditNote>
    </>
  );
}
