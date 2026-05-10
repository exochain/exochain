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
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Pill } from '@/components/ui/Pill';

export const metadata = { title: 'API keys' };

const KEYS = [
  { id: 'k_001', label: 'CI · production', created: '2026-01-12', lastUsed: '2026-05-03', scopes: ['avc.read', 'receipts.read'] },
  { id: 'k_002', label: 'Procurement agent', created: '2026-02-12', lastUsed: '2026-05-04', scopes: ['avc.issue', 'receipts.write'] }
];

export default function Page() {
  return (
    <>
      <AppPageHead
        eyebrow="Extranet · keys"
        title="API keys"
        lede="Per-key scopes. Keys are shown once at creation. Rotate regularly."
      />
      <div className="grid md:grid-cols-2 gap-5">
        {KEYS.map((k) => (
          <Card key={k.id}>
            <CardHeader title={k.label} right={<span className="font-mono text-xs">{k.id}</span>} />
            <CardBody>
              <div className="text-xs text-ink/60 dark:text-vellum-soft/60">created {k.created} · last used {k.lastUsed}</div>
              <div className="mt-2 flex flex-wrap gap-1">
                {k.scopes.map(s => <Pill key={s} tone="neutral">{s}</Pill>)}
              </div>
              <div className="mt-3 flex gap-2 text-xs">
                <button className="underline">Rotate</button>
                <button className="underline text-alert-deep dark:text-alert-soft">Revoke</button>
              </div>
            </CardBody>
          </Card>
        ))}
      </div>
      <AuditNote>Creating, rotating, or revoking a key writes to the audit log.</AuditNote>
    </>
  );
}
