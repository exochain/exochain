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
import { Card, CardBody, CardHeader } from '@/components/ui/Card';

export const metadata = { title: 'Releases' };

const REL = [
  { tag: 'v0.4.2-alpha', date: '2026-04-30', notes: 'Hardened settlement-quote idempotency. Validator gossip backpressure improvements.' },
  { tag: 'v0.4.1-alpha', date: '2026-04-12', notes: 'AVC delegation scope-narrowing tighten-up. Threat model entry T-013 mitigated.' }
];

export default function Page() {
  return (
    <>
      <IntPageHead
        eyebrow="Intranet · releases"
        title="Release notes"
        lede="Editor and publish workflow for release notes."
      />
      <div className="grid md:grid-cols-2 gap-5">
        {REL.map(r => (
          <Card key={r.tag}>
            <CardHeader eyebrow={r.date} title={r.tag} />
            <CardBody className="text-sm">{r.notes}</CardBody>
          </Card>
        ))}
      </div>
    </>
  );
}
