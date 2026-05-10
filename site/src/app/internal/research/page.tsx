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
import { Pill } from '@/components/ui/Pill';

export const metadata = { title: 'Research library' };

const DRAFTS = [
  { title: 'AVC Schema v1 — Final Review', state: 'review' },
  { title: 'Custody-Native Blockchain — Tutorial Companion Paper', state: 'draft' },
  { title: 'Holon Composition Rules', state: 'draft' }
];

export default function Page() {
  return (
    <>
      <IntPageHead
        eyebrow="Intranet · research"
        title="Research library"
        lede="Internal-only drafts. Approval workflow gates public publish."
      />
      <div className="grid md:grid-cols-2 gap-5">
        {DRAFTS.map(d => (
          <Card key={d.title}>
            <CardHeader title={d.title} right={<Pill tone="roadmap">{d.state}</Pill>} />
            <CardBody className="text-sm flex items-center gap-2">
              <button className="underline">Open</button>
              <button className="underline">Request review</button>
            </CardBody>
          </Card>
        ))}
      </div>
    </>
  );
}
