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

export const metadata = { title: 'Docs management' };

const DOCS = [
  '/docs/getting-started', '/docs/concepts', '/docs/avc',
  '/docs/trust-receipts', '/docs/settlement', '/docs/node-api',
  '/docs/validator-guide', '/docs/security', '/docs/governance',
  '/docs/glossary', '/docs/faq'
];

export default function Page() {
  return (
    <>
      <IntPageHead
        eyebrow="Intranet · docs"
        title="Documentation management"
        lede="Docs editor with publish workflow. Migrating to MDX in v0.5."
      />
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
        {DOCS.map(p => (
          <Card key={p}>
            <CardHeader title={<span className="font-mono">{p}</span>} right={<Pill tone="verify">published</Pill>} />
            <CardBody className="text-sm flex items-center gap-2">
              <button className="underline">Edit</button>
              <button className="underline">History</button>
            </CardBody>
          </Card>
        ))}
      </div>
    </>
  );
}
