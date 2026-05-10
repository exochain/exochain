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

import { Section, Eyebrow, H1, H2, Lede } from '@/components/ui/Section';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Pill } from '@/components/ui/Pill';

export const metadata = { title: 'Research' };

const PAPERS = [
  {
    title: 'Chain-of-custody as a First-Class Protocol Property',
    abstract:
      'We argue that chain-of-custody, not value transfer, is the property a custody-native blockchain should be optimized for. We formalize the credential→action→receipt model and show how it composes across delegation hierarchies.',
    status: 'draft'
  },
  {
    title: 'Autonomous Volition Credentials: Operational Intent in Bounded Form',
    abstract:
      'A schema and validation model for credentials that declare, before action, what an autonomous actor may pursue. We examine fail-closed validation, scope narrowing, and revocation cascades.',
    status: 'draft'
  },
  {
    title: 'Zero-Priced Launch Settlement: Mechanism Without Speculation',
    abstract:
      'A treatment of an economic layer that ships the full settlement mechanism while suppressing pricing by policy. We compare the approach to subsidy and humanitarian carve-out paradigms.',
    status: 'draft'
  },
  {
    title: 'Holons in a Custody Fabric',
    abstract:
      'Cross-jurisdictional custody attestation with composite actors. We sketch how holons participate in EXOCHAIN without dissolving the agency of their members.',
    status: 'in progress'
  }
];

export default function Page() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Research</Eyebrow>
        <H1 className="mt-3">Whitepapers and technical notes.</H1>
        <Lede className="mt-5 max-w-prose">
          Working drafts and finalized notes from EXOCHAIN protocol,
          governance, and agent-economy research streams.
        </Lede>
      </Section>
      <Section className="py-6">
        <div className="grid md:grid-cols-2 gap-5">
          {PAPERS.map((p) => (
            <Card key={p.title}>
              <CardHeader
                title={p.title}
                right={<Pill tone="roadmap">{p.status}</Pill>}
              />
              <CardBody>
                <p className="text-sm">{p.abstract}</p>
              </CardBody>
            </Card>
          ))}
        </div>
      </Section>
    </>
  );
}
