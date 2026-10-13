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

import Link from 'next/link';
import { Section, Eyebrow, H1, H2, Lede } from '@/components/ui/Section';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { PilotBanner } from '@/components/commercial/PilotBanner';
import { publicMetadata } from '@/lib/public-site';

export const metadata = publicMetadata({
  title: 'Standards',
  description:
    'EXOCHAIN interoperates with MCP, A2A, x402, and AP2. Payment authorization is not legitimate decision-making authority.',
  path: '/standards',
});

const STANDARDS = [
  {
    name: 'MCP',
    does: 'Standardizes how AI systems connect to tools and resources.',
    leaves: 'A tool call can succeed without a portable proof that the caller was entitled to make that decision.',
  },
  {
    name: 'A2A',
    does: 'Lets agents collaborate across systems.',
    leaves: 'Collaboration still needs a way for each side to verify the other’s delegated authority.',
  },
  {
    name: 'x402',
    does: 'Makes machine-native payments possible.',
    leaves: 'A payment rail does not decide whether the purchase itself was a legitimate exercise of authority.',
  },
  {
    name: 'AP2',
    does: 'Uses signed mandates and receipts for agent-initiated payments.',
    leaves: 'A mandate to spend is not the same record as vendor selection, evidence, conflicts, constraints, and revocation.',
  },
];

export default function StandardsPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Interoperability</Eyebrow>
        <H1 className="mt-3">Do not compete with the standards. Make them accountable.</H1>
        <Lede className="mt-5 max-w-prose">
          MCP, A2A, x402, and AP2 already describe connection, collaboration,
          and payment. EXOCHAIN’s place is the layer they do not replace:
          legitimate decision-making authority that an independent counterparty
          can verify.
        </Lede>
        <p className="mt-4 max-w-prose text-base text-brand-midnight/80">
          Payment authorization is not legitimate decision-making authority.
        </p>
      </Section>
      <Section className="py-8">
        <div className="grid md:grid-cols-2 gap-4">
          {STANDARDS.map((item) => (
            <Card key={item.name}>
              <CardHeader title={item.name} />
              <CardBody>
                <p className="text-sm">{item.does}</p>
                <p className="mt-3 text-sm text-brand-midnight/75">{item.leaves}</p>
              </CardBody>
            </Card>
          ))}
        </div>
      </Section>
      <Section className="py-8">
        <H2>The question a counterparty still has</H2>
        <Lede className="mt-4 max-w-prose">
          An agent may be authorized to spend. That does not answer whether it
          had authority to select the vendor, which evidence supported the
          decision, whether conflicts were disclosed, whether the delegation
          was still valid, or whether applicable constraints were satisfied.
          The counterparty should be able to check that chain without access
          to the issuer’s internal systems.
        </Lede>
        <p className="mt-6 text-sm">
          <Link href="/proof-of-authority" className="underline">
            Proof of Authority
          </Link>
          {' · '}
          <Link href="/lynk" className="underline">
            LYNK for receipted MCP tool use
          </Link>
        </p>
      </Section>
      <PilotBanner />
    </>
  );
}
