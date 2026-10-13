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
import { Card, CardBody } from '@/components/ui/Card';
import { PilotBanner } from '@/components/commercial/PilotBanner';
import { publicMetadata } from '@/lib/public-site';

export const metadata = publicMetadata({
  title: 'The problem',
  description:
    'Autonomous agents need to prove authority, carry obligations, and produce evidence across organizational boundaries. Identity, permissions, and logs were not built for that.',
  path: '/why',
});

const ROWS = [
  {
    assumption: 'Identity establishes who you are',
    replacement: 'Cryptographic identity establishes who or what is acting',
  },
  {
    assumption: 'Permissions establish what you can access',
    replacement: 'Delegated authority establishes what an actor is entitled to decide and do',
  },
  {
    assumption: 'Applications own their workflows',
    replacement: 'Independent agents coordinate across organizational boundaries',
  },
  {
    assumption: 'Contracts define relationships',
    replacement: 'Machine-verifiable agreements and obligations govern interactions',
  },
  {
    assumption: 'Logs establish accountability',
    replacement: 'Verifiable receipts connect authority, evidence, decisions, and outcomes',
  },
  {
    assumption: 'Humans are the only economic actors',
    replacement: 'Humans and authorized AI agents both participate in economic activity',
  },
  {
    assumption: 'Governance is internal overhead',
    replacement: 'Governance becomes shared, reusable economic infrastructure',
  },
];

export default function WhyPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>The problem</Eyebrow>
        <H1 className="mt-3">The missing layer is legitimate authority.</H1>
        <Lede className="mt-5 max-w-prose">
          Today’s systems establish trust, authority, and accountability inside
          each organization and each application. An autonomous agent that
          deals with an agent from another organization cannot inherit that
          private context.
        </Lede>
      </Section>
      <Section className="py-8">
        <H2>What has to travel with the action</H2>
        <Lede className="mt-4 max-w-prose">
          The agent needs to prove its authority, negotiate obligations, execute
          within constraints, and produce evidence of what occurred. Improving
          identity, access control, or logging one at a time does not create
          that portable record.
        </Lede>
        <div className="mt-8 space-y-3">
          {ROWS.map((row) => (
            <Card key={row.assumption}>
              <CardBody>
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs uppercase tracking-eyebrow text-brand-cerulean">
                      Existing assumption
                    </p>
                    <p className="mt-2 text-sm">{row.assumption}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-eyebrow text-brand-cerulean">
                      What autonomous commerce needs
                    </p>
                    <p className="mt-2 text-sm">{row.replacement}</p>
                  </div>
                </div>
              </CardBody>
            </Card>
          ))}
        </div>
      </Section>
      <Section className="py-8">
        <H2>Where a payment mandate stops</H2>
        <Lede className="mt-4 max-w-prose">
          Payment authorization is not legitimate decision-making authority. An
          agent may be allowed to spend a budget and still lack authority to
          select a vendor, a record of the evidence, disclosure of conflicts,
          a check that the delegation is still valid, or a way for an outside
          party to verify that chain without entering the organization’s
          systems.
        </Lede>
        <p className="mt-6 text-sm">
          <Link href="/proof-of-authority" className="underline">
            Proof of Authority
          </Link>
          {' · '}
          <Link href="/standards" className="underline">
            Standards
          </Link>
        </p>
      </Section>
      <PilotBanner />
    </>
  );
}
