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
    'How A2A, MCP, x402 / HTTP 402, and AP2 complement EXOCHAIN authority, bailment, execution evidence, and payment-provider settlement in accountable autonomous commerce.',
  path: '/standards',
});

const STANDARDS = [
  {
    name: 'MCP',
    does: 'Connects AI applications to tools, resources, and prompts through a common protocol.',
    leaves: 'A deployment must bind tool use to scoped authority, active consent, and execution evidence. A successful MCP call alone does not establish that the business decision was authorized.',
    href: 'https://modelcontextprotocol.io/docs/getting-started/intro',
  },
  {
    name: 'A2A',
    does: 'Supports agent discovery, task coordination, and exchange of results across systems.',
    leaves: 'Discovery describes capabilities. The parties still need to validate who delegated the work, what the agreed bailment permits, and whether that authority remains valid.',
    href: 'https://a2a-protocol.org/latest/',
  },
  {
    name: 'x402 / HTTP 402',
    does: 'An open protocol that uses HTTP 402 Payment Required to communicate payment requirements and coordinate payment proofs and verification.',
    leaves: 'Payment providers and their configured infrastructure perform settlement. EXOCHAIN’s current adapter verifies and binds payment evidence; it does not move funds. Payment cannot override an authority denial.',
    href: 'https://docs.x402.org/',
  },
  {
    name: 'AP2',
    does: 'Uses signed mandates to express checkout and payment authorization for agent commerce.',
    leaves: 'These mandates complement organizational delegations and controls for purpose, vendor selection, conflicts, and consent. Payment authorization alone does not establish that every business authority requirement was satisfied.',
    href: 'https://ap2-protocol.org/',
  },
];

export default function StandardsPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Interoperability</Eyebrow>
        <H1 className="mt-3">Open protocols for accountable commerce.</H1>
        <Lede className="mt-5 max-w-prose">
          A2A connects agents. MCP connects tools. x402 coordinates HTTP
          payment flows, and AP2 expresses payment mandates. EXOCHAIN’s
          integration model connects those roles to a shared trust fabric for
          delegated authority, bailment, consent, and verifiable transaction
          evidence.
        </Lede>
        <p className="mt-4 max-w-prose text-base text-brand-midnight/80">
          Payment authorization is one part of a transaction. Business
          authority, agreed obligations, and execution evidence require their
          own checks.
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
                <p className="mt-4 text-sm">
                  <a href={item.href} className="underline">
                    Official {item.name} documentation
                  </a>
                </p>
              </CardBody>
            </Card>
          ))}
        </div>
      </Section>
      <Section className="py-8">
        <H2>One transaction across complementary roles</H2>
        <Lede className="mt-4 max-w-prose">
          Authorize the agent, agree and entrust work under a bailment,
          execute through the selected tools and services, pay through a
          payment provider, and verify the resulting evidence. The record
          should connect the delegation, agreed terms, relevant constraints,
          execution result, and provider payment evidence so a counterparty
          can examine the transaction without relying solely on another
          organization’s internal application.
        </Lede>
        <p className="mt-4 max-w-prose text-base text-brand-midnight/80">
          A provider-issued bond or insurance policy may cover a specified
          transaction under its own terms; reinsurance supports the provider
          carrying that risk. These instruments have separate issuers and
          claims processes. Neither payment evidence nor an EXOCHAIN receipt
          creates coverage. Supported protocol paths and provider integrations
          depend on the agreed deployment and the{' '}
          <Link href="/status" className="underline">release record</Link>.
        </p>
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
