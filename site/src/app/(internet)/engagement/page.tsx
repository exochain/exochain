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
import { Disclaimer } from '@/components/ui/Disclaimer';
import { PilotBanner } from '@/components/commercial/PilotBanner';
import { publicMetadata } from '@/lib/public-site';

export const metadata = publicMetadata({
  title: 'Engagement',
  description:
    'Enterprise deployment, platform licensing, and managed governance services for accountable autonomous commerce, with optional scoped pilots and explicit payment and financial-assurance responsibilities.',
  path: '/engagement',
});

const OFFERS = [
  {
    eyebrow: '01',
    name: 'Enterprise deployment',
    body: 'Define and integrate a real commercial workflow: delegated authority, agreed bailment terms, agent and tool execution, payment-provider settlement, and evidence a counterparty can verify. Scope, supported integrations, acceptance criteria, and operating responsibilities are agreed for the deployment. A constrained pilot is available when a workflow needs evaluation first.',
  },
  {
    eyebrow: '02',
    name: 'Platform licensing',
    body: 'Commercial licensing for the selected control-plane, hosted verification, and enterprise integration services. Terms identify the licensed capabilities, deployment model, support, and service boundaries. The Apache-2.0 core remains available under its open-source license.',
  },
  {
    eyebrow: '03',
    name: 'Managed governance services',
    body: 'Ongoing administration, monitoring, governance and control engineering, integration maintenance, and evidence operations. The service scope names who maintains policies, handles exceptions, reviews revocation, and supports counterparties that need to verify a transaction.',
  },
];

export default function EngagementPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Engagement</Eyebrow>
        <H1 className="mt-3">Deploy accountable autonomous commerce.</H1>
        <Lede className="mt-5 max-w-prose">
          Bring authority, agreement, execution, payment, and evidence into
          one enterprise workflow. Start with an agreed deployment, supported
          by platform licensing and managed governance services. Scope and
          commercial terms follow the workflow, the participating providers,
          and the release evidence.
        </Lede>
      </Section>
      <Section className="py-8">
        <div className="grid lg:grid-cols-3 gap-4">
          {OFFERS.map((item) => (
            <Card key={item.name}>
              <CardHeader eyebrow={item.eyebrow} title={item.name} />
              <CardBody>
                <p className="text-sm">{item.body}</p>
              </CardBody>
            </Card>
          ))}
        </div>
        <div className="mt-6 max-w-prose">
          <Disclaimer>
            Capability and integration availability are established in the
            engagement and the{' '}
            <Link href="/status" className="underline">release record</Link>.
            A commercial agreement does not itself establish that a proposed
            release or provider integration is available in production.
          </Disclaimer>
        </div>
      </Section>
      <Section className="py-4">
        <H2>One transaction, clear responsibilities</H2>
        <Lede className="mt-4 max-w-prose">
          Authorize the agent. Agree and entrust work through a bailment.
          Discover counterparties through A2A where supported by the approved
          release and execute tool calls through the agreed MCP integration.
          Pay through the agreed payment provider,
          using x402 / HTTP 402 where applicable.
          Verify the authority, execution, and payment evidence together.
          Acceptance criteria specify the evidence each party must produce
          and the checks an independent counterparty can run.
        </Lede>
        <p className="mt-4 max-w-prose text-base text-brand-midnight/80">
          Payment providers perform settlement. EXOCHAIN’s current x402
          adapter verifies and binds payment evidence to the authority
          decision; it does not move funds. Deployment work must establish the
          actual provider path and its settlement evidence.
        </p>
      </Section>
      <Section id="assurance" className="py-8">
        <H2>Financial assurance for covered transactions</H2>
        <Lede className="mt-4 max-w-prose">
          Where separately arranged, third-party bonding or insurance can
          cover specified obligations or risks. Each covered transaction must
          identify the provider, the covered obligation or risk, limits,
          exclusions, and the claims route. Reinsurance supports the provider
          carrying the risk under its own contract.
        </Lede>
        <p className="mt-4 max-w-prose text-base text-brand-midnight/80">
          EXOCHAIN is not the insurer, surety, or reinsurer. Coverage requires
          a separately issued provider instrument; it is never automatic with
          platform use or licensing. The proposed financial-assurance
          interface creates no coverage, and this site offers no named
          provider product. Payment, authority, and coverage remain distinct
          responsibilities linked by transaction evidence.
        </p>
        <p className="mt-6 text-sm">
          <Link href="/contact#deployment" className="underline">
            Discuss an enterprise deployment
          </Link>
          {' · '}
          <Link href="/standards" className="underline">
            Protocol and provider roles
          </Link>
        </p>
      </Section>
      <PilotBanner />
    </>
  );
}
