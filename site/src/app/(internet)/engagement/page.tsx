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
import { Disclaimer } from '@/components/ui/Disclaimer';
import { PilotBanner } from '@/components/commercial/PilotBanner';
import { publicMetadata } from '@/lib/public-site';

export const metadata = publicMetadata({
  title: 'Engagement',
  description:
    'EXOCHAIN engagements are a design-partner pilot or implementation, platform licensing, and managed governance services. Prices are not published on this site.',
  path: '/engagement',
});

const OFFERS = [
  {
    eyebrow: '01',
    name: 'Pilot or implementation',
    body: 'A fixed-scope design-partner pilot, or a broader implementation, for one real workflow. Typical work includes the authority model, integration with identity and payments you already use, and a verifier both parties can run. The first useful pilot is a constrained cross-organizational decision, such as procurement or an executive approval.',
  },
  {
    eyebrow: '02',
    name: 'Platform licensing',
    body: 'Annual licensing for the EXOCHAIN control plane, hosted verification, and enterprise integration or gateway access. Licensing is the recurring product. Implementation work does not substitute for it.',
  },
  {
    eyebrow: '03',
    name: 'Managed governance services',
    body: 'Recurring operation of the platform: administration and monitoring, governance and control engineering, integration remediation, and optimization. You purchase the outcome. EXOCHAIN does not sell staff by the hour on this page.',
  },
];

export default function EngagementPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Engagement</Eyebrow>
        <H1 className="mt-3">Buy a result. Keep the fabric shared.</H1>
        <Lede className="mt-5 max-w-prose">
          A design-partner pilot is the way to start. Platform licensing and
          managed governance services are how a deployment continues. Scope is
          agreed per engagement. This site does not publish prices, package
          fees, or a rate card.
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
            Beta v0.2.7 software under normative specification v2.2. Engagement
            does not include insurance, bonding, or assurance coverage.
            Signing an engagement leaves the software in beta.
          </Disclaimer>
        </div>
      </Section>
      <Section className="py-4">
        <H2>What a pilot is for</H2>
        <Lede className="mt-4 max-w-prose">
          One transaction or approval where two independent parties need
          verifiable human authority and neither can safely rely on the
          other’s private application. Success is a receipt the counterparty
          can check, plus a developer path that does not require adopting
          every EXOCHAIN subsystem on day one.
        </Lede>
      </Section>
      <PilotBanner />
    </>
  );
}
