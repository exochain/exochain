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
import { LinkButton } from '@/components/ui/Button';
import { Pill } from '@/components/ui/Pill';
import { Section, Eyebrow, H1, H2, Lede } from '@/components/ui/Section';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Disclaimer } from '@/components/ui/Disclaimer';
import { IllustrativeCalls } from '@/components/commercial/IllustrativeCalls';
import { PilotBanner } from '@/components/commercial/PilotBanner';
import {
  CANONICAL_ORIGIN,
  CORE_LICENSE,
  NORMATIVE_SPEC,
  PRODUCT_CHANNEL,
  publicMetadata,
  RELEASE_VERSION,
  SITE_DESCRIPTION,
  SITE_TITLE,
} from '@/lib/public-site';

export const metadata = publicMetadata({
  title: 'Proven Agentic Action Authority',
  description: SITE_DESCRIPTION,
  path: '/',
  absoluteTitle: SITE_TITLE,
});

const ASSUMPTIONS = [
  ['Identity establishes who you are', 'Cryptographic identity establishes who or what is acting'],
  ['Permissions establish what you can access', 'Delegated authority establishes what you are entitled to decide and do'],
  ['Applications own their workflows', 'Independent agents coordinate across organizational boundaries'],
  ['Logs establish accountability', 'Verifiable receipts connect authority, evidence, decisions, and outcomes'],
];

const STANDARDS = [
  {
    name: 'MCP',
    role: 'Connects AI systems to tools and resources.',
  },
  {
    name: 'A2A',
    role: 'Lets agents collaborate across systems.',
  },
  {
    name: 'x402',
    role: 'Carries machine-native payments.',
  },
  {
    name: 'AP2',
    role: 'Carries signed mandates and receipts for agent-initiated payments.',
  },
];

const ECOSYSTEM = [
  {
    name: 'EXOCHAIN',
    role: 'Infrastructure',
    body: 'The shared trust fabric: open protocols, SDKs, and enterprise services other companies can use without being owned by EXOCHAIN.',
  },
  {
    name: 'CrossChecked',
    role: 'First commercial wedge',
    body: 'Shows who authorized an AI-assisted decision, which evidence and constraints applied, and what occurred afterward. It is an adjacent product, currently a prototype, and it does not itself enforce the constitutional kernel.',
  },
  {
    name: 'AVC',
    role: 'Distribution engine',
    body: 'Incubation and venture formation for companies built on the fabric. Distinct from the protocol’s Autonomous Volition Credential.',
  },
  {
    name: 'AI-SDLC Institute',
    role: 'Independent education and assessment',
    body: 'Training and assessment that stay independent of the products in the commercial network. Assessment here is education, not coverage.',
  },
];

const OFFERS = [
  {
    name: 'Pilot or implementation',
    body: 'A fixed-scope design-partner pilot or deployment for one constrained workflow, including architecture and integration into the systems you already run.',
  },
  {
    name: 'Platform licensing',
    body: 'Licensed access to the EXOCHAIN control plane, hosted verification, and enterprise integration. The platform is the recurring product.',
  },
  {
    name: 'Managed governance services',
    body: 'Ongoing administration, governance engineering, monitoring, remediation, and platform optimization, purchased as an outcome.',
  },
];

const websiteJsonLd = {
  '@context': 'https://schema.org',
  '@type': 'WebSite',
  name: 'EXOCHAIN',
  url: `${CANONICAL_ORIGIN}/`,
  description: SITE_DESCRIPTION,
  publisher: {
    '@type': 'Organization',
    name: 'EXOCHAIN PBC',
    email: 'legal@exochain.com',
  },
};

export default function HomePage() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(websiteJsonLd) }}
      />
      <Section className="pt-16 md:pt-24 pb-12">
        <div className="grid lg:grid-cols-[1.25fr_0.85fr] gap-10 items-end">
          <div>
            <div className="mb-6 h-px w-24 bg-brand-charter" />
            <Eyebrow>The trust fabric for autonomous commerce</Eyebrow>
            <H1 className="mt-4 font-light tracking-normal text-brand-vault">
              Proven Agentic Action Authority
            </H1>
            <Lede className="mt-6 max-w-prose text-brand-midnight/80">
              Every agent action carries proof of who authorized it, the limits
              it ran under, and AI guarding with an E-STOP that fails closed.
            </Lede>
            <p className="mt-4 max-w-prose text-base text-brand-midnight/80">
              E-STOP is a current platform capability. Revocation, policy deny, and fail-closed gates stop an action that is outside authority.
            </p>
            <p className="mt-4 max-w-prose text-base text-brand-midnight/80">
              Payment authorization is not legitimate decision-making authority.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <LinkButton href="/contact#pilot" size="lg">
                Talk to us about a design-partner pilot
              </LinkButton>
              <LinkButton href="/developers" variant="secondary" size="lg">
                Developers and SDK
              </LinkButton>
            </div>
            <div className="mt-6 flex flex-wrap items-center gap-2 text-sm">
              <Pill tone="neutral" className="border border-brand-charter/40 bg-brand-charter/10 text-brand-vault">
                {PRODUCT_CHANNEL} {RELEASE_VERSION}
              </Pill>
              <Pill tone="neutral" className="border border-brand-signal/25 bg-brand-signal/10 text-brand-cerulean">
                normative spec {NORMATIVE_SPEC}
              </Pill>
              <Pill tone="neutral">{CORE_LICENSE} core</Pill>
              <Link href="/lynk" className="underline decoration-brand-signal/40 underline-offset-4">
                LYNK
              </Link>
            </div>
          </div>
          <Card>
            <CardHeader eyebrow="Working category concept" title="Proof of Authority" />
            <CardBody>
              <p className="text-sm text-brand-midnight/80">
                A portable, independently verifiable claim that an agent’s
                specific action falls within a valid chain of delegated
                authority, satisfies applicable constraints, and has an
                attributable outcome.
              </p>
              <div className="mt-4">
                <Disclaimer>
                  Proof of Authority is a working category concept. It is not
                  a new cryptographic primitive and it is not an industry
                  standard.
                </Disclaimer>
              </div>
              <p className="mt-4 text-sm">
                <Link href="/proof-of-authority" className="underline">
                  Read the concept
                </Link>
              </p>
            </CardBody>
          </Card>
        </div>
      </Section>

      <Section className="py-12" id="problem">
        <Eyebrow>The problem</Eyebrow>
        <H2 className="mt-3">Trust is still trapped inside each application.</H2>
        <p className="mt-4 max-w-prose text-xl text-brand-vault">
          {"When an agent acts on your behalf, don't get left holding the bag."}
        </p>
        <Lede className="mt-4 max-w-prose">
          Enterprise software assumes identity, permissions, contracts, and
          logs are enough. Autonomous agents act across organizational
          boundaries, where those assumptions stop being a shared system of
          record.
        </Lede>
        <div className="mt-8 grid md:grid-cols-2 gap-4">
          {ASSUMPTIONS.map(([from, to]) => (
            <Card key={from}>
              <CardBody>
                <p className="text-xs uppercase tracking-eyebrow text-brand-cerulean">
                  Existing assumption
                </p>
                <p className="mt-2 text-sm">{from}</p>
                <p className="mt-4 text-xs uppercase tracking-eyebrow text-brand-cerulean">
                  Replacement
                </p>
                <p className="mt-2 text-sm">{to}</p>
              </CardBody>
            </Card>
          ))}
        </div>
        <p className="mt-6 text-sm">
          <Link href="/why" className="underline">
            The full problem
          </Link>
        </p>
      </Section>

      <Section className="py-12" id="standards">
        <Eyebrow>Interoperability</Eyebrow>
        <H2 className="mt-3">Use the standards. Make the action accountable.</H2>
        <Lede className="mt-4 max-w-prose">
          EXOCHAIN does not replace MCP, A2A, x402, or AP2. An agent can be
          allowed to pay and still lack the authority to choose the vendor,
          the evidence for that choice, or a receipt a counterparty can verify
          on its own.
        </Lede>
        <div className="mt-8 grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {STANDARDS.map((item) => (
            <Card key={item.name}>
              <CardHeader title={item.name} />
              <CardBody>
                <p className="text-sm">{item.role}</p>
              </CardBody>
            </Card>
          ))}
        </div>
        <p className="mt-6 text-sm">
          <Link href="/standards" className="underline">
            How the standards fit together
          </Link>
        </p>
      </Section>

      <Section className="py-12" id="developers">
        <Eyebrow>Developer experience</Eyebrow>
        <H2 className="mt-3">Two calls. Verify authority. Produce evidence.</H2>
        <Lede className="mt-4 max-w-prose">
          The intended experience is two calls: verify that the action is
          within delegated authority, then attest the outcome. The current
          SDK is the 0.2.7 client in the repository. The snippet below is the
          target shape.
        </Lede>
        <div className="mt-8">
          <IllustrativeCalls />
        </div>
        <p className="mt-6 text-sm">
          <Link href="/developers" className="underline">
            Developers and the current SDK
          </Link>
        </p>
      </Section>

      <Section className="py-12" id="ecosystem">
        <Eyebrow>Ecosystem</Eyebrow>
        <H2 className="mt-3">One fabric. Separate roles.</H2>
        <Lede className="mt-4 max-w-prose">
          EXOCHAIN should be useful to companies it did not create and does
          not control. CrossChecked is the first commercial wedge, AVC is the
          distribution engine, and the AI-SDLC Institute keeps education and
          assessment independent.
        </Lede>
        <div className="mt-8 grid md:grid-cols-2 gap-4">
          {ECOSYSTEM.map((item) => (
            <Card key={item.name}>
              <CardHeader eyebrow={item.role} title={item.name} />
              <CardBody>
                <p className="text-sm">{item.body}</p>
              </CardBody>
            </Card>
          ))}
        </div>
        <p className="mt-6 text-sm max-w-prose">
          CyberMedica, LegalDyne, LiveSafe, and Decision.Forum are reference
          implementations and candidates for future independent businesses.
          They are not six products this site is launching at once.
        </p>
        <p className="mt-4 text-sm">
          <Link href="/ecosystem" className="underline">
            Ecosystem roles
          </Link>
        </p>
      </Section>

      <Section className="py-12" id="engagement">
        <Eyebrow>Engagement</Eyebrow>
        <H2 className="mt-3">Three ways to work with EXOCHAIN.</H2>
        <Lede className="mt-4 max-w-prose">
          Offers are scoped in conversation. This site does not publish a rate
          card.
        </Lede>
        <div className="mt-8 grid md:grid-cols-3 gap-4">
          {OFFERS.map((item) => (
            <Card key={item.name}>
              <CardHeader title={item.name} />
              <CardBody>
                <p className="text-sm">{item.body}</p>
              </CardBody>
            </Card>
          ))}
        </div>
        <p className="mt-6 text-sm">
          <Link href="/engagement" className="underline">
            Engagement offerings
          </Link>
        </p>
      </Section>

      <PilotBanner />
    </>
  );
}
