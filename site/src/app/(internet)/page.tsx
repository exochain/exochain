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
import { PilotBanner } from '@/components/commercial/PilotBanner';
import { loadPublicStatus } from '@/lib/public-status';
import {
  CANONICAL_ORIGIN,
  CORE_LICENSE,
  publicMetadata,
  SITE_DESCRIPTION,
  SITE_TITLE,
} from '@/lib/public-site';

export const metadata = publicMetadata({
  title: 'Accountable Autonomous Commerce',
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

const TRANSACTION_STEPS = [
  {
    name: 'Authorize',
    body: 'Identify the agent and its principal. Check the delegated authority, limits, consent, and revocation state before an action runs.',
  },
  {
    name: 'Agree and entrust',
    body: 'Define the work, counterparties, and obligations. Use bailment terms to specify entrusted resources, permitted use, and return or discharge conditions.',
  },
  {
    name: 'Execute',
    body: 'Enforce the decision at the action boundary. Preserve policy denial, revocation, human E-STOP, and evidence of the resulting outcome.',
  },
  {
    name: 'Pay',
    body: 'Connect the agreed payment flow to its provider. Bind payment evidence to the authorized action, including x402 evidence where that integration is in scope.',
  },
  {
    name: 'Verify',
    body: 'Give each party attributable records linking authority, obligations, execution, and payment evidence for independent review.',
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
    role: 'Commercial evidence application',
    body: 'An affiliated application for decisions, supporting evidence, and outcomes. EXOCHAIN anchoring requires a tested, approved integration for the particular deployment.',
  },
  {
    name: 'AVC',
    role: 'Commercialization and implementation',
    body: 'Incubation and venture formation for companies built on the fabric. Distinct from the protocol’s Autonomous Volition Credential.',
  },
  {
    name: 'AI-SDLC Institute',
    role: 'Independent education and assessment',
    body: 'Training and assessment for people building and governing AI systems, independent of the products in the commercial network.',
  },
];

const OFFERS = [
  {
    name: 'Enterprise deployment',
    body: 'Scope an accountable workflow, integrate with the systems you already run, and agree the operating controls and acceptance evidence. A focused pilot is an available entry point.',
  },
  {
    name: 'Platform licensing',
    body: 'Commercial licensing and support for the agreed platform services and integrations, with a defined deployment scope.',
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
  const publicStatus = loadPublicStatus();

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
              Make autonomous commerce accountable.
            </H1>
            <Lede className="mt-6 max-w-prose text-brand-midnight/80">
              Connect agent identity, delegated authority, commercial agreements,
              payments, and verifiable outcomes—across organizational boundaries.
            </Lede>
            <p className="mt-4 max-w-prose text-base text-brand-midnight/80">
              Establish who may act, under which obligations, what occurred,
              and which evidence each counterparty can verify.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <LinkButton href="/contact#deployment" size="lg">
                Explore enterprise deployment
              </LinkButton>
              <LinkButton href="#transaction" variant="secondary" size="lg">
                Explore the transaction flow
              </LinkButton>
            </div>
            <div className="mt-6 flex flex-wrap items-center gap-2 text-sm">
              <Pill tone="neutral" className="border border-brand-charter/40 bg-brand-charter/10 text-brand-vault">
                {publicStatus.maturity} v{publicStatus.publication.version}
              </Pill>
              <Pill tone="neutral" className="border border-brand-signal/25 bg-brand-signal/10 text-brand-cerulean">
                normative spec v{publicStatus.spec.normative_version}
              </Pill>
              <Pill tone="neutral">{CORE_LICENSE} core</Pill>
              <Link href="/status" className="underline decoration-brand-signal/40 underline-offset-4">
                Release scope
              </Link>
              <Link href="/lynk" className="underline decoration-brand-signal/40 underline-offset-4">
                LYNK
              </Link>
            </div>
          </div>
          <Card>
            <CardHeader eyebrow="Proven Agentic Action Authority" title="Proof of Authority" />
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

      <Section className="py-12 scroll-mt-20" id="transaction">
        <Eyebrow>The commercial workflow</Eyebrow>
        <H2 className="mt-3">From delegated authority to verifiable outcomes.</H2>
        <Lede className="mt-4 max-w-prose">
          Design a deployment around the complete transaction. The agreed scope
          identifies the controls, integrations, and evidence required at each
          step; the release record identifies the available implementation.
        </Lede>
        <ol className="mt-8 grid sm:grid-cols-2 xl:grid-cols-5 gap-4">
          {TRANSACTION_STEPS.map((step, index) => (
            <li key={step.name}>
              <Card className="h-full">
                <CardHeader eyebrow={`Step ${index + 1}`} title={step.name} />
                <CardBody><p className="text-sm">{step.body}</p></CardBody>
              </Card>
            </li>
          ))}
        </ol>
        <div className="mt-6 border hairline rounded-md px-6 py-5 max-w-prose">
          <h3 className="font-semibold text-brand-vault">Financial assurance for covered transactions</h3>
          <p className="mt-2 text-sm text-brand-midnight/80">
            Defined obligations and verifiable evidence can support independent
            bonding and insurance arrangements, including reinsurance behind a
            provider. Coverage depends on a separate provider agreement and its
            stated limits, exclusions, and claims process.
          </p>
          <Link href="/engagement#assurance" className="mt-3 inline-block text-sm underline">
            Discuss financial-assurance requirements
          </Link>
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
          Connect tool access, agent collaboration, and payment protocols with
          the authority and evidence an enterprise needs. MCP, A2A, x402, and
          AP2 have distinct roles within an agreed integration.
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
        <H2 className="mt-3">Integrate at the point where agents act.</H2>
        <Lede className="mt-4 max-w-prose">
          Start with the SDK, discover the configured gateway, and connect the
          authority and receipt APIs required for your workflow. LYNK provides
          an integration path for receipted LLM and MCP usage.
        </Lede>
        <p className="mt-6 text-sm">
          <Link href="/developers" className="underline">
            Developers and the current SDK
          </Link>
        </p>
      </Section>

      <Section className="py-12" id="ecosystem">
        <Eyebrow>Ecosystem</Eyebrow>
        <H2 className="mt-3">One fabric. Multiple applications.</H2>
        <Lede className="mt-4 max-w-prose">
          A shared foundation for independent companies and applications.
          EXOCHAIN supplies the trust infrastructure; products, implementation
          partners, and educators contribute distinct capabilities.
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
          Each application has its own deployment scope. Explore the ecosystem
          for product roles and the evidence an integration needs to establish.
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
          Start with the outcome your counterparties need to trust. We will
          scope the deployment, platform services, and ongoing operating support.
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
