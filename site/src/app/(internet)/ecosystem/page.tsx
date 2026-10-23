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
  title: 'Ecosystem',
  description:
    'One shared trust fabric for accountable autonomous commerce, with distinct roles for EXOCHAIN infrastructure, CrossChecked, AVC commercialization, independent education, and service providers.',
  path: '/ecosystem',
});

const LAYERS = [
  {
    name: 'EXOCHAIN',
    role: 'Shared trust infrastructure',
    body: 'Authority, consent, bailment, governed execution, and verifiable evidence for transactions across independent organizations. Open protocols, SDKs, and enterprise services let organizations build on the same fabric. Core software is Apache-2.0; the release record and agreed deployment scope establish available capabilities.',
  },
  {
    name: 'CrossChecked',
    role: 'Commercial evidence application',
    body: 'An affiliated product focused on evidence for AI-assisted decisions: who authorized the work, which records and constraints informed it, and what happened afterward. CrossChecked has its own application and deployment boundary. Any claim of EXOCHAIN enforcement depends on a tested integration with the core trust fabric.',
  },
  {
    name: 'AVC',
    role: 'Venture formation and commercialization',
    body: 'Incubation and commercialization for businesses building on the shared trust fabric. This venture role is distinct from the protocol credential also called an AVC: the Autonomous Volition Credential used to describe delegated authority.',
  },
  {
    name: 'AI-SDLC Institute',
    role: 'Independent education and assessment',
    body: 'Training and assessment for people building and governing AI systems. Educational assessment remains independent of product licensing and commercial delivery. It does not establish a deployment’s enforcement behavior or provide financial coverage for a transaction.',
  },
];

const REFERENCES = [
  {
    name: 'CyberMedica',
    body: 'A clinical-research quality reference implementation. Adjacent to the trust fabric.',
  },
  {
    name: 'LegalDyne',
    body: 'A legal-technology reference implementation. Adjacent to the trust fabric.',
  },
  {
    name: 'LiveSafe',
    body: 'A safety-card reference implementation. Adjacent to the trust fabric, with its own proprietary boundary.',
  },
  {
    name: 'Decision.Forum',
    body: 'A deliberative decision-making reference. The Apache-licensed forum primitive in the repository is not a commercial product release.',
  },
];

export default function EcosystemPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Ecosystem</Eyebrow>
        <H1 className="mt-3">One shared trust fabric.</H1>
        <Lede className="mt-5 max-w-prose">
          Accountable autonomous commerce connects independent organizations
          through a common transaction flow: authorize, agree and entrust,
          execute, pay, and verify. EXOCHAIN provides the shared trust fabric;
          applications, payment providers, and financial-assurance providers
          retain their own responsibilities.
        </Lede>
      </Section>
      <Section className="py-8">
        <div className="grid md:grid-cols-2 gap-4">
          {LAYERS.map((item) => (
            <Card key={item.name}>
              <CardHeader eyebrow={item.role} title={item.name} />
              <CardBody>
                <p className="text-sm">{item.body}</p>
              </CardBody>
            </Card>
          ))}
        </div>
      </Section>
      <Section className="py-8">
        <H2>Independent providers, connected evidence</H2>
        <Lede className="mt-4 max-w-prose">
          A2A supports collaboration between agents, and MCP connects them to
          tools. Bailment records the purpose, permitted use, and obligations
          of entrusted work. x402 uses HTTP 402 to coordinate payment
          requirements and evidence, while payment providers carry out
          settlement through the agreed integration.
        </Lede>
        <p className="mt-4 max-w-prose text-base text-brand-midnight/80">
          Separately issued third-party bonds or insurance may cover specified
          transactions under provider-defined terms. Reinsurance can support
          the provider carrying that risk. EXOCHAIN connects the evidence;
          coverage requires an issued instrument and does not arise from using
          the fabric.
        </p>
      </Section>
      <Section className="py-8">
        <H2>Reference implementations</H2>
        <Lede className="mt-4 max-w-prose">
          CyberMedica, LegalDyne, LiveSafe, and Decision.Forum illustrate
          application domains around the shared infrastructure. Each has its
          own product scope, deployment status, and integration boundary.
        </Lede>
        <div className="mt-8 grid md:grid-cols-2 gap-4">
          {REFERENCES.map((item) => (
            <Card key={item.name}>
              <CardHeader title={item.name} />
              <CardBody>
                <p className="text-sm">{item.body}</p>
              </CardBody>
            </Card>
          ))}
        </div>
        <div className="mt-6 max-w-prose">
          <Disclaimer>
            Naming an adjacent product on this site is not a constitutional
            trust claim or evidence of a customer deployment. Enforcement
            claims require a tested path into EXOCHAIN core and evidence for
            the particular deployment. See the{' '}
            <Link href="/status" className="underline">release record</Link>
            {' '}for published software status.
          </Disclaimer>
        </div>
        <p className="mt-6 text-sm">
          <Link href="/avc" className="underline">
            Autonomous Volition Credential
          </Link>
          {' · '}
          <Link href="/engagement" className="underline">
            Engagement offerings
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
