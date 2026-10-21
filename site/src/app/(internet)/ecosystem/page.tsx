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
    'EXOCHAIN is the infrastructure, CrossChecked is the first commercial wedge, AVC is the distribution engine, and the AI-SDLC Institute is independent education and assessment.',
  path: '/ecosystem',
});

const LAYERS = [
  {
    name: 'EXOCHAIN',
    role: 'Common infrastructure',
    body: 'Open protocols, SDKs, and enterprise services. The platform earns its place by being useful to companies EXOCHAIN did not create, does not own, and does not control. Core software is Apache-2.0 and is in beta (v0.2.7), under normative specification v2.2.',
  },
  {
    name: 'CrossChecked',
    role: 'First commercial wedge',
    body: 'The concrete result a buyer can evaluate: who authorized an AI-assisted decision, what evidence was used, which constraints applied, and what occurred afterward. The CrossChecked application in this repository is an adjacent prototype. It does not mint consent, authority, or governance outcomes, and this site does not claim it enforces the constitutional kernel.',
  },
  {
    name: 'AVC',
    role: 'Distribution engine',
    body: 'Incubation, venture formation, and commercialization for companies built on the fabric. That venture role is separate from the protocol credential also called an AVC — the Autonomous Volition Credential documented at /avc.',
  },
  {
    name: 'AI-SDLC Institute',
    role: 'Independent education and assessment',
    body: 'Training and assessment for people building and governing AI systems. The institute’s value depends on staying independent of the products in the same commercial network. This page does not offer a certificate, a coverage product, or an attestation you can buy.',
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
        <H1 className="mt-3">One fabric. Separate roles.</H1>
        <Lede className="mt-5 max-w-prose">
          Independent companies, developers, agents, and institutions should
          be able to build and transact on a shared fabric. Owning every
          application would make EXOCHAIN a portfolio. The strategic objective
          is a platform other organizations can adopt without permission to
          exist.
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
        <H2>Reference implementations</H2>
        <Lede className="mt-4 max-w-prose">
          CyberMedica, LegalDyne, LiveSafe, Decision.Forum, and CrossChecked
          are not six equally urgent companies to launch. They are reference
          implementations and candidates for future independent businesses on
          the same infrastructure.
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
            trust claim. Enforcement, when it exists, is in the EXOCHAIN core
            and its tested adapters. The core software on this site is beta.
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
        </p>
      </Section>
      <PilotBanner />
    </>
  );
}
