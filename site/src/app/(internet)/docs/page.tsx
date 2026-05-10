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
import { Section, Eyebrow, H1, Lede } from '@/components/ui/Section';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';

export const metadata = { title: 'Documentation' };

const docs = [
  {
    href: '/docs/getting-started',
    title: 'Getting Started',
    body: 'Install the SDK, register an actor, issue your first AVC, and emit a trust receipt.'
  },
  {
    href: '/docs/concepts',
    title: 'Concepts',
    body: 'Identity, authority, volition, consent, execution, custody. The core mental model.'
  },
  {
    href: '/docs/avc',
    title: 'AVC',
    body: 'Schema, validation rules, delegation, expiry, revocation, signature algorithms.'
  },
  {
    href: '/docs/trust-receipts',
    title: 'Trust Receipts',
    body: 'Receipt anatomy, hash chaining, outcomes, custody hash, signature verification.'
  },
  {
    href: '/docs/settlement',
    title: 'Settlement',
    body: 'Quotes, receipts, ZeroFeeReason, launch policy, future governance pathways.'
  },
  {
    href: '/docs/node-api',
    title: 'Node API',
    body: 'REST and GraphQL surfaces exposed by exo-gateway and exo-node.'
  },
  {
    href: '/docs/validator-guide',
    title: 'Validator Guide',
    body: 'Hardware expectations, attestation, key management, observation period.'
  },
  {
    href: '/docs/security',
    title: 'Security Model',
    body: 'Threat model summary, cryptographic primitives, post-quantum readiness.'
  },
  {
    href: '/docs/governance',
    title: 'Governance Model',
    body: 'Constitutional invariants, proposal lifecycle, quorum, ratification.'
  },
  {
    href: '/docs/glossary',
    title: 'Glossary',
    body: 'Vocabulary used consistently across docs, SDK, and the protocol.'
  },
  {
    href: '/docs/faq',
    title: 'FAQ',
    body: 'Frequent questions. If yours is missing, the contact form takes 30 seconds.'
  }
];

export default function DocsIndexPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Docs</Eyebrow>
        <H1 className="mt-3">EXOCHAIN documentation.</H1>
        <Lede className="mt-5 max-w-prose">
          Concepts, schemas, APIs, and operational guides. APIs marked
          <em> Unstable </em> are subject to breaking change without notice.
        </Lede>
      </Section>
      <Section className="py-6">
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-5">
          {docs.map((d) => (
            <Card key={d.href}>
              <CardHeader title={<Link href={d.href} className="underline">{d.title}</Link>} />
              <CardBody>
                <p className="text-sm">{d.body}</p>
              </CardBody>
            </Card>
          ))}
        </div>
      </Section>
    </>
  );
}
