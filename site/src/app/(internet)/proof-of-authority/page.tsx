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
  title: 'Proof of Authority',
  description:
    'Proof of Authority is a working category concept: a portable, independently verifiable claim that an agent action falls within valid delegated authority, satisfies constraints, and has an attributable outcome.',
  path: '/proof-of-authority',
});

const FIELDS = [
  ['Principal', 'The human or institution that holds the original authority'],
  ['Delegate', 'The agent or operator acting under that authority'],
  ['Scope', 'The decisions and actions the delegation allows'],
  ['Constraints', 'Limits that still apply, including amount, purpose, and policy'],
  ['Decision evidence', 'The record the actor relied on for this action'],
  ['Action', 'The specific act being authorized or attested'],
  ['Outcome', 'What occurred after the action was taken'],
  ['Revocation state', 'Whether the delegation was still valid at the time'],
];

export default function ProofOfAuthorityPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Working category concept</Eyebrow>
        <H1 className="mt-3">Proof of Authority</H1>
        <Lede className="mt-5 max-w-prose">
          A portable, independently verifiable claim demonstrating that an
          agent’s specific action falls within a valid chain of delegated
          authority, satisfies applicable constraints, and has an attributable
          outcome.
        </Lede>
        <div className="mt-6 max-w-prose">
          <Disclaimer>
            Proof of Authority is a working category concept. It is not a new
            cryptographic primitive and it is not an industry standard.
            EXOCHAIN normative specification v2.2 and the beta v0.2.7 release
            describe the current software. They do not freeze this category
            name as a completed receipt format.
          </Disclaimer>
        </div>
      </Section>
      <Section className="py-8">
        <H2>What the claim has to carry</H2>
        <Lede className="mt-4 max-w-prose">
          The intended portable receipt binds the parties, the limits, the
          evidence, the action, the outcome, and revocation. These fields are
          the category’s contents. They are not a published interoperability
          profile.
        </Lede>
        <div className="mt-8 grid md:grid-cols-2 gap-4">
          {FIELDS.map(([name, body]) => (
            <Card key={name}>
              <CardHeader title={name} />
              <CardBody>
                <p className="text-sm">{body}</p>
              </CardBody>
            </Card>
          ))}
        </div>
      </Section>
      <Section className="py-8">
        <H2>Pieces already in the beta</H2>
        <Lede className="mt-4 max-w-prose">
          Bailments, consent, revocation, governance, and trust receipts are
          the conceptual pieces EXOCHAIN already implements in beta. The work
          is to expose them as a developer primitive other stacks can call
          without adopting the entire constitutional architecture.
        </Lede>
        <p className="mt-6 text-sm">
          <Link href="/trust-receipts" className="underline">
            Trust receipts
          </Link>
          {' · '}
          <Link href="/avc" className="underline">
            Autonomous Volition Credentials
          </Link>
          {' · '}
          <Link href="/developers" className="underline">
            Two-call developer experience
          </Link>
        </p>
      </Section>
      <PilotBanner />
    </>
  );
}
