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
    'Proof of Authority is a working category concept for a portable claim connecting delegated authority, agreed bailment terms, constraints, and an attributable transaction outcome.',
  path: '/proof-of-authority',
});

const FIELDS = [
  ['Principal', 'The human or institution that holds the original authority'],
  ['Delegate', 'The agent or operator acting under that authority'],
  ['Scope', 'The decisions and actions the delegation allows'],
  ['Bailment and consent', 'The agreed purpose, entrusted work or resources, permitted use, and obligations'],
  ['Constraints', 'Limits that still apply, including amount, purpose, and policy'],
  ['Decision evidence', 'The record the actor relied on for this action'],
  ['Action', 'The specific act being authorized or attested'],
  ['Outcome', 'What occurred after the action was taken'],
  ['Revocation state', 'Whether the delegation was still valid at the time'],
  ['Provider evidence', 'Separate references to payment-provider results and any applicable provider-issued coverage terms'],
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
          authority, observes agreed bailment terms and applicable constraints,
          and has an attributable outcome.
        </Lede>
        <div className="mt-6 max-w-prose">
          <Disclaimer>
            Proof of Authority is a working category concept. It is not a new
            cryptographic primitive and it is not an industry standard.
            The{' '}
            <Link href="/status" className="underline">release record</Link>
            {' '}and deployment evidence establish supported receipt formats
            and verification paths; this category name does not define a
            completed interoperability standard.
          </Disclaimer>
        </div>
      </Section>
      <Section className="py-8">
        <H2>What the claim has to carry</H2>
        <Lede className="mt-4 max-w-prose">
          The category calls for a portable record connecting the parties,
          agreement, limits, evidence, action, outcome, and revocation state.
          Provider records retain their own issuers and verification rules.
          These fields describe the claim’s contents, rather than a published
          interoperability profile.
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
        <H2>The controls behind the claim</H2>
        <Lede className="mt-4 max-w-prose">
          EXOCHAIN’s authority, consent, bailment, revocation, governance, and
          trust-receipt components provide the foundations. A deployment must
          establish where each control runs, which actions it covers, and how
          an independent party verifies the evidence. A successful tool call
          or payment alone cannot establish that the full authority chain was
          valid.
        </Lede>
        <p className="mt-4 max-w-prose text-base text-brand-midnight/80">
          For a service purchase, the record should connect what the agent was
          authorized to buy, the work entrusted under the bailment, the
          execution result, and the payment provider’s evidence. Any bond or
          insurance remains a separately issued provider instrument with its
          own covered obligations and claims route. The authority claim does
          not itself settle a payment or create coverage.
        </p>
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
            Developer integration
          </Link>
        </p>
      </Section>
      <PilotBanner />
    </>
  );
}
