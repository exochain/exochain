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
import { Pre } from '@/components/ui/Code';
import { Pill } from '@/components/ui/Pill';
import { LinkButton } from '@/components/ui/Button';
import { Disclaimer } from '@/components/ui/Disclaimer';
import { IllustrativeCalls } from '@/components/commercial/IllustrativeCalls';
import { PilotBanner } from '@/components/commercial/PilotBanner';
import { publicMetadata, RELEASE_VERSION } from '@/lib/public-site';

export const metadata = publicMetadata({
  title: 'Developers',
  description:
    'The intended EXOCHAIN developer experience is two calls: verify delegated authority, then attest the outcome. The verify and attest snippet is illustrative API design, not the current SDK.',
  path: '/developers',
});

const CURRENT_SDK = `import { ExochainClient, PROTOCOL_VERSION } from '@exochain/sdk';

// PROTOCOL_VERSION in the ${RELEASE_VERSION} TypeScript SDK is "0.2.7".
// Namespaces on ExochainClient: identity, consent, governance, authority, economy.
// discover() and health() are real methods. verify() and attest() are not.

const client = new ExochainClient({
  baseUrl: 'https://gateway.example',
});

const discovery = await client.discover();
const health = await client.health();`;

export default function DevelopersPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Developers</Eyebrow>
        <H1 className="mt-3">Two calls. Verify authority. Produce evidence.</H1>
        <Lede className="mt-5 max-w-prose">
          Adoption has to stay small even when the platform is not. The
          intended developer experience is to verify that a proposed action
          sits inside delegated authority, then attest the decision and its
          outcome.
        </Lede>
        <div className="mt-6 flex flex-wrap gap-2">
          <Pill tone="signal">beta {RELEASE_VERSION}</Pill>
          <Pill tone="unstable">illustrative API</Pill>
          <Pill tone="neutral">Apache-2.0 core</Pill>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Target shape</H2>
        <div className="mt-6">
          <IllustrativeCalls />
        </div>
      </Section>

      <Section className="py-8">
        <H2>What has to be true around those two calls</H2>
        <div className="mt-6 grid md:grid-cols-2 gap-4">
          {[
            ['Freshness and revocation', 'A stale or revoked delegation fails closed before the action runs.'],
            ['Evidence bound to the action', 'The proof cites this action, not a general permission to act later.'],
            ['Enforcement at execution', 'The check sits on the boundary that actually performs the action.'],
            ['Outcome evidence', 'After execution, the receipt records what occurred, not only what was proposed.'],
          ].map(([title, body]) => (
            <Card key={title}>
              <CardHeader title={title} />
              <CardBody>
                <p className="text-sm">{body}</p>
              </CardBody>
            </Card>
          ))}
        </div>
      </Section>

      <Section className="py-8">
        <H2>Current SDK</H2>
        <Lede className="mt-4 max-w-prose">
          The repository ships Rust, TypeScript, and Python SDKs at {RELEASE_VERSION}.
          The TypeScript client below is the current surface. It does not
          implement the illustrative verify and attest calls.
        </Lede>
        <div className="mt-6">
          <Pre caption="Current TypeScript SDK — ExochainClient in @exochain/sdk 0.2.7">
            {CURRENT_SDK}
          </Pre>
          <div className="mt-4">
            <Disclaimer>
              Gateway URLs, API keys, and tenant configuration come from the
              operator. This page does not publish credentials or a hosted
              production endpoint.
            </Disclaimer>
          </div>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Resources</H2>
        <div className="mt-6 grid md:grid-cols-3 gap-5">
          <Card>
            <CardHeader title="Documentation" />
            <CardBody>
              <ul className="text-sm space-y-1.5">
                <li>
                  <Link href="/lynk" className="underline">
                    LYNK Protocol
                  </Link>
                </li>
                <li>
                  <Link href="/docs/getting-started" className="underline">
                    Getting Started
                  </Link>
                </li>
                <li>
                  <Link href="/docs/concepts" className="underline">
                    Concepts
                  </Link>
                </li>
                <li>
                  <Link href="/docs/avc" className="underline">
                    Autonomous Volition Credential docs
                  </Link>
                </li>
                <li>
                  <Link href="/api" className="underline">
                    API reference
                  </Link>
                </li>
              </ul>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Source" />
            <CardBody>
              <p className="text-sm mb-3">
                Apache-2.0 core in the public repository. Commercial products
                that sit on top of the core have their own terms.
              </p>
              <LinkButton
                href="https://github.com/exochain/exochain"
                size="sm"
                variant="secondary"
                external
              >
                github.com/exochain/exochain
              </LinkButton>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Operate" />
            <CardBody>
              <ul className="text-sm space-y-1.5">
                <li>
                  <Link href="/node" className="underline">
                    Run a node
                  </Link>
                </li>
                <li>
                  <Link href="/docs" className="underline">
                    Docs index
                  </Link>
                </li>
                <li>
                  <Link href="/contact#pilot" className="underline">
                    Design-partner pilot
                  </Link>
                </li>
              </ul>
            </CardBody>
          </Card>
        </div>
      </Section>
      <PilotBanner />
    </>
  );
}
