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
import { PilotBanner } from '@/components/commercial/PilotBanner';
import { publicMetadata } from '@/lib/public-site';
import { loadPublicStatus } from '@/lib/public-status';

export const metadata = publicMetadata({
  title: 'Developers',
  description:
    'Integrate EXOCHAIN at the agent action boundary with the documented SDK, gateway discovery, authority controls, and verifiable receipt evidence.',
  path: '/developers',
});

const CURRENT_SDK = `import { ExochainClient } from '@exochain/sdk';

// Use the gateway URL supplied by your deployment operator.
const client = new ExochainClient({
  baseUrl: 'https://gateway.example',
});

const discovery = await client.discover();
const health = await client.health();`;

export default function DevelopersPage() {
  const publicStatus = loadPublicStatus();

  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Developers</Eyebrow>
        <H1 className="mt-3">Build accountable agent workflows.</H1>
        <Lede className="mt-5 max-w-prose">
          Connect the systems your agents already use to delegated authority,
          consent, policy enforcement, and verifiable outcomes. Start with
          discovery, then integrate the controls at the boundary where your
          application executes an action.
        </Lede>
        <div className="mt-6 flex flex-wrap gap-2">
          <Pill tone="signal">{publicStatus.maturity} v{publicStatus.publication.version}</Pill>
          <Pill tone="neutral">Apache-2.0 core</Pill>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Build around the enforcement boundary</H2>
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
        <H2>Start with the documented SDK</H2>
        <Lede className="mt-4 max-w-prose">
          The TypeScript client exposes discovery and health methods. This
          example reads the configured gateway; authorization and receipt
          emission require the corresponding APIs and deployment credentials.
          Select package versions from the{' '}
          <a href={publicStatus.publication.github_url} className="underline">published release record</a>.
        </Lede>
        <div className="mt-6">
          <Pre caption="TypeScript SDK — gateway discovery and health">
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
        <p className="mt-4 text-sm">
          <a href="https://github.com/exochain/exochain/tree/main/packages/exochain-sdk" className="underline">
            TypeScript SDK source and usage
          </a>
          {' · '}
          <Link href="/status" className="underline">Release scope and capability boundaries</Link>
        </p>
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
                  <Link href="/contact#deployment" className="underline">
                    Enterprise deployment
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
