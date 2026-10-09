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

export const metadata = { title: 'Developers' };

export default function DevelopersPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Developers</Eyebrow>
        <H1 className="mt-3">Build on EXOCHAIN.</H1>
        <Lede className="mt-5 max-w-prose">
          The published SDKs are libraries. Install them from crates.io, npm,
          or PyPI. API examples live in each package README. This page does
          not show a sample client, because an earlier sample was not the
          SDK API.
        </Lede>
        <div className="mt-6 flex flex-wrap gap-2">
          <Pill tone="signal">beta</Pill>
          <Pill tone="unstable">0.x APIs may change</Pill>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Quickstart</H2>
        <div className="mt-6 grid lg:grid-cols-2 gap-5">
          <Card>
            <CardHeader eyebrow="01" title="Rust" />
            <CardBody>
              <Pre>{`cargo add exochain-sdk`}</Pre>
              <p className="mt-3 text-sm">
                Crate README:{' '}
                <a className="underline" href="https://github.com/exochain/exochain/blob/main/crates/exochain-sdk/README.md">
                  crates/exochain-sdk/README.md
                </a>
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="02" title="TypeScript" />
            <CardBody>
              <Pre>{`npm install @exochain/sdk`}</Pre>
              <p className="mt-3 text-sm">
                Package README:{' '}
                <a className="underline" href="https://github.com/exochain/exochain/blob/main/packages/exochain-sdk/README.md">
                  packages/exochain-sdk/README.md
                </a>
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="03" title="Python" />
            <CardBody>
              <Pre>{`pip install exochain`}</Pre>
              <p className="mt-3 text-sm">
                Package README:{' '}
                <a className="underline" href="https://github.com/exochain/exochain/blob/main/packages/exochain-py/README.md">
                  packages/exochain-py/README.md
                </a>
              </p>
            </CardBody>
          </Card>
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
                    AVC docs
                  </Link>
                </li>
                <li>
                  <Link href="/docs/node-api" className="underline">
                    Node API
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
            <CardHeader title="Operate" />
            <CardBody>
              <ul className="text-sm space-y-1.5">
                <li>
                  <Link href="/node" className="underline">
                    Run a node
                  </Link>
                </li>
                <li>
                  <Link href="/docs/validator-guide" className="underline">
                    Validator guide
                  </Link>
                </li>
                <li>
                  <Link href="/app/validators" className="underline">
                    Validator onboarding
                  </Link>
                </li>
              </ul>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Source" />
            <CardBody>
              <p className="text-sm mb-3">
                Apache-2.0 applies to EXOCHAIN core primitives. The public
                repository is{' '}
                <a className="underline" href="https://github.com/exochain/exochain">
                  github.com/exochain/exochain
                </a>
                .
              </p>
              <LinkButton href="https://github.com/exochain/exochain" size="sm" variant="secondary" external>
                View source
              </LinkButton>
            </CardBody>
          </Card>
        </div>
      </Section>
    </>
  );
}
