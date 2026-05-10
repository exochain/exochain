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
import { CustodyFlowDiagram } from '@/components/diagrams/CustodyFlow';
import { IdentityToCustodyDiagram } from '@/components/diagrams/IdentityToCustody';
import { MechanismVsPurposeDiagram } from '@/components/diagrams/MechanismVsPurpose';
import { ZeroPriceBanner } from '@/components/ui/ZeroPriceBanner';
import { mockNetworkMetrics } from '@/lib/mock-data';

export default function HomePage() {
  return (
    <>
      <Section className="surface-grain pt-16 md:pt-24 pb-12">
        <div className="grid md:grid-cols-[1.2fr_1fr] gap-10 items-end">
          <div>
            <Eyebrow>EXOCHAIN · custody-native blockchain · alpha</Eyebrow>
            <H1 className="mt-4">
              EXOCHAIN is chain-of-custody for autonomous execution.
            </H1>
            <Lede className="mt-6 max-w-prose">
              Credential autonomous intent, verify delegated authority, and
              preserve evidentiary custody for agents, holons, humans, and
              AI-native systems.
            </Lede>
            <div className="mt-8 flex flex-wrap gap-3">
              <LinkButton href="/developers" size="lg">
                Build on EXOCHAIN
              </LinkButton>
              <LinkButton href="/contact" variant="secondary" size="lg">
                Talk to us
              </LinkButton>
              <LinkButton href="/avc" variant="ghost" size="lg">
                What is an AVC? →
              </LinkButton>
            </div>
            <div className="mt-6 flex flex-wrap items-center gap-2 text-sm">
              <Pill tone="signal">alpha</Pill>
              <Pill tone="custody">zero-priced launch</Pill>
              <span className="text-ink/60 dark:text-vellum-soft/60">
                Network mode: {mockNetworkMetrics.networkMode} · last release{' '}
                <span className="font-mono">
                  {mockNetworkMetrics.lastReleaseTag}
                </span>{' '}
                · <Link href="/status" className="underline">status</Link>
              </span>
            </div>
          </div>
          <div className="border hairline rounded-md p-4">
            <CustodyFlowDiagram />
            <p className="text-xs text-ink/60 dark:text-vellum-soft/60 mt-3">
              Human → AVC → Agent → EXOCHAIN → Trust Receipt. Revocation
              cascades back through the credential graph.
            </p>
          </div>
        </div>
      </Section>

      <Section className="py-12">
        <div className="border hairline rounded-md p-6 md:p-10">
          <Eyebrow>The frame</Eyebrow>
          <p className="mt-3 text-2xl md:text-3xl font-semibold tracking-tightish leading-tight max-w-3xl">
            Blockchain is the mechanism. Chain-of-custody is the purpose.
          </p>
          <p className="mt-4 text-ink/75 dark:text-vellum-soft/75 max-w-2xl">
            EXOCHAIN preserves every property you expect from a serious
            distributed ledger — deterministic ordering, cryptographic
            signatures, quorum, finality — and reframes the chain as a
            chain-of-custody for autonomous action.
          </p>
          <div className="mt-8">
            <MechanismVsPurposeDiagram />
          </div>
        </div>
      </Section>

      <Section className="py-12">
        <Eyebrow>The stack</Eyebrow>
        <H2 className="mt-3 max-w-2xl">
          Identity proves who an actor is. AVC proves what it may pursue.
          EXOCHAIN proves what actually happened.
        </H2>
        <div className="mt-10">
          <IdentityToCustodyDiagram />
        </div>
        <div className="mt-10 grid md:grid-cols-3 gap-5">
          <Card>
            <CardHeader
              eyebrow="Pillar 1"
              title="Autonomous Volition Credentials"
            />
            <CardBody>
              <p className="text-sm text-ink/80 dark:text-vellum-soft/80">
                Portable, signed, machine-verifiable credentials that declare
                what an autonomous actor is authorized to pursue{' '}
                <em>before</em> it acts. Validation is fail-closed. Delegation
                strictly narrows scope.
              </p>
              <Link
                href="/avc"
                className="mt-3 inline-block text-sm underline"
              >
                Read the AVC explainer →
              </Link>
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="Pillar 2" title="Trust Receipts" />
            <CardBody>
              <p className="text-sm text-ink/80 dark:text-vellum-soft/80">
                Hash-chained, signed records proving identity, authority,
                consent, policy, action, timestamp, revocation state, and
                custody hash for each execution event.
              </p>
              <Link
                href="/trust-receipts"
                className="mt-3 inline-block text-sm underline"
              >
                See receipt anatomy →
              </Link>
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="Pillar 3" title="Zero-priced launch settlement" />
            <CardBody>
              <p className="text-sm text-ink/80 dark:text-vellum-soft/80">
                The economic transaction mechanism is live. Every active price
                resolves to <span className="font-mono">0 EXO</span> with an
                explicit <span className="font-mono">ZeroFeeReason</span>.
                Trust is not paywalled.
              </p>
              <Link
                href="/custody-native-blockchain#economy"
                className="mt-3 inline-block text-sm underline"
              >
                How it works →
              </Link>
            </CardBody>
          </Card>
        </div>
      </Section>

      <Section className="py-12">
        <ZeroPriceBanner />
      </Section>

      <Section className="py-12">
        <Eyebrow>For</Eyebrow>
        <div className="mt-6 grid md:grid-cols-3 gap-5">
          <Card>
            <CardHeader title="Developers" />
            <CardBody>
              <p className="text-sm">
                Issue and validate AVCs. Generate trust receipts. Run a node.
                The Rust SDK is shipping; Node and Python are on the roadmap.
              </p>
              <div className="mt-3">
                <LinkButton href="/developers" size="sm">
                  Quickstart
                </LinkButton>
              </div>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Enterprises" />
            <CardBody>
              <p className="text-sm">
                Stand up an organization, register actors and policy domains,
                issue scoped AVCs to your agents, and export deterministic
                audit packets.
              </p>
              <div className="mt-3">
                <LinkButton href="/contact" size="sm" variant="secondary">
                  Talk to us
                </LinkButton>
              </div>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Validators · Researchers" />
            <CardBody>
              <p className="text-sm">
                Operate as a custody verifier. Read whitepapers. Engage with
                governance and the open security disclosure program.
              </p>
              <div className="mt-3 flex gap-2">
                <LinkButton href="/node" size="sm" variant="secondary">
                  Node
                </LinkButton>
                <LinkButton href="/research" size="sm" variant="ghost">
                  Research
                </LinkButton>
              </div>
            </CardBody>
          </Card>
        </div>
      </Section>
    </>
  );
}
