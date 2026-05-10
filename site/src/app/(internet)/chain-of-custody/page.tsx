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

import { Section, Eyebrow, H1, H2, Lede } from '@/components/ui/Section';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { CustodyFlowDiagram } from '@/components/diagrams/CustodyFlow';
import { Pill } from '@/components/ui/Pill';

export const metadata = { title: 'Chain-of-Custody for AI' };

export default function ChainOfCustodyPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Chain-of-custody</Eyebrow>
        <H1 className="mt-3">
          Chain-of-custody for autonomous execution.
        </H1>
        <Lede className="mt-5 max-w-prose">
          In evidentiary contexts, chain-of-custody is the documentation that
          shows who held an item, when, and under what authority — preserved
          unbroken from origin to use. EXOCHAIN extends that discipline to
          autonomous action.
        </Lede>
      </Section>

      <Section className="py-8">
        <div className="border hairline rounded-md p-4">
          <CustodyFlowDiagram />
        </div>
      </Section>

      <Section className="py-8">
        <H2>What chain-of-custody preserves</H2>
        <div className="mt-6 grid md:grid-cols-2 gap-5">
          <Card>
            <CardHeader title="Sequence" />
            <CardBody>
              <p className="text-sm">
                The blockchain mechanism preserves order. Each block extends
                the prior block&apos;s hash, and the order in which receipts are
                committed cannot be revised after finality without detection.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Responsibility" />
            <CardBody>
              <p className="text-sm">
                Chain-of-custody preserves <em>responsibility</em>. Every
                action references the credential that authorized it, the
                principal that issued the credential, and the consent, policy,
                and revocation state in effect when the action occurred.
              </p>
            </CardBody>
          </Card>
        </div>
        <div className="mt-6 flex flex-wrap gap-2">
          <Pill tone="neutral">Blockchain proves sequence.</Pill>
          <Pill tone="custody">Chain-of-custody proves responsibility.</Pill>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Revocation cascades</H2>
        <div className="prose-exo max-w-prose">
          <p>
            Revocation is a first-class operation on the credential graph.
            When an issuer revokes an AVC, every credential derived from it
            inherits the revocation. Already-issued receipts remain as
            evidence of past authorization; future actions under the revoked
            credential fail-closed at validation.
          </p>
        </div>
      </Section>
    </>
  );
}
