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

export const metadata = { title: 'Governance' };

export default function Page() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Governance</Eyebrow>
        <H1 className="mt-3">A constitutional kernel, plus public process.</H1>
        <Lede className="mt-5 max-w-prose">
          EXOCHAIN governance is bounded by invariants the protocol will
          not relax: fail-closed validation, scope narrowing under
          delegation, independence of trust and economy, no
          floating-point arithmetic. Every other decision routes through a
          documented proposal lifecycle.
        </Lede>
      </Section>
      <Section className="py-8">
        <div className="grid md:grid-cols-2 gap-5">
          <Card>
            <CardHeader title="Constitutional invariants" />
            <CardBody>
              <p className="text-sm">
                Enforced by the governance kernel on every governance path.
                Invariants cannot be modified by ordinary amendment.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Proposal lifecycle" />
            <CardBody>
              <ol className="list-decimal pl-5 text-sm space-y-1">
                <li>Draft and commentary.</li>
                <li>Quorum vote.</li>
                <li>Ratification with cooldown.</li>
                <li>Activation behind feature flag.</li>
              </ol>
            </CardBody>
          </Card>
        </div>
        <p className="mt-6 text-sm">
          The public governance documents and traceability matrix live in
          the open source repository under <code>governance/</code>.{' '}
          <Link href="/research" className="underline">Read research →</Link>
        </p>
      </Section>
    </>
  );
}
