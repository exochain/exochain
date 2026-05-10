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

export const metadata = { title: 'Run a Node' };

export default function Page() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Operate</Eyebrow>
        <H1 className="mt-3">Run an EXOCHAIN node.</H1>
        <Lede className="mt-5 max-w-prose">
          Two roles, one binary: <em>node</em> and <em>validator</em>. Nodes
          serve queries and propagate gossip. Validators do the same and
          additionally produce blocks while attesting custody.
        </Lede>
      </Section>
      <Section className="py-8">
        <H2>Operator vs. validator</H2>
        <div className="mt-6 grid md:grid-cols-2 gap-5">
          <Card>
            <CardHeader title="Node operator" />
            <CardBody>
              <p className="text-sm">
                Lower bar. Runs the binary, exposes the gateway surface,
                propagates blocks. Does not require hardware attestation in
                alpha. Onboard at <Link href="/app/nodes" className="underline">/app/nodes</Link>.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Validator operator" />
            <CardBody>
              <p className="text-sm">
                Higher bar. Hardware attestation, key management discipline,
                synchronized time, observation period before joining quorum.
                Onboard at <Link href="/app/validators" className="underline">/app/validators</Link>.
              </p>
            </CardBody>
          </Card>
        </div>
      </Section>
      <Section className="py-8">
        <H2>What you&apos;ll need</H2>
        <ul className="mt-3 list-disc pl-6 text-sm space-y-1.5">
          <li>An organization registered on EXOCHAIN.</li>
          <li>A signing key pair you control. HSM strongly recommended for validators.</li>
          <li>Network: outbound to the validator mesh, inbound for gossip.</li>
          <li>Time: NTP / chronyd or equivalent.</li>
          <li>Storage: durable, snappable, sized for the chain you intend to track.</li>
        </ul>
      </Section>
    </>
  );
}
