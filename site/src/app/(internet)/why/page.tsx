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
import { Pill } from '@/components/ui/Pill';

export const metadata = { title: 'Why EXOCHAIN' };

export default function WhyPage() {
  return (
    <>
      <Section className="pt-16 pb-10">
        <Eyebrow>Why</Eyebrow>
        <H1 className="mt-3">
          Autonomous systems can act faster than institutions can verify
          authority.
        </H1>
        <Lede className="mt-5 max-w-prose">
          Identity systems prove who an actor is. Access controls decide what
          they can call. Logs record what they did. None of these, alone or
          together, give boards, auditors, regulators, or counterparties what
          they actually need: an evidentiary chain that ties a specific
          autonomous action to a specific delegated authority, with consent,
          policy, and revocation state preserved.
        </Lede>
      </Section>

      <Section className="py-10">
        <H2>The gap</H2>
        <div className="mt-6 grid md:grid-cols-3 gap-5">
          <Card>
            <CardHeader eyebrow="Identity" title="Necessary, not sufficient" />
            <CardBody>
              <p className="text-sm">
                Knowing an agent is who it claims to be is the start of
                accountability, not the end. An identified agent operating
                outside its authorized scope is still operating outside its
                authorized scope.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader
              eyebrow="Access control"
              title="Local, not portable"
            />
            <CardBody>
              <p className="text-sm">
                ACLs and IAM rules live inside individual systems. They do not
                travel between organizations or between agents. Cross-agent
                delegation is invisible to the systems being acted upon.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="Logs" title="After-the-fact, untrusted" />
            <CardBody>
              <p className="text-sm">
                Logs describe behavior but do not prove authority for that
                behavior. They can be tampered with, lost, or selectively
                produced. They are a record of the system, not of the
                relationship between principal and subject.
              </p>
            </CardBody>
          </Card>
        </div>
      </Section>

      <Section className="py-10">
        <H2>The solution</H2>
        <Lede className="mt-4 max-w-prose">
          Chain-of-custody for autonomous execution. Each step in the
          delegation graph carries a signed credential. Each action produces a
          signed, hash-chained receipt that references the credential, the
          policy, the consent, and the outcome. Revocation is first-class and
          cascades.
        </Lede>
        <div className="mt-6 flex flex-wrap gap-2">
          <Pill tone="custody">credentialed volition</Pill>
          <Pill tone="custody">evidentiary execution</Pill>
          <Pill tone="custody">revocation as a primitive</Pill>
        </div>
      </Section>

      <Section className="py-10">
        <H2>Worked examples</H2>
        <div className="mt-6 grid md:grid-cols-3 gap-5">
          <Card>
            <CardHeader title="Delegated procurement" />
            <CardBody>
              <p className="text-sm">
                A finance leader delegates an agent to purchase office goods up
                to a fixed ceiling, from a vendor allowlist, for a quarter.
                The agent in turn delegates a narrower scope to a sub-agent.
                Each purchase yields a receipt that references the entire
                delegation chain. Revocation at any layer cascades.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Cross-org research access" />
            <CardBody>
              <p className="text-sm">
                A research consortium grants a holon read-only access to a
                shared dataset for the duration of an approved study. The
                holon&apos;s verifier daemon produces a receipt for every read.
                When the study closes, the consortium revokes; outstanding
                receipts remain valid evidence of past access.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Operational AI assist" />
            <CardBody>
              <p className="text-sm">
                A clinical operations team delegates an assistive agent to
                triage non-clinical workflows under strict policy constraints.
                Every action carries a receipt that an auditor can later
                verify against the issued AVC and the active policy at
                execution time.
              </p>
            </CardBody>
          </Card>
        </div>
      </Section>
    </>
  );
}
