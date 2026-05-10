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

export const metadata = { title: 'Security' };

export default function Page() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Security</Eyebrow>
        <H1 className="mt-3">Coordinated disclosure.</H1>
        <Lede className="mt-5 max-w-prose">
          We treat security findings with priority and precision. Reports
          should reach us through the channels below, not through public
          social posts.
        </Lede>
        <div className="mt-4">
          <Pill tone="signal">bug bounty in design — not yet active</Pill>
        </div>
      </Section>

      <Section className="py-8">
        <div className="grid md:grid-cols-2 gap-5">
          <Card>
            <CardHeader title="Email" />
            <CardBody>
              <p className="text-sm">
                <code>security@exochain.io</code>{' '}
                <span className="text-ink/60 dark:text-vellum-soft/60">
                  (PGP key fingerprint published with v0.5)
                </span>
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Scope" />
            <CardBody>
              <p className="text-sm">
                The protocol, the reference Rust implementation,{' '}
                <code>exo-gateway</code>, and the public site under{' '}
                <code>exochain.io</code>. Out-of-scope: third-party
                deployments not operated by us.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="What to include" />
            <CardBody>
              <ul className="list-disc pl-5 text-sm space-y-1">
                <li>Reproduction steps. The fewer assumptions, the better.</li>
                <li>Suspected severity and rationale.</li>
                <li>Intended disclosure timeline.</li>
                <li>Your contact preference for follow-up.</li>
              </ul>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="What we'll do" />
            <CardBody>
              <ul className="list-disc pl-5 text-sm space-y-1">
                <li>Acknowledge within 3 business days.</li>
                <li>Assign severity and CVE if applicable.</li>
                <li>Coordinate disclosure date.</li>
                <li>Credit reporters who request it.</li>
              </ul>
            </CardBody>
          </Card>
        </div>
      </Section>
    </>
  );
}
