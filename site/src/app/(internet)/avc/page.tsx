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
import { Pre } from '@/components/ui/Code';

export const metadata = { title: 'Autonomous Volition Credentials' };

export default function AVCPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>AVC</Eyebrow>
        <H1 className="mt-3">Autonomous Volition Credentials.</H1>
        <Lede className="mt-5 max-w-prose">
          An AVC is a portable, signed, machine-verifiable credential that
          declares what an autonomous actor is authorized to pursue —{' '}
          <em>before</em> it acts. Validation is fail-closed and
          deterministic. Delegation strictly narrows scope.
        </Lede>
      </Section>

      <Section className="py-10">
        <H2>Identity vs. authority vs. volition vs. execution</H2>
        <div className="mt-6 grid md:grid-cols-4 gap-4 text-sm">
          <Card>
            <CardHeader eyebrow="01" title="Identity" />
            <CardBody>Who an actor is. A signing key, a name, a registration.</CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="02" title="Authority" />
            <CardBody>What an actor may invoke under policy. Often local to a system.</CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="03" title="Volition" />
            <CardBody>
              The delegated operational intent encoded in an AVC. Scoped,
              expiring, revocable, hierarchical.
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="04" title="Execution" />
            <CardBody>
              What the actor actually did. Recorded as a trust receipt.
            </CardBody>
          </Card>
        </div>
      </Section>

      <Section className="py-10">
        <H2>Volition, defined precisely</H2>
        <div className="prose-exo mt-4 max-w-prose">
          <p>
            EXOCHAIN does not claim that AI systems possess consciousness or
            human-like will. <em>Volition</em> here is operational and
            delegated. It refers to the authorized intent that a principal
            (human, organization, agent, or holon) hands to a subject for the
            purpose of autonomous action.
          </p>
          <p>
            Volition is bounded. It has a scope (a set of permitted actions),
            a policy domain, optional constraints (such as a ceiling, an
            allowlist, a region), a validity window, a parent credential
            where applicable, and a signature from the issuer.
          </p>
        </div>
        <div className="mt-6">
          <Disclaimer>
            AVCs are operational credentials, not securities. They confer
            authority to pursue declared actions; they do not represent
            ownership, equity, or revenue rights.
          </Disclaimer>
        </div>
      </Section>

      <Section className="py-10">
        <H2>Worked examples</H2>
        <div className="mt-6 grid md:grid-cols-2 gap-5">
          <Card>
            <CardHeader title="Human → Agent" />
            <CardBody>
              <p className="text-sm">
                A finance leader issues an AVC to a procurement agent. Scope:
                <code> procure.search · procure.quote · procure.purchase</code>.
                Constraints: <code>ceiling_usd ≤ 50000</code>, vendor
                allowlist. Validity: 6 months.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Agent → Sub-Agent (delegation)" />
            <CardBody>
              <p className="text-sm">
                The agent issues a derivative AVC to a sub-agent for a
                narrower window: <code>procure.search · procure.quote</code>{' '}
                only, <code>ceiling_usd ≤ 5000</code>. Validation rejects any
                attempt to widen scope beyond the parent.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Org → Department agent" />
            <CardBody>
              <p className="text-sm">
                An organization delegates a department-scoped agent. Receipts
                reference the org as ultimate principal in the delegation
                chain.
              </p>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Holon participation" />
            <CardBody>
              <p className="text-sm">
                A multi-organization holon issues AVCs to validators it has
                vetted. Holon-issued AVCs participate in custody attestation
                across jurisdictions.
              </p>
            </CardBody>
          </Card>
        </div>
      </Section>

      <Section className="py-10">
        <H2>Anatomy of an AVC</H2>
        <p className="mt-3 text-sm text-ink/70 dark:text-vellum-soft/70 max-w-prose">
          The on-chain canonical encoding is deterministic; the JSON below is
          the human-readable view rendered by the SDK.
        </p>
        <div className="mt-5">
          <Pre caption="Sample AVC · human-readable view">
            {`{
  "id": "avc_001",
  "subject_actor_id": "actor_003",
  "issuer_actor_id": "actor_002",
  "policy_domain_id": "aperture.procurement",
  "scope": {
    "actions": ["procure.search", "procure.quote", "procure.purchase"],
    "constraints": {
      "ceiling_usd": 50000,
      "vendor_allowlist": "aperture-tier1"
    }
  },
  "not_before": "2026-02-12T18:00:00Z",
  "not_after":  "2026-08-12T18:00:00Z",
  "signature": {
    "algorithm": "ML-DSA-65",
    "value": "0xa11d…f0c2"
  }
}`}
          </Pre>
        </div>
      </Section>

      <Section className="py-10">
        <H2>Validation is fail-closed</H2>
        <div className="prose-exo max-w-prose">
          <p>
            Validation does not consult pricing or settlement state. It
            evaluates signature, validity window, scope inclusion, parent
            chain, revocation status, and policy expressions deterministically.
            If any check fails or is indeterminate, validation returns FAIL
            with a structured reason code.
          </p>
          <p>
            This guarantees that trust never depends on the economic layer
            being available, and that pricing changes can never weaken
            credentialing.
          </p>
        </div>
        <div className="mt-5 flex gap-3">
          <Link href="/docs/avc" className="text-sm underline">
            AVC docs →
          </Link>
          <Link href="/trust-receipts" className="text-sm underline">
            How AVCs become receipts →
          </Link>
        </div>
      </Section>
    </>
  );
}
