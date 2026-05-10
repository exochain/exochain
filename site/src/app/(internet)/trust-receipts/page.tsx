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
import { Pre } from '@/components/ui/Code';
import { ZeroPriceBanner } from '@/components/ui/ZeroPriceBanner';
import { ZeroPricedSettlementDiagram } from '@/components/diagrams/ZeroPricedSettlement';

export const metadata = { title: 'Trust Receipts' };

export default function TrustReceiptsPage() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Trust Receipts</Eyebrow>
        <H1 className="mt-3">Evidence that an autonomous action was authorized.</H1>
        <Lede className="mt-5 max-w-prose">
          A trust receipt is a hash-chained, signed record that proves
          identity, authority, consent, policy, action, timestamp,
          revocation state, and custody hash for a single execution event.
        </Lede>
      </Section>

      <Section className="py-8">
        <H2>What a receipt asserts</H2>
        <div className="mt-6 grid md:grid-cols-3 gap-5 text-sm">
          <Card>
            <CardHeader eyebrow="Who" title="Identity & authority" />
            <CardBody>
              References the acting actor and the AVC that authorized the
              action, including the full delegation chain.
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="What" title="Action & policy" />
            <CardBody>
              Records the action descriptor, the policy domain in effect,
              the policy hash at execution time, and the outcome:
              <code> permitted · denied · partial</code>.
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="Where in time" title="Sequence & custody" />
            <CardBody>
              Carries a custody hash linked to the prior receipt for the same
              actor, plus a deterministic timestamp and signature.
            </CardBody>
          </Card>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Anatomy</H2>
        <div className="mt-5">
          <Pre caption="Sample trust receipt · human-readable view">
            {`{
  "id": "tr_0003",
  "avc_id": "avc_001",
  "actor_id": "actor_003",
  "policy_hash": "sha3:bb01…aa44",
  "action_descriptor": "procure.purchase:po-2026-0234",
  "outcome": "permitted",
  "custody_hash": "sha3:0003…cccc",
  "prev_hash":    "sha3:0002…bbbb",
  "timestamp": "2026-02-13T09:22:46Z",
  "signature": { "algorithm": "ML-DSA-65", "value": "0xa11d…f0c2" }
}`}
          </Pre>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Trust receipt vs. settlement receipt</H2>
        <div className="prose-exo max-w-prose">
          <p>
            Trust receipts always exist when an authorized autonomous action
            occurs. Settlement receipts exist when the economic layer is
            invoked. The two layers are independent: AVC validity does not
            consult pricing, and settlement issuance does not gate trust.
          </p>
          <p>
            Under the launch policy, every settlement receipt carries
            <code> amount = 0 EXO</code> with an explicit{' '}
            <code>ZeroFeeReason</code>. The transaction mechanism is live,
            preserved for the day governance enables nonzero pricing.
          </p>
        </div>
      </Section>

      <Section className="py-8">
        <ZeroPriceBanner />
      </Section>

      <Section className="py-8">
        <H2>Settlement under the launch policy</H2>
        <div className="mt-6 border hairline rounded-md p-4">
          <ZeroPricedSettlementDiagram />
        </div>
      </Section>
    </>
  );
}
