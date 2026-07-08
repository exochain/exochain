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
          Issue and validate AVCs. Generate trust receipts. Run a node. The
          Rust SDK is the reference; Node/TypeScript and Python are on the
          roadmap.
        </Lede>
        <div className="mt-6 flex flex-wrap gap-2">
          <Pill tone="signal">alpha</Pill>
          <Pill tone="unstable">unstable APIs</Pill>
        </div>
      </Section>

      <Section className="py-8">
        <H2>Quickstart</H2>
        <div className="mt-6 grid lg:grid-cols-2 gap-5">
          <Card>
            <CardHeader eyebrow="01" title="Install the SDK" />
            <CardBody>
              <Pre>
{`# Cargo (Rust reference)
cargo add exochain-sdk

# Roadmap
# npm install @exochain/sdk    (v0.5)
# pip install exochain         (v0.5)`}
              </Pre>
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="02" title="Register an actor" />
            <CardBody>
              <Pre>
{`use exochain_sdk::{Client, ActorKind};

let client = Client::connect_default().await?;
let actor = client.register_actor(
  ActorKind::Agent,
  "Aperture Procurement Agent",
  parent_org_id,
).await?;`}
              </Pre>
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="03" title="Issue an AVC" />
            <CardBody>
              <Pre>
{`let avc = client.issue_avc(IssueAvcParams {
  subject: actor.id,
  policy_domain: "aperture.procurement".into(),
  scope: vec!["procure.search","procure.quote","procure.purchase"],
  constraints: serde_json::json!({"ceiling_usd": 50_000}),
  not_after: now + Duration::days(180),
}).await?;`}
              </Pre>
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="04" title="Validate, then act" />
            <CardBody>
              <Pre>
{`let v = client.validate_avc(&avc.token).await?;
match v {
  Validation::Pass(scope) => agent.act(scope).await?,
  Validation::Fail(reason) => abort(reason),
}`}
              </Pre>
            </CardBody>
          </Card>
          <Card>
            <CardHeader eyebrow="05" title="Generate a trust receipt" />
            <CardBody>
              <Pre>
{`let receipt = client.emit_trust_receipt(EmitParams {
  avc_id: avc.id,
  action_descriptor: "procure.purchase:po-2026-0234",
  outcome: Outcome::Permitted,
}).await?;`}
              </Pre>
            </CardBody>
          </Card>
          <Card>
            <CardHeader
              eyebrow="06"
              title="Settlement (zero-priced launch policy)"
            />
            <CardBody>
              <Pre>
{`let quote = client.settlement_quote(receipt.id).await?;
assert_eq!(quote.amount, "0");           // launch_policy_zero
let sr = client.commit_settlement(quote).await?;
assert_eq!(sr.amount, "0");`}
              </Pre>
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
                Apache-2.0 reference implementation. The public repository
                link is forthcoming.
              </p>
              <LinkButton href="/contact" size="sm" variant="secondary">
                Request access
              </LinkButton>
            </CardBody>
          </Card>
        </div>
      </Section>
    </>
  );
}
