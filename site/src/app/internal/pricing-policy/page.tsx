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

import { IntPageHead, StepUpRequired, QuorumRequired } from '@/components/content/IntPageHead';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Pill } from '@/components/ui/Pill';
import { Pre } from '@/components/ui/Code';

export const metadata = { title: 'Pricing policy' };

export default function Page() {
  return (
    <>
      <IntPageHead
        eyebrow="Intranet · governance"
        title="Pricing policy"
        lede="Active pricing must remain zero. Future config is staged behind feature flag and quorum."
        pills={
          <>
            <Pill tone="custody">launch_policy_zero</Pill>
            <StepUpRequired />
            <QuorumRequired />
          </>
        }
      />

      <div className="grid lg:grid-cols-2 gap-5">
        <Card>
          <CardHeader title="Active policy (read-only)" />
          <CardBody>
            <Pre>
{`{
  "policy_version": "alpha-launch-1",
  "default_amount": "0",
  "currency": "EXO",
  "default_zero_fee_reason": "launch_policy_zero",
  "scope_overrides": [
    { "domain": "*", "amount": "0", "reason": "launch_policy_zero" }
  ]
}`}
            </Pre>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Future config (staged)" />
          <CardBody className="text-sm">
            <p>Future pricing parameters can be authored here. They are not active.</p>
            <Pre>
{`{
  "policy_version": "v1-pending",
  "default_amount": "0",
  "scope_overrides": [
    { "domain": "research.*", "amount": "0", "reason": "humanitarian_carve_out" }
  ],
  "activates_at": null,
  "requires_quorum": 7
}`}
            </Pre>
            <button className="mt-3 border hairline rounded-sm px-3 py-2 text-sm bg-ink text-vellum-soft">
              Save staged policy (placeholder)
            </button>
          </CardBody>
        </Card>
      </div>
    </>
  );
}
