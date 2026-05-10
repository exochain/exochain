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

import { AppPageHead } from '@/components/content/AppPageHead';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Pre } from '@/components/ui/Code';
import { Pill } from '@/components/ui/Pill';

export const metadata = { title: 'Validate AVC' };

export default function Page() {
  return (
    <>
      <AppPageHead
        eyebrow="Extranet · AVCs"
        title="Validate an AVC"
        lede="Paste an AVC token or upload JSON. Validation is fail-closed and deterministic."
      />
      <div className="grid lg:grid-cols-[1fr_1fr] gap-6">
        <Card>
          <CardHeader title="Input" />
          <CardBody>
            <form className="space-y-4 text-sm">
              <label className="block">
                <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Token (JWT-like) or JSON</div>
                <textarea className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent font-mono" rows={10} placeholder="eyJ…" />
              </label>
              <button type="button" className="border hairline rounded-sm px-3 py-2 text-sm bg-ink text-vellum-soft">
                Validate (placeholder)
              </button>
            </form>
          </CardBody>
        </Card>
        <Card>
          <CardHeader
            title="Result · sample"
            right={<Pill tone="verify">PASS</Pill>}
          />
          <CardBody>
            <Pre caption="Sample validator output">
{`{
  "result": "PASS",
  "avc_id": "avc_001",
  "subject_actor_id": "actor_003",
  "issuer_actor_id": "actor_002",
  "checks": {
    "signature":      "PASS",
    "validity_window":"PASS",
    "subject_active": "PASS",
    "issuer_active":  "PASS",
    "scope_subset":   "PASS",
    "policy_eval":    "PASS",
    "revocation":     "PASS"
  },
  "verifier": "exo-gateway/v0.4.2-alpha",
  "timestamp": "2026-05-04T13:11:09Z"
}`}
            </Pre>
          </CardBody>
        </Card>
      </div>
    </>
  );
}
