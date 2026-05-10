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
import { Disclaimer } from '@/components/ui/Disclaimer';

export const metadata = { title: 'Security requests' };

export default function Page() {
  return (
    <>
      <AppPageHead
        eyebrow="Extranet · security"
        title="Security requests"
        lede="Coordinated-disclosure submissions and security questionnaires. Routes to the internal security queue."
      />
      <Card>
        <CardHeader title="Submit a finding or request" />
        <CardBody className="space-y-4">
          <Disclaimer>
            For active production-impacting findings, also email{' '}
            <code>security@exochain.io</code> directly.
          </Disclaimer>
          <form className="space-y-4 text-sm">
            <label className="block">
              <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Type</div>
              <select className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent">
                <option>Vulnerability disclosure</option>
                <option>Security questionnaire response</option>
                <option>Penetration test plan</option>
              </select>
            </label>
            <label className="block">
              <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Summary</div>
              <textarea className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent min-h-[120px]" />
            </label>
            <button className="border hairline rounded-sm px-3 py-2 bg-ink text-vellum-soft">
              Submit (placeholder)
            </button>
          </form>
        </CardBody>
      </Card>
    </>
  );
}
