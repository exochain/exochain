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

export const metadata = { title: 'Support' };

export default function Page() {
  return (
    <>
      <AppPageHead
        eyebrow="Extranet · support"
        title="Support"
        lede="Open a ticket. We respond by severity. For security findings, use the security requests page."
      />
      <Card>
        <CardHeader title="New ticket" />
        <CardBody>
          <form className="space-y-4 text-sm">
            <label className="block">
              <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Subject</div>
              <input className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent" />
            </label>
            <label className="block">
              <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Severity</div>
              <select className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent">
                <option>P3 · question</option>
                <option>P2 · degraded</option>
                <option>P1 · production impact</option>
              </select>
            </label>
            <label className="block">
              <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Details</div>
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
