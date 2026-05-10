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

import { AppPageHead, AuditNote } from '@/components/content/AppPageHead';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';

export const metadata = { title: 'Audit exports' };

export default function Page() {
  return (
    <>
      <AppPageHead
        eyebrow="Extranet · audit"
        title="Audit packet exports"
        lede="Request a deterministic, signed audit packet by date range and scope."
      />
      <div className="grid lg:grid-cols-[1fr_1fr] gap-6">
        <Card>
          <CardHeader title="Request export" />
          <CardBody>
            <form className="space-y-4 text-sm">
              <div className="grid grid-cols-2 gap-3">
                <label className="block">
                  <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">From</div>
                  <input type="date" className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent" />
                </label>
                <label className="block">
                  <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">To</div>
                  <input type="date" className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent" />
                </label>
              </div>
              <label className="block">
                <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Scope</div>
                <select className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent">
                  <option>All AVCs · all actors</option>
                  <option>AVCs by policy domain</option>
                  <option>Specific actor</option>
                </select>
              </label>
              <button className="border hairline rounded-sm px-3 py-2 bg-ink text-vellum-soft">
                Request export (placeholder)
              </button>
              <AuditNote>Exports are step-up authenticated and recorded in the audit log.</AuditNote>
            </form>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Recent exports" />
          <CardBody>
            <ul className="text-sm divide-y hairline">
              <li className="py-3 flex items-center justify-between">
                <span>2026-Q1 · Aperture · all</span>
                <span className="font-mono text-xs">au_pkt_0011</span>
              </li>
            </ul>
          </CardBody>
        </Card>
      </div>
    </>
  );
}
