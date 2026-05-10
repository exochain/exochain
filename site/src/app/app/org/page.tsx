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

export const metadata = { title: 'Organization' };

export default function Page() {
  return (
    <>
      <AppPageHead
        eyebrow="Extranet · organization"
        title="Aperture Holdings"
        lede="Organization profile, verified domains, default policy domain, designated auditors."
      />
      <div className="grid md:grid-cols-2 gap-5">
        <Card>
          <CardHeader title="Profile" />
          <CardBody>
            <dl className="text-sm grid grid-cols-[140px_1fr] gap-y-2">
              <dt className="text-ink/60 dark:text-vellum-soft/60">Legal name</dt><dd>Aperture Holdings, Inc.</dd>
              <dt className="text-ink/60 dark:text-vellum-soft/60">Domain</dt><dd>aperture.example</dd>
              <dt className="text-ink/60 dark:text-vellum-soft/60">Org actor id</dt><dd className="font-mono">actor_002</dd>
              <dt className="text-ink/60 dark:text-vellum-soft/60">Default policy domain</dt><dd>aperture.procurement</dd>
            </dl>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Designated auditors" />
          <CardBody>
            <ul className="text-sm space-y-1">
              <li>auditor@auditfirm.example · scope: 2026-Q1, 2026-Q2 · time-bounded</li>
            </ul>
          </CardBody>
        </Card>
      </div>
    </>
  );
}
