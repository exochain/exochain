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
import { Section, Eyebrow, H1, Lede } from '@/components/ui/Section';
import { Pill } from '@/components/ui/Pill';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';

export const metadata = { title: 'API Reference' };

export default function Page() {
  return (
    <Section className="py-12">
      <Eyebrow>API</Eyebrow>
      <H1 className="mt-3">API Reference</H1>
      <Lede className="mt-5 max-w-prose">
        This site does not embed an OpenAPI document. Gateway routes are
        implemented in <code>exo-gateway</code>; treat unpublished URL shapes
        on this page as descriptions, not a contract.
      </Lede>
      <div className="mt-4 flex flex-wrap gap-2">
        <Pill tone="roadmap">Not mounted here</Pill>
        <Pill tone="unstable">0.x</Pill>
      </div>
      <div className="mt-10 grid md:grid-cols-2 gap-5">
        <Card>
          <CardHeader title="Where the routes live" />
          <CardBody>
            <p className="text-sm">
              The endpoint shape is summarized in the Node API doc. Published
              SDK packages are the installable contract; treat gateway URL
              paths as subject to change between minor versions.
            </p>
            <Link
              href="/docs/node-api"
              className="mt-3 inline-block underline text-sm"
            >
              Node API doc →
            </Link>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Not on this site" />
          <CardBody>
              <p className="text-sm">
              This page does not mount a generated OpenAPI viewer and does
              not promise a versioned public snapshot.
            </p>
          </CardBody>
        </Card>
      </div>
    </Section>
  );
}
