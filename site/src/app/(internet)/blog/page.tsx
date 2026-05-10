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

import { Section, Eyebrow, H1, Lede } from '@/components/ui/Section';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';

export const metadata = { title: 'Field Notes' };

const POSTS = [
  {
    date: '2026-04-30',
    title: 'Why we shipped the economy with prices set to zero',
    excerpt:
      'Trust is not paywalled. Building the full settlement mechanism with launch prices set to zero lets us preserve transaction mechanics while keeping the human and machine trust layer accessible.'
  },
  {
    date: '2026-04-12',
    title: 'Validator attestation, the alpha way',
    excerpt:
      'A practical writeup on what hardware attestation we are checking, what we are not yet checking, and how the observation period catches surprises before quorum.'
  },
  {
    date: '2026-03-22',
    title: 'Receipts after revocation',
    excerpt:
      'Trust receipts are evidence of the past, not predictions of the future. We explain why revocation cascades through the credential graph but does not erase already-issued receipts.'
  }
];

export default function Page() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Field Notes</Eyebrow>
        <H1 className="mt-3">Notes from the protocol team.</H1>
        <Lede className="mt-5 max-w-prose">
          Engineering, governance, and ecosystem updates. Short on
          marketing, long on substance.
        </Lede>
      </Section>
      <Section className="py-6">
        <div className="grid md:grid-cols-2 gap-5">
          {POSTS.map((p) => (
            <Card key={p.title}>
              <CardHeader eyebrow={p.date} title={p.title} />
              <CardBody>
                <p className="text-sm">{p.excerpt}</p>
              </CardBody>
            </Card>
          ))}
        </div>
      </Section>
    </>
  );
}
