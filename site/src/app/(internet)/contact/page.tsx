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

import { ContactForm } from './ContactForm';
import { Section, Eyebrow, H1, Lede } from '@/components/ui/Section';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';

export const metadata = { title: 'Contact' };

export default function Page() {
  return (
    <>
      <Section className="pt-16 pb-8">
        <Eyebrow>Contact</Eyebrow>
        <H1 className="mt-3">Talk to EXOCHAIN.</H1>
        <Lede className="mt-5 max-w-prose">
          We will direct your message to the right team. For urgent
          security findings, please use the responsible-disclosure channel
          on the security page.
        </Lede>
      </Section>
      <Section className="py-8">
        <div className="grid md:grid-cols-[1.2fr_1fr] gap-6">
          <Card>
            <CardHeader title="Early access form" />
            <CardBody>
              <ContactForm />
            </CardBody>
          </Card>
          <div className="space-y-4">
            <Card>
              <CardHeader title="Press" />
              <CardBody>
                <p className="text-sm">press@exochain.io</p>
              </CardBody>
            </Card>
            <Card>
              <CardHeader title="Partnerships" />
              <CardBody>
                <p className="text-sm">partners@exochain.io</p>
              </CardBody>
            </Card>
            <Card>
              <CardHeader title="Security" />
              <CardBody>
                <p className="text-sm">security@exochain.io · see <a className="underline" href="/security">/security</a></p>
              </CardBody>
            </Card>
          </div>
        </div>
      </Section>
    </>
  );
}
