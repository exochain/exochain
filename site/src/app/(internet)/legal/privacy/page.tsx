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

import { Section, Eyebrow, H1, H2 } from '@/components/ui/Section';
import { Disclaimer } from '@/components/ui/Disclaimer';

export const metadata = { title: 'Privacy' };

export default function Page() {
  return (
    <Section className="py-12 max-w-prose">
      <Eyebrow>Legal</Eyebrow>
      <H1 className="mt-3">Privacy</H1>
      <div className="prose-exo mt-6">
        <Disclaimer>
          This is a v0 placeholder. Counsel will review and finalize before
          public launch.
        </Disclaimer>
        <h2>What we collect</h2>
        <p>
          For the public site we collect minimal request metadata required
          to operate the service. We do not run third-party advertising
          trackers. Analytics, when added, will be privacy-preserving and
          documented in the Trust Center before deployment.
        </p>
        <h2>Authenticated surfaces</h2>
        <p>
          Account information is what you provide at sign-up: email, role,
          organization. API key usage is logged for security and rate
          limiting.
        </p>
        <h2>Data subject requests</h2>
        <p>
          Contact <code>privacy@exochain.io</code> for access, correction,
          or deletion requests. We will respond within timelines required
          by applicable law.
        </p>
      </div>
    </Section>
  );
}
