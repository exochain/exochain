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

import { LinkButton } from '@/components/ui/Button';
import { Section, H2, Lede } from '@/components/ui/Section';

export function PilotBanner() {
  return (
    <Section className="py-16" id="deployment">
      <span id="pilot" aria-hidden="true" />
      <div className="border hairline rounded-md bg-brand-white/70 px-6 py-10 md:px-10">
        <H2>Put accountable agent commerce to work.</H2>
        <Lede className="mt-4 max-w-prose">
          Bring a workflow, the parties involved, and the outcome each must
          be able to verify. We will scope the authority model, commercial
          obligations, integrations, and acceptance evidence for your deployment.
          A focused pilot is available as an entry point.
        </Lede>
        <div className="mt-6 flex flex-wrap gap-3">
          <LinkButton href="/contact#deployment" size="lg">
            Explore enterprise deployment
          </LinkButton>
          <LinkButton href="/developers" variant="secondary" size="lg">
            Developers and SDK
          </LinkButton>
        </div>
      </div>
    </Section>
  );
}
