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

import { IntPageHead } from '@/components/content/IntPageHead';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';

export const metadata = { title: 'Releases' };

export default function Page() {
  return (
    <>
      <IntPageHead
        eyebrow="Intranet · releases"
        title="Release notes"
        lede="This console does not publish release notes. The reviewed publication record is the public status page."
      />
      <div className="grid md:grid-cols-2 gap-5">
          <Card>
            <CardHeader eyebrow="Published" title="See /status" />
            <CardBody className="text-sm">
              Earlier cards on this page named v0.4.2-alpha and v0.4.1-alpha.
              Those tags are not EXOCHAIN releases. Use the public status page
              for the published version, spec, and default-off boundaries.
            </CardBody>
          </Card>
      </div>
    </>
  );
}
