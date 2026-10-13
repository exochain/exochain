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

import { Pre } from '@/components/ui/Code';
import { Disclaimer } from '@/components/ui/Disclaimer';

const ILLUSTRATIVE_SOURCE = `const authority = await exochain.verify({
  agent: agentIdentity,
  action: proposedAction,
  mandate: delegatedAuthority,
  context: decisionEvidence
});

if (!authority.allowed) {
  throw new Error("Not authorized");
}

const receipt = await exochain.attest({
  authority,
  decision: proposedAction,
  outcome: executionResult
});`;

export function IllustrativeCalls() {
  return (
    <div>
      <Pre caption="Illustrative API design — not the current EXOCHAIN SDK">
        {ILLUSTRATIVE_SOURCE}
      </Pre>
      <div className="mt-4">
        <Disclaimer>
          Illustrative API design, not the current EXOCHAIN SDK. Proof of
          Authority remains a working category concept. A production call
          sequence still has to check freshness and revocation, bind evidence
          to the exact action, enforce the decision at the execution boundary,
          and record outcome evidence after execution.
        </Disclaimer>
      </div>
    </div>
  );
}
