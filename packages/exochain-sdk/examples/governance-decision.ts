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

/**
 * Example: build a governance decision, cast votes, and check the quorum.
 *
 * Run: node --experimental-strip-types examples/governance-decision.ts
 */

import { Identity, DecisionBuilder, Vote, VoteChoice } from '../dist/index.js';

async function main(): Promise<void> {
  const proposer = await Identity.generate('proposer');

  // Create a decision in the "proposed" lifecycle state.
  const decision = await new DecisionBuilder({
    title: 'Increase validator quorum to 3',
    description: 'Raise the minimum approvals required for ordinary decisions.',
    proposer: proposer.did,
  })
    .decisionClass('ordinary')
    .build();

  console.log('Decision created:', decision.decisionId);

  // Cast a handful of votes.
  const voters = await Promise.all([
    Identity.generate('v1'),
    Identity.generate('v2'),
    Identity.generate('v3'),
    Identity.generate('v4'),
  ]);
  decision.castVote(new Vote({ voter: voters[0]!.did, choice: VoteChoice.Approve }));
  decision.castVote(new Vote({ voter: voters[1]!.did, choice: VoteChoice.Approve }));
  decision.castVote(new Vote({ voter: voters[2]!.did, choice: VoteChoice.Reject }));
  decision.castVote(new Vote({ voter: voters[3]!.did, choice: VoteChoice.Abstain }));

  const quorum = decision.checkQuorum(2);
  console.log('Quorum result:', quorum);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
