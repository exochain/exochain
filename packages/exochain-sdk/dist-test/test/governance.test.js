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
import { test } from 'node:test';
import { strictEqual, notStrictEqual, ok, rejects, throws } from 'node:assert/strict';
import { Decision, DecisionBuilder } from '../src/governance/decision.js';
import { Vote, VoteChoice } from '../src/governance/vote.js';
import { GovernanceError } from '../src/errors.js';
const PROPOSER = 'did:exo:proposer';
function assertLowercaseHash256(value) {
    strictEqual(value.length, 64);
    ok(/^[0-9a-f]{64}$/.test(value));
}
async function baseDecision() {
    return new DecisionBuilder({
        title: 'Fund proposal',
        description: 'Allocate budget',
        proposer: PROPOSER,
    }).build();
}
test('DecisionBuilder produces a decision in proposed state', async () => {
    const d = await baseDecision();
    strictEqual(d.title, 'Fund proposal');
    strictEqual(d.description, 'Allocate budget');
    strictEqual(d.status, 'proposed');
    strictEqual(d.votes.length, 0);
    strictEqual(d.decisionId.length, 64);
});
test('DecisionBuilder rejects empty title', async () => {
    await rejects(async () => new DecisionBuilder({ title: '', description: 'x', proposer: PROPOSER }).build(), GovernanceError);
});
test('DecisionBuilder optional class is surfaced', async () => {
    const d = await new DecisionBuilder({
        title: 't',
        description: 'd',
        proposer: PROPOSER,
    })
        .decisionClass('ordinary')
        .build();
    strictEqual(d.class, 'ordinary');
});
test('castVote appends to the decision', async () => {
    const d = await baseDecision();
    d.castVote(new Vote({ voter: 'did:exo:v1', choice: VoteChoice.Approve }));
    strictEqual(d.votes.length, 1);
    strictEqual(d.votes[0]?.choice, 'approve');
});
test('castVote rejects duplicate voter', async () => {
    const d = await baseDecision();
    d.castVote(new Vote({ voter: 'did:exo:v1', choice: VoteChoice.Approve }));
    throws(() => d.castVote(new Vote({ voter: 'did:exo:v1', choice: VoteChoice.Reject })), GovernanceError);
});
test('checkQuorum tallies approvals vs rejections vs abstentions', async () => {
    const d = await baseDecision();
    d.castVote(new Vote({ voter: 'did:exo:v1', choice: VoteChoice.Approve }));
    d.castVote(new Vote({ voter: 'did:exo:v2', choice: VoteChoice.Approve }));
    d.castVote(new Vote({ voter: 'did:exo:v3', choice: VoteChoice.Reject }));
    d.castVote(new Vote({ voter: 'did:exo:v4', choice: VoteChoice.Abstain }));
    const q = d.checkQuorum(2);
    ok(q.met);
    strictEqual(q.threshold, 2);
    strictEqual(q.totalVotes, 4);
    strictEqual(q.approvals, 2);
    strictEqual(q.rejections, 1);
    strictEqual(q.abstentions, 1);
});
test('checkQuorum reports not-met when below threshold', async () => {
    const d = await baseDecision();
    d.castVote(new Vote({ voter: 'did:exo:v1', choice: VoteChoice.Approve }));
    const q = d.checkQuorum(3);
    strictEqual(q.met, false);
    strictEqual(q.approvals, 1);
});
test('checkQuorum rejects invalid threshold', async () => {
    const d = await baseDecision();
    throws(() => d.checkQuorum(-1), GovernanceError);
    throws(() => d.checkQuorum(1.5), GovernanceError);
});
test('Vote withRationale returns a new vote with rationale', () => {
    const v = new Vote({ voter: 'did:exo:v', choice: VoteChoice.Reject }).withRationale('too risky');
    strictEqual(v.rationale, 'too risky');
});
test('Vote rejects invalid choice', () => {
    throws(() => new Vote({
        voter: 'did:exo:v',
        choice: 'maybe',
    }), GovernanceError);
});
test('Decision IDs are deterministic for identical inputs', async () => {
    const a = await baseDecision();
    const b = await baseDecision();
    strictEqual(a.decisionId, b.decisionId);
});
test('Decision IDs frame delimiter-collision inputs', async () => {
    const a = await new DecisionBuilder({
        title: 'a',
        description: 'b\0c',
        proposer: PROPOSER,
    }).build();
    const b = await new DecisionBuilder({
        title: 'a\0b',
        description: 'c',
        proposer: PROPOSER,
    }).build();
    notStrictEqual(a.decisionId, b.decisionId);
    assertLowercaseHash256(a.decisionId);
    assertLowercaseHash256(b.decisionId);
});
test('Decision ID matches the literal Unicode cross-language fixture', async () => {
    const decision = await new DecisionBuilder({
        title: 'Budget 🛡️',
        description: 'Allocate 10 EXO',
        proposer: 'did:exo:alice',
    }).build();
    strictEqual(decision.decisionId, 'ea4c36142a07f33ee7d008831c2417d502efbcfa1573a46b6d4ee6a51ccbaf53');
    assertLowercaseHash256(decision.decisionId);
});
test('Decision constructor preserves a legacy SHA-256 decision ID', () => {
    const legacyDecisionId = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const decision = new Decision({
        decisionId: legacyDecisionId,
        title: 'Legacy decision',
        description: 'Stored before decision ID v2',
        proposer: 'did:exo:alice',
    });
    strictEqual(decision.decisionId, legacyDecisionId);
});
test('Decision IDs reject ill-formed Unicode instead of aliasing replacement text', async () => {
    const replacement = await new DecisionBuilder({
        title: '\ufffd',
        description: 'd',
        proposer: 'did:exo:alice',
    }).build();
    assertLowercaseHash256(replacement.decisionId);
    await rejects(new DecisionBuilder({
        title: '\ud800',
        description: 'd',
        proposer: 'did:exo:alice',
    }).build(), GovernanceError);
});
//# sourceMappingURL=governance.test.js.map