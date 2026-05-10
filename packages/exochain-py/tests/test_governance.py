# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for Decision, DecisionBuilder, Vote, and quorum checks."""

from __future__ import annotations

import pytest

from exochain import (
    Decision,
    DecisionBuilder,
    DecisionStatus,
    Did,
    GovernanceError,
    Vote,
    VoteChoice,
)

PROPOSER: Did = "did:exo:prop000001"
V1: Did = "did:exo:voter00001"
V2: Did = "did:exo:voter00002"
V3: Did = "did:exo:voter00003"


def _make_decision() -> Decision:
    return DecisionBuilder("Fund proposal", "Allocate budget for Q3", PROPOSER).build()


def test_builder_creates_decision() -> None:
    """The builder produces a Decision with id, title, and Proposed status."""
    d = _make_decision()
    assert d.title == "Fund proposal"
    assert d.description == "Allocate budget for Q3"
    assert d.proposer == PROPOSER
    assert d.status == DecisionStatus.PROPOSED
    assert d.votes == []
    assert len(d.decision_id) == 16


def test_decision_id_is_deterministic() -> None:
    """Two equivalent builders produce matching decision_ids."""
    a = DecisionBuilder("t", "d", PROPOSER).build()
    b = DecisionBuilder("t", "d", PROPOSER).build()
    assert a.decision_id == b.decision_id


def test_builder_rejects_empty_title() -> None:
    """Empty or whitespace-only titles raise GovernanceError."""
    with pytest.raises(GovernanceError):
        DecisionBuilder("", "d", PROPOSER).build()
    with pytest.raises(GovernanceError):
        DecisionBuilder("   ", "d", PROPOSER).build()


def test_cast_vote_adds_to_list() -> None:
    """Casting a vote appends it to the decision's votes."""
    d = _make_decision()
    d.cast_vote(Vote(voter=V1, choice=VoteChoice.APPROVE))
    assert len(d.votes) == 1
    assert d.votes[0].voter == V1
    assert d.votes[0].choice == VoteChoice.APPROVE


def test_duplicate_voter_rejected() -> None:
    """A voter that has already cast a vote cannot cast a second one."""
    d = _make_decision()
    d.cast_vote(Vote(voter=V1, choice=VoteChoice.APPROVE))
    with pytest.raises(GovernanceError):
        d.cast_vote(Vote(voter=V1, choice=VoteChoice.REJECT))


def test_quorum_met() -> None:
    """Quorum is met when approvals >= threshold."""
    d = _make_decision()
    d.cast_vote(Vote(voter=V1, choice=VoteChoice.APPROVE))
    d.cast_vote(Vote(voter=V2, choice=VoteChoice.APPROVE))
    d.cast_vote(Vote(voter=V3, choice=VoteChoice.REJECT))
    q = d.check_quorum(2)
    assert q.met is True
    assert q.threshold == 2
    assert q.approvals == 2
    assert q.rejections == 1
    assert q.abstentions == 0
    assert q.total_votes == 3


def test_quorum_not_met() -> None:
    """Quorum is not met when approvals fall short of threshold."""
    d = _make_decision()
    d.cast_vote(Vote(voter=V1, choice=VoteChoice.APPROVE))
    d.cast_vote(Vote(voter=V2, choice=VoteChoice.REJECT))
    q = d.check_quorum(2)
    assert q.met is False
    assert q.approvals == 1


def test_quorum_counts_abstentions() -> None:
    """Abstentions are tallied but do not count toward the approval threshold."""
    d = _make_decision()
    d.cast_vote(Vote(voter=V1, choice=VoteChoice.APPROVE))
    d.cast_vote(Vote(voter=V2, choice=VoteChoice.ABSTAIN))
    d.cast_vote(Vote(voter=V3, choice=VoteChoice.ABSTAIN))
    q = d.check_quorum(2)
    assert q.met is False
    assert q.approvals == 1
    assert q.abstentions == 2
    assert q.total_votes == 3


def test_vote_carries_rationale() -> None:
    """A vote may optionally carry a rationale string."""
    vote = Vote(voter=V1, choice=VoteChoice.REJECT, rationale="risk too high")
    assert vote.rationale == "risk too high"
