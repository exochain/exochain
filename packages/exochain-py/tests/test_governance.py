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
    assert len(d.decision_id) == 64
    assert all(character in "0123456789abcdef" for character in d.decision_id)


def test_decision_id_is_deterministic() -> None:
    """Two equivalent builders produce matching decision_ids."""
    a = DecisionBuilder("t", "d", PROPOSER).build()
    b = DecisionBuilder("t", "d", PROPOSER).build()
    assert a.decision_id == b.decision_id


def test_decision_id_frames_delimiter_collision_inputs() -> None:
    """NUL-containing fields cannot alias a different title/description split."""
    a = DecisionBuilder("a", "b\0c", "did:exo:alice").build()
    b = DecisionBuilder("a\0b", "c", "did:exo:alice").build()

    assert a.decision_id != b.decision_id
    assert len(a.decision_id) == 64
    assert len(b.decision_id) == 64


def test_decision_id_matches_literal_unicode_cross_language_fixture() -> None:
    """Python emits the same canonical-CBOR/BLAKE3 ID as the Rust and TypeScript SDKs."""
    decision = DecisionBuilder("Budget 🛡️", "Allocate 10 EXO", "did:exo:alice").build()

    assert (
        decision.decision_id == "ea4c36142a07f33ee7d008831c2417d502efbcfa1573a46b6d4ee6a51ccbaf53"
    )


@pytest.mark.parametrize(
    ("description_length", "expected"),
    [
        (0, "0a400b4d15d70e56088d1138dc233df9882be32d62a54c69ee7ef0a5dc121d81"),
        (23, "8c812e872cfc8cdea78aa2d395e176b11e8f7c680dbaa7e0bad7a58430262ba1"),
        (24, "27affb4c9f114538bad5203ac2761ffadacc535c33e25ff2762e8043ba5942c5"),
        (255, "24ddff9f6fdbeaea835a8d50aa9f2f16a8650bd7f7aea3b4b323dda7fbbd249c"),
        (256, "a8a1247de117fa9b5049eb9dc8a48894798df8126c186b1d919951beb7f13730"),
        (65_535, "6e79ec72edce29ff75a8ca91c04d5e91e84983de2fe29e25395c254057937cd5"),
        (65_536, "34397f6a475fe08dced0957006954f9725bfa478bd35c67abe411f5dc0553434"),
    ],
)
def test_decision_id_matches_cbor_text_length_boundary_vectors(
    description_length: int, expected: str
) -> None:
    """Canonical CBOR length headers match the committed Rust/TypeScript vectors."""
    decision = DecisionBuilder("Boundary", "x" * description_length, "did:exo:alice").build()

    assert decision.decision_id == expected


def test_decision_id_rejects_ill_formed_unicode() -> None:
    """An isolated surrogate cannot alias Unicode replacement text during hashing."""
    with pytest.raises(GovernanceError, match="well-formed Unicode"):
        DecisionBuilder("\ud800", "d", "did:exo:alice").build()


def test_decision_id_hashes_str_subclass_contents_without_dispatching_encode() -> None:
    """A str subclass cannot substitute bytes that differ from its stored text value."""

    class AliasedEncoding(str):
        def encode(self, *_args: object, **_kwargs: object) -> bytes:
            return b"same-attacker-bytes"

    first = DecisionBuilder(AliasedEncoding("first title"), "d", "did:exo:alice").build()
    second = DecisionBuilder(AliasedEncoding("second title"), "d", "did:exo:alice").build()
    canonical_first = DecisionBuilder("first title", "d", "did:exo:alice").build()

    assert first.title == "first title"
    assert second.title == "second title"
    assert first.decision_id == canonical_first.decision_id
    assert first.decision_id != second.decision_id


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
