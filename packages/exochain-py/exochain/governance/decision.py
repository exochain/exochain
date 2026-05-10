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

"""Governance decisions — titled proposals with collected votes and quorum checks."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256

from pydantic import BaseModel, ConfigDict, Field

from ..errors import GovernanceError
from ..types import Did, QuorumResult
from .vote import Vote, VoteChoice


class DecisionStatus(StrEnum):
    """Lifecycle status for a :class:`Decision`."""

    PROPOSED = "proposed"
    DELIBERATING = "deliberating"
    APPROVED = "approved"
    REJECTED = "rejected"
    CHALLENGED = "challenged"


class Decision(BaseModel):
    """A governance decision with accumulated votes.

    Decisions are mutable only via :meth:`cast_vote` (which rejects duplicate
    voters) and by setting :attr:`status`. The :attr:`decision_id` is a
    deterministic 16-hex-char prefix of SHA-256 over title/description/proposer.
    """

    model_config = ConfigDict(validate_assignment=True)

    decision_id: str
    title: str
    description: str
    proposer: Did
    status: DecisionStatus = DecisionStatus.PROPOSED
    decision_class: str | None = None
    votes: list[Vote] = Field(default_factory=list)

    def cast_vote(self, vote: Vote) -> None:
        """Append ``vote`` to this decision. Raises if the voter already voted.

        Raises:
            GovernanceError: if the voter has already cast a vote.
        """
        if any(v.voter == vote.voter for v in self.votes):
            raise GovernanceError(f"voter {vote.voter} has already cast a vote")
        self.votes.append(vote)

    def check_quorum(self, threshold: int) -> QuorumResult:
        """Tally votes and report whether approvals meet ``threshold``."""
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 0:
            raise GovernanceError("threshold must be a non-negative integer")

        approvals = sum(1 for v in self.votes if v.choice == VoteChoice.APPROVE)
        rejections = sum(1 for v in self.votes if v.choice == VoteChoice.REJECT)
        abstentions = sum(1 for v in self.votes if v.choice == VoteChoice.ABSTAIN)
        total_votes = len(self.votes)

        return QuorumResult(
            met=approvals >= threshold,
            threshold=threshold,
            total_votes=total_votes,
            approvals=approvals,
            rejections=rejections,
            abstentions=abstentions,
        )


class DecisionBuilder:
    """Fluent builder for a :class:`Decision`."""

    def __init__(self, title: str, description: str, proposer: Did) -> None:
        self._title = title
        self._description = description
        self._proposer = proposer
        self._decision_class: str | None = None

    def decision_class(self, cls: str) -> DecisionBuilder:
        """Attach an optional free-form classification label."""
        if not isinstance(cls, str) or not cls.strip():
            raise GovernanceError("decision_class must be a non-empty string")
        self._decision_class = cls
        return self

    def build(self) -> Decision:
        """Validate and produce a :class:`Decision`."""
        if not isinstance(self._title, str) or not self._title.strip():
            raise GovernanceError("title must be non-empty")
        if not isinstance(self._description, str):
            raise GovernanceError("description must be a string")

        payload = f"{self._title}\x00{self._description}\x00{self._proposer}"
        digest = sha256(payload.encode("utf-8")).hexdigest()
        decision_id = digest[:16]

        return Decision(
            decision_id=decision_id,
            title=self._title,
            description=self._description,
            proposer=self._proposer,
            decision_class=self._decision_class,
        )


__all__ = ["Decision", "DecisionBuilder", "DecisionStatus"]
