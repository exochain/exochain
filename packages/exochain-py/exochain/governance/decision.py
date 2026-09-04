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

from blake3 import blake3
from pydantic import BaseModel, ConfigDict, Field

from ..errors import GovernanceError
from ..types import Did, QuorumResult
from .vote import Vote, VoteChoice

_DECISION_ID_DOMAIN = "exochain:decision-id:v2"
_CBOR_TEXT_INLINE_MAX = 23
_CBOR_UINT8_MAX = 0xFF
_CBOR_UINT16_MAX = 0xFFFF
_CBOR_UINT32_MAX = 0xFFFFFFFF


def _encode_canonical_cbor_text(value: str) -> bytes:
    """Encode one Unicode string as a preferred-serialization CBOR text item."""
    try:
        encoded = str.encode(value, "utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise GovernanceError("decision ID text must be well-formed Unicode") from exc

    byte_length = len(encoded)
    if byte_length <= _CBOR_TEXT_INLINE_MAX:
        header = bytes((0x60 | byte_length,))
    elif byte_length <= _CBOR_UINT8_MAX:
        header = bytes((0x78, byte_length))
    elif byte_length <= _CBOR_UINT16_MAX:
        header = b"\x79" + byte_length.to_bytes(2, "big")
    elif byte_length <= _CBOR_UINT32_MAX:
        header = b"\x7a" + byte_length.to_bytes(4, "big")
    else:
        raise GovernanceError("decision ID text exceeds the supported CBOR length")
    return header + encoded


def _decision_id_for(title: str, description: str, proposer: Did) -> str:
    """Hash the versioned canonical-CBOR decision frame with full BLAKE3."""
    frame = (_DECISION_ID_DOMAIN, title, description, proposer)
    canonical = b"\x84" + b"".join(_encode_canonical_cbor_text(value) for value in frame)
    return blake3(canonical).hexdigest()


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
    full BLAKE3 digest over a versioned canonical-CBOR frame.
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

        decision_id = _decision_id_for(self._title, self._description, self._proposer)

        return Decision(
            decision_id=decision_id,
            title=self._title,
            description=self._description,
            proposer=self._proposer,
            decision_class=self._decision_class,
        )


__all__ = ["Decision", "DecisionBuilder", "DecisionStatus"]
