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

"""Vote primitives for governance decisions."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from ..types import Did


class VoteChoice(StrEnum):
    """A voter's choice on a governance decision."""

    APPROVE = "approve"
    REJECT = "reject"
    ABSTAIN = "abstain"


class Vote(BaseModel):
    """A single vote cast on a :class:`~exochain.governance.Decision`."""

    model_config = ConfigDict(frozen=True)

    voter: Did
    choice: VoteChoice
    rationale: str | None = None


__all__ = ["Vote", "VoteChoice"]
