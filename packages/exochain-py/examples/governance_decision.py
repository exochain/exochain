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

"""Create a governance decision, cast votes, and check quorum.

Run:
    python examples/governance_decision.py
"""

from __future__ import annotations

from exochain import DecisionBuilder, Identity, Vote, VoteChoice


def main() -> None:
    proposer = Identity.generate("proposer")
    voters = [Identity.generate(f"voter-{i}") for i in range(3)]

    decision = DecisionBuilder(
        title="Fund Q3 safety initiative",
        description="Allocate 2% of treasury to AI safety research.",
        proposer=proposer.did,
    ).build()

    print(f"Decision id: {decision.decision_id}")
    print(f"Status:      {decision.status}")

    # Two approvals, one rejection.
    decision.cast_vote(Vote(voter=voters[0].did, choice=VoteChoice.APPROVE))
    decision.cast_vote(
        Vote(voter=voters[1].did, choice=VoteChoice.APPROVE, rationale="strong plan")
    )
    decision.cast_vote(
        Vote(voter=voters[2].did, choice=VoteChoice.REJECT, rationale="too costly")
    )

    quorum = decision.check_quorum(threshold=2)
    print(f"Quorum met:  {quorum.met}")
    print(
        f"Tally:       approvals={quorum.approvals} "
        f"rejections={quorum.rejections} "
        f"abstentions={quorum.abstentions} "
        f"total={quorum.total_votes}"
    )


if __name__ == "__main__":
    main()
