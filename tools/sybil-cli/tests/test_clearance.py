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

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codex.clearance import ClearanceMode, ClearancePolicy, evaluate_clearance
from codex.schemas import CustodyEvent, DecisionRecord
from codex.store import compute_record_hash


class MemoryKeyRegistry:
    def __init__(self, keys: dict[str, str]) -> None:
        self._keys = keys

    def get(self, actor_id: str) -> str | None:
        return self._keys.get(actor_id)


def strict_signature_verifier(
    message_hex: str, *, signature_b64: str, public_key_b64: str
) -> bool:
    del message_hex
    return signature_b64 == f"signed-by:{public_key_b64}"


def clearance_policy() -> ClearancePolicy:
    return ClearancePolicy(
        mode=ClearanceMode.single,
        quorum=1,
        allowed_roles=["reviewer"],
        require_valid_signatures=True,
    )


def decision_record_with_attestation(
    *, actor_id: str, signature: str, event_public_key: str | None
) -> DecisionRecord:
    record = DecisionRecord(
        id="DR-test-clearance",
        title="Registry-bound clearance",
        context="Current decision context",
        decision="Use trusted registry keys",
        consequences="Event-supplied verifier keys do not authorize clearance",
    )
    record_hash = compute_record_hash(record)
    record.record_hash = record_hash
    record.custody.append(
        CustodyEvent(
            actor_id=actor_id,
            role="reviewer",
            action="attest:approve",
            attestation="approve",
            record_hash=record_hash,
            signature=signature,
            public_key_b64=event_public_key,
        )
    )
    return record


class ClearanceKeyRegistryTests(unittest.TestCase):
    def test_clearance_source_does_not_use_event_public_key_for_verification(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "codex" / "clearance.py").read_text(
            encoding="utf-8"
        )
        verifier_block = source.split("if policy.require_valid_signatures:", 1)[1].split(
            "if sig_valid is False:", 1
        )[0]

        self.assertIn("_trusted_public_key_for_actor(ev.actor_id, key_registry)", verifier_block)
        self.assertNotIn("ev.public_key_b64 or", verifier_block)
        self.assertNotIn("public_key_b64=ev.public_key_b64", verifier_block)

    def test_event_supplied_public_key_cannot_authorize_clearance(self) -> None:
        record = decision_record_with_attestation(
            actor_id="did:exo:reviewer",
            signature="signed-by:attacker-key",
            event_public_key="attacker-key",
        )
        registry = MemoryKeyRegistry({"did:exo:reviewer": "trusted-registry-key"})

        with patch("codex.clearance.verify_detached", strict_signature_verifier):
            result = evaluate_clearance(
                record, policy=clearance_policy(), key_registry=registry
            )

        self.assertFalse(result.cleared)
        self.assertEqual([], result.approvals)
        self.assertIn("quorum_not_met", result.reason or "")

    def test_registered_public_key_authorizes_clearance_even_when_event_carries_key(
        self,
    ) -> None:
        record = decision_record_with_attestation(
            actor_id="did:exo:reviewer",
            signature="signed-by:trusted-registry-key",
            event_public_key="attacker-key",
        )
        registry = MemoryKeyRegistry({"did:exo:reviewer": "trusted-registry-key"})

        with patch("codex.clearance.verify_detached", strict_signature_verifier):
            result = evaluate_clearance(
                record, policy=clearance_policy(), key_registry=registry
            )

        self.assertTrue(result.cleared)
        self.assertEqual(["did:exo:reviewer"], [a.actor_id for a in result.approvals])
        self.assertTrue(result.approvals[0].signature_valid)

    def test_missing_registered_key_fails_closed_even_with_event_public_key(self) -> None:
        record = decision_record_with_attestation(
            actor_id="did:exo:reviewer",
            signature="signed-by:attacker-key",
            event_public_key="attacker-key",
        )
        registry = MemoryKeyRegistry({})

        with patch("codex.clearance.verify_detached", strict_signature_verifier):
            result = evaluate_clearance(
                record, policy=clearance_policy(), key_registry=registry
            )

        self.assertFalse(result.cleared)
        self.assertEqual([], result.approvals)
        self.assertIn("quorum_not_met", result.reason or "")


if __name__ == "__main__":
    unittest.main()
