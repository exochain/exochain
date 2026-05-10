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

"""Anchoring interface.

Anchoring turns a local DecisionRecord hash into a globally referencable receipt.

In MVP, we provide:
- a provider interface (so you can swap chains / backends)
- a local simulation provider (writes receipts to a log)

EXOCHAIN integration can be implemented by adding a real provider that:
- submits record_hash to Exochain
- returns txid + confirmations/metadata
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Protocol
from uuid import uuid4

from .schemas import AnchorReceipt


class AnchorProvider(Protocol):
    name: str

    def anchor(self, record_hash: str, *, metadata: Optional[Dict[str, Any]] = None) -> AnchorReceipt:
        ...


@dataclass
class LocalSimAnchorProvider:
    """A safe default: no network calls, just logs a receipt locally."""

    root: Path = Path(".decision_forum")
    name: str = "local_sim"

    @property
    def log_path(self) -> Path:
        return self.root / "anchors.log"

    def anchor(self, record_hash: str, *, metadata: Optional[Dict[str, Any]] = None) -> AnchorReceipt:
        self.root.mkdir(parents=True, exist_ok=True)
        txid = f"sim-{uuid4().hex[:16]}"
        receipt = AnchorReceipt(
            chain=self.name,
            anchored_at=datetime.utcnow(),
            record_hash=record_hash,
            txid=txid,
            metadata={"note": "simulation only", **(metadata or {})},
        )
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(receipt.model_dump(), default=str) + "\n")
        return receipt


@dataclass
class ExochainSimAnchorProvider(LocalSimAnchorProvider):
    """Alias provider for EXOCHAIN-style receipts (still simulated)."""

    name: str = "exochain_sim"


def get_provider(name: str, *, root: Path) -> AnchorProvider:
    name = (name or "").strip().lower()
    if name in ("local", "local_sim", "sim"):
        return LocalSimAnchorProvider(root=root)
    if name in ("exochain", "exochain_sim", "exo"):
        return ExochainSimAnchorProvider(root=root)
    raise ValueError(f"Unknown anchor provider: {name}")
