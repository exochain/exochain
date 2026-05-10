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

"""Local, Git-friendly store for Decision Records.

Why file-backed first?
- It makes decisions *versionable*.
- It makes reviews *diffable*.
- It keeps the MVP portable.

The storage layout is intentionally boring:

.decision_forum/
  records/
    DR-2026-02-08-1f2c3a.json
  keys.json
  anchors.log
  index.json
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import List, Optional

from .schemas import (
    AnchorReceipt,
    CrosscheckReport,
    CustodyEvent,
    DecisionRecord,
    DecisionStatus,
    EvidenceItem,
)


def _utcnow() -> datetime:
    return datetime.utcnow()


def _canonical_payload(record: DecisionRecord) -> dict:
    """Return the payload used for hashing/signing.

    We exclude:
    - custody (because custody events refer to the record hash)
    - anchors (because anchors refer to the record hash)
    - record_hash itself
    """

    d = record.model_dump()
    for k in ("custody", "anchors", "record_hash", "created_at", "updated_at", "status"):
        d.pop(k, None)
    return d


def compute_record_hash(record: DecisionRecord) -> str:
    payload = _canonical_payload(record)
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )
    return sha256(blob).hexdigest()


@dataclass
class CodexStore:
    """A minimal store for decision records."""

    root: Path = Path(".decision_forum")

    @property
    def records_dir(self) -> Path:
        return self.root / "records"

    def init(self) -> None:
        self.records_dir.mkdir(parents=True, exist_ok=True)
        (self.root / "index.json").touch(exist_ok=True)

    def _record_path(self, record_id: str) -> Path:
        return self.records_dir / f"{record_id}.json"

    def _next_id(self) -> str:
        # Human-readable + sortable-ish; uniqueness via uuid suffix.
        # Example: DR-2026-02-08-1f2c3a
        date = _utcnow().strftime("%Y-%m-%d")
        suffix = uuid.uuid4().hex[:6]
        return f"DR-{date}-{suffix}"

    def create(
        self,
        *,
        title: str,
        context: str,
        decision: str,
        consequences: str,
        tags: Optional[List[str]] = None,
        actor_id: str = "local",
    ) -> DecisionRecord:
        self.init()

        record = DecisionRecord(
            id=self._next_id(),
            title=title,
            status=DecisionStatus.draft,
            created_at=_utcnow(),
            updated_at=_utcnow(),
            context=context,
            decision=decision,
            consequences=consequences,
            tags=tags or [],
        )
        record.record_hash = compute_record_hash(record)
        record.custody.append(
            CustodyEvent(
                actor_id=actor_id,
                role="proposer",
                action="create",
                record_hash=record.record_hash,
            )
        )
        self.save(record)
        return record

    def load(self, record_id: str) -> DecisionRecord:
        path = self._record_path(record_id)
        if not path.exists():
            raise FileNotFoundError(f"Decision record not found: {record_id}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return DecisionRecord.model_validate(data)

    def save(self, record: DecisionRecord) -> None:
        self.init()
        record.updated_at = _utcnow()
        record.record_hash = compute_record_hash(record)
        path = self._record_path(record.id)
        path.write_text(
            json.dumps(record.model_dump(), indent=2, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
        )

    def list(self, status: Optional[DecisionStatus] = None) -> List[DecisionRecord]:
        self.init()
        out: List[DecisionRecord] = []
        for p in sorted(self.records_dir.glob("DR-*.json")):
            try:
                rec = DecisionRecord.model_validate(json.loads(p.read_text("utf-8")))
            except Exception:
                continue
            if status and rec.status != status:
                continue
            out.append(rec)
        return out

    # ---------------------------
    # Mutations (gravity actions)
    # ---------------------------

    def add_evidence(self, record_id: str, evidence: EvidenceItem, actor_id: str = "local") -> None:
        rec = self.load(record_id)
        rec.evidence.append(evidence)
        rec.record_hash = compute_record_hash(rec)
        rec.custody.append(
            CustodyEvent(
                actor_id=actor_id,
                role="participant",
                action="add_evidence",
                record_hash=rec.record_hash,
            )
        )
        self.save(rec)

    def add_crosscheck(self, record_id: str, report: CrosscheckReport, actor_id: str = "local") -> None:
        rec = self.load(record_id)
        rec.crosschecks.append(report)
        rec.record_hash = compute_record_hash(rec)
        rec.custody.append(
            CustodyEvent(
                actor_id=actor_id,
                role="participant",
                action="add_crosscheck",
                record_hash=rec.record_hash,
            )
        )
        self.save(rec)

    def add_custody_event(self, record_id: str, event: CustodyEvent) -> None:
        rec = self.load(record_id)
        # Ensure event targets the current hash (if caller didn't set it).
        rec.record_hash = compute_record_hash(rec)
        if not event.record_hash:
            event.record_hash = rec.record_hash
        rec.custody.append(event)
        self.save(rec)

    def add_anchor(self, record_id: str, receipt: AnchorReceipt, actor_id: str = "local") -> None:
        rec = self.load(record_id)
        # Anchors should reference the current canonical hash.
        rec.record_hash = compute_record_hash(rec)
        if receipt.record_hash != rec.record_hash:
            receipt.record_hash = rec.record_hash
        rec.anchors.append(receipt)
        rec.custody.append(
            CustodyEvent(
                actor_id=actor_id,
                role="steward",
                action="anchor",
                record_hash=rec.record_hash,
                metadata={"chain": receipt.chain, "txid": receipt.txid},
            )
        )
        self.save(rec)

    def set_status(self, record_id: str, status: DecisionStatus, actor_id: str = "local") -> None:
        rec = self.load(record_id)
        rec.status = status
        rec.record_hash = compute_record_hash(rec)
        rec.custody.append(
            CustodyEvent(
                actor_id=actor_id,
                role="reviewer" if status in (DecisionStatus.accepted, DecisionStatus.rejected) else "participant",
                action=f"set_status:{status}",
                record_hash=rec.record_hash,
            )
        )
        self.save(rec)
