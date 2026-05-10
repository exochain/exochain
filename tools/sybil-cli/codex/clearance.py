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

"""Forum clearance rules.

A forum gets *gravity* when decisions require:
- explicit attestation (review/approval)
- optional cryptographic custody (signatures)
- a quorum (for higher-stakes decisions)

This module evaluates whether a DecisionRecord is "cleared" under a given policy.

MVP philosophy:
- defaults are permissive (no signatures required)
- but the primitives are there for stricter governance.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from pydantic import BaseModel, Field

from .identity import verify_detached
from .key_registry import KeyRegistry
from .schemas import CustodyEvent, DecisionRecord
from .store import compute_record_hash


class ClearanceMode(str, Enum):
    single = "single"
    quorum = "quorum"


class ClearancePolicy(BaseModel):
    """Rules for what counts as a cleared decision."""

    mode: ClearanceMode = Field(default=ClearanceMode.quorum)
    quorum: int = Field(default=2, ge=1)

    allowed_roles: List[str] = Field(
        default_factory=lambda: ["reviewer", "steward"],
        description="Only attestations from these roles count toward quorum.",
    )

    require_valid_signatures: bool = Field(
        default=False,
        description="If true, each counted attestation must carry a valid signature.",
    )

    reject_veto: bool = Field(
        default=True,
        description="If true, any counted reject attestation blocks clearance.",
    )

    # Action naming conventions (tweakable).
    approve_actions: List[str] = Field(default_factory=lambda: ["attest:approve"])
    reject_actions: List[str] = Field(default_factory=lambda: ["attest:reject"])
    abstain_actions: List[str] = Field(default_factory=lambda: ["attest:abstain"])


class AttestationDetail(BaseModel):
    actor_id: str
    role: str
    action: str
    at: datetime
    signature_valid: Optional[bool] = None


class ClearanceResult(BaseModel):
    cleared: bool
    record_id: str
    record_hash: str

    required_quorum: int
    approvals: List[AttestationDetail] = Field(default_factory=list)
    rejects: List[AttestationDetail] = Field(default_factory=list)
    abstains: List[AttestationDetail] = Field(default_factory=list)

    reason: Optional[str] = None
    evaluated_at: datetime = Field(default_factory=lambda: datetime.utcnow())


class ClearanceCertificate(BaseModel):
    """A portable proof that a record met clearance policy at a point in time."""

    id: str = Field(default_factory=lambda: f"CC-{uuid4().hex[:10]}")
    issued_at: datetime = Field(default_factory=lambda: datetime.utcnow())

    record_id: str
    record_hash: str
    policy: Dict

    approvals: List[str] = Field(default_factory=list)
    rejects: List[str] = Field(default_factory=list)
    abstains: List[str] = Field(default_factory=list)

    cleared: bool


def _attestation_kind(ev: CustodyEvent) -> Optional[str]:
    # Prefer explicit field
    if ev.attestation:
        return ev.attestation.strip().lower()
    # Fallback: action prefix
    if ev.action.startswith("attest:"):
        return ev.action.split(":", 1)[1].strip().lower()
    return None


def evaluate_clearance(
    record: DecisionRecord,
    *,
    policy: Optional[ClearancePolicy] = None,
    key_registry: Optional[KeyRegistry] = None,
) -> ClearanceResult:
    policy = policy or ClearancePolicy()
    key_registry = key_registry or KeyRegistry(root=__import__("pathlib").Path(".decision_forum"))

    # Ensure we evaluate against the current canonical hash.
    current_hash = compute_record_hash(record)

    approvals: List[AttestationDetail] = []
    rejects: List[AttestationDetail] = []
    abstains: List[AttestationDetail] = []

    # De-duplicate by actor_id per kind: latest attestation wins.
    latest_by_actor: Dict[Tuple[str, str], AttestationDetail] = {}

    for ev in record.custody:
        kind = _attestation_kind(ev)
        if kind is None:
            continue

        # Normalize action string for policy matching.
        action_norm = ev.action.strip().lower()

        # Only accept attestations for the current hash (prevents signing an older version).
        if (ev.record_hash or "") != current_hash:
            continue

        # Role must be allowed (counts toward quorum).
        if policy.allowed_roles and (ev.role not in policy.allowed_roles):
            continue

        # Signature verification (optional).
        sig_valid: Optional[bool] = None
        if policy.require_valid_signatures:
            if not ev.signature:
                sig_valid = False
            else:
                pub = ev.public_key_b64 or key_registry.get(ev.actor_id)
                if not pub:
                    sig_valid = False
                else:
                    sig_valid = verify_detached(
                        current_hash, signature_b64=ev.signature, public_key_b64=pub
                    )

            if sig_valid is False:
                # If signatures are required and invalid, this event doesn't count.
                continue

        detail = AttestationDetail(
            actor_id=ev.actor_id,
            role=ev.role,
            action=ev.action,
            at=ev.at,
            signature_valid=sig_valid,
        )

        latest_by_actor[(ev.actor_id, kind)] = detail

    for (actor_id, kind), detail in latest_by_actor.items():
        if kind == "approve" or detail.action.strip().lower() in policy.approve_actions:
            approvals.append(detail)
        elif kind == "reject" or detail.action.strip().lower() in policy.reject_actions:
            rejects.append(detail)
        elif kind == "abstain" or detail.action.strip().lower() in policy.abstain_actions:
            abstains.append(detail)
        else:
            # Unknown kinds do not affect clearance, but could be useful later.
            pass

    approvals_actor_set = {a.actor_id for a in approvals}
    rejects_actor_set = {r.actor_id for r in rejects}

    required_quorum = 1 if policy.mode == ClearanceMode.single else policy.quorum

    if policy.reject_veto and rejects_actor_set:
        return ClearanceResult(
            cleared=False,
            record_id=record.id,
            record_hash=current_hash,
            required_quorum=required_quorum,
            approvals=approvals,
            rejects=rejects,
            abstains=abstains,
            reason=f"reject_veto: {sorted(rejects_actor_set)}",
        )

    if len(approvals_actor_set) < required_quorum:
        return ClearanceResult(
            cleared=False,
            record_id=record.id,
            record_hash=current_hash,
            required_quorum=required_quorum,
            approvals=approvals,
            rejects=rejects,
            abstains=abstains,
            reason=f"quorum_not_met: approvals={len(approvals_actor_set)}/{required_quorum}",
        )

    return ClearanceResult(
        cleared=True,
        record_id=record.id,
        record_hash=current_hash,
        required_quorum=required_quorum,
        approvals=approvals,
        rejects=rejects,
        abstains=abstains,
        reason="cleared",
    )


def issue_certificate(
    result: ClearanceResult,
    *,
    policy: ClearancePolicy,
) -> ClearanceCertificate:
    return ClearanceCertificate(
        record_id=result.record_id,
        record_hash=result.record_hash,
        policy=policy.model_dump(),
        approvals=[a.actor_id for a in result.approvals],
        rejects=[r.actor_id for r in result.rejects],
        abstains=[a.actor_id for a in result.abstains],
        cleared=result.cleared,
    )
