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

"""Core schemas for decision.forum.

The schema deliberately starts from the ADR / decision-record pattern:
context -> decision -> consequences.

We extend it with the minimum required for *gravity*:
- custody events (who touched it, when, with what signature)
- crosscheck reports (plural intelligence + dissent)
- anchoring hooks (e.g., Exochain tx hash / receipt)

Design goal: stay lightweight, portable, and Git-friendly.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class DecisionStatus(str, Enum):
    draft = "draft"
    rfc = "rfc"  # request for comment
    accepted = "accepted"
    rejected = "rejected"
    superseded = "superseded"
    deprecated = "deprecated"


class EvidenceItem(BaseModel):
    """A pointer to supporting material.

    MVP supports:
    - uri: link to doc, repo, ticket, etc
    - content_hash: sha256 of the artifact, if you want immutable references
    """

    kind: str = Field(..., description="e.g., link, doc, repo, dataset, transcript")
    description: str
    uri: Optional[str] = None
    content_hash: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentKind(str, Enum):
    ai = "ai"
    human = "human"
    hybrid = "hybrid"
    unknown = "unknown"


class CrosscheckOpinion(BaseModel):
    """One voice in the crosscheck field.

    crosschecked.ai should emit one of these per 'voice'/agent.
    """

    agent_id: str = Field(..., description="public identity / DID / key fingerprint")
    agent_kind: AgentKind = Field(default=AgentKind.ai)
    agent_label: Optional[str] = Field(
        default=None, description="human-friendly name for the voice (e.g., Red Team)"
    )
    model: Optional[str] = None
    policy_id: Optional[str] = Field(
        default=None,
        description="optional policy tag, e.g., 'strict_citation', 'redteam_v1'",
    )

    # A normalized stance keeps crosschecks machine-comparable.
    stance: str = Field(..., description="support | oppose | amend | abstain")
    summary: str
    rationale: Optional[str] = None

    confidence: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Optional confidence score"
    )
    risks: List[str] = Field(default_factory=list)
    suggested_edits: Optional[str] = None
    evidence_refs: List[str] = Field(
        default_factory=list,
        description="Optional references to EvidenceItem content_hash/uri, decision IDs, etc.",
    )


class CrosscheckReport(BaseModel):
    """A plural-intelligence snapshot for a proposal.

    This object is designed to be:
    - portable (JSON)
    - append-only (you can attach multiple reports over time)
    - auditable (opinions + synthesis + dissent are preserved)
    """

    schema_version: str = Field(default="0.2")
    id: str = Field(default_factory=lambda: f"CR-{uuid4().hex[:10]}")

    created_at: datetime = Field(default_factory=lambda: datetime.utcnow())
    created_by: Optional[str] = Field(
        default=None, description="actor_id / agent_id that produced this report"
    )

    question: Optional[str] = Field(
        default=None, description="What question was crosschecked?"
    )
    method: str = Field(
        default="mosaic",
        description="e.g., mosaic | adversarial | redteam | debate | jury",
    )
    prompt: Optional[str] = None
    inputs: List[str] = Field(
        default_factory=list,
        description="Optional references to inputs (e.g., decision context, evidence URIs, datasets).",
    )

    opinions: List[CrosscheckOpinion] = Field(default_factory=list)

    # Synthesis should reconcile; dissent should preserve minority/edge-case views.
    synthesis: Optional[str] = None
    dissent: Optional[str] = None
    dissenters: List[str] = Field(
        default_factory=list, description="agent_ids of dissenting voices, if known"
    )

    metadata: Dict[str, Any] = Field(default_factory=dict)


class CustodyEvent(BaseModel):
    """A custody event: who did what, when, and (optionally) signed it."""

    at: datetime = Field(default_factory=lambda: datetime.utcnow())
    actor_id: str
    role: str = Field(default="participant", description="e.g., proposer, reviewer, steward")
    action: str = Field(
        ..., description="e.g., create, comment, attest:approve, clear, anchor"
    )

    # Optional structured attestation (kept redundant with action for ergonomics).
    attestation: Optional[str] = Field(
        default=None, description="e.g., approve | reject | abstain | amend"
    )

    notes: Optional[str] = None

    # Integrity / signatures
    record_hash: Optional[str] = None
    signature: Optional[str] = Field(
        default=None,
        description="Detached signature over record_hash (base64), if available",
    )
    public_key_b64: Optional[str] = Field(
        default=None,
        description="Optional public key (base64) used for signature verification.",
    )

    metadata: Dict[str, Any] = Field(default_factory=dict)


class AnchorReceipt(BaseModel):
    """An anchoring receipt (e.g., Exochain)."""

    chain: str = Field(default="exochain")
    anchored_at: datetime = Field(default_factory=lambda: datetime.utcnow())
    record_hash: str
    txid: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ForumRef(BaseModel):
    name: str = Field(default="decision.forum")
    scope: Optional[str] = Field(
        default=None,
        description="e.g., local, org, public, global; or a namespace like exochain://...",
    )


class DecisionRecord(BaseModel):
    """The unit of gravity."""

    schema_version: str = Field(default="0.2")

    id: str
    title: str
    status: DecisionStatus = DecisionStatus.draft

    forum: ForumRef = Field(default_factory=ForumRef)

    created_at: datetime = Field(default_factory=lambda: datetime.utcnow())
    updated_at: datetime = Field(default_factory=lambda: datetime.utcnow())

    # ADR-like core
    context: str
    decision: str
    consequences: str

    # Extensions
    assumptions: List[str] = Field(default_factory=list)
    options_considered: List[str] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    crosschecks: List[CrosscheckReport] = Field(default_factory=list)
    custody: List[CustodyEvent] = Field(default_factory=list)
    anchors: List[AnchorReceipt] = Field(default_factory=list)

    tags: List[str] = Field(default_factory=list)

    supersedes: Optional[str] = None

    # Computed / integrity
    record_hash: Optional[str] = Field(
        default=None,
        description="sha256 of the canonical JSON representation (excluding signatures)",
    )
