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

"""Decision.forum Codex

This package contains the minimal primitives that create *gravity*:

- A DecisionRecord schema (ADR-inspired) with custody, crosscheck, and anchoring hooks.
- A local file-backed store so decisions are versionable (Git-friendly).
- Clearance rules (quorum/signatures) so legitimacy is conferred, not claimed.
- Anchoring interface so decisions can be globally referenced (e.g., EXOCHAIN).

MVP philosophy: start with *legibility* and *custody* first; automation later.
"""

from .schemas import (
    AnchorReceipt,
    CrosscheckOpinion,
    CrosscheckReport,
    CustodyEvent,
    DecisionRecord,
    DecisionStatus,
    EvidenceItem,
)
from .store import CodexStore, compute_record_hash
from .clearance import ClearancePolicy, ClearanceResult, evaluate_clearance, issue_certificate
from .anchors import AnchorProvider, get_provider
from .key_registry import KeyRegistry

__all__ = [
    "AnchorReceipt",
    "CrosscheckOpinion",
    "CrosscheckReport",
    "CustodyEvent",
    "DecisionRecord",
    "DecisionStatus",
    "EvidenceItem",
    "CodexStore",
    "compute_record_hash",
    "ClearancePolicy",
    "ClearanceResult",
    "evaluate_clearance",
    "issue_certificate",
    "AnchorProvider",
    "get_provider",
    "KeyRegistry",
]
