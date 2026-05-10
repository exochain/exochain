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

"""Small utility helpers for the MVP.

This file intentionally stays dependency-light.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


def load_upk(path: str | Path = "upk.yaml") -> Dict[str, Any]:
    """Load the Root Prompt Kernel (UPK) YAML."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"UPK not found at {p.resolve()}")
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def retrieve_memory_context(_prompt: str) -> str:
    """Placeholder for vector/graph memory retrieval.

    MVP returns empty string to keep the CLI usable without external services.
    """

    return ""
