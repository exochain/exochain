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

"""DID (Decentralized Identifier) validation helpers.

A DID on the exo network is an opaque string of the form ``did:exo:<suffix>``,
where ``<suffix>`` is a base58-alphanumeric identifier derived from a
public key.
"""

from __future__ import annotations

import re

from ..errors import IdentityError
from ..types import Did

_DID_PATTERN = re.compile(r"^did:exo:[A-Za-z0-9]+$")


def validate_did(s: str) -> Did:
    """Validate ``s`` as a DID and return it branded as :data:`Did`.

    Raises:
        IdentityError: if ``s`` is not a syntactically valid DID.
    """
    if not isinstance(s, str) or not _DID_PATTERN.match(s) or len(s) < 10:
        raise IdentityError(f"invalid DID format: {s!r}")
    return s


def is_did(s: str) -> bool:
    """Return ``True`` if ``s`` is a syntactically valid DID, without raising."""
    if not isinstance(s, str) or len(s) < 10:
        return False
    return bool(_DID_PATTERN.match(s))


__all__ = ["is_did", "validate_did"]
