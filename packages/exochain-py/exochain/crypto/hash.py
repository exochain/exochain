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

"""SHA-256 helpers backed by :mod:`hashlib`."""

from __future__ import annotations

from hashlib import sha256 as _sha256


def sha256(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of ``data``."""
    return _sha256(bytes(data)).digest()


def sha256_hex(data: bytes) -> str:
    """Return the 64-character lowercase hex SHA-256 digest of ``data``."""
    return _sha256(bytes(data)).hexdigest()


__all__ = ["sha256", "sha256_hex"]
