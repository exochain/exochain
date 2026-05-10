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

"""Identity + signing primitives.

For a global forum nexus, *custody* matters:
- who made the proposal
- who reviewed
- who accepted

In MVP we use Ed25519 keys (via PyNaCl / libsodium) because they're fast,
compact, and widely supported.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Optional


class IdentityError(RuntimeError):
    pass


@dataclass(frozen=True)
class Keypair:
    public_key_b64: str
    secret_key_b64: str


def _require_pynacl():
    try:
        from nacl.signing import SigningKey  # noqa: F401
    except Exception as e:  # pragma: no cover
        raise IdentityError(
            "PyNaCl is required for signing. Install with: pip install pynacl"
        ) from e


def generate_keypair() -> Keypair:
    _require_pynacl()
    from nacl.signing import SigningKey

    sk = SigningKey.generate()
    vk = sk.verify_key
    return Keypair(
        public_key_b64=base64.b64encode(bytes(vk)).decode("utf-8"),
        secret_key_b64=base64.b64encode(bytes(sk)).decode("utf-8"),
    )


def sign_detached(message_hex: str, *, secret_key_b64: str) -> str:
    """Sign a hex string (e.g., record_hash) and return a base64 signature."""
    _require_pynacl()
    from nacl.signing import SigningKey

    sk_bytes = base64.b64decode(secret_key_b64)
    sk = SigningKey(sk_bytes)
    sig = sk.sign(message_hex.encode("utf-8")).signature
    return base64.b64encode(sig).decode("utf-8")


def verify_detached(message_hex: str, *, signature_b64: str, public_key_b64: str) -> bool:
    _require_pynacl()
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    vk = VerifyKey(base64.b64decode(public_key_b64))
    try:
        vk.verify(message_hex.encode("utf-8"), base64.b64decode(signature_b64))
        return True
    except BadSignatureError:
        return False
