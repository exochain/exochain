"""Ed25519-backed Identity objects.

An :class:`Identity` bundles a keypair with a derived DID. The private key
never leaves the object; callers interact with :meth:`Identity.sign` and the
static :meth:`Identity.verify` method.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..errors import IdentityError
from ..types import Did


def derive_did(public_key_bytes: bytes) -> Did:
    """Derive ``did:exo:<first 16 hex chars of BLAKE3(public_key_bytes)>``.

    Canonical across all three SDKs (Rust, TypeScript, Python) as of A-050.
    See ``tests/fixtures/did-derivation.json`` for cross-language vectors.
    """
    digest = blake3(public_key_bytes).digest()
    return Did(f"did:exo:{digest[:8].hex()}")


@dataclass
class Identity:
    """An Ed25519 keypair with a content-addressed DID.

    The DID is derived deterministically from the public key:
    ``did:exo:<hex(blake3(pubkey_raw)[:8])>``. (A-050)
    """

    did: Did
    public_key_hex: str
    label: str
    _private_key: Ed25519PrivateKey = field(repr=False)

    @classmethod
    def generate(cls, label: str) -> Identity:
        """Generate a fresh Ed25519 keypair and derive a DID from its public key."""
        if not isinstance(label, str) or not label.strip():
            raise IdentityError("label must be a non-empty string")

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        )
        return cls(
            did=derive_did(public_bytes),
            public_key_hex=public_bytes.hex(),
            label=label,
            _private_key=private_key,
        )

    def sign(self, message: bytes) -> bytes:
        """Sign ``message`` with this identity's private key. Returns raw 64-byte signature."""
        if not isinstance(message, (bytes, bytearray)):
            raise IdentityError("message must be bytes")
        return self._private_key.sign(bytes(message))

    @staticmethod
    def verify(public_key_hex: str, message: bytes, signature: bytes) -> bool:
        """Verify ``signature`` over ``message`` against the given public key hex.

        Returns ``False`` for any verification failure — invalid key, wrong
        signature, malformed hex — rather than raising.
        """
        try:
            public_bytes = bytes.fromhex(public_key_hex)
            pub = Ed25519PublicKey.from_public_bytes(public_bytes)
            pub.verify(bytes(signature), bytes(message))
            return True
        except (ValueError, InvalidSignature, TypeError):
            return False


__all__ = ["Identity", "derive_did"]
