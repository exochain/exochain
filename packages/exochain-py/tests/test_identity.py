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

"""Tests for DID validation and the Identity Ed25519 keypair."""

from __future__ import annotations

import pytest

from exochain import Identity, IdentityError, is_did, validate_did


def test_generate_creates_valid_did() -> None:
    """`Identity.generate` produces a syntactically valid DID prefixed with did:exo:."""
    identity = Identity.generate("alice")
    assert identity.did.startswith("did:exo:")
    assert is_did(identity.did)
    assert identity.label == "alice"
    # Public key is 32 bytes Ed25519, hex-encoded = 64 chars.
    assert len(identity.public_key_hex) == 64
    # Suffix after the "did:exo:" prefix is 16 hex chars (first 8 bytes of sha256).
    assert len(identity.did.removeprefix("did:exo:")) == 16


def test_sign_and_verify_roundtrip() -> None:
    """A signature created by `sign` verifies against the same public key."""
    identity = Identity.generate("bob")
    message = b"constitutional governance"
    signature = identity.sign(message)
    assert len(signature) == 64
    assert Identity.verify(identity.public_key_hex, message, signature)


def test_verify_rejects_wrong_key() -> None:
    """A signature from identity A must not verify under identity B's key."""
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    message = b"hello"
    sig = alice.sign(message)
    assert not Identity.verify(bob.public_key_hex, message, sig)


def test_verify_rejects_tampered_message() -> None:
    """A signature over one message must not verify against a different message."""
    identity = Identity.generate("carol")
    sig = identity.sign(b"original")
    assert not Identity.verify(identity.public_key_hex, b"tampered", sig)


def test_verify_handles_malformed_inputs() -> None:
    """`verify` returns False (not raises) on malformed hex or bad signature length."""
    identity = Identity.generate("dave")
    # Bad hex public key.
    assert not Identity.verify("zzzz", b"m", b"\x00" * 64)
    # Bad signature length.
    assert not Identity.verify(identity.public_key_hex, b"m", b"\x00" * 10)


def test_did_uniqueness_across_generations() -> None:
    """Independent generations should produce distinct DIDs with overwhelming probability."""
    a = Identity.generate("x")
    b = Identity.generate("x")
    assert a.did != b.did
    assert a.public_key_hex != b.public_key_hex


def test_generate_rejects_empty_label() -> None:
    """An empty or whitespace-only label is rejected."""
    with pytest.raises(IdentityError):
        Identity.generate("")
    with pytest.raises(IdentityError):
        Identity.generate("   ")


def test_validate_did_accepts_valid_format() -> None:
    """`validate_did` returns the string unchanged when valid."""
    did = validate_did("did:exo:abc123XYZ")
    assert did == "did:exo:abc123XYZ"


def test_validate_did_rejects_bad_format() -> None:
    """Malformed DIDs raise IdentityError."""
    for bad in ["", "did:foo:bar", "did:exo:", "did:exo:!!!", "not-a-did"]:
        with pytest.raises(IdentityError):
            validate_did(bad)


def test_is_did_returns_false_for_invalid() -> None:
    """`is_did` is the non-raising check corresponding to `validate_did`."""
    assert is_did("did:exo:abc12345")
    assert not is_did("did:other:xyz")
    assert not is_did("")
