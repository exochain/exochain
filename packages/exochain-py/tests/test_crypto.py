"""Tests for the SHA-256 hash helpers."""

from __future__ import annotations

from exochain import PROTOCOL_VERSION, sha256, sha256_hex


def test_protocol_version_is_exported() -> None:
    """The Python SDK exposes the fabric protocol version for skew checks."""
    assert PROTOCOL_VERSION == "0.1.0-beta"


def test_sha256_is_deterministic() -> None:
    """SHA-256 produces the same digest for the same input, twice."""
    assert sha256(b"hello") == sha256(b"hello")


def test_sha256_length_is_32() -> None:
    """SHA-256 produces exactly 32 raw bytes."""
    assert len(sha256(b"")) == 32
    assert len(sha256(b"any length input")) == 32


def test_sha256_hex_matches_known_vector() -> None:
    """The empty-string SHA-256 matches the published test vector."""
    # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert (
        sha256_hex(b"")
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_sha256_hex_format() -> None:
    """sha256_hex produces a 64-character lowercase hex string."""
    h = sha256_hex(b"exochain")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_sha256_and_hex_agree() -> None:
    """Raw digest and hex digest represent the same value."""
    data = b"constitutional fabric"
    assert sha256(data).hex() == sha256_hex(data)


def test_sha256_differs_for_different_inputs() -> None:
    """Different inputs produce different digests."""
    assert sha256_hex(b"a") != sha256_hex(b"b")
