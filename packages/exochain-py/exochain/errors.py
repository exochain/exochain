"""Exception hierarchy for the EXOCHAIN SDK.

All SDK-specific exceptions derive from :class:`ExochainError` so callers can
catch the base type when they do not care about the specific failure mode.
"""

from __future__ import annotations


class ExochainError(Exception):
    """Base exception for all EXOCHAIN SDK errors."""


class IdentityError(ExochainError):
    """Raised for identity / DID / keypair failures."""


class ConsentError(ExochainError):
    """Raised for consent-related failures (e.g. bailment validation)."""


class GovernanceError(ExochainError):
    """Raised for governance failures (e.g. decision / voting errors)."""


class AuthorityError(ExochainError):
    """Raised for authority chain validation failures."""


class KernelError(ExochainError):
    """Raised for constitutional kernel errors."""


class CryptoError(ExochainError):
    """Raised for cryptographic failures."""


class TransportError(ExochainError):
    """Raised for HTTP / network transport failures.

    Exposes ``status`` (HTTP status code when the request got a response) and
    ``body`` (raw response body when available) so callers can programmatically
    retry on 503 / 429 or branch on 401 without string-matching the message.
    Mirrors the TypeScript SDK's TransportError shape. (A-061)
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        body: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


__all__ = [
    "AuthorityError",
    "ConsentError",
    "CryptoError",
    "ExochainError",
    "GovernanceError",
    "IdentityError",
    "KernelError",
    "TransportError",
]
