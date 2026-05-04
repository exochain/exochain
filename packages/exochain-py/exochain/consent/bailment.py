"""Bailment consent proposals.

A *bailment* is a scoped, time-bounded delegation of custody from a bailor
to a bailee. :class:`BailmentBuilder` assembles and validates a proposal,
producing an immutable :class:`BailmentProposal` with a deterministic id.
"""

from __future__ import annotations

from hashlib import sha256
from struct import pack

from pydantic import BaseModel, ConfigDict

from ..errors import ConsentError
from ..types import Did, Hash256Hex

MAX_SAFE_INTEGER = 9_007_199_254_740_991
HLC_LOGICAL_MAX = 0xFFFF_FFFF


class HlcTimestamp(BaseModel):
    """Caller-supplied Hybrid Logical Clock timestamp."""

    model_config = ConfigDict(frozen=True)

    physical_ms: int
    logical: int


class BailmentProposal(BaseModel):
    """A validated, immutable bailment proposal."""

    model_config = ConfigDict(frozen=True)

    proposal_id: Hash256Hex
    bailor: Did
    bailee: Did
    scope: str
    duration_hours: int
    created_at: int
    created_at_logical: int


class BailmentBuilder:
    """Fluent builder for a :class:`BailmentProposal`.

    Example:
        >>> proposal = (
        ...     BailmentBuilder("did:exo:alice", "did:exo:bob")
        ...     .scope("read:medical-records")
        ...     .duration_hours(48)
        ...     .created_at_hlc(1_700_000_000_000, 0)
        ...     .build()
        ... )
    """

    def __init__(self, bailor: Did, bailee: Did) -> None:
        self._bailor: Did = bailor
        self._bailee: Did = bailee
        self._scope: str | None = None
        self._duration_hours: int | None = None
        self._created_at_hlc: HlcTimestamp | None = None

    def scope(self, scope: str) -> BailmentBuilder:
        """Set the scope descriptor for this bailment."""
        if not isinstance(scope, str) or not scope.strip():
            raise ConsentError("scope cannot be empty")
        self._scope = scope
        return self

    def duration_hours(self, hours: int) -> BailmentBuilder:
        """Set the duration of the bailment in hours."""
        self._duration_hours = _positive_safe_integer(hours, "duration_hours")
        return self

    def created_at_hlc(self, physical_ms: int, logical: int = 0) -> BailmentBuilder:
        """Set the caller-supplied HLC creation timestamp."""
        self._created_at_hlc = HlcTimestamp(
            physical_ms=_positive_safe_integer(physical_ms, "created_at physical_ms"),
            logical=_hlc_logical(logical),
        )
        return self

    def build(self) -> BailmentProposal:
        """Validate and produce a :class:`BailmentProposal`.

        The ``proposal_id`` is the hex-encoded SHA-256 of a canonical payload
        containing the bailor, bailee, scope, duration, and caller-supplied HLC.
        """
        if self._scope is None:
            raise ConsentError("scope is required")
        if self._duration_hours is None:
            raise ConsentError("duration_hours is required")
        if self._created_at_hlc is None:
            raise ConsentError("created_at_hlc is required")

        payload = _proposal_payload(
            self._bailor,
            self._bailee,
            self._scope,
            self._duration_hours,
            self._created_at_hlc,
        )
        proposal_id: Hash256Hex = sha256(payload).hexdigest()
        return BailmentProposal(
            proposal_id=proposal_id,
            bailor=self._bailor,
            bailee=self._bailee,
            scope=self._scope,
            duration_hours=self._duration_hours,
            created_at=self._created_at_hlc.physical_ms,
            created_at_logical=self._created_at_hlc.logical,
        )


def _proposal_payload(
    bailor: Did,
    bailee: Did,
    scope: str,
    duration_hours: int,
    created_at_hlc: HlcTimestamp,
) -> bytes:
    return b"\0".join(
        [
            bailor.encode("utf-8"),
            bailee.encode("utf-8"),
            scope.encode("utf-8"),
            pack("<Q", duration_hours),
            pack("<Q", created_at_hlc.physical_ms),
            pack("<I", created_at_hlc.logical),
        ]
    )


def _positive_safe_integer(value: int, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
        or value > MAX_SAFE_INTEGER
    ):
        raise ConsentError(f"{field} must be a positive safe integer")
    return value


def _hlc_logical(value: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > HLC_LOGICAL_MAX
    ):
        raise ConsentError(
            f"created_at logical must be an integer between 0 and {HLC_LOGICAL_MAX}"
        )
    return value


__all__ = ["BailmentBuilder", "BailmentProposal", "HlcTimestamp"]
