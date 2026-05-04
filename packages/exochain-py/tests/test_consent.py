"""Tests for the BailmentBuilder and BailmentProposal."""

from __future__ import annotations

from pathlib import Path

import pytest

from exochain import BailmentBuilder, ConsentError, Did

ALICE: Did = "did:exo:alice0001"
BOB: Did = "did:exo:bob0000002"
CREATED_AT_MS = 1_700_000_000_000
CREATED_AT_LOGICAL = 7


def test_builder_happy_path() -> None:
    """A fully-specified builder produces a frozen proposal with a hash id."""
    proposal = (
        BailmentBuilder(ALICE, BOB)
        .scope("read:health-record")
        .duration_hours(48)
        .created_at_hlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build()
    )
    assert proposal.bailor == ALICE
    assert proposal.bailee == BOB
    assert proposal.scope == "read:health-record"
    assert proposal.duration_hours == 48
    assert proposal.created_at == CREATED_AT_MS
    assert proposal.created_at_logical == CREATED_AT_LOGICAL
    # SHA-256 hex is 64 characters.
    assert len(proposal.proposal_id) == 64


def test_missing_scope_fails() -> None:
    """Calling `build` without setting a scope raises ConsentError."""
    builder = BailmentBuilder(ALICE, BOB).duration_hours(12)
    with pytest.raises(ConsentError):
        builder.build()


def test_missing_duration_fails() -> None:
    """Calling `build` without an explicit duration raises ConsentError."""
    builder = BailmentBuilder(ALICE, BOB).scope("read").created_at_hlc(
        CREATED_AT_MS,
        CREATED_AT_LOGICAL,
    )
    with pytest.raises(ConsentError):
        builder.build()


def test_missing_hlc_fails() -> None:
    """Calling `build` without caller-supplied HLC metadata raises ConsentError."""
    builder = BailmentBuilder(ALICE, BOB).scope("read").duration_hours(12)
    with pytest.raises(ConsentError):
        builder.build()


def test_empty_scope_rejected() -> None:
    """An empty or whitespace-only scope is rejected on set."""
    with pytest.raises(ConsentError):
        BailmentBuilder(ALICE, BOB).scope("")
    with pytest.raises(ConsentError):
        BailmentBuilder(ALICE, BOB).scope("   ")


def test_negative_duration_fails() -> None:
    """Non-positive durations are rejected."""
    with pytest.raises(ConsentError):
        BailmentBuilder(ALICE, BOB).scope("x").duration_hours(0)
    with pytest.raises(ConsentError):
        BailmentBuilder(ALICE, BOB).scope("x").duration_hours(-1)


def test_duration_outside_javascript_safe_integer_range_fails() -> None:
    """Durations must stay portable across the first-party SDKs."""
    with pytest.raises(ConsentError):
        BailmentBuilder(ALICE, BOB).scope("x").duration_hours(2**53)


def test_invalid_hlc_fields_fail() -> None:
    """HLC physical time and logical counter must be bounded integers."""
    with pytest.raises(ConsentError):
        BailmentBuilder(ALICE, BOB).created_at_hlc(0, 0)
    with pytest.raises(ConsentError):
        BailmentBuilder(ALICE, BOB).created_at_hlc(CREATED_AT_MS, 2**32)


def test_proposal_id_is_deterministic() -> None:
    """Two equivalent builders produce the same proposal_id."""
    a = (
        BailmentBuilder(ALICE, BOB)
        .scope("read")
        .duration_hours(24)
        .created_at_hlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build()
    )
    b = (
        BailmentBuilder(ALICE, BOB)
        .scope("read")
        .duration_hours(24)
        .created_at_hlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build()
    )
    assert a.proposal_id == b.proposal_id


def test_proposal_id_differs_for_different_inputs() -> None:
    """Distinct scopes or durations produce distinct ids."""
    base = (
        BailmentBuilder(ALICE, BOB)
        .scope("read")
        .duration_hours(24)
        .created_at_hlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build()
    )
    diff_scope = (
        BailmentBuilder(ALICE, BOB)
        .scope("write")
        .duration_hours(24)
        .created_at_hlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build()
    )
    diff_duration = (
        BailmentBuilder(ALICE, BOB)
        .scope("read")
        .duration_hours(48)
        .created_at_hlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build()
    )
    diff_hlc = (
        BailmentBuilder(ALICE, BOB)
        .scope("read")
        .duration_hours(24)
        .created_at_hlc(CREATED_AT_MS, CREATED_AT_LOGICAL + 1)
        .build()
    )
    assert base.proposal_id != diff_scope.proposal_id
    assert base.proposal_id != diff_duration.proposal_id
    assert base.proposal_id != diff_hlc.proposal_id


def test_proposal_is_frozen() -> None:
    """Proposal fields cannot be mutated after construction."""
    proposal = (
        BailmentBuilder(ALICE, BOB)
        .scope("x")
        .duration_hours(1)
        .created_at_hlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build()
    )
    with pytest.raises((TypeError, ValueError)):
        proposal.scope = "other"


def test_builder_source_does_not_read_wall_clock_time() -> None:
    """The builder must not source timestamps from process wall-clock APIs."""
    source = (
        Path(__file__).resolve().parents[1] / "exochain" / "consent" / "bailment.py"
    ).read_text(encoding="utf-8")
    assert "time.time" not in source
    assert "datetime.now" not in source
