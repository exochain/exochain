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

"""Tests for AuthorityChainBuilder topology validation."""

from __future__ import annotations

import pytest

from exochain import AuthorityChainBuilder, AuthorityError, Did

ROOT: Did = "did:exo:root000001"
MID: Did = "did:exo:mid0000001"
LEAF: Did = "did:exo:leaf000001"
OTHER: Did = "did:exo:other00001"


def test_valid_two_link_chain() -> None:
    """A well-formed two-link chain builds successfully."""
    chain = (
        AuthorityChainBuilder()
        .add_link(ROOT, MID, ["read"])
        .add_link(MID, LEAF, ["read"])
        .build(LEAF)
    )
    assert chain.depth == 2
    assert chain.terminal == LEAF
    assert chain.links[0].grantor == ROOT
    assert chain.links[1].grantee == LEAF


def test_valid_single_link_chain() -> None:
    """A single link chain terminating at its grantee is valid."""
    chain = AuthorityChainBuilder().add_link(ROOT, LEAF, ["all"]).build(LEAF)
    assert chain.depth == 1
    assert chain.terminal == LEAF


def test_empty_chain_rejected() -> None:
    """Building with no links raises AuthorityError."""
    with pytest.raises(AuthorityError):
        AuthorityChainBuilder().build(LEAF)


def test_broken_chain_rejected() -> None:
    """A chain where links[i].grantee != links[i+1].grantor is rejected."""
    with pytest.raises(AuthorityError):
        (
            AuthorityChainBuilder()
            .add_link(ROOT, MID, ["read"])
            .add_link(OTHER, LEAF, ["read"])
            .build(LEAF)
        )


def test_wrong_terminal_rejected() -> None:
    """A chain ending at someone other than terminal_actor is rejected."""
    with pytest.raises(AuthorityError):
        (
            AuthorityChainBuilder()
            .add_link(ROOT, MID, ["read"])
            .add_link(MID, LEAF, ["read"])
            .build(OTHER)
        )


def test_permissions_must_be_list_of_strings() -> None:
    """Non-list or non-string permissions are rejected at add_link time."""
    b = AuthorityChainBuilder()
    with pytest.raises(AuthorityError):
        b.add_link(ROOT, MID, "read")  # type: ignore[arg-type]
    with pytest.raises(AuthorityError):
        b.add_link(ROOT, MID, [1, 2])  # type: ignore[list-item]
