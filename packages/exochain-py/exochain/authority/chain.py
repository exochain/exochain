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

"""Authority chain builder and validated chain type.

An *authority chain* is an ordered list of delegation links where the grantee
of each link is the grantor of the next. The chain terminates at a specific
terminal actor. :class:`AuthorityChainBuilder` accumulates links and performs
topology validation in :meth:`AuthorityChainBuilder.build`.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from ..errors import AuthorityError
from ..types import Did


class ChainLink(BaseModel):
    """A single delegation link: grantor → grantee with scoped permissions."""

    model_config = ConfigDict(frozen=True)

    grantor: Did
    grantee: Did
    permissions: list[str]


class ValidatedChain(BaseModel):
    """An authority chain that has passed topology validation."""

    model_config = ConfigDict(frozen=True)

    depth: int
    links: list[ChainLink]
    terminal: Did


class AuthorityChainBuilder:
    """Fluent builder that accumulates links and validates on ``build``."""

    def __init__(self) -> None:
        self._links: list[ChainLink] = []

    def add_link(
        self, grantor: Did, grantee: Did, permissions: list[str]
    ) -> AuthorityChainBuilder:
        """Append a delegation link to the chain."""
        if not isinstance(permissions, list) or not all(
            isinstance(p, str) for p in permissions
        ):
            raise AuthorityError("permissions must be a list of strings")
        self._links.append(
            ChainLink(grantor=grantor, grantee=grantee, permissions=list(permissions))
        )
        return self

    def build(self, terminal_actor: Did) -> ValidatedChain:
        """Validate the accumulated links and produce a :class:`ValidatedChain`.

        Validation rules:
          * The chain must contain at least one link.
          * For each consecutive pair, ``links[i].grantee == links[i+1].grantor``.
          * ``links[-1].grantee == terminal_actor``.

        Raises:
            AuthorityError: if any validation rule is violated.
        """
        if not self._links:
            raise AuthorityError("authority chain is empty")

        for a, b in zip(self._links, self._links[1:], strict=False):
            if a.grantee != b.grantor:
                raise AuthorityError(
                    f"broken delegation: {a.grantee} != {b.grantor}"
                )

        last = self._links[-1]
        if last.grantee != terminal_actor:
            raise AuthorityError(
                f"terminal mismatch: chain ends at {last.grantee} "
                f"but terminal_actor is {terminal_actor}"
            )

        return ValidatedChain(
            depth=len(self._links),
            links=list(self._links),
            terminal=terminal_actor,
        )


__all__ = ["AuthorityChainBuilder", "ChainLink", "ValidatedChain"]
