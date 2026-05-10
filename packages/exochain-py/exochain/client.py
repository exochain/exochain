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

"""High-level :class:`ExochainClient` — a typed facade over the HTTP transport.

The client is intentionally small: it owns an :class:`HttpTransport`, exposes
per-domain methods, and returns typed Pydantic models. Most applications should
prefer this class over constructing a transport directly.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from .errors import KernelError, TransportError
from .transport.http import HttpTransport
from .types import TrustReceipt


class ExochainClient:
    """A typed, async client for an EXOCHAIN fabric endpoint."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float | httpx.Timeout = 30.0,
    ) -> None:
        self._transport: HttpTransport = HttpTransport(
            base_url,
            api_key=api_key,
            timeout=timeout,
        )

    @classmethod
    def from_transport(cls, transport: HttpTransport) -> ExochainClient:
        """Construct a client from a pre-configured :class:`HttpTransport`."""
        obj = cls.__new__(cls)
        obj._transport = transport
        return obj

    @property
    def transport(self) -> HttpTransport:
        """Expose the underlying transport for advanced use cases."""
        return self._transport

    # ---- Kernel ---------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        """Probe the fabric's ``/health`` endpoint."""
        return await self._transport.health()

    async def submit_action(self, action: dict[str, Any]) -> TrustReceipt:
        """Submit an action to the constitutional kernel and get a receipt back."""
        try:
            body = await self._transport.post("/kernel/actions", action)
        except TransportError as exc:
            raise KernelError(f"submit_action failed: {exc}") from exc
        try:
            return TrustReceipt.model_validate(body)
        except Exception as exc:  # pragma: no cover — defensive
            raise KernelError(f"malformed trust receipt: {exc}") from exc

    # ---- Identity -------------------------------------------------------

    async def resolve_did(self, did: str) -> dict[str, Any]:
        """Resolve a DID document from the fabric."""
        return await self._transport.get(f"/identity/{did}")

    # ---- Consent --------------------------------------------------------

    async def submit_bailment(self, proposal: dict[str, Any]) -> dict[str, Any]:
        """Submit a bailment proposal for acceptance by the bailee."""
        return await self._transport.post("/consent/bailments", proposal)

    # ---- Governance -----------------------------------------------------

    async def submit_decision(self, decision: dict[str, Any]) -> dict[str, Any]:
        """Submit a governance decision for quorum-based evaluation."""
        return await self._transport.post("/governance/decisions", decision)

    async def cast_vote(self, decision_id: str, vote: dict[str, Any]) -> dict[str, Any]:
        """Cast a vote on an existing governance decision."""
        return await self._transport.post(
            f"/governance/decisions/{decision_id}/votes", vote
        )

    # ---- Lifecycle ------------------------------------------------------

    async def close(self) -> None:
        """Release network resources."""
        await self._transport.close()

    async def __aenter__(self) -> ExochainClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()


__all__ = ["ExochainClient"]
