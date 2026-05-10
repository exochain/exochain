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

"""Async HTTP transport built on :mod:`httpx`."""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from ..errors import TransportError

_DEFAULT_USER_AGENT = "exochain-py/0.1.0"


class HttpTransport:
    """Thin async wrapper around ``httpx.AsyncClient`` with typed error mapping.

    All network errors are surfaced as :class:`~exochain.errors.TransportError`
    with ``status`` + ``body`` preserved so callers can retry on 503/429 or
    branch on 401 without parsing exception strings. (A-061)

    ``timeout`` accepts either a plain float (seconds, applied to every phase)
    or a fully-configured ``httpx.Timeout`` for per-phase control (connect,
    read, write, pool). (A-061)
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float | httpx.Timeout = 30.0,
    ) -> None:
        headers: dict[str, str] = {"User-Agent": _DEFAULT_USER_AGENT}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client: httpx.AsyncClient = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )

    async def health(self) -> dict[str, Any]:
        """Call ``GET /health`` and return the decoded JSON body."""
        return await self.get("/health")

    async def get(self, path: str) -> dict[str, Any]:
        """Issue a ``GET`` request and return the decoded JSON body."""
        try:
            response = await self._client.get(path)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            raise TransportError(
                f"GET {path} failed: {exc}",
                status=exc.response.status_code,
                body=exc.response.text,
            ) from exc
        except httpx.HTTPError as exc:
            raise TransportError(f"GET {path} failed: {exc}") from exc
        if not isinstance(data, dict):
            raise TransportError(f"GET {path} did not return a JSON object")
        return data

    async def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """Issue a ``POST`` with a JSON body and return the decoded JSON response."""
        try:
            response = await self._client.post(path, json=body)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            raise TransportError(
                f"POST {path} failed: {exc}",
                status=exc.response.status_code,
                body=exc.response.text,
            ) from exc
        except httpx.HTTPError as exc:
            raise TransportError(f"POST {path} failed: {exc}") from exc
        if not isinstance(data, dict):
            raise TransportError(f"POST {path} did not return a JSON object")
        return data

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> HttpTransport:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()


__all__ = ["HttpTransport"]
