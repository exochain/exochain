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

import asyncio
import json
import math
from collections.abc import AsyncIterator
from types import TracebackType
from typing import Any

import httpx

from ..errors import TransportError

_DEFAULT_USER_AGENT = "exochain-py/0.2.6"
_DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024
_RESPONSE_READ_CHUNK_BYTES = 64 * 1024
_INVALID_RESPONSE_LIMIT = "max_response_bytes must be a positive built-in int"
_INVALID_TOTAL_TIMEOUT = "total_timeout must be a positive finite built-in int or float"
_TOTAL_TIMEOUT_EXCEEDED = "total request deadline exceeded"
_MALFORMED_CONTENT_LENGTH = "response Content-Length is malformed"
_UNSUPPORTED_CONTENT_ENCODING = "response Content-Encoding must be identity"


class _BuiltinBytesAsyncStream(httpx.AsyncByteStream):
    """Normalize transport chunks without invoking subclass conversion hooks."""

    def __init__(self, stream: httpx.AsyncByteStream) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._stream:
            yield bytes.__getitem__(chunk, slice(None))

    async def aclose(self) -> None:
        await self._stream.aclose()


class HttpTransport:
    """Thin async wrapper around ``httpx.AsyncClient`` with typed error mapping.

    All network errors are surfaced as :class:`~exochain.errors.TransportError`
    with ``status`` + ``body`` preserved so callers can retry on 503/429 or
    branch on 401 without parsing exception strings. (A-061)

    ``timeout`` accepts either a plain float (seconds, applied to every phase)
    or a fully-configured ``httpx.Timeout`` for per-phase control (connect,
    read, write, pool). ``total_timeout`` is a separate positive finite number
    of seconds for the aggregate request deadline, from response acquisition
    through complete response-body consumption. Both default to 30 seconds.
    (A-061)

    Response bodies are streamed and capped at ``max_response_bytes`` before
    JSON decoding. The default one-MiB boundary is finite for both successful
    and error responses; callers expecting a larger protocol payload must opt
    into an explicit positive byte limit.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float | httpx.Timeout = 30.0,
        total_timeout: float | int = 30.0,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        if type(total_timeout) not in (int, float):
            raise ValueError(_INVALID_TOTAL_TIMEOUT)
        try:
            normalized_total_timeout = float(total_timeout)
        except OverflowError as exc:
            raise ValueError(_INVALID_TOTAL_TIMEOUT) from exc
        if not math.isfinite(normalized_total_timeout) or normalized_total_timeout <= 0:
            raise ValueError(_INVALID_TOTAL_TIMEOUT)
        if type(max_response_bytes) is not int or max_response_bytes <= 0:
            raise ValueError(_INVALID_RESPONSE_LIMIT)

        headers: dict[str, str] = {
            "Accept-Encoding": "identity",
            "User-Agent": _DEFAULT_USER_AGENT,
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._total_timeout = normalized_total_timeout
        self._max_response_bytes = max_response_bytes
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
        return await self._request_json("GET", path)

    async def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """Issue a ``POST`` with a JSON body and return the decoded JSON response."""
        return await self._request_json("POST", path, body=body)

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            async with asyncio.timeout(self._total_timeout):
                async with self._client.stream(method, path, json=body) as response:
                    response_body = await self._read_response_body(response)
                    try:
                        response.raise_for_status()
                    except httpx.HTTPStatusError as exc:
                        response_encoding = response.encoding or "utf-8"
                        try:
                            error_body = bytes.decode(response_body, response_encoding, "replace")
                        except (LookupError, UnicodeError):
                            error_body = bytes.decode(response_body, "utf-8", "replace")
                        raise TransportError(
                            f"{method} {path} failed: {exc}",
                            status=response.status_code,
                            body=error_body,
                        ) from exc
        except TimeoutError as exc:
            raise TransportError(f"{method} {path} failed: {_TOTAL_TIMEOUT_EXCEEDED}") from exc
        except httpx.HTTPError as exc:
            raise TransportError(f"{method} {path} failed: {exc}") from exc

        data: Any = json.loads(response_body)
        if not isinstance(data, dict):
            raise TransportError(f"{method} {path} did not return a JSON object")
        return data

    async def _read_response_body(self, response: httpx.Response) -> bytes:
        content_encoding = response.headers.get("content-encoding")
        if content_encoding is not None:
            try:
                encoded_content_encoding = str.encode(content_encoding, "ascii", "strict")
            except UnicodeEncodeError as exc:
                raise TransportError(
                    _UNSUPPORTED_CONTENT_ENCODING,
                    status=response.status_code,
                ) from exc
            normalized_content_encoding = bytes.lower(bytes.strip(encoded_content_encoding, b" \t"))
            if normalized_content_encoding not in (b"", b"identity"):
                raise TransportError(
                    _UNSUPPORTED_CONTENT_ENCODING,
                    status=response.status_code,
                )

        declared_length = response.headers.get("content-length")
        if declared_length is not None:
            try:
                encoded_length = str.encode(declared_length, "ascii", "strict")
            except UnicodeEncodeError as exc:
                raise TransportError(
                    _MALFORMED_CONTENT_LENGTH,
                    status=response.status_code,
                ) from exc

            if bytes.__len__(encoded_length) == 0 or any(
                byte < ord("0") or byte > ord("9") for byte in encoded_length
            ):
                raise TransportError(
                    _MALFORMED_CONTENT_LENGTH,
                    status=response.status_code,
                )

            significant_length = bytes.lstrip(encoded_length, b"0") or b"0"
            encoded_limit = str.encode(str(self._max_response_bytes), "ascii", "strict")
            declared_digits = bytes.__len__(significant_length)
            limit_digits = bytes.__len__(encoded_limit)
            if declared_digits > limit_digits or (
                declared_digits == limit_digits and significant_length > encoded_limit
            ):
                raise self._oversized_response_error(response)

        body = bytearray()
        chunk_size = min(_RESPONSE_READ_CHUNK_BYTES, self._max_response_bytes + 1)
        if not isinstance(response.stream, httpx.AsyncByteStream):
            raise TransportError(
                "response did not provide an asynchronous byte stream",
                status=response.status_code,
            )
        response.stream = _BuiltinBytesAsyncStream(response.stream)
        async for chunk in response.aiter_bytes(chunk_size=chunk_size):
            current_length = bytearray.__len__(body)
            chunk_length = bytes.__len__(chunk)
            if chunk_length > self._max_response_bytes - current_length:
                raise self._oversized_response_error(response)
            bytearray.extend(body, chunk)
        return bytes(body)

    def _oversized_response_error(self, response: httpx.Response) -> TransportError:
        return TransportError(
            f"response body exceeds configured maximum of {self._max_response_bytes} bytes",
            status=response.status_code,
        )

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
