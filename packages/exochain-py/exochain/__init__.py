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

"""EXOCHAIN SDK for Python.

EXOCHAIN is a constitutional governance fabric for AI agents and data
sovereignty. This package is the pure-Python SDK — Ed25519 identity,
bailment consent, governance decisions, authority chains, and an async
HTTP client.

Quick start:

    >>> from exochain import Identity
    >>> alice = Identity.generate("alice")
    >>> alice.did.startswith("did:exo:")
    True
    >>> sig = alice.sign(b"hello")
    >>> Identity.verify(alice.public_key_hex, b"hello", sig)
    True

See :class:`ExochainClient` for the async fabric client.
"""

from __future__ import annotations

from .authority.chain import AuthorityChainBuilder, ChainLink, ValidatedChain
from .client import ExochainClient
from .consent.bailment import BailmentBuilder, BailmentProposal, HlcTimestamp
from .crypto.hash import sha256, sha256_hex
from .errors import (
    AuthorityError,
    ConsentError,
    CryptoError,
    ExochainError,
    GovernanceError,
    IdentityError,
    KernelError,
    TransportError,
)
from .governance.decision import Decision, DecisionBuilder, DecisionStatus
from .governance.vote import Vote, VoteChoice
from .identity.did import is_did, validate_did
from .identity.keypair import Identity, derive_did
from .transport.http import HttpTransport
from .types import (
    Did,
    ExochainAvcDiscoveryRoutes,
    ExochainDiscoveryResponse,
    ExochainDiscoveryRoutes,
    ExochainMcpDiscovery,
    ExochainSdkDiscovery,
    Hash256Hex,
    QuorumResult,
    TrustReceipt,
)

__version__ = "0.2.1b0"

#: Fabric protocol version this SDK speaks (A-066). Clients may ``/version``-probe
#: a target gateway on init and warn when the server reports a different
#: major/minor so users can distinguish protocol skew from transport errors.
PROTOCOL_VERSION = "0.2.1-beta"

__all__ = [
    "PROTOCOL_VERSION",
    "AuthorityChainBuilder",
    "AuthorityError",
    "BailmentBuilder",
    "BailmentProposal",
    "ChainLink",
    "ConsentError",
    "CryptoError",
    "Decision",
    "DecisionBuilder",
    "DecisionStatus",
    "Did",
    "ExochainAvcDiscoveryRoutes",
    "ExochainDiscoveryResponse",
    "ExochainDiscoveryRoutes",
    "ExochainClient",
    "ExochainError",
    "ExochainMcpDiscovery",
    "ExochainSdkDiscovery",
    "GovernanceError",
    "Hash256Hex",
    "HlcTimestamp",
    "HttpTransport",
    "Identity",
    "IdentityError",
    "KernelError",
    "QuorumResult",
    "TransportError",
    "TrustReceipt",
    "ValidatedChain",
    "Vote",
    "VoteChoice",
    "__version__",
    "derive_did",
    "is_did",
    "sha256",
    "sha256_hex",
    "validate_did",
]
