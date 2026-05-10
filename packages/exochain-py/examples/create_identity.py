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

"""Create a new EXOCHAIN identity and sign a message.

Run:
    python examples/create_identity.py
"""

from __future__ import annotations

from exochain import Identity


def main() -> None:
    # Generate a fresh Ed25519 keypair with a derived DID.
    alice = Identity.generate("alice")
    print(f"DID:        {alice.did}")
    print(f"Public key: {alice.public_key_hex}")
    print(f"Label:      {alice.label}")

    # Sign a message.
    message = b"I agree to the terms."
    signature = alice.sign(message)
    print(f"Signature:  {signature.hex()}")

    # Verify — anyone with the public key can check the signature.
    ok = Identity.verify(alice.public_key_hex, message, signature)
    print(f"Verifies:   {ok}")


if __name__ == "__main__":
    main()
