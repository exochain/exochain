<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# ULTRAPLAN-GAP-004-IDENTITY

## 1. 0dentity Architecture

The 0dentity architecture in Exochain serves as the definitive bridge between an ephemeral, unverified agent and a cryptographically authenticated actor with tangible real-world standing. At its core, the system operates as a polar graph identity map. On one pole sits the real-world entity—a natural person or organization possessing physical evidence (biometrics, government ID, known-good devices). On the opposite pole sits the Decentralized Identifier (DID)—the cryptographic anchor within the Exochain network.

The gap between these poles is bridged by "Identity Proofs." A DID document by itself is merely a self-asserted string of text representing a public key. To establish cryptographic standing, 0dentity mandates an accumulation of evidence binding the DID to the entity. This evidence is diverse, ranging from low-friction One-Time Passwords (OTP) and basic digital signatures, to high-assurance WebAuthn assertions and robust Know Your Customer (KYC) tokens. 

The 0dentity architecture avoids centralized trusted registries by shifting the burden of trust to a risk-scoring model. A `DidRegistry` locally tracks the state of known DIDs, but its ultimate role is to serve as a conduit for verification ceremonies. During a ceremony, proofs are submitted, evaluated, and accumulated. Once sufficient proof is provided, the registry or the broader network issues a `RiskAttestation`, transforming the self-asserted DID into a "Verified DID."

## 2. Cryptographic Standing

Cryptographic standing refers to the incontrovertible proof that an actor controls the private key associated with a specific DID without ever exposing that key or requiring centralized authorization. In Exochain, cryptographic standing is achieved through the integration of modern authentication protocols like WebAuthn and Passkeys, heavily augmented by BLAKE3 hashing.

When a user initiates an action—such as entering a bailment contract—they cannot merely provide their `bailee_did`. They must prove control of it. 0dentity leverages asymmetric cryptography where the verification methods within a `DidDocument` define the acceptable authentication parameters. 

WebAuthn acts as a primary vector for establishing this standing. A Passkey, stored securely on a user's device (e.g., in a secure enclave), generates a signature over a strictly defined challenge using the corresponding private key. This assertion is mathematically verifiable against the public key listed in the DID Document. Because the private key never leaves the device, and the signature is uniquely tied to the challenge and the domain, the standing is unforgeable. All internal hash operations to normalize or identify assertions utilize BLAKE3 for performant, secure deterministic resolution.

## 3. Identity Verification Ceremony

The Identity Verification Ceremony is a structured, stateful workflow designed to elevate an anonymous session into a verified identity. This ceremony tracks the accumulation of evidence over time.

**Step-by-Step Flow:**
1. **Initiation**: A user, represented by an initial DID, initiates a verification ceremony. The system creates a `VerificationCeremony` instance, recording the target DID, the initiation timestamp, and a unique session ID.
2. **Proof Submission**: The user submits various forms of `IdentityProof`. Each proof is independently validated:
   - *Signature*: A payload signed by the DID's private key.
   - *OTP*: A One-Time Password sent to a registered communication channel.
   - *WebAuthnAssertion*: A cryptographic assertion from a Passkey.
   - *KycToken*: A verifiable credential from an external KYC provider.
3. **Accumulation**: Validated proofs are added to the ceremony's internal state. Invalid proofs are rejected.
4. **Scoring Check**: After each submission, the system evaluates the accumulated proofs against the scoring engine to determine the current risk score.
5. **Finalization**: The user (or the system, upon reaching a threshold) requests finalization. If the accumulated proofs yield a satisfactory risk score (e.g., above 5000 basis points), the ceremony concludes successfully.
6. **Attestation Generation**: Upon successful finalization, the system generates a `RiskAttestation` for the DID, encoding the achieved risk level and an expiration timestamp. The DID is now verified.

## 4. Risk Scoring

The Risk Scoring engine is the arbiter of trust within 0dentity. It replaces binary "verified/unverified" flags with a nuanced, deterministic basis-point (bps) system.

The scoring model is additive. Each valid `IdentityProof` contributes a specific weight to the total score. The deterministic function `calculate_risk_score` evaluates the collection of proofs:
- A basic cryptographic signature might yield 1000 bps.
- An OTP validation adds 2000 bps.
- A WebAuthn Assertion provides a substantial 4000 bps.
- A full KYC token grants 5000 bps.

The total score determines the `RiskLevel` assigned in the final `RiskAttestation` (e.g., `Low`, `Medium`, `High`, `Critical`). A `BTreeMap` is heavily utilized to map proof types to their respective scores to ensure deterministic ordering and behavior without the non-determinism associated with HashMaps. Because this operates strictly on integer basis points, floating-point math is explicitly forbidden, preventing rounding errors or consensus divergence across nodes.

## 5. Integration Points

The completion of GAP-004 has significant ramifications for the rest of Exochain:

- **Bailment Contracts (`exo-consent`)**: The `bailor_did` and `bailee_did` fields will no longer accept arbitrary strings. The contract engine will query the `LocalDidRegistry` for a valid `RiskAttestation`. If the DID lacks cryptographic standing or falls below the required risk threshold for the contract value, the bailment is rejected.
- **Decision Forum (`decision-forum`)**: Voting weight or proposal submission rights can be gated by risk level, preventing sybil attacks by requiring a minimum threshold of verified standing.
- **Gateway Enforcement**: The node gateway will intercept incoming requests and validate the accompanying signatures against the known standing of the DID, effectively acting as an identity firewall.

## 6. Implementation Plan

The implementation will proceed in the following ordered sequence:

1. **Foundational Types**: Define `IdentityProof`, `VerificationCeremony`, and `VerificationCeremonyError` (using `thiserror`) in a new `verification.rs` module within `exo-identity`.
2. **Scoring Logic**: Implement the deterministic `calculate_risk_score` function, strictly utilizing integer math and BTreeMaps.
3. **Ceremony State Machine**: Build the logic to initiate, update, and finalize a `VerificationCeremony`, including the generation of the `RiskAttestation`.
4. **Local Registry**: Implement `LocalDidRegistry` in `registry.rs`, providing a robust in-memory implementation of the `DidRegistry` trait, incorporating BLAKE3 hashing for indexing and state tracking.
5. **Test Driven Development**: Write a comprehensive suite of 12 tests covering all lifecycle events, edge cases (expired ceremonies, invalid proofs), and integration scenarios between the registry and the ceremony.
6. **Stub Removal**: Refactor `crates/exo-node/src/zerodentity/store.rs` to integrate the new types, removing "stub" comments and connecting the actual verification logic to the node's storage layer.
7. **Validation**: Run `cargo test` and `cargo clippy` to ensure zero warnings and full adherence to the constitutional constraints (No floats, No HashMap, No unsafe).