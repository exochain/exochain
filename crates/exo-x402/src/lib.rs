// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! # exo-x402 — authorization facilitator adapter
//!
//! x402 defines client, server, and payment facilitator. Exochain is the
//! **authorization facilitator**: Cloudflare's edge asks "may this agent
//! pay and consume?" and later "here is the receipt."
//!
//! This crate deliberately does **not** embed x402/MPP/USDC protocol types
//! in `exo-avc`. It hashes generic payment evidence and maps AVC decisions
//! onto HTTP 403 / 428 / 402 / 200.
//!
//! ## Determinism contract
//!
//! - Integer minor units only. No floating-point arithmetic.
//! - Canonical CBOR (`ciborium`) for all hashed evidence.
//! - `BTreeMap` only if a map is required; this crate uses structs.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod error;
pub mod evidence;
pub mod http;

pub use error::{Result, X402Error};
pub use evidence::PaymentEvidence;
pub use http::{
    AUTHORIZATION_CHALLENGE_SCHEMA, AuthorizationChallenge, AuthorizationHttpMapping,
    HEADER_PAYMENT_REQUIRED, HEADER_PAYMENT_RESPONSE, HEADER_PAYMENT_SIGNATURE, HTTP_FORBIDDEN,
    HTTP_OK, HTTP_PAYMENT_REQUIRED, HTTP_PRECONDITION_REQUIRED, is_never_paywalled_path,
    map_authorization_to_http,
};

#[cfg(test)]
mod hygiene_tests {
    #[test]
    fn no_hashmap_or_hashset_in_production_sources() {
        let sources = [
            include_str!("error.rs"),
            include_str!("evidence.rs"),
            include_str!("http.rs"),
            include_str!("lib.rs"),
        ];
        let banned_map = ["Hash", "Map"].concat();
        let banned_set = ["Hash", "Set"].concat();
        for src in sources {
            let production = src.split("#[cfg(test)]").next().unwrap();
            assert!(
                !production.contains(&banned_map),
                "x402 production sources must not use HashMap"
            );
            assert!(
                !production.contains(&banned_set),
                "x402 production sources must not use HashSet"
            );
        }
    }

    #[test]
    fn no_floating_point_in_production_sources() {
        let sources = [
            include_str!("error.rs"),
            include_str!("evidence.rs"),
            include_str!("http.rs"),
            include_str!("lib.rs"),
        ];
        for src in sources {
            let production = src.split("#[cfg(test)]").next().unwrap();
            for token in [": f32", ": f64", "as f32", "as f64", "f32::", "f64::"] {
                assert!(
                    !production.contains(token),
                    "x402 production sources must not contain `{token}`"
                );
            }
        }
    }

    #[test]
    fn does_not_import_x402_protocol_crates() {
        let sources = [
            include_str!("error.rs"),
            include_str!("evidence.rs"),
            include_str!("http.rs"),
            include_str!("lib.rs"),
        ];
        for src in sources {
            let production = src.split("#[cfg(test)]").next().unwrap();
            assert!(
                !production.contains("x402_rs")
                    && !production.contains("x402-hono")
                    && !production.contains("coinbase"),
                "adapter must not import x402 protocol implementations"
            );
        }
    }
}
