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

//! Authority delegation and chain verification.
//!
//! An **authority chain** is an ordered list of delegation links where the
//! `grantee` of each link is the `grantor` of the next. The chain terminates
//! at a specific actor (the "terminal"). [`AuthorityChainBuilder`] accumulates
//! links and validates the resulting topology on
//! [`AuthorityChainBuilder::build`]. Structurally:
//!
//! ```text
//! root --[perms]--> middle --[perms]--> leaf
//! ```
//!
//! ## Why use this module
//!
//! - You need to prove that a terminal actor was delegated authority through
//!   a well-formed chain rooted at a specific principal.
//! - You want the SDK to reject broken topologies (gaps, wrong terminal,
//!   empty chain) before you ever submit them to the kernel.
//! - You want the validated chain as a serializable artifact that survives
//!   network hops and storage.
//!
//! ## Quick start
//!
//! ```
//! use exochain_sdk::authority::AuthorityChainBuilder;
//! use exo_core::Did;
//!
//! let root = Did::new("did:exo:root").expect("valid");
//! let mid = Did::new("did:exo:mid").expect("valid");
//! let leaf = Did::new("did:exo:leaf").expect("valid");
//!
//! let chain = AuthorityChainBuilder::new()
//!     .add_link(root, mid.clone(), vec!["delegate".into()])
//!     .add_link(mid, leaf.clone(), vec!["read".into()])
//!     .build(&leaf)?;
//!
//! assert_eq!(chain.depth, 2);
//! assert_eq!(chain.terminal, leaf);
//! # Ok::<(), exochain_sdk::error::ExoError>(())
//! ```

use exo_core::Did;
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::error::{ExoError, ExoResult};

/// Maximum delegation links accepted in an SDK authority chain.
///
/// This bound prevents untrusted chain material from driving unbounded memory
/// growth while remaining far above the constitutional delegation depths used
/// by the runtime.
pub const MAX_CHAIN_DEPTH: usize = 64;

/// Builder for a validated authority chain.
///
/// Links are appended one at a time with [`AuthorityChainBuilder::add_link`]
/// and the full chain is validated by [`AuthorityChainBuilder::build`]. The
/// builder is `Default` and `Clone`, so a partially-built chain can be forked.
///
/// # Examples
///
/// ```
/// use exochain_sdk::authority::AuthorityChainBuilder;
/// use exo_core::Did;
///
/// let root = Did::new("did:exo:root").expect("valid");
/// let leaf = Did::new("did:exo:leaf").expect("valid");
/// let chain = AuthorityChainBuilder::new()
///     .add_link(root, leaf.clone(), vec!["all".into()])
///     .build(&leaf)?;
/// assert_eq!(chain.depth, 1);
/// # Ok::<(), exochain_sdk::error::ExoError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct AuthorityChainBuilder {
    links: Vec<ChainLink>,
    overflowed: bool,
}

impl AuthorityChainBuilder {
    /// Construct an empty builder.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::authority::AuthorityChainBuilder;
    /// let builder = AuthorityChainBuilder::new();
    /// # let _ = builder;
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            links: Vec::new(),
            overflowed: false,
        }
    }

    /// Append a new delegation link.
    ///
    /// Each link records that `grantor` has delegated `permissions` to
    /// `grantee`. Permission strings are opaque to the SDK; downstream
    /// consumers are free to interpret them.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::authority::AuthorityChainBuilder;
    /// # use exo_core::Did;
    /// let a = Did::new("did:exo:a").expect("valid");
    /// let b = Did::new("did:exo:b").expect("valid");
    /// let builder = AuthorityChainBuilder::new()
    ///     .add_link(a, b, vec!["read".into(), "write".into()]);
    /// # let _ = builder;
    /// ```
    #[must_use]
    pub fn add_link(mut self, grantor: Did, grantee: Did, permissions: Vec<String>) -> Self {
        if self.links.len() >= MAX_CHAIN_DEPTH {
            self.overflowed = true;
            return self;
        }
        self.links.push(ChainLink {
            grantor,
            grantee,
            permissions,
        });
        self
    }

    /// Validate the chain topology and produce a [`ValidatedChain`].
    ///
    /// Validation rules:
    /// - The chain must contain at least one link.
    /// - For each consecutive pair of links,
    ///   `links[i].grantee == links[i+1].grantor`.
    /// - The final link's `grantee` must equal `terminal_actor`.
    ///
    /// # Errors
    ///
    /// Returns [`ExoError::Authority`] if any rule is violated: empty chain,
    /// a broken delegation between consecutive links, or a mismatch between
    /// the terminal link's grantee and `terminal_actor`.
    ///
    /// # Examples
    ///
    /// A valid three-link chain:
    ///
    /// ```
    /// use exochain_sdk::authority::AuthorityChainBuilder;
    /// use exo_core::Did;
    ///
    /// let root = Did::new("did:exo:root").expect("valid");
    /// let mid = Did::new("did:exo:mid").expect("valid");
    /// let leaf = Did::new("did:exo:leaf").expect("valid");
    /// let chain = AuthorityChainBuilder::new()
    ///     .add_link(root, mid.clone(), vec!["delegate".into()])
    ///     .add_link(mid, leaf.clone(), vec!["read".into()])
    ///     .build(&leaf)?;
    /// assert_eq!(chain.depth, 2);
    /// # Ok::<(), exochain_sdk::error::ExoError>(())
    /// ```
    ///
    /// A broken chain (middle grantee does not match next grantor):
    ///
    /// ```
    /// use exochain_sdk::authority::AuthorityChainBuilder;
    /// use exochain_sdk::error::ExoError;
    /// use exo_core::Did;
    ///
    /// let root = Did::new("did:exo:root").expect("valid");
    /// let mid = Did::new("did:exo:mid").expect("valid");
    /// let other = Did::new("did:exo:other").expect("valid");
    /// let leaf = Did::new("did:exo:leaf").expect("valid");
    /// let err = AuthorityChainBuilder::new()
    ///     .add_link(root, mid, vec!["read".into()])
    ///     .add_link(other, leaf.clone(), vec!["read".into()])
    ///     .build(&leaf)
    ///     .unwrap_err();
    /// assert!(matches!(err, ExoError::Authority(_)));
    /// ```
    pub fn build(self, terminal_actor: &Did) -> ExoResult<ValidatedChain> {
        if self.overflowed {
            return Err(ExoError::Authority(format!(
                "authority chain depth exceeds maximum of {MAX_CHAIN_DEPTH}"
            )));
        }
        let depth = self.links.len();
        validate_chain_parts(depth, &self.links, terminal_actor).map_err(ExoError::Authority)?;
        Ok(ValidatedChain {
            depth,
            links: self.links,
            terminal: terminal_actor.clone(),
        })
    }
}

struct BoundedChainLinks(Vec<ChainLink>);

impl<'de> Deserialize<'de> for BoundedChainLinks {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedChainLinksVisitor)
    }
}

struct BoundedChainLinksVisitor;

impl<'de> de::Visitor<'de> for BoundedChainLinksVisitor {
    type Value = BoundedChainLinks;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "an authority chain containing at most {MAX_CHAIN_DEPTH} links"
        )
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        if seq.size_hint().is_some_and(|hint| hint > MAX_CHAIN_DEPTH) {
            return Err(de::Error::custom(format!(
                "authority chain depth exceeds maximum of {MAX_CHAIN_DEPTH}"
            )));
        }

        let mut links = Vec::new();
        while let Some(link) = seq.next_element()? {
            if links.len() >= MAX_CHAIN_DEPTH {
                return Err(de::Error::custom(format!(
                    "authority chain depth exceeds maximum of {MAX_CHAIN_DEPTH}"
                )));
            }
            links.push(link);
        }

        Ok(BoundedChainLinks(links))
    }
}

/// A single delegation link in an authority chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLink {
    /// The delegating authority.
    pub grantor: Did,
    /// The recipient of the delegation.
    pub grantee: Did,
    /// Permissions delegated at this link.
    pub permissions: Vec<String>,
}

/// A validated authority chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidatedChain {
    /// Number of links in the chain.
    pub depth: usize,
    /// The chain of delegation links, root-first.
    pub links: Vec<ChainLink>,
    /// The terminal actor the chain delegates authority to.
    pub terminal: Did,
}

impl<'de> Deserialize<'de> for ValidatedChain {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireValidatedChain {
            depth: usize,
            links: BoundedChainLinks,
            terminal: Did,
        }

        let wire = WireValidatedChain::deserialize(deserializer)?;
        let links = wire.links.0;
        validate_chain_parts(wire.depth, &links, &wire.terminal).map_err(de::Error::custom)?;
        Ok(Self {
            depth: wire.depth,
            links,
            terminal: wire.terminal,
        })
    }
}

fn validate_chain_parts(depth: usize, links: &[ChainLink], terminal: &Did) -> Result<(), String> {
    if depth > MAX_CHAIN_DEPTH || links.len() > MAX_CHAIN_DEPTH {
        return Err(format!(
            "authority chain depth exceeds maximum of {MAX_CHAIN_DEPTH}"
        ));
    }
    if links.is_empty() {
        return Err("authority chain is empty".into());
    }
    if depth != links.len() {
        return Err(format!(
            "authority chain depth {depth} does not match link count {}",
            links.len()
        ));
    }

    for window in links.windows(2) {
        let a = &window[0];
        let b = &window[1];
        if a.grantee != b.grantor {
            return Err(format!("broken delegation: {} != {}", a.grantee, b.grantor));
        }
    }

    let Some(last) = links.last() else {
        return Err("authority chain is empty".into());
    };
    if &last.grantee != terminal {
        return Err(format!(
            "terminal mismatch: chain ends at {} but terminal_actor is {}",
            last.grantee, terminal
        ));
    }

    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid DID")
    }

    #[test]
    fn valid_chain_passes() {
        let root = did("did:exo:root");
        let mid = did("did:exo:mid");
        let leaf = did("did:exo:leaf");
        let chain = AuthorityChainBuilder::new()
            .add_link(root.clone(), mid.clone(), vec!["read".into()])
            .add_link(mid.clone(), leaf.clone(), vec!["read".into()])
            .build(&leaf)
            .expect("valid");
        assert_eq!(chain.depth, 2);
        assert_eq!(chain.terminal, leaf);
        assert_eq!(chain.links[0].grantor, root);
        assert_eq!(chain.links[1].grantee, leaf);
    }

    #[test]
    fn single_link_chain_passes() {
        let root = did("did:exo:root");
        let leaf = did("did:exo:leaf");
        let chain = AuthorityChainBuilder::new()
            .add_link(root, leaf.clone(), vec!["all".into()])
            .build(&leaf)
            .expect("valid");
        assert_eq!(chain.depth, 1);
    }

    #[test]
    fn empty_chain_fails() {
        let leaf = did("did:exo:leaf");
        let err = AuthorityChainBuilder::new().build(&leaf).unwrap_err();
        assert!(matches!(err, ExoError::Authority(_)));
    }

    #[test]
    fn broken_chain_fails() {
        let root = did("did:exo:root");
        let mid = did("did:exo:mid");
        let other = did("did:exo:other");
        let leaf = did("did:exo:leaf");
        let err = AuthorityChainBuilder::new()
            .add_link(root, mid, vec!["read".into()])
            .add_link(other, leaf.clone(), vec!["read".into()])
            .build(&leaf)
            .unwrap_err();
        assert!(matches!(err, ExoError::Authority(_)));
    }

    #[test]
    fn wrong_terminal_fails() {
        let root = did("did:exo:root");
        let mid = did("did:exo:mid");
        let leaf = did("did:exo:leaf");
        let claimed = did("did:exo:claimed");
        let err = AuthorityChainBuilder::new()
            .add_link(root, mid.clone(), vec!["read".into()])
            .add_link(mid, leaf, vec!["read".into()])
            .build(&claimed)
            .unwrap_err();
        assert!(matches!(err, ExoError::Authority(_)));
    }

    #[test]
    fn validated_chain_serde_roundtrip() {
        let root = did("did:exo:root");
        let leaf = did("did:exo:leaf");
        let chain = AuthorityChainBuilder::new()
            .add_link(root, leaf.clone(), vec!["read".into(), "write".into()])
            .build(&leaf)
            .expect("ok");
        let json = serde_json::to_string(&chain).expect("serialize");
        let decoded: ValidatedChain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(chain, decoded);
    }

    #[test]
    fn validated_chain_deserialization_rejects_broken_topology() {
        let json = serde_json::json!({
            "depth": 2,
            "links": [
                {
                    "grantor": "did:exo:root",
                    "grantee": "did:exo:mid",
                    "permissions": ["read"]
                },
                {
                    "grantor": "did:exo:other",
                    "grantee": "did:exo:leaf",
                    "permissions": ["read"]
                }
            ],
            "terminal": "did:exo:leaf"
        });

        let result = serde_json::from_value::<ValidatedChain>(json);

        assert!(
            result.is_err(),
            "deserialization must enforce authority-chain continuity"
        );
    }

    #[test]
    fn validated_chain_deserialization_rejects_depth_mismatch() {
        let root = did("did:exo:root");
        let leaf = did("did:exo:leaf");
        let chain = AuthorityChainBuilder::new()
            .add_link(root, leaf.clone(), vec!["read".into()])
            .build(&leaf)
            .expect("valid");
        let mut json = serde_json::to_value(&chain).expect("serialize");
        json["depth"] = serde_json::json!(usize::MAX);

        let result = serde_json::from_value::<ValidatedChain>(json);

        assert!(
            result.is_err(),
            "deserialization must reject forged depth metadata"
        );
    }

    #[test]
    fn builder_rejects_chain_beyond_maximum_depth() {
        let mut builder = AuthorityChainBuilder::new();
        for i in 0..65 {
            builder = builder.add_link(
                did(&format!("did:exo:node-{i}")),
                did(&format!("did:exo:node-{}", i + 1)),
                vec!["read".into()],
            );
        }

        let err = builder
            .build(&did("did:exo:node-65"))
            .expect_err("authority chains deeper than 64 links must be rejected");

        assert!(matches!(err, ExoError::Authority(_)));
    }

    #[test]
    fn builder_accepts_chain_at_maximum_depth() {
        let mut builder = AuthorityChainBuilder::new();
        for i in 0..MAX_CHAIN_DEPTH {
            builder = builder.add_link(
                did(&format!("did:exo:max-node-{i}")),
                did(&format!("did:exo:max-node-{}", i + 1)),
                vec!["read".into()],
            );
        }

        let chain = builder
            .build(&did(&format!("did:exo:max-node-{MAX_CHAIN_DEPTH}")))
            .expect("authority chains at the maximum depth must remain valid");

        assert_eq!(chain.depth, MAX_CHAIN_DEPTH);
    }

    #[test]
    fn builder_does_not_retain_links_beyond_maximum_depth() {
        let mut builder = AuthorityChainBuilder::new();
        for i in 0..(MAX_CHAIN_DEPTH + 10) {
            builder = builder.add_link(
                did(&format!("did:exo:capped-node-{i}")),
                did(&format!("did:exo:capped-node-{}", i + 1)),
                vec!["read".into()],
            );
        }

        assert_eq!(builder.links.len(), MAX_CHAIN_DEPTH);
        assert!(
            builder.overflowed,
            "builder must remember that an over-depth chain was attempted"
        );
    }

    #[test]
    fn validated_chain_deserialization_rejects_chain_beyond_maximum_depth() {
        let links: Vec<_> = (0..65)
            .map(|i| {
                serde_json::json!({
                    "grantor": format!("did:exo:node-{i}"),
                    "grantee": format!("did:exo:node-{}", i + 1),
                    "permissions": ["read"]
                })
            })
            .collect();
        let json = serde_json::json!({
            "depth": 65,
            "links": links,
            "terminal": "did:exo:node-65"
        });

        assert!(
            serde_json::from_value::<ValidatedChain>(json).is_err(),
            "deserialization must reject authority chains deeper than 64 links"
        );
    }

    #[test]
    fn validated_chain_deserialization_accepts_chain_at_maximum_depth() {
        let links: Vec<_> = (0..MAX_CHAIN_DEPTH)
            .map(|i| {
                serde_json::json!({
                    "grantor": format!("did:exo:serde-max-node-{i}"),
                    "grantee": format!("did:exo:serde-max-node-{}", i + 1),
                    "permissions": ["read"]
                })
            })
            .collect();
        let json = serde_json::json!({
            "depth": MAX_CHAIN_DEPTH,
            "links": links,
            "terminal": format!("did:exo:serde-max-node-{MAX_CHAIN_DEPTH}")
        });

        let chain =
            serde_json::from_value::<ValidatedChain>(json).expect("max-depth chain is valid");

        assert_eq!(chain.depth, MAX_CHAIN_DEPTH);
        assert_eq!(chain.links.len(), MAX_CHAIN_DEPTH);
    }

    #[test]
    fn default_builder_is_empty() {
        let b = AuthorityChainBuilder::default();
        assert!(b.links.is_empty());
    }
}
