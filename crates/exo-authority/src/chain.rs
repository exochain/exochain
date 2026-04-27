//! Authority chain — ordered sequence of delegation links.
//!
//! Authority flows from root to leaf. Scope can only narrow at each link.
//! Max delegation depth: 5 (configurable).

use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{
    error::AuthorityError,
    permission::{Permission, PermissionSet},
};

/// Default maximum delegation depth.
pub const DEFAULT_MAX_DEPTH: usize = 5;
/// Domain tag for authority delegation signatures.
pub const AUTHORITY_LINK_SIGNING_DOMAIN: &str = "exo.authority.delegation.v1";
const AUTHORITY_LINK_SIGNING_SCHEMA_VERSION: u16 = 1;

#[derive(Serialize)]
struct AuthorityLinkSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    delegator_did: &'a Did,
    delegate_did: &'a Did,
    scope: &'a [Permission],
    created: &'a Timestamp,
    expires: &'a Option<Timestamp>,
    depth: usize,
    delegatee_kind: &'a DelegateeKind,
}

/// Distinguishes human delegatees from AI agent delegatees.
///
/// This field is part of the signed payload in [`AuthorityLink`], making
/// the delegatee kind cryptographically bound to the delegation grant.
/// AI-agent delegations are distinguishable in compliance reports without
/// relying on caller-supplied flags.
///
/// Uses `#[serde(default)]` on the containing field so existing serialised
/// delegation records without this field deserialise as `Unknown` rather
/// than failing — preserving backward compatibility across CBOR round-trips.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DelegateeKind {
    /// A human principal authenticated through the identity layer.
    Human,
    /// An AI agent operating under a constitutional delegation.
    ///
    /// `model_id` identifies the AI model. In redacted compliance reports
    /// this is replaced with `BLAKE3(tenant_id || model_id || redaction_salt)`.
    AiAgent { model_id: String },
    /// Kind was not specified at delegation creation time (legacy records).
    #[default]
    Unknown,
}

/// A single link in an authority chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityLink {
    pub delegator_did: Did,
    pub delegate_did: Did,
    pub scope: Vec<Permission>,
    pub created: Timestamp,
    pub expires: Option<Timestamp>,
    pub signature: Signature,
    pub depth: usize,
    /// Kind of delegatee — Human, AiAgent, or Unknown for legacy records.
    /// Defaults to `Unknown` when deserialising records that predate this field.
    #[serde(default)]
    pub delegatee_kind: DelegateeKind,
}

impl AuthorityLink {
    /// Compute a deterministic ID for this link.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityError::SigningPayloadEncoding` if canonical CBOR
    /// encoding of the signed payload fails.
    pub fn id(&self) -> Result<Hash256, AuthorityError> {
        Ok(Hash256::digest(&self.signing_payload()?))
    }

    /// The canonical payload that must be signed by the delegator.
    ///
    /// The payload is domain-separated canonical CBOR and excludes the
    /// signature itself. Permissions are represented as a deterministic set so
    /// caller ordering cannot alter the grant identity.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityError::SigningPayloadEncoding` if canonical CBOR
    /// encoding fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, AuthorityError> {
        let scope: Vec<Permission> = PermissionSet::from_permissions(&self.scope)
            .iter()
            .copied()
            .collect();
        let payload = AuthorityLinkSigningPayload {
            domain: AUTHORITY_LINK_SIGNING_DOMAIN,
            schema_version: AUTHORITY_LINK_SIGNING_SCHEMA_VERSION,
            delegator_did: &self.delegator_did,
            delegate_did: &self.delegate_did,
            scope: &scope,
            created: &self.created,
            expires: &self.expires,
            depth: self.depth,
            delegatee_kind: &self.delegatee_kind,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf).map_err(|e| {
            AuthorityError::SigningPayloadEncoding {
                reason: e.to_string(),
            }
        })?;
        Ok(buf)
    }
}

/// An ordered sequence of authority links from root to leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityChain {
    pub links: Vec<AuthorityLink>,
    pub max_depth: usize,
}

impl AuthorityChain {
    #[must_use]
    pub fn depth(&self) -> usize {
        self.links.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// The root delegator (first link's delegator).
    #[must_use]
    pub fn root(&self) -> Option<&Did> {
        self.links.first().map(|l| &l.delegator_did)
    }

    /// The leaf delegate (last link's delegate).
    #[must_use]
    pub fn leaf(&self) -> Option<&Did> {
        self.links.last().map(|l| &l.delegate_did)
    }
}

/// Build an authority chain from a slice of links.
///
/// Validates:
/// - Non-empty
/// - Continuity: each link's delegate == next link's delegator
/// - Depth limits
/// - Depth values are correct (0, 1, 2, ...)
///
/// # Errors
/// Returns `AuthorityError` if validation fails.
pub fn build_chain(links: &[AuthorityLink]) -> Result<AuthorityChain, AuthorityError> {
    build_chain_with_depth(links, DEFAULT_MAX_DEPTH)
}

/// Build a chain with a custom max depth.
pub fn build_chain_with_depth(
    links: &[AuthorityLink],
    max_depth: usize,
) -> Result<AuthorityChain, AuthorityError> {
    if links.is_empty() {
        return Err(AuthorityError::EmptyChain);
    }

    if links.len() > max_depth {
        return Err(AuthorityError::DepthExceeded {
            depth: links.len(),
            max_depth,
        });
    }

    // Validate continuity and depth values
    for (i, link) in links.iter().enumerate() {
        if link.depth != i {
            return Err(AuthorityError::ChainBroken {
                index: i,
                reason: format!("expected depth {i}, got {}", link.depth),
            });
        }
        if i > 0 {
            let prev = &links[i - 1];
            if prev.delegate_did != link.delegator_did {
                return Err(AuthorityError::ChainBroken {
                    index: i,
                    reason: format!(
                        "gap: {} -> {} but expected {}",
                        prev.delegate_did, link.delegator_did, prev.delegate_did
                    ),
                });
            }
        }
    }

    Ok(AuthorityChain {
        links: links.to_vec(),
        max_depth,
    })
}

/// Verify an authority chain with cryptographic signature verification.
///
/// `resolve_key` maps a DID to a `PublicKey`. Each link's signature is verified
/// against the delegator's public key and the link's canonical signable payload.
///
/// # Errors
/// Returns `AuthorityError` on any verification failure:
/// - Empty chain, depth exceeded, expired links, scope widening
/// - Invalid or forged Ed25519 signatures
pub fn verify_chain<F>(
    chain: &AuthorityChain,
    now: &Timestamp,
    resolve_key: F,
) -> Result<(), AuthorityError>
where
    F: Fn(&Did) -> Option<PublicKey>,
{
    if chain.links.is_empty() {
        return Err(AuthorityError::EmptyChain);
    }

    if chain.links.len() > chain.max_depth {
        return Err(AuthorityError::DepthExceeded {
            depth: chain.links.len(),
            max_depth: chain.max_depth,
        });
    }

    let mut prev_scope: Option<PermissionSet> = None;

    for (i, link) in chain.links.iter().enumerate() {
        // Check signature is non-empty
        if link.signature.is_empty() {
            return Err(AuthorityError::InvalidSignature { index: i });
        }

        // Real Ed25519 signature verification
        let pub_key = resolve_key(&link.delegator_did)
            .ok_or(AuthorityError::InvalidSignature { index: i })?;
        let payload = link.signing_payload()?;
        if !exo_core::crypto::verify(&payload, &link.signature, &pub_key) {
            return Err(AuthorityError::InvalidSignature { index: i });
        }

        // Check expiry
        if let Some(exp) = &link.expires {
            if exp.is_expired(now) {
                return Err(AuthorityError::ExpiredLink { index: i });
            }
        }

        // Check scope narrows (each link's scope must be subset of previous)
        let current_scope = PermissionSet::from_permissions(&link.scope);
        if let Some(ref prev) = prev_scope {
            if !PermissionSet::is_subset(&current_scope, prev) {
                return Err(AuthorityError::ScopeWidening { index: i });
            }
        }
        prev_scope = Some(current_scope);
    }

    Ok(())
}

/// Check if a chain grants a specific permission.
///
/// The permission must appear in the leaf (last) link's scope,
/// and scope must have narrowed properly through the chain.
#[must_use]
pub fn has_permission(chain: &AuthorityChain, permission: &Permission) -> bool {
    // All links must contain the permission (scope narrows but must include it)
    chain
        .links
        .iter()
        .all(|link| link.scope.contains(permission))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use exo_core::crypto::KeyPair;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).unwrap()
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }
    fn now() -> Timestamp {
        ts(5000)
    }

    /// A test key registry mapping DIDs to keypairs.
    struct KeyRegistry {
        keys: HashMap<String, KeyPair>,
    }

    impl KeyRegistry {
        fn new() -> Self {
            Self {
                keys: HashMap::new(),
            }
        }

        fn register(&mut self, name: &str) -> PublicKey {
            let kp = KeyPair::generate();
            let pk = *kp.public_key();
            self.keys.insert(format!("did:exo:{name}"), kp);
            pk
        }

        fn resolve(&self, did: &Did) -> Option<PublicKey> {
            self.keys.get(did.as_str()).map(|kp| *kp.public_key())
        }

        fn resolver(&self) -> impl Fn(&Did) -> Option<PublicKey> + '_ {
            |did| self.resolve(did)
        }
    }

    /// Create a properly-signed authority link.
    fn signed_link(
        registry: &KeyRegistry,
        from: &str,
        to: &str,
        scope: Vec<Permission>,
        depth: usize,
        exp: Option<Timestamp>,
    ) -> AuthorityLink {
        let mut link = AuthorityLink {
            delegator_did: did(from),
            delegate_did: did(to),
            scope,
            created: ts(1000),
            expires: exp,
            signature: Signature::empty(),
            depth,
            delegatee_kind: DelegateeKind::Human,
        };
        let payload = link.signing_payload().expect("canonical signing payload");
        let kp = registry
            .keys
            .get(&format!("did:exo:{from}"))
            .expect("key not registered");
        link.signature = kp.sign(&payload);
        link
    }

    /// Create a link with a fake (non-verified) signature for structural tests.
    fn fake_link(
        from: &str,
        to: &str,
        scope: Vec<Permission>,
        depth: usize,
        exp: Option<Timestamp>,
    ) -> AuthorityLink {
        AuthorityLink {
            delegator_did: did(from),
            delegate_did: did(to),
            scope,
            created: ts(1000),
            expires: exp,
            signature: Signature::from_bytes([0xA5u8; 64]),
            depth,
            delegatee_kind: DelegateeKind::Human,
        }
    }

    // -- build_chain tests (structural only, no sig verification) --

    #[test]
    fn build_single_link() {
        let links = vec![fake_link(
            "root",
            "alice",
            vec![Permission::Read, Permission::Write],
            0,
            None,
        )];
        let chain = build_chain(&links);
        assert!(chain.is_ok());
        let c = chain.unwrap();
        assert_eq!(c.depth(), 1);
        assert_eq!(c.root().unwrap(), &did("root"));
        assert_eq!(c.leaf().unwrap(), &did("alice"));
    }

    #[test]
    fn build_multi_link() {
        let links = vec![
            fake_link(
                "root",
                "alice",
                vec![Permission::Read, Permission::Write, Permission::Delegate],
                0,
                None,
            ),
            fake_link(
                "alice",
                "bob",
                vec![Permission::Read, Permission::Write],
                1,
                None,
            ),
            fake_link("bob", "charlie", vec![Permission::Read], 2, None),
        ];
        let chain = build_chain(&links).unwrap();
        assert_eq!(chain.depth(), 3);
    }

    #[test]
    fn build_rejects_empty() {
        assert_eq!(build_chain(&[]), Err(AuthorityError::EmptyChain));
    }

    #[test]
    fn build_rejects_depth_exceeded() {
        let links: Vec<AuthorityLink> = (0..6)
            .map(|i| {
                fake_link(
                    &format!("n{i}"),
                    &format!("n{}", i + 1),
                    vec![Permission::Read],
                    i,
                    None,
                )
            })
            .collect();
        let result = build_chain(&links);
        assert!(matches!(result, Err(AuthorityError::DepthExceeded { .. })));
    }

    #[test]
    fn build_custom_depth() {
        let links: Vec<AuthorityLink> = (0..3)
            .map(|i| {
                fake_link(
                    &format!("n{i}"),
                    &format!("n{}", i + 1),
                    vec![Permission::Read],
                    i,
                    None,
                )
            })
            .collect();
        assert!(build_chain_with_depth(&links, 2).is_err());
        assert!(build_chain_with_depth(&links, 3).is_ok());
    }

    #[test]
    fn build_rejects_gap() {
        let links = vec![
            fake_link("root", "alice", vec![Permission::Read], 0, None),
            fake_link("bob", "charlie", vec![Permission::Read], 1, None),
        ];
        assert!(matches!(
            build_chain(&links),
            Err(AuthorityError::ChainBroken { .. })
        ));
    }

    #[test]
    fn build_rejects_wrong_depth() {
        let links = vec![
            fake_link("root", "alice", vec![Permission::Read], 0, None),
            fake_link("alice", "bob", vec![Permission::Read], 5, None),
        ];
        assert!(matches!(
            build_chain(&links),
            Err(AuthorityError::ChainBroken { .. })
        ));
    }

    // -- verify_chain tests with REAL Ed25519 verification --

    #[test]
    fn verify_valid_chain_real_signatures() {
        let mut reg = KeyRegistry::new();
        reg.register("root");
        reg.register("alice");

        let links = vec![
            signed_link(
                &reg,
                "root",
                "alice",
                vec![Permission::Read, Permission::Write],
                0,
                None,
            ),
            signed_link(&reg, "alice", "bob", vec![Permission::Read], 1, None),
        ];
        let chain = build_chain(&links).unwrap();
        assert!(verify_chain(&chain, &now(), reg.resolver()).is_ok());
    }

    #[test]
    fn verify_rejects_forged_signature() {
        let mut reg = KeyRegistry::new();
        reg.register("root");

        let mut link = signed_link(&reg, "root", "alice", vec![Permission::Read], 0, None);
        // Forge: replace signature with random bytes
        link.signature = Signature::from_bytes([0xDE; 64]);
        let chain = build_chain(&[link]).unwrap();
        assert!(matches!(
            verify_chain(&chain, &now(), reg.resolver()),
            Err(AuthorityError::InvalidSignature { index: 0 })
        ));
    }

    #[test]
    fn verify_rejects_wrong_key_signature() {
        let mut reg = KeyRegistry::new();
        reg.register("root");
        reg.register("alice");

        // Sign with alice's key but claim root is delegator
        let mut link = AuthorityLink {
            delegator_did: did("root"),
            delegate_did: did("alice"),
            scope: vec![Permission::Read],
            created: ts(1000),
            expires: None,
            signature: Signature::empty(),
            depth: 0,
            delegatee_kind: DelegateeKind::Human,
        };
        let payload = link.signing_payload().expect("canonical signing payload");
        // Sign with alice's key (wrong key for root)
        let alice_kp = reg.keys.get("did:exo:alice").unwrap();
        link.signature = alice_kp.sign(&payload);

        let chain = build_chain(&[link]).unwrap();
        assert!(matches!(
            verify_chain(&chain, &now(), reg.resolver()),
            Err(AuthorityError::InvalidSignature { index: 0 })
        ));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let mut reg = KeyRegistry::new();
        reg.register("root");

        let mut link = signed_link(&reg, "root", "alice", vec![Permission::Read], 0, None);
        // Tamper: change the delegate after signing
        link.delegate_did = did("mallory");
        let chain = build_chain(&[link]).unwrap();
        assert!(matches!(
            verify_chain(&chain, &now(), reg.resolver()),
            Err(AuthorityError::InvalidSignature { index: 0 })
        ));
    }

    #[test]
    fn verify_rejects_empty_signature() {
        let mut reg = KeyRegistry::new();
        reg.register("root");

        let mut link = signed_link(&reg, "root", "alice", vec![Permission::Read], 0, None);
        link.signature = Signature::empty();
        let chain = build_chain(&[link]).unwrap();
        assert!(matches!(
            verify_chain(&chain, &now(), reg.resolver()),
            Err(AuthorityError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn verify_rejects_expired_link() {
        let mut reg = KeyRegistry::new();
        reg.register("root");

        let links = vec![signed_link(
            &reg,
            "root",
            "alice",
            vec![Permission::Read],
            0,
            Some(ts(1000)),
        )];
        let chain = build_chain(&links).unwrap();
        assert!(matches!(
            verify_chain(&chain, &now(), reg.resolver()),
            Err(AuthorityError::ExpiredLink { .. })
        ));
    }

    #[test]
    fn verify_rejects_scope_widening() {
        let mut reg = KeyRegistry::new();
        reg.register("root");
        reg.register("alice");

        let links = vec![
            signed_link(&reg, "root", "alice", vec![Permission::Read], 0, None),
            signed_link(
                &reg,
                "alice",
                "bob",
                vec![Permission::Read, Permission::Write],
                1,
                None,
            ),
        ];
        let chain = build_chain(&links).unwrap();
        assert!(matches!(
            verify_chain(&chain, &now(), reg.resolver()),
            Err(AuthorityError::ScopeWidening { .. })
        ));
    }

    #[test]
    fn verify_accepts_equal_scope() {
        let mut reg = KeyRegistry::new();
        reg.register("root");
        reg.register("alice");

        let links = vec![
            signed_link(
                &reg,
                "root",
                "alice",
                vec![Permission::Read, Permission::Write],
                0,
                None,
            ),
            signed_link(
                &reg,
                "alice",
                "bob",
                vec![Permission::Read, Permission::Write],
                1,
                None,
            ),
        ];
        let chain = build_chain(&links).unwrap();
        assert!(verify_chain(&chain, &now(), reg.resolver()).is_ok());
    }

    #[test]
    fn verify_rejects_unknown_delegator() {
        let reg = KeyRegistry::new();
        // Don't register "root" — key resolution will fail
        let link = fake_link("root", "alice", vec![Permission::Read], 0, None);
        let chain = build_chain(&[link]).unwrap();
        assert!(matches!(
            verify_chain(&chain, &now(), reg.resolver()),
            Err(AuthorityError::InvalidSignature { index: 0 })
        ));
    }

    #[test]
    fn has_permission_present() {
        let links = vec![
            fake_link(
                "root",
                "alice",
                vec![Permission::Read, Permission::Write],
                0,
                None,
            ),
            fake_link("alice", "bob", vec![Permission::Read], 1, None),
        ];
        let chain = build_chain(&links).unwrap();
        assert!(has_permission(&chain, &Permission::Read));
        assert!(!has_permission(&chain, &Permission::Write));
    }

    #[test]
    fn has_permission_empty_chain() {
        let chain = AuthorityChain {
            links: vec![],
            max_depth: 5,
        };
        assert!(has_permission(&chain, &Permission::Read));
    }

    #[test]
    fn link_id_deterministic() {
        let l = fake_link("root", "alice", vec![Permission::Read], 0, None);
        let id1 = l.id().expect("canonical link id");
        let id2 = l.id().expect("canonical link id");
        assert_eq!(id1, id2);
    }

    #[test]
    fn signing_payload_deterministic() {
        let l = fake_link("root", "alice", vec![Permission::Read], 0, None);
        assert_eq!(
            l.signing_payload().expect("canonical signing payload"),
            l.signing_payload().expect("canonical signing payload")
        );
    }

    #[test]
    fn authority_link_signing_payload_is_domain_tagged_cbor() {
        #[derive(Deserialize)]
        struct DecodedPayload {
            domain: String,
            schema_version: u16,
        }

        let link = fake_link("root", "alice", vec![Permission::Read], 0, None);
        let payload = link.signing_payload().expect("canonical signing payload");
        let decoded: DecodedPayload =
            ciborium::from_reader(payload.as_slice()).expect("decode authority payload");

        assert_eq!(decoded.domain, AUTHORITY_LINK_SIGNING_DOMAIN);
        assert_eq!(decoded.schema_version, 1);
    }

    #[test]
    fn chain_is_empty() {
        let chain = AuthorityChain {
            links: vec![],
            max_depth: 5,
        };
        assert!(chain.is_empty());
        assert!(chain.root().is_none());
        assert!(chain.leaf().is_none());
    }

    #[test]
    fn verify_chain_rejects_over_depth() {
        let mut reg = KeyRegistry::new();
        for i in 0..3 {
            reg.register(&format!("n{i}"));
        }

        let links: Vec<AuthorityLink> = (0..3)
            .map(|i| {
                signed_link(
                    &reg,
                    &format!("n{i}"),
                    &format!("n{}", i + 1),
                    vec![Permission::Read],
                    i,
                    None,
                )
            })
            .collect();
        let mut chain = build_chain(&links).unwrap();
        chain.max_depth = 2;
        assert!(matches!(
            verify_chain(&chain, &now(), reg.resolver()),
            Err(AuthorityError::DepthExceeded { .. })
        ));
    }

    #[test]
    fn verify_empty_chain_errors() {
        let chain = AuthorityChain {
            links: vec![],
            max_depth: 5,
        };
        let reg = KeyRegistry::new();
        assert_eq!(
            verify_chain(&chain, &now(), reg.resolver()),
            Err(AuthorityError::EmptyChain)
        );
    }

    #[test]
    fn verify_non_expired_link() {
        let mut reg = KeyRegistry::new();
        reg.register("root");

        let links = vec![signed_link(
            &reg,
            "root",
            "alice",
            vec![Permission::Read],
            0,
            Some(ts(10000)),
        )];
        let chain = build_chain(&links).unwrap();
        assert!(verify_chain(&chain, &now(), reg.resolver()).is_ok());
    }

    #[test]
    fn verify_three_link_chain_real_crypto() {
        let mut reg = KeyRegistry::new();
        reg.register("ceo");
        reg.register("vp");
        reg.register("manager");

        let links = vec![
            signed_link(
                &reg,
                "ceo",
                "vp",
                vec![Permission::Read, Permission::Write, Permission::Delegate],
                0,
                None,
            ),
            signed_link(
                &reg,
                "vp",
                "manager",
                vec![Permission::Read, Permission::Write],
                1,
                None,
            ),
            signed_link(&reg, "manager", "analyst", vec![Permission::Read], 2, None),
        ];
        let chain = build_chain(&links).unwrap();
        assert!(verify_chain(&chain, &now(), reg.resolver()).is_ok());
    }
}
