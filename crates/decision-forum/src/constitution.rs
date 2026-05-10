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

//! Constitutional corpus management (GOV-001, GOV-002, GOV-006).
//!
//! Per-tenant machine-readable constitutional corpus with semantic versioning,
//! temporal binding (every decision stores the constitution hash), and a
//! conflict resolution hierarchy:
//! Articles > Bylaws > Resolutions > Charters > Policies (GOV-006).

use std::collections::BTreeSet;

use exo_core::{
    crypto,
    hash::hash_structured,
    types::{Did, Hash256, PublicKey, Signature, Timestamp, Version},
};
use serde::{Deserialize, Serialize};

use crate::error::{ForumError, Result};

const CONSTITUTION_CORPUS_HASH_DOMAIN: &str = "decision.forum.constitution_corpus.v1";
const CONSTITUTION_CORPUS_HASH_SCHEMA_VERSION: u16 = 1;
const CONSTITUTION_RATIFICATION_SIGNATURE_DOMAIN: &str =
    "decision.forum.constitution_ratification_signature.v1";
const CONSTITUTION_AMENDMENT_SIGNATURE_DOMAIN: &str =
    "decision.forum.constitution_amendment_signature.v1";
const CONSTITUTION_AMENDMENT_HASH_DOMAIN: &str = "decision.forum.constitution_amendment_hash.v1";

/// Document tier in the conflict resolution hierarchy (GOV-006).
/// Articles override Bylaws, Bylaws override Resolutions, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DocumentTier {
    Articles = 0,
    Bylaws = 1,
    Resolutions = 2,
    Charters = 3,
    Policies = 4,
}

impl DocumentTier {
    fn as_str(self) -> &'static str {
        match self {
            DocumentTier::Articles => "Articles",
            DocumentTier::Bylaws => "Bylaws",
            DocumentTier::Resolutions => "Resolutions",
            DocumentTier::Charters => "Charters",
            DocumentTier::Policies => "Policies",
        }
    }
}

/// Status of a constitutional article.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArticleStatus {
    Active,
    Amended,
    Repealed,
}

/// A single article within a constitutional document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Article {
    pub id: String,
    pub title: String,
    pub tier: DocumentTier,
    pub text_hash: Hash256,
    pub status: ArticleStatus,
}

/// Quorum policy for ratification / amendments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstitutionQuorum {
    pub required_signatures: usize,
    pub required_fraction_pct: u32,
}

/// The full constitutional corpus for a tenant (GOV-001).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstitutionCorpus {
    pub version: Version,
    pub hash: Hash256,
    pub articles: Vec<Article>,
    pub ratified_at: Option<Timestamp>,
    pub amendment_count: u32,
}

impl ConstitutionCorpus {
    /// Create a new constitution from a set of articles. Computes the
    /// corpus hash deterministically.
    pub fn new(articles: Vec<Article>) -> Result<Self> {
        let hash = compute_corpus_hash(&articles)?;
        Ok(ConstitutionCorpus {
            version: Version::ZERO.next(),
            hash,
            articles,
            ratified_at: None,
            amendment_count: 0,
        })
    }

    /// Returns true if the constitution has been ratified.
    #[must_use]
    pub fn is_ratified(&self) -> bool {
        self.ratified_at.is_some()
    }

    /// Look up an article by ID.
    #[must_use]
    pub fn find_article(&self, id: &str) -> Option<&Article> {
        self.articles.iter().find(|a| a.id == id)
    }

    /// Returns the number of active articles.
    #[must_use]
    pub fn active_article_count(&self) -> usize {
        self.articles
            .iter()
            .filter(|a| a.status == ArticleStatus::Active)
            .count()
    }

    /// Resolve a conflict between two articles based on tier hierarchy.
    /// Returns the article with the higher-priority (lower ordinal) tier.
    #[must_use]
    pub fn resolve_conflict<'a>(&self, a: &'a Article, b: &'a Article) -> &'a Article {
        if a.tier <= b.tier { a } else { b }
    }
}

/// Resolve a signer DID to a public key for constitution signature verification.
pub trait PublicKeyResolver {
    fn resolve(&self, did: &Did) -> Option<PublicKey>;
}

impl<F> PublicKeyResolver for F
where
    F: Fn(&Did) -> Option<PublicKey>,
{
    fn resolve(&self, did: &Did) -> Option<PublicKey> {
        (self)(did)
    }
}

#[derive(Debug, Clone, Serialize)]
struct RatificationSignaturePayload<'a> {
    domain: &'static str,
    action_type: &'static str,
    signer_did: &'a Did,
    corpus_hash: &'a Hash256,
    version: &'a Version,
    amendment_count: u32,
    quorum: &'a ConstitutionQuorum,
    timestamp: &'a Timestamp,
}

#[derive(Debug, Clone, Serialize)]
struct AmendmentSignaturePayload<'a> {
    domain: &'static str,
    action_type: &'static str,
    signer_did: &'a Did,
    corpus_hash: &'a Hash256,
    version: &'a Version,
    amendment_count: u32,
    amendment_hash: &'a Hash256,
    quorum: &'a ConstitutionQuorum,
    timestamp: &'a Timestamp,
}

#[derive(Debug, Clone, Serialize)]
struct AmendmentHashPayload<'a> {
    domain: &'static str,
    amendment: &'a Article,
}

fn amendment_hash(amendment: &Article) -> Result<Hash256> {
    Ok(hash_structured(&AmendmentHashPayload {
        domain: CONSTITUTION_AMENDMENT_HASH_DOMAIN,
        amendment,
    })?)
}

/// Canonical message bytes to sign for corpus ratification.
pub fn ratification_signature_message(
    corpus: &ConstitutionCorpus,
    signer_did: &Did,
    quorum: &ConstitutionQuorum,
    timestamp: Timestamp,
) -> Result<Vec<u8>> {
    let digest = hash_structured(&RatificationSignaturePayload {
        domain: CONSTITUTION_RATIFICATION_SIGNATURE_DOMAIN,
        action_type: "ratify",
        signer_did,
        corpus_hash: &corpus.hash,
        version: &corpus.version,
        amendment_count: corpus.amendment_count,
        quorum,
        timestamp: &timestamp,
    })?;
    Ok(digest.as_ref().to_vec())
}

/// Canonical message bytes to sign for a proposed amendment.
pub fn amendment_signature_message(
    corpus: &ConstitutionCorpus,
    amendment: &Article,
    signer_did: &Did,
    quorum: &ConstitutionQuorum,
    timestamp: Timestamp,
) -> Result<Vec<u8>> {
    let amendment_hash = amendment_hash(amendment)?;
    let digest = hash_structured(&AmendmentSignaturePayload {
        domain: CONSTITUTION_AMENDMENT_SIGNATURE_DOMAIN,
        action_type: "amend",
        signer_did,
        corpus_hash: &corpus.hash,
        version: &corpus.version,
        amendment_count: corpus.amendment_count,
        amendment_hash: &amendment_hash,
        quorum,
        timestamp: &timestamp,
    })?;
    Ok(digest.as_ref().to_vec())
}

fn required_signature_count(quorum: &ConstitutionQuorum, eligible_count: usize) -> Result<usize> {
    if quorum.required_fraction_pct > 100 {
        return Err(ForumError::ConstitutionalConflict {
            reason: format!(
                "required_fraction_pct must be <= 100, got {}",
                quorum.required_fraction_pct
            ),
        });
    }

    let by_fraction = if quorum.required_fraction_pct == 0 || eligible_count == 0 {
        0
    } else {
        let eligible_count =
            u128::try_from(eligible_count).map_err(|_| ForumError::ConstitutionalConflict {
                reason: "eligible signer count cannot be represented for quorum math".to_string(),
            })?;
        let numerator = eligible_count * u128::from(quorum.required_fraction_pct);
        usize::try_from(numerator.div_ceil(100)).map_err(|_| {
            ForumError::ConstitutionalConflict {
                reason: "required signature count exceeds platform capacity".to_string(),
            }
        })?
    };

    Ok(quorum.required_signatures.max(by_fraction))
}

fn count_verified_signatures<R, F>(
    signatures: &[(Did, Signature)],
    eligible_signers: &BTreeSet<Did>,
    resolver: &R,
    mut message_for: F,
) -> Result<usize>
where
    R: PublicKeyResolver,
    F: FnMut(&Did) -> Result<Vec<u8>>,
{
    let mut verified = BTreeSet::new();

    for (did, signature) in signatures {
        if !eligible_signers.contains(did) || verified.contains(did) {
            continue;
        }
        if signature.is_empty() || signature.ed25519_component_is_zero() {
            continue;
        }
        let Some(public_key) = resolver.resolve(did) else {
            continue;
        };
        let message = message_for(did)?;
        if crypto::verify(&message, signature, &public_key) {
            verified.insert(did.clone());
        }
    }

    Ok(verified.len())
}

fn ensure_verified_quorum<R, F>(
    signatures: &[(Did, Signature)],
    quorum: &ConstitutionQuorum,
    eligible_signers: &BTreeSet<Did>,
    resolver: &R,
    message_for: F,
) -> Result<usize>
where
    R: PublicKeyResolver,
    F: FnMut(&Did) -> Result<Vec<u8>>,
{
    let required = required_signature_count(quorum, eligible_signers.len())?;
    let actual = count_verified_signatures(signatures, eligible_signers, resolver, message_for)?;
    if actual < required {
        return Err(ForumError::QuorumNotMet { required, actual });
    }
    Ok(actual)
}

/// Ratify a constitution after verifying distinct eligible signer signatures.
pub fn ratify_verified<R: PublicKeyResolver>(
    corpus: &mut ConstitutionCorpus,
    signatures: &[(Did, Signature)],
    quorum: &ConstitutionQuorum,
    timestamp: Timestamp,
    eligible_signers: &BTreeSet<Did>,
    resolver: &R,
) -> Result<()> {
    if corpus.is_ratified() {
        return Err(ForumError::NotRatified {
            reason: "already ratified".into(),
        });
    }
    ensure_verified_quorum(signatures, quorum, eligible_signers, resolver, |did| {
        ratification_signature_message(corpus, did, quorum, timestamp)
    })?;
    corpus.ratified_at = Some(timestamp);
    Ok(())
}

/// Amend a ratified constitution after verifying distinct eligible signer signatures.
pub fn amend_verified<R: PublicKeyResolver>(
    corpus: &mut ConstitutionCorpus,
    amendment: Article,
    signatures: &[(Did, Signature)],
    quorum: &ConstitutionQuorum,
    timestamp: Timestamp,
    eligible_signers: &BTreeSet<Did>,
    resolver: &R,
) -> Result<()> {
    if !corpus.is_ratified() {
        return Err(ForumError::AmendmentFailed {
            reason: "not ratified".into(),
        });
    }
    ensure_verified_quorum(signatures, quorum, eligible_signers, resolver, |did| {
        amendment_signature_message(corpus, &amendment, did, quorum, timestamp)
    })?;

    let next_version = Version(corpus.version.value().checked_add(1).ok_or_else(|| {
        ForumError::AmendmentFailed {
            reason: format!(
                "constitution version overflow: cannot advance beyond {}",
                corpus.version.value()
            ),
        }
    })?);
    let next_amendment_count =
        corpus
            .amendment_count
            .checked_add(1)
            .ok_or_else(|| ForumError::AmendmentFailed {
                reason: format!(
                    "amendment count overflow: cannot advance beyond {}",
                    corpus.amendment_count
                ),
            })?;
    let mut next_articles = corpus.articles.clone();
    next_articles.push(amendment);
    let next_hash = compute_corpus_hash(&next_articles)?;

    corpus.articles = next_articles;
    corpus.version = next_version;
    corpus.hash = next_hash;
    corpus.amendment_count = next_amendment_count;
    Ok(())
}

/// Deprecated fail-closed API. Use [`ratify_verified`].
#[deprecated(note = "use ratify_verified; non-cryptographic signature counting is rejected")]
pub fn ratify(
    _corpus: &mut ConstitutionCorpus,
    _signatures: &[(Did, Signature)],
    _quorum: &ConstitutionQuorum,
    _timestamp: Timestamp,
) -> Result<()> {
    Err(ForumError::AuthorityInvalid {
        reason: "ratification requires cryptographic verification via ratify_verified".into(),
    })
}

/// Deprecated fail-closed API. Use [`amend_verified`].
#[deprecated(note = "use amend_verified; non-cryptographic signature counting is rejected")]
pub fn amend(
    _corpus: &mut ConstitutionCorpus,
    _amendment: Article,
    _signatures: &[(Did, Signature)],
) -> Result<()> {
    Err(ForumError::AuthorityInvalid {
        reason: "amendment requires cryptographic verification via amend_verified".into(),
    })
}

/// Dry-run mode: check whether an amendment would conflict with existing
/// articles without actually applying it.
pub fn dry_run_amendment(corpus: &ConstitutionCorpus, proposed: &Article) -> Result<Vec<String>> {
    let mut conflicts = Vec::new();
    for existing in &corpus.articles {
        if existing.status != ArticleStatus::Active {
            continue;
        }
        // Same tier, same ID => direct conflict
        if existing.id == proposed.id {
            conflicts.push(format!(
                "Article '{}' already exists at tier {}",
                existing.id,
                existing.tier.as_str()
            ));
        }
    }
    Ok(conflicts)
}

#[derive(Debug, Clone, Serialize)]
struct CorpusHashPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    articles: &'a [Article],
}

fn corpus_hash_payload(articles: &[Article]) -> CorpusHashPayload<'_> {
    CorpusHashPayload {
        domain: CONSTITUTION_CORPUS_HASH_DOMAIN,
        schema_version: CONSTITUTION_CORPUS_HASH_SCHEMA_VERSION,
        articles,
    }
}

/// Compute a deterministic hash over all articles in the corpus.
fn compute_corpus_hash(articles: &[Article]) -> Result<Hash256> {
    hash_structured(&corpus_hash_payload(articles)).map_err(ForumError::from)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use exo_core::{
        crypto::{self, KeyPair},
        types::{PublicKey, Signature},
    };

    use super::*;

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).expect("valid")
    }
    fn sig() -> Signature {
        let mut s = [0u8; 64];
        s[0] = 1;
        Signature::from_bytes(s)
    }
    fn empty_sig() -> Signature {
        Signature::from_bytes([0u8; 64])
    }

    fn keypair(seed: u8) -> KeyPair {
        KeyPair::from_secret_bytes([seed; 32]).expect("deterministic keypair")
    }

    fn public_key_map(entries: &[(Did, &KeyPair)]) -> BTreeMap<Did, PublicKey> {
        entries
            .iter()
            .map(|(did, keypair)| (did.clone(), *keypair.public_key()))
            .collect()
    }

    fn sign_ratification(
        corpus: &ConstitutionCorpus,
        signer_did: &Did,
        quorum: &ConstitutionQuorum,
        timestamp: Timestamp,
        keypair: &KeyPair,
    ) -> Signature {
        let message = ratification_signature_message(corpus, signer_did, quorum, timestamp)
            .expect("ratification payload");
        crypto::sign(&message, keypair.secret_key())
    }

    fn sign_amendment(
        corpus: &ConstitutionCorpus,
        amendment: &Article,
        signer_did: &Did,
        quorum: &ConstitutionQuorum,
        timestamp: Timestamp,
        keypair: &KeyPair,
    ) -> Signature {
        let message = amendment_signature_message(corpus, amendment, signer_did, quorum, timestamp)
            .expect("amendment payload");
        crypto::sign(&message, keypair.secret_key())
    }

    fn article(id: &str, tier: DocumentTier) -> Article {
        Article {
            id: id.into(),
            title: id.into(),
            tier,
            text_hash: Hash256::digest(id.as_bytes()),
            status: ArticleStatus::Active,
        }
    }

    fn quorum() -> ConstitutionQuorum {
        ConstitutionQuorum {
            required_signatures: 2,
            required_fraction_pct: 50,
        }
    }

    fn eligible(dids: &[Did]) -> BTreeSet<Did> {
        dids.iter().cloned().collect()
    }

    #[test]
    fn new_not_ratified() {
        let c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        assert!(!c.is_ratified());
        assert_eq!(c.version, Version::ZERO.next());
    }

    #[test]
    fn ratify_ok() {
        let alice = did("a");
        let bob = did("b");
        let alice_key = keypair(1);
        let bob_key = keypair(2);
        let keys = public_key_map(&[(alice.clone(), &alice_key), (bob.clone(), &bob_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let sigs = vec![
            (
                alice.clone(),
                sign_ratification(&c, &alice, &quorum(), Timestamp::ZERO, &alice_key),
            ),
            (
                bob.clone(),
                sign_ratification(&c, &bob, &quorum(), Timestamp::ZERO, &bob_key),
            ),
        ];
        ratify_verified(
            &mut c,
            &sigs,
            &quorum(),
            Timestamp::ZERO,
            &eligible(&[alice, bob]),
            &resolver,
        )
        .expect("ok");
        assert!(c.is_ratified());
    }

    #[test]
    fn ratify_quorum_not_met() {
        let alice = did("a");
        let bob = did("b");
        let alice_key = keypair(1);
        let bob_key = keypair(2);
        let keys = public_key_map(&[(alice.clone(), &alice_key), (bob.clone(), &bob_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let sigs = vec![(
            alice.clone(),
            sign_ratification(&c, &alice, &quorum(), Timestamp::ZERO, &alice_key),
        )];
        let err = ratify_verified(
            &mut c,
            &sigs,
            &quorum(),
            Timestamp::ZERO,
            &eligible(&[alice, bob]),
            &resolver,
        )
        .unwrap_err();
        assert!(matches!(err, ForumError::QuorumNotMet { .. }));
    }

    #[test]
    fn ratify_already() {
        let alice = did("a");
        let bob = did("b");
        let alice_key = keypair(1);
        let bob_key = keypair(2);
        let keys = public_key_map(&[(alice.clone(), &alice_key), (bob.clone(), &bob_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let sigs = vec![
            (
                alice.clone(),
                sign_ratification(&c, &alice, &quorum(), Timestamp::ZERO, &alice_key),
            ),
            (
                bob.clone(),
                sign_ratification(&c, &bob, &quorum(), Timestamp::ZERO, &bob_key),
            ),
        ];
        ratify_verified(
            &mut c,
            &sigs,
            &quorum(),
            Timestamp::ZERO,
            &eligible(&[alice.clone(), bob.clone()]),
            &resolver,
        )
        .expect("ok");
        assert!(
            ratify_verified(
                &mut c,
                &sigs,
                &quorum(),
                Timestamp::ZERO,
                &eligible(&[alice, bob]),
                &resolver,
            )
            .is_err()
        );
    }

    #[test]
    fn empty_sig_not_counted() {
        let alice = did("a");
        let bob = did("b");
        let alice_key = keypair(1);
        let bob_key = keypair(2);
        let keys = public_key_map(&[(alice.clone(), &alice_key), (bob.clone(), &bob_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let sigs = vec![
            (
                alice.clone(),
                sign_ratification(&c, &alice, &quorum(), Timestamp::ZERO, &alice_key),
            ),
            (bob.clone(), empty_sig()),
        ];
        assert!(
            ratify_verified(
                &mut c,
                &sigs,
                &quorum(),
                Timestamp::ZERO,
                &eligible(&[alice, bob]),
                &resolver,
            )
            .is_err()
        );
    }

    #[test]
    fn amend_ok() {
        let alice = did("a");
        let bob = did("b");
        let alice_key = keypair(1);
        let bob_key = keypair(2);
        let keys = public_key_map(&[(alice.clone(), &alice_key), (bob.clone(), &bob_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let ratify_sigs = vec![
            (
                alice.clone(),
                sign_ratification(&c, &alice, &quorum(), Timestamp::ZERO, &alice_key),
            ),
            (
                bob.clone(),
                sign_ratification(&c, &bob, &quorum(), Timestamp::ZERO, &bob_key),
            ),
        ];
        ratify_verified(
            &mut c,
            &ratify_sigs,
            &quorum(),
            Timestamp::ZERO,
            &eligible(&[alice.clone(), bob.clone()]),
            &resolver,
        )
        .expect("ok");
        let old_hash = c.hash;
        let amendment = article("a2", DocumentTier::Bylaws);
        let amendment_sigs = vec![
            (
                alice.clone(),
                sign_amendment(
                    &c,
                    &amendment,
                    &alice,
                    &quorum(),
                    Timestamp::ZERO,
                    &alice_key,
                ),
            ),
            (
                bob.clone(),
                sign_amendment(&c, &amendment, &bob, &quorum(), Timestamp::ZERO, &bob_key),
            ),
        ];
        amend_verified(
            &mut c,
            amendment,
            &amendment_sigs,
            &quorum(),
            Timestamp::ZERO,
            &eligible(&[alice, bob]),
            &resolver,
        )
        .expect("ok");
        assert_eq!(c.articles.len(), 2);
        assert_eq!(c.version, Version::ZERO.next().next());
        assert_ne!(c.hash, old_hash);
        assert_eq!(c.amendment_count, 1);
    }

    #[test]
    fn amend_not_ratified() {
        let alice = did("a");
        let alice_key = keypair(1);
        let keys = public_key_map(&[(alice.clone(), &alice_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let amendment = article("a2", DocumentTier::Bylaws);
        let q = ConstitutionQuorum {
            required_signatures: 1,
            required_fraction_pct: 100,
        };
        let amendment_sigs = vec![(
            alice.clone(),
            sign_amendment(&c, &amendment, &alice, &q, Timestamp::ZERO, &alice_key),
        )];
        assert!(
            amend_verified(
                &mut c,
                amendment,
                &amendment_sigs,
                &q,
                Timestamp::ZERO,
                &eligible(&[alice]),
                &resolver,
            )
            .is_err()
        );
    }

    #[test]
    fn amend_no_valid_sigs() {
        let alice = did("a");
        let bob = did("b");
        let alice_key = keypair(1);
        let bob_key = keypair(2);
        let keys = public_key_map(&[(alice.clone(), &alice_key), (bob.clone(), &bob_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let ratify_sigs = vec![
            (
                alice.clone(),
                sign_ratification(&c, &alice, &quorum(), Timestamp::ZERO, &alice_key),
            ),
            (
                bob.clone(),
                sign_ratification(&c, &bob, &quorum(), Timestamp::ZERO, &bob_key),
            ),
        ];
        ratify_verified(
            &mut c,
            &ratify_sigs,
            &quorum(),
            Timestamp::ZERO,
            &eligible(&[alice.clone(), bob.clone()]),
            &resolver,
        )
        .expect("ok");
        let amendment = article("a2", DocumentTier::Bylaws);
        assert!(
            amend_verified(
                &mut c,
                amendment,
                &[(alice.clone(), empty_sig())],
                &quorum(),
                Timestamp::ZERO,
                &eligible(&[alice, bob]),
                &resolver,
            )
            .is_err()
        );
    }

    #[test]
    fn conflict_resolution_hierarchy() {
        let c = ConstitutionCorpus::new(vec![]).expect("valid corpus");
        let art = article("a1", DocumentTier::Articles);
        let bylaw = article("b1", DocumentTier::Bylaws);
        assert_eq!(c.resolve_conflict(&art, &bylaw).id, "a1");
        assert_eq!(c.resolve_conflict(&bylaw, &art).id, "a1");
    }

    #[test]
    fn dry_run_detects_conflict() {
        let c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let conflicts = dry_run_amendment(&c, &article("a1", DocumentTier::Articles)).expect("ok");
        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn dry_run_conflicts_use_stable_tier_labels() {
        let c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let conflicts = dry_run_amendment(&c, &article("a1", DocumentTier::Articles)).expect("ok");
        assert_eq!(
            conflicts,
            vec!["Article 'a1' already exists at tier Articles"]
        );
    }

    #[test]
    fn dry_run_no_conflict() {
        let c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let conflicts = dry_run_amendment(&c, &article("a2", DocumentTier::Bylaws)).expect("ok");
        assert!(conflicts.is_empty());
    }

    #[test]
    fn corpus_hash_payload_is_domain_separated_cbor() {
        let articles = vec![article("a1", DocumentTier::Articles)];
        let payload = corpus_hash_payload(&articles);
        assert_eq!(payload.domain, CONSTITUTION_CORPUS_HASH_DOMAIN);
        assert_eq!(
            payload.schema_version,
            CONSTITUTION_CORPUS_HASH_SCHEMA_VERSION
        );
        assert_eq!(payload.articles.len(), 1);
        assert_eq!(payload.articles[0].id, "a1");
    }

    #[test]
    fn corpus_hash_changes_when_article_title_changes() {
        let base = article("a1", DocumentTier::Articles);
        let mut renamed = base.clone();
        renamed.title = "renamed article".into();
        let c1 = ConstitutionCorpus::new(vec![base]).expect("valid corpus");
        let c2 = ConstitutionCorpus::new(vec![renamed]).expect("valid corpus");
        assert_ne!(c1.hash, c2.hash);
    }

    #[test]
    fn corpus_hash_changes_when_article_status_changes() {
        let base = article("a1", DocumentTier::Articles);
        let mut repealed = base.clone();
        repealed.status = ArticleStatus::Repealed;
        let c1 = ConstitutionCorpus::new(vec![base]).expect("valid corpus");
        let c2 = ConstitutionCorpus::new(vec![repealed]).expect("valid corpus");
        assert_ne!(c1.hash, c2.hash);
    }

    #[test]
    fn ratify_verified_rejects_forged_non_empty_signatures() {
        let alice = did("alice");
        let bob = did("bob");
        let alice_key = keypair(1);
        let bob_key = keypair(2);
        let keys = public_key_map(&[(alice.clone(), &alice_key), (bob.clone(), &bob_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");

        let err = ratify_verified(
            &mut c,
            &[(alice.clone(), sig()), (bob.clone(), sig())],
            &quorum(),
            Timestamp::ZERO,
            &eligible(&[alice, bob]),
            &resolver,
        )
        .unwrap_err();

        assert!(matches!(err, ForumError::QuorumNotMet { .. }));
        assert!(!c.is_ratified());
    }

    #[test]
    fn ratify_verified_enforces_required_fraction_pct() {
        let alice = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let dave = did("dave");
        let alice_key = keypair(1);
        let bob_key = keypair(2);
        let carol_key = keypair(3);
        let dave_key = keypair(4);
        let keys = public_key_map(&[
            (alice.clone(), &alice_key),
            (bob.clone(), &bob_key),
            (carol.clone(), &carol_key),
            (dave.clone(), &dave_key),
        ]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let q = ConstitutionQuorum {
            required_signatures: 1,
            required_fraction_pct: 75,
        };
        let sigs = vec![
            (
                alice.clone(),
                sign_ratification(&c, &alice, &q, Timestamp::ZERO, &alice_key),
            ),
            (
                bob.clone(),
                sign_ratification(&c, &bob, &q, Timestamp::ZERO, &bob_key),
            ),
        ];

        let err = ratify_verified(
            &mut c,
            &sigs,
            &q,
            Timestamp::ZERO,
            &eligible(&[alice, bob, carol, dave]),
            &resolver,
        )
        .unwrap_err();

        assert_eq!(
            err,
            ForumError::QuorumNotMet {
                required: 3,
                actual: 2
            }
        );
        assert!(!c.is_ratified());
    }

    #[test]
    fn ratification_payload_is_bound_to_signer_quorum_and_timestamp() {
        let alice = did("alice");
        let bob = did("bob");
        let c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let base_quorum = ConstitutionQuorum {
            required_signatures: 1,
            required_fraction_pct: 50,
        };
        let stricter_quorum = ConstitutionQuorum {
            required_signatures: 1,
            required_fraction_pct: 100,
        };

        let alice_payload =
            ratification_signature_message(&c, &alice, &base_quorum, Timestamp::new(1000, 0))
                .expect("payload");
        let bob_payload =
            ratification_signature_message(&c, &bob, &base_quorum, Timestamp::new(1000, 0))
                .expect("payload");
        let later_payload =
            ratification_signature_message(&c, &alice, &base_quorum, Timestamp::new(1001, 0))
                .expect("payload");
        let stricter_payload =
            ratification_signature_message(&c, &alice, &stricter_quorum, Timestamp::new(1000, 0))
                .expect("payload");

        assert_ne!(alice_payload, bob_payload);
        assert_ne!(alice_payload, later_payload);
        assert_ne!(alice_payload, stricter_payload);
    }

    #[test]
    fn ratify_verified_rejects_signature_replayed_under_different_timestamp() {
        let alice = did("alice");
        let alice_key = keypair(1);
        let keys = public_key_map(&[(alice.clone(), &alice_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let q = ConstitutionQuorum {
            required_signatures: 1,
            required_fraction_pct: 100,
        };
        let collected_at = Timestamp::new(1000, 0);
        let replayed_at = Timestamp::new(1001, 0);
        let message = ratification_signature_message(&c, &alice, &q, collected_at)
            .expect("ratification payload");
        let signature = crypto::sign(&message, alice_key.secret_key());

        let err = ratify_verified(
            &mut c,
            &[(alice.clone(), signature)],
            &q,
            replayed_at,
            &eligible(&[alice]),
            &resolver,
        )
        .unwrap_err();

        assert_eq!(
            err,
            ForumError::QuorumNotMet {
                required: 1,
                actual: 0
            }
        );
        assert!(!c.is_ratified());
    }

    #[test]
    fn amendment_payload_is_bound_to_signer_quorum_timestamp_and_amendment_hash() {
        let alice = did("alice");
        let bob = did("bob");
        let c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let amendment = article("a2", DocumentTier::Bylaws);
        let other_amendment = article("a3", DocumentTier::Bylaws);
        let base_quorum = ConstitutionQuorum {
            required_signatures: 1,
            required_fraction_pct: 50,
        };
        let stricter_quorum = ConstitutionQuorum {
            required_signatures: 1,
            required_fraction_pct: 100,
        };

        let alice_payload = amendment_signature_message(
            &c,
            &amendment,
            &alice,
            &base_quorum,
            Timestamp::new(2000, 0),
        )
        .expect("payload");
        let bob_payload = amendment_signature_message(
            &c,
            &amendment,
            &bob,
            &base_quorum,
            Timestamp::new(2000, 0),
        )
        .expect("payload");
        let later_payload = amendment_signature_message(
            &c,
            &amendment,
            &alice,
            &base_quorum,
            Timestamp::new(2001, 0),
        )
        .expect("payload");
        let stricter_payload = amendment_signature_message(
            &c,
            &amendment,
            &alice,
            &stricter_quorum,
            Timestamp::new(2000, 0),
        )
        .expect("payload");
        let other_amendment_payload = amendment_signature_message(
            &c,
            &other_amendment,
            &alice,
            &base_quorum,
            Timestamp::new(2000, 0),
        )
        .expect("payload");

        assert_ne!(alice_payload, bob_payload);
        assert_ne!(alice_payload, later_payload);
        assert_ne!(alice_payload, stricter_payload);
        assert_ne!(alice_payload, other_amendment_payload);
    }

    #[test]
    fn ratify_verified_accepts_distinct_valid_signatures() {
        let alice = did("alice");
        let bob = did("bob");
        let alice_key = keypair(1);
        let bob_key = keypair(2);
        let keys = public_key_map(&[(alice.clone(), &alice_key), (bob.clone(), &bob_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let sigs = vec![
            (
                alice.clone(),
                sign_ratification(&c, &alice, &quorum(), Timestamp::ZERO, &alice_key),
            ),
            (
                bob.clone(),
                sign_ratification(&c, &bob, &quorum(), Timestamp::ZERO, &bob_key),
            ),
        ];

        ratify_verified(
            &mut c,
            &sigs,
            &quorum(),
            Timestamp::ZERO,
            &eligible(&[alice, bob]),
            &resolver,
        )
        .expect("verified ratification");

        assert!(c.is_ratified());
    }

    #[test]
    fn ratify_verified_rejects_duplicate_signer() {
        let alice = did("alice");
        let alice_key = keypair(1);
        let keys = public_key_map(&[(alice.clone(), &alice_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let q = ConstitutionQuorum {
            required_signatures: 2,
            required_fraction_pct: 100,
        };
        let sig = sign_ratification(&c, &alice, &q, Timestamp::ZERO, &alice_key);

        let err = ratify_verified(
            &mut c,
            &[(alice.clone(), sig.clone()), (alice.clone(), sig)],
            &q,
            Timestamp::ZERO,
            &eligible(&[alice]),
            &resolver,
        )
        .unwrap_err();

        assert!(matches!(err, ForumError::QuorumNotMet { actual: 1, .. }));
        assert!(!c.is_ratified());
    }

    #[test]
    fn amend_verified_rejects_forged_non_empty_signature() {
        let alice = did("alice");
        let alice_key = keypair(1);
        let keys = public_key_map(&[(alice.clone(), &alice_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let q = ConstitutionQuorum {
            required_signatures: 1,
            required_fraction_pct: 100,
        };
        let ratify_sig = sign_ratification(&c, &alice, &q, Timestamp::ZERO, &alice_key);
        ratify_verified(
            &mut c,
            &[(alice.clone(), ratify_sig)],
            &q,
            Timestamp::ZERO,
            &eligible(std::slice::from_ref(&alice)),
            &resolver,
        )
        .expect("ratified");

        let amendment = article("a2", DocumentTier::Bylaws);
        let err = amend_verified(
            &mut c,
            amendment,
            &[(alice.clone(), sig())],
            &q,
            Timestamp::ZERO,
            &eligible(&[alice]),
            &resolver,
        )
        .unwrap_err();

        assert!(matches!(err, ForumError::QuorumNotMet { .. }));
    }

    #[test]
    fn amend_verified_accepts_valid_signature_and_updates_hash() {
        let alice = did("alice");
        let alice_key = keypair(1);
        let keys = public_key_map(&[(alice.clone(), &alice_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let q = ConstitutionQuorum {
            required_signatures: 1,
            required_fraction_pct: 100,
        };
        let ratify_sig = sign_ratification(&c, &alice, &q, Timestamp::ZERO, &alice_key);
        ratify_verified(
            &mut c,
            &[(alice.clone(), ratify_sig)],
            &q,
            Timestamp::ZERO,
            &eligible(std::slice::from_ref(&alice)),
            &resolver,
        )
        .expect("ratified");
        let old_hash = c.hash;
        let amendment = article("a2", DocumentTier::Bylaws);
        let amendment_sig = sign_amendment(&c, &amendment, &alice, &q, Timestamp::ZERO, &alice_key);

        amend_verified(
            &mut c,
            amendment,
            &[(alice.clone(), amendment_sig)],
            &q,
            Timestamp::ZERO,
            &eligible(&[alice]),
            &resolver,
        )
        .expect("verified amendment");

        assert_eq!(c.amendment_count, 1);
        assert_ne!(c.hash, old_hash);
    }

    #[test]
    fn amend_verified_rejects_amendment_count_overflow_without_mutation() {
        let alice = did("alice");
        let alice_key = keypair(1);
        let keys = public_key_map(&[(alice.clone(), &alice_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let q = ConstitutionQuorum {
            required_signatures: 1,
            required_fraction_pct: 100,
        };
        let ratify_sig = sign_ratification(&c, &alice, &q, Timestamp::ZERO, &alice_key);
        ratify_verified(
            &mut c,
            &[(alice.clone(), ratify_sig)],
            &q,
            Timestamp::ZERO,
            &eligible(std::slice::from_ref(&alice)),
            &resolver,
        )
        .expect("ratified");
        c.amendment_count = u32::MAX;
        let before = c.clone();
        let amendment = article("a2", DocumentTier::Bylaws);
        let amendment_sig = sign_amendment(&c, &amendment, &alice, &q, Timestamp::ZERO, &alice_key);

        let err = amend_verified(
            &mut c,
            amendment,
            &[(alice.clone(), amendment_sig)],
            &q,
            Timestamp::ZERO,
            &eligible(&[alice]),
            &resolver,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ForumError::AmendmentFailed { reason }
                if reason.contains("amendment count overflow")
        ));
        assert_eq!(c.version, before.version);
        assert_eq!(c.hash, before.hash);
        assert_eq!(c.articles.len(), before.articles.len());
        assert_eq!(c.amendment_count, before.amendment_count);
    }

    #[test]
    fn amend_verified_rejects_version_overflow_without_mutation() {
        let alice = did("alice");
        let alice_key = keypair(1);
        let keys = public_key_map(&[(alice.clone(), &alice_key)]);
        let resolver = |d: &Did| keys.get(d).copied();
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let q = ConstitutionQuorum {
            required_signatures: 1,
            required_fraction_pct: 100,
        };
        let ratify_sig = sign_ratification(&c, &alice, &q, Timestamp::ZERO, &alice_key);
        ratify_verified(
            &mut c,
            &[(alice.clone(), ratify_sig)],
            &q,
            Timestamp::ZERO,
            &eligible(std::slice::from_ref(&alice)),
            &resolver,
        )
        .expect("ratified");
        c.version = Version(u64::MAX);
        let before = c.clone();
        let amendment = article("a2", DocumentTier::Bylaws);
        let amendment_sig = sign_amendment(&c, &amendment, &alice, &q, Timestamp::ZERO, &alice_key);

        let err = amend_verified(
            &mut c,
            amendment,
            &[(alice.clone(), amendment_sig)],
            &q,
            Timestamp::ZERO,
            &eligible(&[alice]),
            &resolver,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ForumError::AmendmentFailed { reason }
                if reason.contains("constitution version overflow")
        ));
        assert_eq!(c.version, before.version);
        assert_eq!(c.hash, before.hash);
        assert_eq!(c.articles.len(), before.articles.len());
        assert_eq!(c.amendment_count, before.amendment_count);
    }

    #[test]
    fn constitution_production_source_has_no_raw_corpus_hashing() {
        let production = include_str!("constitution.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(!production.contains("blake3::Hasher"));
        assert!(!production.contains("hasher.update"));
        assert!(
            !production.contains("already exists at tier {:?}"),
            "constitution conflict labels must not depend on DocumentTier Debug output"
        );
    }

    #[test]
    fn find_article() {
        let c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        assert!(c.find_article("a1").is_some());
        assert!(c.find_article("nope").is_none());
    }

    #[test]
    fn active_count() {
        let mut c = ConstitutionCorpus::new(vec![
            article("a1", DocumentTier::Articles),
            article("a2", DocumentTier::Articles),
        ])
        .expect("valid corpus");
        c.articles[1].status = ArticleStatus::Repealed;
        assert_eq!(c.active_article_count(), 1);
    }

    #[test]
    fn hash_deterministic() {
        let c1 = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let c2 = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        assert_eq!(c1.hash, c2.hash);
    }

    #[test]
    fn document_tier_ordering() {
        assert!(DocumentTier::Articles < DocumentTier::Bylaws);
        assert!(DocumentTier::Bylaws < DocumentTier::Resolutions);
        assert!(DocumentTier::Resolutions < DocumentTier::Charters);
        assert!(DocumentTier::Charters < DocumentTier::Policies);
    }
}
