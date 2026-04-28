//! Constitutional corpus management (GOV-001, GOV-002, GOV-006).
//!
//! Per-tenant machine-readable constitutional corpus with semantic versioning,
//! temporal binding (every decision stores the constitution hash), and a
//! conflict resolution hierarchy:
//! Articles > Bylaws > Resolutions > Charters > Policies (GOV-006).

use exo_core::{
    hash::hash_structured,
    types::{Did, Hash256, Signature, Timestamp, Version},
};
use serde::{Deserialize, Serialize};

use crate::error::{ForumError, Result};

const CONSTITUTION_CORPUS_HASH_DOMAIN: &str = "decision.forum.constitution_corpus.v1";
const CONSTITUTION_CORPUS_HASH_SCHEMA_VERSION: u16 = 1;

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

/// Ratify a constitution given signatures and a quorum policy.
pub fn ratify(
    corpus: &mut ConstitutionCorpus,
    signatures: &[(Did, Signature)],
    quorum: &ConstitutionQuorum,
    timestamp: Timestamp,
) -> Result<()> {
    if corpus.is_ratified() {
        return Err(ForumError::NotRatified {
            reason: "already ratified".into(),
        });
    }
    let valid = signatures.iter().filter(|(_, s)| !s.is_empty()).count();
    if valid < quorum.required_signatures {
        return Err(ForumError::QuorumNotMet {
            required: quorum.required_signatures,
            actual: valid,
        });
    }
    corpus.ratified_at = Some(timestamp);
    Ok(())
}

/// Amend a constitution by adding a new article. The constitution must be
/// ratified first. The amendment bumps the version and rehashes.
pub fn amend(
    corpus: &mut ConstitutionCorpus,
    amendment: Article,
    signatures: &[(Did, Signature)],
) -> Result<()> {
    if !corpus.is_ratified() {
        return Err(ForumError::AmendmentFailed {
            reason: "not ratified".into(),
        });
    }
    let valid = signatures.iter().filter(|(_, s)| !s.is_empty()).count();
    if valid == 0 {
        return Err(ForumError::AmendmentFailed {
            reason: "no valid signatures".into(),
        });
    }
    corpus.articles.push(amendment);
    corpus.version = corpus.version.next();
    corpus.hash = compute_corpus_hash(&corpus.articles)?;
    corpus.amendment_count += 1;
    Ok(())
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
                "Article '{}' already exists at tier {:?}",
                existing.id, existing.tier
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
mod tests {
    use exo_core::types::Signature;

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

    #[test]
    fn new_not_ratified() {
        let c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        assert!(!c.is_ratified());
        assert_eq!(c.version, Version::ZERO.next());
    }

    #[test]
    fn ratify_ok() {
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        ratify(
            &mut c,
            &[(did("a"), sig()), (did("b"), sig())],
            &quorum(),
            Timestamp::ZERO,
        )
        .expect("ok");
        assert!(c.is_ratified());
    }

    #[test]
    fn ratify_quorum_not_met() {
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        let err = ratify(&mut c, &[(did("a"), sig())], &quorum(), Timestamp::ZERO).unwrap_err();
        assert!(matches!(err, ForumError::QuorumNotMet { .. }));
    }

    #[test]
    fn ratify_already() {
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        ratify(
            &mut c,
            &[(did("a"), sig()), (did("b"), sig())],
            &quorum(),
            Timestamp::ZERO,
        )
        .expect("ok");
        assert!(
            ratify(
                &mut c,
                &[(did("a"), sig()), (did("b"), sig())],
                &quorum(),
                Timestamp::ZERO
            )
            .is_err()
        );
    }

    #[test]
    fn empty_sig_not_counted() {
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        assert!(
            ratify(
                &mut c,
                &[(did("a"), sig()), (did("b"), empty_sig())],
                &quorum(),
                Timestamp::ZERO
            )
            .is_err()
        );
    }

    #[test]
    fn amend_ok() {
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        ratify(
            &mut c,
            &[(did("a"), sig()), (did("b"), sig())],
            &quorum(),
            Timestamp::ZERO,
        )
        .expect("ok");
        let old_hash = c.hash;
        amend(
            &mut c,
            article("a2", DocumentTier::Bylaws),
            &[(did("a"), sig())],
        )
        .expect("ok");
        assert_eq!(c.articles.len(), 2);
        assert_eq!(c.version, Version::ZERO.next().next());
        assert_ne!(c.hash, old_hash);
        assert_eq!(c.amendment_count, 1);
    }

    #[test]
    fn amend_not_ratified() {
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        assert!(
            amend(
                &mut c,
                article("a2", DocumentTier::Bylaws),
                &[(did("a"), sig())]
            )
            .is_err()
        );
    }

    #[test]
    fn amend_no_valid_sigs() {
        let mut c = ConstitutionCorpus::new(vec![article("a1", DocumentTier::Articles)])
            .expect("valid corpus");
        ratify(
            &mut c,
            &[(did("a"), sig()), (did("b"), sig())],
            &quorum(),
            Timestamp::ZERO,
        )
        .expect("ok");
        assert!(
            amend(
                &mut c,
                article("a2", DocumentTier::Bylaws),
                &[(did("a"), empty_sig())]
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
    fn constitution_production_source_has_no_raw_corpus_hashing() {
        let production = include_str!("constitution.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(!production.contains("blake3::Hasher"));
        assert!(!production.contains("hasher.update"));
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
