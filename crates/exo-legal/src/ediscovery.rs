//! Electronic discovery — eDiscovery search and production.

use exo_core::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{evidence::Evidence, privilege::PrivilegeAssertion};

/// Parameters for an eDiscovery search: custodians, date range, and search terms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryRequest {
    pub requester: Did,
    pub scope: String,
    pub date_range: (Timestamp, Timestamp),
    pub custodians: Vec<Did>,
    pub search_terms: Vec<String>,
}

/// Result of an eDiscovery search containing matched documents, a privilege log, and a production hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub documents: Vec<Evidence>,
    pub privilege_log: Vec<PrivilegeAssertion>,
    pub production_hash: Hash256,
}

/// Filters an evidence corpus by the discovery request criteria and returns a hashed production set.
#[must_use]
pub fn search(request: &DiscoveryRequest, corpus: &[Evidence]) -> DiscoveryResponse {
    let documents: Vec<Evidence> = corpus
        .iter()
        .filter(|ev| {
            let cust = request.custodians.is_empty() || request.custodians.contains(&ev.creator);
            let date = ev.timestamp >= request.date_range.0 && ev.timestamp <= request.date_range.1;
            let term = request.search_terms.is_empty()
                || request
                    .search_terms
                    .iter()
                    .any(|t| ev.type_tag.contains(t.as_str()));
            cust && date && term
        })
        .cloned()
        .collect();
    let mut hasher = blake3::Hasher::new();
    for doc in &documents {
        hasher.update(doc.hash.as_bytes());
    }
    DiscoveryResponse {
        documents,
        privilege_log: Vec::new(),
        production_hash: Hash256::from_bytes(*hasher.finalize().as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::create_evidence;
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }
    fn corpus() -> Vec<Evidence> {
        let (a, b) = (did("alice"), did("bob"));
        let e1 = create_evidence(b"contract", &a, "contract", Timestamp::new(100, 0)).unwrap();
        let e2 = create_evidence(b"email", &b, "email", Timestamp::new(200, 0)).unwrap();
        let e3 = create_evidence(b"memo", &a, "memo", Timestamp::new(300, 0)).unwrap();
        vec![e1, e2, e3]
    }
    fn req(custodians: Vec<Did>, terms: Vec<String>, range: (u64, u64)) -> DiscoveryRequest {
        DiscoveryRequest {
            requester: did("counsel"),
            scope: "all".into(),
            date_range: (Timestamp::new(range.0, 0), Timestamp::new(range.1, 0)),
            custodians,
            search_terms: terms,
        }
    }
    #[test]
    fn by_custodian() {
        let r = search(&req(vec![did("alice")], vec![], (0, 500)), &corpus());
        assert_eq!(r.documents.len(), 2);
    }
    #[test]
    fn by_date() {
        let r = search(&req(vec![], vec![], (150, 250)), &corpus());
        assert_eq!(r.documents.len(), 1);
    }
    #[test]
    fn by_terms() {
        let r = search(&req(vec![], vec!["contract".into()], (0, 500)), &corpus());
        assert_eq!(r.documents.len(), 1);
    }
    #[test]
    fn empty_corpus() {
        let r = search(&req(vec![], vec![], (0, 500)), &[]);
        assert!(r.documents.is_empty());
    }
    #[test]
    fn no_match() {
        let r = search(&req(vec![did("nobody")], vec![], (0, 500)), &corpus());
        assert!(r.documents.is_empty());
    }
    #[test]
    fn hash_deterministic() {
        let rq = req(vec![], vec![], (0, 500));
        let c = corpus();
        assert_eq!(
            search(&rq, &c).production_hash,
            search(&rq, &c).production_hash
        );
    }
    #[test]
    fn combined() {
        let r = search(
            &req(vec![did("alice")], vec!["contract".into()], (0, 150)),
            &corpus(),
        );
        assert_eq!(r.documents.len(), 1);
    }
}
