//! Electronic discovery — eDiscovery search and production.

use exo_core::{Did, Hash256, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{LegalError, Result},
    evidence::{AdmissibilityStatus, CustodyTransfer, Evidence},
    privilege::PrivilegeAssertion,
};

const EDISCOVERY_PRODUCTION_HASH_DOMAIN: &str = "exo.legal.ediscovery.production_hash.v1";
const EDISCOVERY_PRODUCTION_HASH_SCHEMA_VERSION: u16 = 1;

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

#[derive(Debug, Clone, Serialize)]
struct EdiscoveryProductionDocumentPayload {
    id: Uuid,
    type_tag: String,
    hash: Hash256,
    creator: Did,
    timestamp: Timestamp,
    chain_of_custody: Vec<CustodyTransfer>,
    admissibility_status: AdmissibilityStatus,
}

#[derive(Debug, Clone, Serialize)]
struct EdiscoveryProductionHashPayload {
    domain: &'static str,
    schema_version: u16,
    requester: Did,
    scope: String,
    date_start: Timestamp,
    date_end: Timestamp,
    custodians: Vec<Did>,
    search_terms: Vec<String>,
    documents: Vec<EdiscoveryProductionDocumentPayload>,
}

/// Filters an evidence corpus by the discovery request criteria and returns a hashed production set.
///
/// # Errors
///
/// Returns [`LegalError::DiscoveryHashEncodingFailed`] if canonical CBOR
/// encoding of the production-set hash payload fails.
pub fn search(request: &DiscoveryRequest, corpus: &[Evidence]) -> Result<DiscoveryResponse> {
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

    let production_hash = ediscovery_production_hash(request, &documents)?;

    Ok(DiscoveryResponse {
        documents,
        privilege_log: Vec::new(),
        production_hash,
    })
}

fn ediscovery_production_hash_payload(
    request: &DiscoveryRequest,
    documents: &[Evidence],
) -> EdiscoveryProductionHashPayload {
    EdiscoveryProductionHashPayload {
        domain: EDISCOVERY_PRODUCTION_HASH_DOMAIN,
        schema_version: EDISCOVERY_PRODUCTION_HASH_SCHEMA_VERSION,
        requester: request.requester.clone(),
        scope: request.scope.clone(),
        date_start: request.date_range.0,
        date_end: request.date_range.1,
        custodians: request.custodians.clone(),
        search_terms: request.search_terms.clone(),
        documents: documents
            .iter()
            .map(|doc| EdiscoveryProductionDocumentPayload {
                id: doc.id,
                type_tag: doc.type_tag.clone(),
                hash: doc.hash,
                creator: doc.creator.clone(),
                timestamp: doc.timestamp,
                chain_of_custody: doc.chain_of_custody.clone(),
                admissibility_status: doc.admissibility_status.clone(),
            })
            .collect(),
    }
}

fn ediscovery_production_hash(
    request: &DiscoveryRequest,
    documents: &[Evidence],
) -> Result<Hash256> {
    hash_structured(&ediscovery_production_hash_payload(request, documents)).map_err(|e| {
        LegalError::DiscoveryHashEncodingFailed {
            reason: format!("eDiscovery production hash canonical CBOR hash failed: {e}"),
        }
    })
}

#[cfg(test)]
mod tests {
    use exo_core::hash::hash_structured;

    use super::*;
    use crate::evidence::{create_evidence, transfer_custody};
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }
    fn corpus() -> Vec<Evidence> {
        let (a, b) = (did("alice"), did("bob"));
        let e1 = create_evidence(
            Uuid::from_u128(0x501),
            b"contract",
            &a,
            "contract",
            Timestamp::new(100, 0),
        )
        .unwrap();
        let e2 = create_evidence(
            Uuid::from_u128(0x502),
            b"email",
            &b,
            "email",
            Timestamp::new(200, 0),
        )
        .unwrap();
        let e3 = create_evidence(
            Uuid::from_u128(0x503),
            b"memo",
            &a,
            "memo",
            Timestamp::new(300, 0),
        )
        .unwrap();
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
        let r = search(&req(vec![did("alice")], vec![], (0, 500)), &corpus()).unwrap();
        assert_eq!(r.documents.len(), 2);
    }
    #[test]
    fn by_date() {
        let r = search(&req(vec![], vec![], (150, 250)), &corpus()).unwrap();
        assert_eq!(r.documents.len(), 1);
    }
    #[test]
    fn by_terms() {
        let r = search(&req(vec![], vec!["contract".into()], (0, 500)), &corpus()).unwrap();
        assert_eq!(r.documents.len(), 1);
    }
    #[test]
    fn empty_corpus() {
        let r = search(&req(vec![], vec![], (0, 500)), &[]).unwrap();
        assert!(r.documents.is_empty());
    }
    #[test]
    fn no_match() {
        let r = search(&req(vec![did("nobody")], vec![], (0, 500)), &corpus()).unwrap();
        assert!(r.documents.is_empty());
    }
    #[test]
    fn hash_deterministic() {
        let rq = req(vec![], vec![], (0, 500));
        let c = corpus();
        assert_eq!(
            search(&rq, &c).unwrap().production_hash,
            search(&rq, &c).unwrap().production_hash
        );
    }
    #[test]
    fn combined() {
        let r = search(
            &req(vec![did("alice")], vec!["contract".into()], (0, 150)),
            &corpus(),
        )
        .unwrap();
        assert_eq!(r.documents.len(), 1);
    }

    #[test]
    fn production_hash_payload_is_domain_separated_cbor() {
        let rq = req(vec![], vec![], (0, 500));
        let docs = corpus();
        let payload = ediscovery_production_hash_payload(&rq, &docs);

        assert_eq!(payload.domain, EDISCOVERY_PRODUCTION_HASH_DOMAIN);
        assert_eq!(
            payload.schema_version,
            EDISCOVERY_PRODUCTION_HASH_SCHEMA_VERSION
        );
        assert_eq!(payload.requester, rq.requester);
        assert_eq!(payload.scope, rq.scope);
        assert_eq!(payload.documents.len(), docs.len());
        assert_eq!(payload.documents[0].id, docs[0].id);
        assert_eq!(payload.documents[0].hash, docs[0].hash);

        let expected = hash_structured(&payload).unwrap();
        assert_eq!(ediscovery_production_hash(&rq, &docs).unwrap(), expected);
    }

    #[test]
    fn production_hash_rejects_legacy_doc_hash_concat() {
        let rq = req(vec![], vec![], (0, 500));
        let response = search(&rq, &corpus()).unwrap();

        let mut legacy_hasher = blake3::Hasher::new();
        for doc in &response.documents {
            legacy_hasher.update(doc.hash.as_bytes());
        }
        let legacy_hash = Hash256::from_bytes(*legacy_hasher.finalize().as_bytes());

        assert_ne!(response.production_hash, legacy_hash);
    }

    #[test]
    fn production_hash_binds_request_scope_and_terms() {
        let mut all_docs = Vec::new();
        for n in 0_u64..3 {
            all_docs.push(
                create_evidence(
                    Uuid::from_u128(0x600 + u128::from(n)),
                    format!("document {n}").as_bytes(),
                    &did("alice"),
                    "record",
                    Timestamp::new(100 + n, 0),
                )
                .unwrap(),
            );
        }

        let mut scoped_request = req(vec![did("alice")], vec![], (0, 500));
        scoped_request.scope = "all".into();
        let mut other_scope = scoped_request.clone();
        other_scope.scope = "matter-42".into();
        let mut explicit_term = scoped_request.clone();
        explicit_term.search_terms = vec!["record".into()];

        let scoped = search(&scoped_request, &all_docs).unwrap();
        let scope_changed = search(&other_scope, &all_docs).unwrap();
        let terms_changed = search(&explicit_term, &all_docs).unwrap();

        assert_eq!(scoped.documents.len(), scope_changed.documents.len());
        assert_eq!(scoped.documents.len(), terms_changed.documents.len());
        assert_ne!(scoped.production_hash, scope_changed.production_hash);
        assert_ne!(scoped.production_hash, terms_changed.production_hash);
    }

    #[test]
    fn production_hash_binds_document_identity_and_timestamp() {
        let rq = req(vec![did("alice")], vec!["contract".into()], (0, 500));
        let first = vec![
            create_evidence(
                Uuid::from_u128(0x700),
                b"same content",
                &did("alice"),
                "contract",
                Timestamp::new(100, 0),
            )
            .unwrap(),
        ];
        let different_id = vec![
            create_evidence(
                Uuid::from_u128(0x701),
                b"same content",
                &did("alice"),
                "contract",
                Timestamp::new(100, 0),
            )
            .unwrap(),
        ];
        let different_timestamp = vec![
            create_evidence(
                Uuid::from_u128(0x700),
                b"same content",
                &did("alice"),
                "contract",
                Timestamp::new(101, 0),
            )
            .unwrap(),
        ];

        assert_eq!(first[0].hash, different_id[0].hash);
        assert_eq!(first[0].hash, different_timestamp[0].hash);
        assert_ne!(
            search(&rq, &first).unwrap().production_hash,
            search(&rq, &different_id).unwrap().production_hash
        );
        assert_ne!(
            search(&rq, &first).unwrap().production_hash,
            search(&rq, &different_timestamp).unwrap().production_hash
        );
    }

    #[test]
    fn production_hash_binds_custody_chain() {
        let rq = req(vec![did("alice")], vec!["contract".into()], (0, 500));
        let first = create_evidence(
            Uuid::from_u128(0x800),
            b"custody content",
            &did("alice"),
            "contract",
            Timestamp::new(100, 0),
        )
        .unwrap();
        let mut transferred = first.clone();
        transfer_custody(
            &mut transferred,
            &did("alice"),
            &did("counsel"),
            Timestamp::new(200, 0),
            "litigation hold",
        )
        .unwrap();

        assert_eq!(first.hash, transferred.hash);
        assert_ne!(
            search(&rq, &[first]).unwrap().production_hash,
            search(&rq, &[transferred]).unwrap().production_hash
        );
    }

    fn production_source() -> &'static str {
        let source = include_str!("ediscovery.rs");
        let end = source
            .find("#[cfg(test)]")
            .expect("test module marker exists");
        &source[..end]
    }

    #[test]
    fn ediscovery_production_source_has_no_raw_hash_loop() {
        let production = production_source();
        assert!(
            !production.contains("blake3::Hasher"),
            "eDiscovery production hashes must use domain-separated canonical CBOR"
        );
    }
}
