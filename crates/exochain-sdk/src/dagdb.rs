//! SDK re-exports for ExoChain DAG DB DTOs.
//!
//! This module intentionally re-exports the `exo-dag-db-api` DTOs rather than
//! defining a parallel SDK shape. JSON fixture tests guard against drift.

pub use exo_dag_db_api::{
    CanonicalizationDecision, CanonicalizationDecisionKind, CatalogEntryResponse, ConsentPurpose,
    ContextPacketMemoryRef, CouncilDecisionStatus, CouncilReviewStatus, CredentialStatus,
    DagDbCatalogLookupRequest, DagDbCatalogLookupResponse, DagDbContextPacketRequest,
    DagDbContextPacketResponse, DagDbCouncilDecisionRequest, DagDbCouncilDecisionResponse,
    DagDbErrorEnvelope, DagDbExportRequest, DagDbExportResponse, DagDbImportRequest,
    DagDbImportResponse, DagDbIntakeRequest, DagDbIntakeResponse, DagDbReceiptLookupRequest,
    DagDbReceiptLookupResponse, DagDbRouteLookupRequest, DagDbRouteLookupResponse,
    DagDbRouteRequest, DagDbRouteResponse, DagDbTrustCheckRequest, DagDbTrustCheckResponse,
    DagDbValidateRequest, DagDbValidateResponse, DagDbWritebackRequest, DagDbWritebackResponse,
    DagFinalityStatus, DecisionSource, GraphEdgeRef, GraphView, GraphViewType, MemoryCandidate,
    MemoryCandidateKind, MemoryCandidateUse, MemoryEdgeKind, MemoryEdgeType, MemoryGraphStyle,
    MemoryNodeKind, MemoryNodeType, PlacementResult, RedactionCode, RiskClass,
    RouteInvalidationReceipt, RouteInvalidationStatus, RouteInvalidationTrigger, RouteStatus,
    SafeMetadata, SafeMetadataDecision, SimilarityResult, SimilarityType, SourceType, SubjectKind,
    ValidationDecision, ValidationStatus,
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, PercentEncode, utf8_percent_encode};

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
const QUERY_COMPONENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn encode_path_segment(value: &str) -> PercentEncode<'_> {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET)
}

fn encode_query_component(value: &str) -> PercentEncode<'_> {
    utf8_percent_encode(value, QUERY_COMPONENT_ENCODE_SET)
}

/// HTTP verb for an SDK-prepared DAG DB request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagDbHttpMethod {
    /// HTTP GET request.
    Get,
    /// HTTP POST request.
    Post,
}

/// Request metadata prepared by the SDK without redefining DTO shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagDbRequestSpec<T> {
    /// HTTP method to use for the request.
    pub method: DagDbHttpMethod,
    /// Path and query string relative to the gateway origin.
    pub path: String,
    /// JSON body for mutation routes; lookup routes carry `None`.
    pub body: Option<T>,
}

/// Lightweight helpers for constructing every DAG DB REST call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagDbClient {
    prefix: String,
}

impl Default for DagDbClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DagDbClient {
    /// Create a client helper bound to the canonical DAG DB REST prefix.
    pub fn new() -> Self {
        Self {
            prefix: "/api/v1/dag-db".to_owned(),
        }
    }

    /// Build a `POST /api/v1/dag-db/intake` request spec.
    pub fn intake(&self, request: DagDbIntakeRequest) -> DagDbRequestSpec<DagDbIntakeRequest> {
        self.post("/intake", request)
    }

    /// Build a `POST /api/v1/dag-db/route` request spec.
    pub fn route(&self, request: DagDbRouteRequest) -> DagDbRequestSpec<DagDbRouteRequest> {
        self.post("/route", request)
    }

    /// Build a `POST /api/v1/dag-db/context-packet` request spec.
    pub fn context_packet(
        &self,
        request: DagDbContextPacketRequest,
    ) -> DagDbRequestSpec<DagDbContextPacketRequest> {
        self.post("/context-packet", request)
    }

    /// Build a `POST /api/v1/dag-db/validate` request spec.
    pub fn validate(
        &self,
        request: DagDbValidateRequest,
    ) -> DagDbRequestSpec<DagDbValidateRequest> {
        self.post("/validate", request)
    }

    /// Build a `POST /api/v1/dag-db/writeback` request spec.
    pub fn writeback(
        &self,
        request: DagDbWritebackRequest,
    ) -> DagDbRequestSpec<DagDbWritebackRequest> {
        self.post("/writeback", request)
    }

    /// Build a `POST /api/v1/dag-db/import` request spec.
    pub fn dagdb_import(
        &self,
        request: DagDbImportRequest,
    ) -> DagDbRequestSpec<DagDbImportRequest> {
        self.post("/import", request)
    }

    /// Build a `POST /api/v1/dag-db/export` request spec.
    pub fn dagdb_export(
        &self,
        request: DagDbExportRequest,
    ) -> DagDbRequestSpec<DagDbExportRequest> {
        self.post("/export", request)
    }

    /// Build a `POST /api/v1/dag-db/trust-check` request spec.
    pub fn trust_check(
        &self,
        request: DagDbTrustCheckRequest,
    ) -> DagDbRequestSpec<DagDbTrustCheckRequest> {
        self.post("/trust-check", request)
    }

    /// Build a `POST /api/v1/dag-db/council/decision` request spec.
    pub fn council_decision(
        &self,
        request: DagDbCouncilDecisionRequest,
    ) -> DagDbRequestSpec<DagDbCouncilDecisionRequest> {
        self.post("/council/decision", request)
    }

    /// Build a `GET /api/v1/dag-db/receipts/:receipt_hash` request spec.
    pub fn receipt_lookup(
        &self,
        request: DagDbReceiptLookupRequest,
    ) -> DagDbRequestSpec<DagDbReceiptLookupRequest> {
        let mut path = format!(
            "{}/receipts/{}?tenant_id={}&namespace={}",
            self.prefix,
            encode_path_segment(&request.receipt_hash),
            encode_query_component(&request.tenant_id),
            encode_query_component(&request.namespace)
        );
        append_bool_query(&mut path, "include_body", request.include_body);
        self.get(path)
    }

    /// Build a `GET /api/v1/dag-db/catalog/:catalog_id` request spec.
    pub fn catalog_lookup(
        &self,
        request: DagDbCatalogLookupRequest,
    ) -> DagDbRequestSpec<DagDbCatalogLookupRequest> {
        let mut path = format!(
            "{}/catalog/{}?tenant_id={}&namespace={}",
            self.prefix,
            encode_path_segment(&request.catalog_id),
            encode_query_component(&request.tenant_id),
            encode_query_component(&request.namespace)
        );
        append_bool_query(&mut path, "include_children", request.include_children);
        append_bool_query(&mut path, "include_routes", request.include_routes);
        self.get(path)
    }

    /// Build a `GET /api/v1/dag-db/routes/:route_id` request spec.
    pub fn route_lookup(
        &self,
        request: DagDbRouteLookupRequest,
    ) -> DagDbRequestSpec<DagDbRouteLookupRequest> {
        let mut path = format!(
            "{}/routes/{}?tenant_id={}&namespace={}",
            self.prefix,
            encode_path_segment(&request.route_id),
            encode_query_component(&request.tenant_id),
            encode_query_component(&request.namespace)
        );
        append_bool_query(
            &mut path,
            "include_memory_refs",
            request.include_memory_refs,
        );
        append_bool_query(&mut path, "include_validation", request.include_validation);
        self.get(path)
    }

    fn post<T>(&self, suffix: &str, request: T) -> DagDbRequestSpec<T> {
        DagDbRequestSpec {
            method: DagDbHttpMethod::Post,
            path: format!("{}{}", self.prefix, suffix),
            body: Some(request),
        }
    }

    fn get<T>(&self, path: String) -> DagDbRequestSpec<T> {
        DagDbRequestSpec {
            method: DagDbHttpMethod::Get,
            path,
            body: None,
        }
    }
}

fn append_bool_query(path: &mut String, name: &str, value: Option<bool>) {
    if let Some(value) = value {
        path.push('&');
        path.push_str(name);
        path.push('=');
        path.push_str(if value { "true" } else { "false" });
    }
}

#[cfg(feature = "http-client")]
pub use transport::{
    BearerToken, DagDbAuthConfig, DagDbClientError, DagDbHttpClient, DagDbServerError,
    DagDbSignatureHeaders, MAX_DAGDB_RESPONSE_BYTES,
};

/// Real async HTTP transport for the DAG DB REST surface.
///
/// Compiled only under the non-default `http-client` feature so the spec-only
/// SDK (the [`DagDbClient`] request-spec builder above) stays free of the async
/// HTTP stack. With the feature enabled, [`DagDbHttpClient`] turns the same
/// specs into real `reqwest` calls: it injects the four gateway auth headers
/// (`Authorization`, `x-exo-tenant-id`, `x-exo-namespace`,
/// `x-exo-authority-scope`) with the per-route `{action}:{tenant}:{namespace}`
/// scope, sends the request, and maps the response into typed
/// [`DagDbClientError`] variants (transport/timeout, governed server error
/// carrying the [`DagDbErrorEnvelope`], schema-version mismatch, or decode
/// failure) without ever swallowing an error.
#[cfg(feature = "http-client")]
mod transport {
    use std::fmt;

    use reqwest::{
        Client, StatusCode,
        header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue},
    };
    use serde::{Serialize, de::DeserializeOwned};
    use zeroize::Zeroize;

    use super::{
        DagDbCatalogLookupRequest, DagDbCatalogLookupResponse, DagDbClient,
        DagDbContextPacketRequest, DagDbContextPacketResponse, DagDbCouncilDecisionRequest,
        DagDbCouncilDecisionResponse, DagDbErrorEnvelope, DagDbExportRequest, DagDbExportResponse,
        DagDbHttpMethod, DagDbImportRequest, DagDbImportResponse, DagDbIntakeRequest,
        DagDbIntakeResponse, DagDbReceiptLookupRequest, DagDbReceiptLookupResponse,
        DagDbRequestSpec, DagDbRouteLookupRequest, DagDbRouteLookupResponse, DagDbRouteRequest,
        DagDbRouteResponse, DagDbTrustCheckRequest, DagDbTrustCheckResponse, DagDbValidateRequest,
        DagDbValidateResponse, DagDbWritebackRequest, DagDbWritebackResponse,
    };

    /// Maximum accepted DAG DB HTTP response body size in bytes.
    pub const MAX_DAGDB_RESPONSE_BYTES: usize = 1_048_576;
    const OVERSIZED_RESPONSE_MESSAGE: &str = "response body exceeds the 1048576-byte limit";

    /// Gateway header carrying the requesting tenant id.
    const TENANT_HEADER: &str = "x-exo-tenant-id";
    /// Gateway header carrying the requesting namespace.
    const NAMESPACE_HEADER: &str = "x-exo-namespace";
    /// Gateway header carrying the `{action}:{tenant}:{namespace}` authority scope.
    const AUTHORITY_SCOPE_HEADER: &str = "x-exo-authority-scope";
    /// Gateway header carrying the signed write payload.
    const WRITE_SIGNATURE_HEADER: &str = "x-exo-write-signature";
    /// Gateway header carrying the signed default-route approval payload.
    const DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER: &str = "x-exo-default-route-approval-signature";
    /// Gateway header naming the external default-route approval authority DID.
    const DEFAULT_ROUTE_APPROVAL_DID_HEADER: &str = "x-exo-default-route-approval-did";
    /// Gateway header carrying the external default-route approval timestamp.
    const DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-default-route-approval-timestamp";
    /// Gateway header carrying the signed context-packet approval payload.
    const CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER: &str =
        "x-exo-context-packet-approval-signature";
    /// Gateway header naming the external context-packet approval authority DID.
    const CONTEXT_PACKET_APPROVAL_DID_HEADER: &str = "x-exo-context-packet-approval-did";
    /// Gateway header carrying the external context-packet approval timestamp.
    const CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER: &str =
        "x-exo-context-packet-approval-timestamp";
    /// Gateway header carrying the signed lifecycle payload.
    const LIFECYCLE_SIGNATURE_HEADER: &str = "x-exo-lifecycle-signature";
    /// Gateway header carrying the signed continuation payload.
    const CONTINUATION_SIGNATURE_HEADER: &str = "x-exo-continuation-signature";
    /// Gateway header naming the external lifecycle-finality authority DID.
    const LIFECYCLE_APPROVAL_DID_HEADER: &str = "x-exo-lifecycle-approval-did";
    /// Gateway header naming the external continuation-finality authority DID.
    const CONTINUATION_APPROVAL_DID_HEADER: &str = "x-exo-continuation-approval-did";
    /// Gateway header carrying the external lifecycle approval timestamp.
    const LIFECYCLE_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-lifecycle-approval-timestamp";
    /// Gateway header carrying the external continuation approval timestamp.
    const CONTINUATION_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-continuation-approval-timestamp";
    /// Gateway header carrying the signed import finality approval payload.
    const IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER: &str = "x-exo-import-approval-signature";
    /// Gateway header naming the external import finality authority DID.
    const IMPORT_FINALITY_APPROVAL_DID_HEADER: &str = "x-exo-import-approval-did";
    /// Gateway header carrying the external import finality approval timestamp.
    const IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-import-approval-timestamp";
    /// Gateway header carrying the signed export finality approval payload.
    const EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER: &str = "x-exo-export-approval-signature";
    /// Gateway header naming the external export finality authority DID.
    const EXPORT_FINALITY_APPROVAL_DID_HEADER: &str = "x-exo-export-approval-did";
    /// Gateway header carrying the external export finality approval timestamp.
    const EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-export-approval-timestamp";

    /// Bearer token wrapper that never exposes its secret via [`fmt::Debug`].
    ///
    /// The inner string is zeroized on drop and redacted in both `Debug` and
    /// `Display`, so a token cannot leak through a `{:?}` of an auth config,
    /// client, or error. Read the raw value only at the point of header
    /// construction, via the bearer token's reveal accessor.
    #[derive(Clone, Zeroize)]
    #[zeroize(drop)]
    pub struct BearerToken(String);

    impl BearerToken {
        /// Wrap a raw bearer token string.
        pub fn new(token: impl Into<String>) -> Self {
            Self(token.into())
        }

        /// Borrow the raw token. Use only to build the `Authorization` header;
        /// never log the result.
        fn reveal(&self) -> &str {
            &self.0
        }
    }

    impl From<String> for BearerToken {
        fn from(token: String) -> Self {
            Self(token)
        }
    }

    impl From<&str> for BearerToken {
        fn from(token: &str) -> Self {
            Self(token.to_owned())
        }
    }

    impl fmt::Debug for BearerToken {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("BearerToken(<redacted>)")
        }
    }

    impl fmt::Display for BearerToken {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("<redacted>")
        }
    }

    /// Tenant- and namespace-scoped auth material the gateway requires on every
    /// DAG DB request. The bearer token is held redacted (see [`BearerToken`]);
    /// `tenant_id`/`namespace` populate the matching headers and the
    /// `{action}:{tenant}:{namespace}` authority scope.
    #[derive(Clone, Debug)]
    pub struct DagDbAuthConfig {
        /// Bearer token presented as `Authorization: Bearer <token>`.
        pub token: BearerToken, // pragma-allowlist-secret (field type, not a credential)
        /// Tenant id for the `x-exo-tenant-id` header and the scope grammar.
        pub tenant_id: String,
        /// Namespace for the `x-exo-namespace` header and the scope grammar.
        pub namespace: String,
    }

    impl DagDbAuthConfig {
        /// Build an auth config from a token, tenant id, and namespace.
        pub fn new(
            token: impl Into<BearerToken>,
            tenant_id: impl Into<String>,
            namespace: impl Into<String>,
        ) -> Self {
            Self {
                token: token.into(),
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
            }
        }

        /// Render the `{action}:{tenant}:{namespace}` authority scope for an action.
        fn authority_scope(&self, action: &str) -> String {
            format!("{action}:{}:{}", self.tenant_id, self.namespace)
        }
    }

    /// Per-request DAG DB signature headers supplied by an operator-owned signer.
    ///
    /// Values are opaque to the SDK and are only revealed while constructing
    /// HTTP headers. `Debug` is redacted so signatures cannot leak through
    /// routine diagnostics.
    #[derive(Clone, PartialEq, Eq)]
    pub struct DagDbSignatureHeaders {
        write_signature: String,
        default_route_approval_signature: Option<String>,
        default_route_approval_did: Option<String>,
        default_route_approval_timestamp: Option<String>,
        context_packet_approval_signature: Option<String>,
        context_packet_approval_did: Option<String>,
        context_packet_approval_timestamp: Option<String>,
        lifecycle_signature: Option<String>,
        continuation_signature: Option<String>,
        lifecycle_approval_did: Option<String>,
        continuation_approval_did: Option<String>,
        lifecycle_approval_timestamp: Option<String>,
        continuation_approval_timestamp: Option<String>,
        import_approval_signature: Option<String>,
        import_approval_did: Option<String>,
        import_approval_timestamp: Option<String>,
        export_approval_signature: Option<String>,
        export_approval_did: Option<String>,
        export_approval_timestamp: Option<String>,
    }

    impl DagDbSignatureHeaders {
        /// Header set for routes that require only `x-exo-write-signature`.
        #[must_use]
        pub fn write(write_signature: impl Into<String>) -> Self {
            Self {
                write_signature: write_signature.into(),
                default_route_approval_signature: None,
                default_route_approval_did: None,
                default_route_approval_timestamp: None,
                context_packet_approval_signature: None,
                context_packet_approval_did: None,
                context_packet_approval_timestamp: None,
                lifecycle_signature: None,
                continuation_signature: None,
                lifecycle_approval_did: None,
                continuation_approval_did: None,
                lifecycle_approval_timestamp: None,
                continuation_approval_timestamp: None,
                import_approval_signature: None,
                import_approval_did: None,
                import_approval_timestamp: None,
                export_approval_signature: None,
                export_approval_did: None,
                export_approval_timestamp: None,
            }
        }

        /// Header set for default-route persistence, which requires an external
        /// finality authority signature in addition to the requester write
        /// signature.
        #[must_use]
        pub fn default_route(
            write_signature: impl Into<String>,
            approval_signature: impl Into<String>,
            approval_authority_did: impl Into<String>,
            approval_timestamp: impl Into<String>,
        ) -> Self {
            Self {
                write_signature: write_signature.into(),
                default_route_approval_signature: Some(approval_signature.into()),
                default_route_approval_did: Some(approval_authority_did.into()),
                default_route_approval_timestamp: Some(approval_timestamp.into()),
                context_packet_approval_signature: None,
                context_packet_approval_did: None,
                context_packet_approval_timestamp: None,
                lifecycle_signature: None,
                continuation_signature: None,
                lifecycle_approval_did: None,
                continuation_approval_did: None,
                lifecycle_approval_timestamp: None,
                continuation_approval_timestamp: None,
                import_approval_signature: None,
                import_approval_did: None,
                import_approval_timestamp: None,
                export_approval_signature: None,
                export_approval_did: None,
                export_approval_timestamp: None,
            }
        }

        /// Header set for context-packet persistence, which requires an
        /// external finality authority signature in addition to the requester
        /// write signature.
        #[must_use]
        pub fn context_packet(
            write_signature: impl Into<String>,
            approval_signature: impl Into<String>,
            approval_authority_did: impl Into<String>,
            approval_timestamp: impl Into<String>,
        ) -> Self {
            Self {
                write_signature: write_signature.into(),
                default_route_approval_signature: None,
                default_route_approval_did: None,
                default_route_approval_timestamp: None,
                context_packet_approval_signature: Some(approval_signature.into()),
                context_packet_approval_did: Some(approval_authority_did.into()),
                context_packet_approval_timestamp: Some(approval_timestamp.into()),
                lifecycle_signature: None,
                continuation_signature: None,
                lifecycle_approval_did: None,
                continuation_approval_did: None,
                lifecycle_approval_timestamp: None,
                continuation_approval_timestamp: None,
                import_approval_signature: None,
                import_approval_did: None,
                import_approval_timestamp: None,
                export_approval_signature: None,
                export_approval_did: None,
                export_approval_timestamp: None,
            }
        }

        /// Header set for writeback, which requires all three signature headers
        /// plus distinct finality-authority DID headers.
        #[must_use]
        pub fn writeback(
            write_signature: impl Into<String>,
            lifecycle_signature: impl Into<String>,
            continuation_signature: impl Into<String>,
            lifecycle_approval_did: impl Into<String>,
            continuation_approval_did: impl Into<String>,
            lifecycle_approval_timestamp: impl Into<String>,
            continuation_approval_timestamp: impl Into<String>,
        ) -> Self {
            Self {
                write_signature: write_signature.into(),
                default_route_approval_signature: None,
                default_route_approval_did: None,
                default_route_approval_timestamp: None,
                context_packet_approval_signature: None,
                context_packet_approval_did: None,
                context_packet_approval_timestamp: None,
                lifecycle_signature: Some(lifecycle_signature.into()),
                continuation_signature: Some(continuation_signature.into()),
                lifecycle_approval_did: Some(lifecycle_approval_did.into()),
                continuation_approval_did: Some(continuation_approval_did.into()),
                lifecycle_approval_timestamp: Some(lifecycle_approval_timestamp.into()),
                continuation_approval_timestamp: Some(continuation_approval_timestamp.into()),
                import_approval_signature: None,
                import_approval_did: None,
                import_approval_timestamp: None,
                export_approval_signature: None,
                export_approval_did: None,
                export_approval_timestamp: None,
            }
        }

        /// Header set for import, which requires requester write signature and
        /// independent import-finality authority material.
        #[must_use]
        pub fn dagdb_import(
            write_signature: impl Into<String>,
            approval_signature: impl Into<String>,
            approval_authority_did: impl Into<String>,
            approval_timestamp: impl Into<String>,
        ) -> Self {
            Self {
                write_signature: write_signature.into(),
                default_route_approval_signature: None,
                default_route_approval_did: None,
                default_route_approval_timestamp: None,
                context_packet_approval_signature: None,
                context_packet_approval_did: None,
                context_packet_approval_timestamp: None,
                lifecycle_signature: None,
                continuation_signature: None,
                lifecycle_approval_did: None,
                continuation_approval_did: None,
                lifecycle_approval_timestamp: None,
                continuation_approval_timestamp: None,
                import_approval_signature: Some(approval_signature.into()),
                import_approval_did: Some(approval_authority_did.into()),
                import_approval_timestamp: Some(approval_timestamp.into()),
                export_approval_signature: None,
                export_approval_did: None,
                export_approval_timestamp: None,
            }
        }

        /// Header set for export, which requires requester write signature and
        /// independent export-finality authority material.
        #[must_use]
        pub fn dagdb_export(
            write_signature: impl Into<String>,
            approval_signature: impl Into<String>,
            approval_authority_did: impl Into<String>,
            approval_timestamp: impl Into<String>,
        ) -> Self {
            Self {
                write_signature: write_signature.into(),
                default_route_approval_signature: None,
                default_route_approval_did: None,
                default_route_approval_timestamp: None,
                context_packet_approval_signature: None,
                context_packet_approval_did: None,
                context_packet_approval_timestamp: None,
                lifecycle_signature: None,
                continuation_signature: None,
                lifecycle_approval_did: None,
                continuation_approval_did: None,
                lifecycle_approval_timestamp: None,
                continuation_approval_timestamp: None,
                import_approval_signature: None,
                import_approval_did: None,
                import_approval_timestamp: None,
                export_approval_signature: Some(approval_signature.into()),
                export_approval_did: Some(approval_authority_did.into()),
                export_approval_timestamp: Some(approval_timestamp.into()),
            }
        }

        fn insert_into(&self, headers: &mut HeaderMap) -> Result<(), DagDbClientError> {
            headers.insert(
                HeaderName::from_static(WRITE_SIGNATURE_HEADER),
                signature_header_value(&self.write_signature, WRITE_SIGNATURE_HEADER)?,
            );
            if let Some(signature) = self.lifecycle_signature.as_deref() {
                headers.insert(
                    HeaderName::from_static(LIFECYCLE_SIGNATURE_HEADER),
                    signature_header_value(signature, LIFECYCLE_SIGNATURE_HEADER)?,
                );
            }
            if let Some(signature) = self.default_route_approval_signature.as_deref() {
                headers.insert(
                    HeaderName::from_static(DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER),
                    signature_header_value(signature, DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER)?,
                );
            }
            if let Some(did) = self.default_route_approval_did.as_deref() {
                headers.insert(
                    HeaderName::from_static(DEFAULT_ROUTE_APPROVAL_DID_HEADER),
                    signature_header_value(did, DEFAULT_ROUTE_APPROVAL_DID_HEADER)?,
                );
            }
            if let Some(timestamp) = self.default_route_approval_timestamp.as_deref() {
                headers.insert(
                    HeaderName::from_static(DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER),
                    signature_header_value(timestamp, DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER)?,
                );
            }
            if let Some(signature) = self.context_packet_approval_signature.as_deref() {
                headers.insert(
                    HeaderName::from_static(CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER),
                    signature_header_value(signature, CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER)?,
                );
            }
            if let Some(did) = self.context_packet_approval_did.as_deref() {
                headers.insert(
                    HeaderName::from_static(CONTEXT_PACKET_APPROVAL_DID_HEADER),
                    signature_header_value(did, CONTEXT_PACKET_APPROVAL_DID_HEADER)?,
                );
            }
            if let Some(timestamp) = self.context_packet_approval_timestamp.as_deref() {
                headers.insert(
                    HeaderName::from_static(CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER),
                    signature_header_value(timestamp, CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER)?,
                );
            }
            if let Some(signature) = self.continuation_signature.as_deref() {
                headers.insert(
                    HeaderName::from_static(CONTINUATION_SIGNATURE_HEADER),
                    signature_header_value(signature, CONTINUATION_SIGNATURE_HEADER)?,
                );
            }
            if let Some(did) = self.lifecycle_approval_did.as_deref() {
                headers.insert(
                    HeaderName::from_static(LIFECYCLE_APPROVAL_DID_HEADER),
                    signature_header_value(did, LIFECYCLE_APPROVAL_DID_HEADER)?,
                );
            }
            if let Some(did) = self.continuation_approval_did.as_deref() {
                headers.insert(
                    HeaderName::from_static(CONTINUATION_APPROVAL_DID_HEADER),
                    signature_header_value(did, CONTINUATION_APPROVAL_DID_HEADER)?,
                );
            }
            if let Some(timestamp) = self.lifecycle_approval_timestamp.as_deref() {
                headers.insert(
                    HeaderName::from_static(LIFECYCLE_APPROVAL_TIMESTAMP_HEADER),
                    signature_header_value(timestamp, LIFECYCLE_APPROVAL_TIMESTAMP_HEADER)?,
                );
            }
            if let Some(timestamp) = self.continuation_approval_timestamp.as_deref() {
                headers.insert(
                    HeaderName::from_static(CONTINUATION_APPROVAL_TIMESTAMP_HEADER),
                    signature_header_value(timestamp, CONTINUATION_APPROVAL_TIMESTAMP_HEADER)?,
                );
            }
            if let Some(signature) = self.import_approval_signature.as_deref() {
                headers.insert(
                    HeaderName::from_static(IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER),
                    signature_header_value(signature, IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER)?,
                );
            }
            if let Some(did) = self.import_approval_did.as_deref() {
                headers.insert(
                    HeaderName::from_static(IMPORT_FINALITY_APPROVAL_DID_HEADER),
                    signature_header_value(did, IMPORT_FINALITY_APPROVAL_DID_HEADER)?,
                );
            }
            if let Some(timestamp) = self.import_approval_timestamp.as_deref() {
                headers.insert(
                    HeaderName::from_static(IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER),
                    signature_header_value(timestamp, IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER)?,
                );
            }
            if let Some(signature) = self.export_approval_signature.as_deref() {
                headers.insert(
                    HeaderName::from_static(EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER),
                    signature_header_value(signature, EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER)?,
                );
            }
            if let Some(did) = self.export_approval_did.as_deref() {
                headers.insert(
                    HeaderName::from_static(EXPORT_FINALITY_APPROVAL_DID_HEADER),
                    signature_header_value(did, EXPORT_FINALITY_APPROVAL_DID_HEADER)?,
                );
            }
            if let Some(timestamp) = self.export_approval_timestamp.as_deref() {
                headers.insert(
                    HeaderName::from_static(EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER),
                    signature_header_value(timestamp, EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER)?,
                );
            }
            Ok(())
        }

        fn validate_for(
            &self,
            requirement: DagDbSignatureRequirement,
        ) -> Result<(), DagDbClientError> {
            require_signature_material(
                Some(self.write_signature.as_str()),
                WRITE_SIGNATURE_HEADER,
            )?;

            match requirement {
                DagDbSignatureRequirement::None => Ok(()),
                DagDbSignatureRequirement::WriteOnly => Ok(()),
                DagDbSignatureRequirement::DefaultRoute => {
                    require_signature_material(
                        self.default_route_approval_signature.as_deref(),
                        DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER,
                    )?;
                    require_signature_material(
                        self.default_route_approval_did.as_deref(),
                        DEFAULT_ROUTE_APPROVAL_DID_HEADER,
                    )?;
                    require_signature_material(
                        self.default_route_approval_timestamp.as_deref(),
                        DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER,
                    )
                }
                DagDbSignatureRequirement::ContextPacket => {
                    require_signature_material(
                        self.context_packet_approval_signature.as_deref(),
                        CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER,
                    )?;
                    require_signature_material(
                        self.context_packet_approval_did.as_deref(),
                        CONTEXT_PACKET_APPROVAL_DID_HEADER,
                    )?;
                    require_signature_material(
                        self.context_packet_approval_timestamp.as_deref(),
                        CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER,
                    )
                }
                DagDbSignatureRequirement::Writeback => {
                    require_signature_material(
                        self.lifecycle_signature.as_deref(),
                        LIFECYCLE_SIGNATURE_HEADER,
                    )?;
                    require_signature_material(
                        self.continuation_signature.as_deref(),
                        CONTINUATION_SIGNATURE_HEADER,
                    )?;
                    require_signature_material(
                        self.lifecycle_approval_did.as_deref(),
                        LIFECYCLE_APPROVAL_DID_HEADER,
                    )?;
                    require_signature_material(
                        self.continuation_approval_did.as_deref(),
                        CONTINUATION_APPROVAL_DID_HEADER,
                    )?;
                    require_signature_material(
                        self.lifecycle_approval_timestamp.as_deref(),
                        LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
                    )?;
                    require_signature_material(
                        self.continuation_approval_timestamp.as_deref(),
                        CONTINUATION_APPROVAL_TIMESTAMP_HEADER,
                    )
                }
                DagDbSignatureRequirement::Import => {
                    require_signature_material(
                        self.import_approval_signature.as_deref(),
                        IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
                    )?;
                    require_signature_material(
                        self.import_approval_did.as_deref(),
                        IMPORT_FINALITY_APPROVAL_DID_HEADER,
                    )?;
                    require_signature_material(
                        self.import_approval_timestamp.as_deref(),
                        IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
                    )
                }
                DagDbSignatureRequirement::Export => {
                    require_signature_material(
                        self.export_approval_signature.as_deref(),
                        EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
                    )?;
                    require_signature_material(
                        self.export_approval_did.as_deref(),
                        EXPORT_FINALITY_APPROVAL_DID_HEADER,
                    )?;
                    require_signature_material(
                        self.export_approval_timestamp.as_deref(),
                        EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
                    )
                }
            }
        }
    }

    impl fmt::Debug for DagDbSignatureHeaders {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("DagDbSignatureHeaders(<redacted>)")
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum DagDbSignatureRequirement {
        None,
        WriteOnly,
        DefaultRoute,
        ContextPacket,
        Writeback,
        Import,
        Export,
    }

    /// Governed error returned by the gateway for a non-2xx DAG DB response.
    ///
    /// Carries the parsed [`DagDbErrorEnvelope`] fields so a caller can branch
    /// on `error_code`, surface the operator message, follow the
    /// `receipt_hash`, or route a `requires_council_review` case to governance —
    /// without re-parsing the body.
    #[derive(Clone, Debug, thiserror::Error)]
    #[error("DAG DB gateway returned {status} ({error_code}): {message}")]
    pub struct DagDbServerError {
        /// HTTP status code the gateway returned.
        pub status: u16,
        /// Stable machine error code (e.g. `tenant_scope_mismatch`).
        pub error_code: String,
        /// Human-readable operator message.
        pub message: String,
        /// Receipt hash for the denied/failed action, when the gateway emits one.
        pub receipt_hash: Option<String>,
        /// Validation report id, when the failure is a validation rejection.
        pub validation_report_id: Option<String>,
        /// Whether the action is parked pending council review.
        pub requires_council_review: bool,
    }

    /// Every failure mode of a [`DagDbHttpClient`] call. No error is swallowed:
    /// a call returns `Ok(Resp)` only on a 2xx whose body deserializes and whose
    /// `schema_version` matches the expected per-DTO constant.
    #[derive(Debug, thiserror::Error)]
    pub enum DagDbClientError {
        /// The request never produced an HTTP response (DNS/connect/TLS) or the
        /// connection failed mid-flight.
        #[error("DAG DB transport error: {0}")]
        Transport(#[source] reqwest::Error),

        /// The request exceeded the configured timeout.
        #[error("DAG DB request timed out: {0}")]
        Timeout(#[source] reqwest::Error),

        /// The gateway returned a non-2xx status with a parsed error envelope.
        #[error(transparent)]
        Server(DagDbServerError),

        /// The gateway returned a non-2xx status whose body was not a valid
        /// [`DagDbErrorEnvelope`], or a response body exceeded the fixed SDK
        /// limit. The body is either the bounded raw text or a stable limit
        /// marker, so attacker-controlled responses cannot grow the error.
        #[error("DAG DB gateway returned {status} with unusable response body: {body}")]
        UnexpectedStatus {
            /// HTTP status code returned.
            status: u16,
            /// Bounded raw response body, or a stable response-limit marker.
            body: String,
        },

        /// A 2xx response body failed to deserialize into the expected DTO.
        #[error("DAG DB response decode error: {0}")]
        Decode(#[source] reqwest::Error),

        /// A 2xx response deserialized, but its `schema_version` did not match
        /// the constant this SDK was built against — surfaced, never ignored.
        #[error("DAG DB schema version mismatch: expected `{expected}`, got `{actual}`")]
        SchemaVersionMismatch {
            /// Schema version this SDK expects for the DTO.
            expected: &'static str,
            /// Schema version the gateway actually emitted.
            actual: String,
        },

        /// Auth material (token/tenant/namespace/scope) contained bytes that are
        /// not a legal HTTP header value, so the request was never sent. The
        /// token itself is never included in this error.
        #[error("DAG DB auth header `{header}` is not a valid HTTP header value")]
        InvalidAuthHeader {
            /// Name of the header that could not be constructed.
            header: &'static str,
        },

        /// Required per-request signature or finality-authority material is
        /// absent or blank, so the request was never sent.
        #[error("DAG DB signature material `{header}` is missing; request was not sent")]
        MissingSignatureMaterial {
            /// Name of the missing header.
            header: &'static str,
        },

        /// Per-request signature material contained bytes that are not a legal
        /// HTTP header value, so the request was never sent. The signature value
        /// itself is never included in this error.
        #[error("DAG DB signature header `{header}` is not a valid HTTP header value")]
        InvalidSignatureHeader {
            /// Name of the header that could not be constructed.
            header: &'static str,
        },

        /// The request DTO's tenant or namespace does not match the configured
        /// auth scope, so the request was never sent.
        #[error(
            "DAG DB request tenant/namespace mismatch: request `{request_tenant_id}`/`{request_namespace}` does not match auth `{auth_tenant_id}`/`{auth_namespace}`"
        )]
        TenantNamespaceMismatch {
            /// Tenant id carried by the request DTO.
            request_tenant_id: String,
            /// Namespace carried by the request DTO.
            request_namespace: String,
            /// Tenant id configured in the auth headers.
            auth_tenant_id: String,
            /// Namespace configured in the auth headers.
            auth_namespace: String,
        },
    }

    impl DagDbClientError {
        /// Classify a `reqwest::Error` into the timeout vs. transport variant.
        fn from_reqwest(err: reqwest::Error) -> Self {
            if err.is_timeout() {
                Self::Timeout(err)
            } else {
                Self::Transport(err)
            }
        }
    }

    /// Async HTTP client for the DAG DB REST surface.
    ///
    /// Holds the base URL, auth config, and a `reqwest::Client`. Each typed
    /// method reuses the [`DagDbClient`] spec builder, attaches the four auth
    /// headers (with the route's `{action}` baked into the authority scope),
    /// sends the request, and maps the response. The bearer token is never
    /// logged: `DagDbHttpClient` deliberately does not derive `Debug`.
    pub struct DagDbHttpClient {
        base_url: String,
        auth: DagDbAuthConfig,
        specs: DagDbClient,
        http: Client,
    }

    impl DagDbHttpClient {
        /// Build a client against `base_url` (gateway origin, e.g.
        /// `https://gateway.example.com`) using the supplied auth config and a
        /// default-configured `reqwest::Client`.
        ///
        /// # Errors
        /// Returns [`DagDbClientError::Transport`] if the underlying
        /// `reqwest::Client` cannot be constructed.
        pub fn new(
            base_url: impl Into<String>,
            auth: DagDbAuthConfig,
        ) -> Result<Self, DagDbClientError> {
            let http = Client::builder()
                .build()
                .map_err(DagDbClientError::from_reqwest)?;
            Ok(Self::with_client(base_url, auth, http))
        }

        /// Build a client with a caller-supplied `reqwest::Client` (for shared
        /// connection pools, custom timeouts, proxies, or TLS roots).
        pub fn with_client(
            base_url: impl Into<String>,
            auth: DagDbAuthConfig,
            http: Client,
        ) -> Self {
            Self {
                base_url: trim_trailing_slash(base_url.into()),
                auth,
                specs: DagDbClient::new(),
                http,
            }
        }

        /// Fail closed for `POST /api/v1/dag-db/intake` without requester
        /// write signature material.
        pub async fn intake(
            &self,
            request: DagDbIntakeRequest,
        ) -> Result<DagDbIntakeResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.intake(request),
                "dagdb:intake",
                exo_dag_db_api::DAGDB_INTAKE_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbIntakeResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::WriteOnly,
            )
            .await
        }

        /// `POST /api/v1/dag-db/intake` with requester write signature.
        pub async fn intake_with_signatures(
            &self,
            request: DagDbIntakeRequest,
            signatures: DagDbSignatureHeaders,
        ) -> Result<DagDbIntakeResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.intake(request),
                "dagdb:intake",
                exo_dag_db_api::DAGDB_INTAKE_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbIntakeResponse| r.schema_version.as_str(),
                Some(signatures),
                DagDbSignatureRequirement::WriteOnly,
            )
            .await
        }

        /// Fail closed for `POST /api/v1/dag-db/route` without the required
        /// write and default-route approval signatures.
        pub async fn route(
            &self,
            request: DagDbRouteRequest,
        ) -> Result<DagDbRouteResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.route(request),
                "dagdb:route",
                exo_dag_db_api::DAGDB_ROUTE_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbRouteResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::DefaultRoute,
            )
            .await
        }

        /// `POST /api/v1/dag-db/route` with gateway write and external
        /// default-route approval signatures.
        pub async fn route_with_signatures(
            &self,
            request: DagDbRouteRequest,
            signatures: DagDbSignatureHeaders,
        ) -> Result<DagDbRouteResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.route(request),
                "dagdb:route",
                exo_dag_db_api::DAGDB_ROUTE_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbRouteResponse| r.schema_version.as_str(),
                Some(signatures),
                DagDbSignatureRequirement::DefaultRoute,
            )
            .await
        }

        /// Fail closed for `POST /api/v1/dag-db/context-packet` without the
        /// required write and context-packet approval signatures.
        pub async fn context_packet(
            &self,
            request: DagDbContextPacketRequest,
        ) -> Result<DagDbContextPacketResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.context_packet(request),
                "dagdb:context_packet",
                exo_dag_db_api::DAGDB_CONTEXT_PACKET_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbContextPacketResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::ContextPacket,
            )
            .await
        }

        /// `POST /api/v1/dag-db/context-packet` with gateway write and
        /// external context-packet approval signatures.
        pub async fn context_packet_with_signatures(
            &self,
            request: DagDbContextPacketRequest,
            signatures: DagDbSignatureHeaders,
        ) -> Result<DagDbContextPacketResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.context_packet(request),
                "dagdb:context_packet",
                exo_dag_db_api::DAGDB_CONTEXT_PACKET_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbContextPacketResponse| r.schema_version.as_str(),
                Some(signatures),
                DagDbSignatureRequirement::ContextPacket,
            )
            .await
        }

        /// Fail closed for `POST /api/v1/dag-db/validate` without requester
        /// write signature material.
        pub async fn validate(
            &self,
            request: DagDbValidateRequest,
        ) -> Result<DagDbValidateResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.validate(request),
                "dagdb:validate",
                exo_dag_db_api::DAGDB_VALIDATE_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbValidateResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::WriteOnly,
            )
            .await
        }

        /// `POST /api/v1/dag-db/validate` with requester write signature.
        pub async fn validate_with_signatures(
            &self,
            request: DagDbValidateRequest,
            signatures: DagDbSignatureHeaders,
        ) -> Result<DagDbValidateResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.validate(request),
                "dagdb:validate",
                exo_dag_db_api::DAGDB_VALIDATE_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbValidateResponse| r.schema_version.as_str(),
                Some(signatures),
                DagDbSignatureRequirement::WriteOnly,
            )
            .await
        }

        /// Fail closed for `POST /api/v1/dag-db/writeback` without the
        /// required writeback signature set.
        pub async fn writeback(
            &self,
            request: DagDbWritebackRequest,
        ) -> Result<DagDbWritebackResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.writeback(request),
                "dagdb:writeback",
                exo_dag_db_api::DAGDB_WRITEBACK_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbWritebackResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::Writeback,
            )
            .await
        }

        /// `POST /api/v1/dag-db/writeback` with all gateway signature headers.
        pub async fn writeback_with_signatures(
            &self,
            request: DagDbWritebackRequest,
            signatures: DagDbSignatureHeaders,
        ) -> Result<DagDbWritebackResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.writeback(request),
                "dagdb:writeback",
                exo_dag_db_api::DAGDB_WRITEBACK_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbWritebackResponse| r.schema_version.as_str(),
                Some(signatures),
                DagDbSignatureRequirement::Writeback,
            )
            .await
        }

        /// Fail closed for `POST /api/v1/dag-db/import` without the required
        /// write signature.
        pub async fn dagdb_import(
            &self,
            request: DagDbImportRequest,
        ) -> Result<DagDbImportResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.dagdb_import(request),
                "dagdb:import",
                exo_dag_db_api::DAGDB_IMPORT_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbImportResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::Import,
            )
            .await
        }

        /// `POST /api/v1/dag-db/import` with gateway write signature and
        /// independent import-finality approval headers.
        pub async fn dagdb_import_with_signatures(
            &self,
            request: DagDbImportRequest,
            signatures: DagDbSignatureHeaders,
        ) -> Result<DagDbImportResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.dagdb_import(request),
                "dagdb:import",
                exo_dag_db_api::DAGDB_IMPORT_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbImportResponse| r.schema_version.as_str(),
                Some(signatures),
                DagDbSignatureRequirement::Import,
            )
            .await
        }

        /// Fail closed for `POST /api/v1/dag-db/export` without the required
        /// write signature.
        pub async fn dagdb_export(
            &self,
            request: DagDbExportRequest,
        ) -> Result<DagDbExportResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.dagdb_export(request),
                "dagdb:export",
                exo_dag_db_api::DAGDB_EXPORT_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbExportResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::Export,
            )
            .await
        }

        /// `POST /api/v1/dag-db/export` with gateway write signature and
        /// independent export-finality approval headers.
        pub async fn dagdb_export_with_signatures(
            &self,
            request: DagDbExportRequest,
            signatures: DagDbSignatureHeaders,
        ) -> Result<DagDbExportResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.dagdb_export(request),
                "dagdb:export",
                exo_dag_db_api::DAGDB_EXPORT_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbExportResponse| r.schema_version.as_str(),
                Some(signatures),
                DagDbSignatureRequirement::Export,
            )
            .await
        }

        /// Fail closed for `POST /api/v1/dag-db/trust-check` without
        /// requester write signature material.
        pub async fn trust_check(
            &self,
            request: DagDbTrustCheckRequest,
        ) -> Result<DagDbTrustCheckResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.trust_check(request),
                "dagdb:trust_check",
                exo_dag_db_api::DAGDB_TRUST_CHECK_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbTrustCheckResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::WriteOnly,
            )
            .await
        }

        /// `POST /api/v1/dag-db/trust-check` with requester write signature.
        pub async fn trust_check_with_signatures(
            &self,
            request: DagDbTrustCheckRequest,
            signatures: DagDbSignatureHeaders,
        ) -> Result<DagDbTrustCheckResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.trust_check(request),
                "dagdb:trust_check",
                exo_dag_db_api::DAGDB_TRUST_CHECK_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbTrustCheckResponse| r.schema_version.as_str(),
                Some(signatures),
                DagDbSignatureRequirement::WriteOnly,
            )
            .await
        }

        /// Fail closed for `POST /api/v1/dag-db/council/decision` without
        /// requester write signature material.
        pub async fn council_decision(
            &self,
            request: DagDbCouncilDecisionRequest,
        ) -> Result<DagDbCouncilDecisionResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.council_decision(request),
                "dagdb:council_decision",
                exo_dag_db_api::DAGDB_COUNCIL_DECISION_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbCouncilDecisionResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::WriteOnly,
            )
            .await
        }

        /// `POST /api/v1/dag-db/council/decision` with requester write
        /// signature.
        pub async fn council_decision_with_signatures(
            &self,
            request: DagDbCouncilDecisionRequest,
            signatures: DagDbSignatureHeaders,
        ) -> Result<DagDbCouncilDecisionResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.council_decision(request),
                "dagdb:council_decision",
                exo_dag_db_api::DAGDB_COUNCIL_DECISION_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbCouncilDecisionResponse| r.schema_version.as_str(),
                Some(signatures),
                DagDbSignatureRequirement::WriteOnly,
            )
            .await
        }

        /// `GET /api/v1/dag-db/receipts/:receipt_hash` with auth scope.
        pub async fn receipt_lookup(
            &self,
            request: DagDbReceiptLookupRequest,
        ) -> Result<DagDbReceiptLookupResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.receipt_lookup(request),
                "dagdb:receipt_lookup",
                exo_dag_db_api::DAGDB_RECEIPT_LOOKUP_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbReceiptLookupResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::None,
            )
            .await
        }

        /// `GET /api/v1/dag-db/catalog/:catalog_id` with auth scope.
        pub async fn catalog_lookup(
            &self,
            request: DagDbCatalogLookupRequest,
        ) -> Result<DagDbCatalogLookupResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.catalog_lookup(request),
                "dagdb:catalog_lookup",
                exo_dag_db_api::DAGDB_CATALOG_LOOKUP_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbCatalogLookupResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::None,
            )
            .await
        }

        /// `GET /api/v1/dag-db/routes/:route_id` with auth scope.
        pub async fn route_lookup(
            &self,
            request: DagDbRouteLookupRequest,
        ) -> Result<DagDbRouteLookupResponse, DagDbClientError> {
            self.ensure_request_scope(&request.tenant_id, &request.namespace)?;
            self.send(
                self.specs.route_lookup(request),
                "dagdb:route_lookup",
                exo_dag_db_api::DAGDB_ROUTE_LOOKUP_RESPONSE_SCHEMA_VERSION,
                |r: &DagDbRouteLookupResponse| r.schema_version.as_str(),
                None,
                DagDbSignatureRequirement::None,
            )
            .await
        }

        fn ensure_request_scope(
            &self,
            request_tenant_id: &str,
            request_namespace: &str,
        ) -> Result<(), DagDbClientError> {
            if request_tenant_id == self.auth.tenant_id && request_namespace == self.auth.namespace
            {
                return Ok(());
            }

            Err(DagDbClientError::TenantNamespaceMismatch {
                request_tenant_id: request_tenant_id.to_owned(),
                request_namespace: request_namespace.to_owned(),
                auth_tenant_id: self.auth.tenant_id.clone(),
                auth_namespace: self.auth.namespace.clone(),
            })
        }

        /// Build, sign, send, and map one request spec.
        ///
        /// `action` is the gateway authority action (e.g. `dagdb:intake`) baked
        /// into the `{action}:{tenant}:{namespace}` scope header. `expected` is
        /// the `schema_version` constant this SDK was built against;
        /// `schema_of` extracts the version from the decoded response so a
        /// mismatch is surfaced as [`DagDbClientError::SchemaVersionMismatch`].
        async fn send<Body, Resp>(
            &self,
            spec: DagDbRequestSpec<Body>,
            action: &str,
            expected: &'static str,
            schema_of: impl Fn(&Resp) -> &str,
            signatures: Option<DagDbSignatureHeaders>,
            signature_requirement: DagDbSignatureRequirement,
        ) -> Result<Resp, DagDbClientError>
        where
            Body: Serialize,
            Resp: DeserializeOwned,
        {
            let signatures = if signature_requirement == DagDbSignatureRequirement::None {
                None
            } else {
                let signatures =
                    signatures
                        .as_ref()
                        .ok_or(DagDbClientError::MissingSignatureMaterial {
                            header: WRITE_SIGNATURE_HEADER,
                        })?;
                signatures.validate_for(signature_requirement)?;
                Some(signatures)
            };

            let url = format!("{}{}", self.base_url, spec.path);
            let mut builder = match spec.method {
                DagDbHttpMethod::Get => self.http.get(url),
                DagDbHttpMethod::Post => self.http.post(url),
            };
            builder = builder.headers(self.auth_headers(action, signatures)?);
            if let Some(body) = spec.body.as_ref() {
                builder = builder.json(body);
            }

            let response = builder
                .send()
                .await
                .map_err(DagDbClientError::from_reqwest)?;
            let status = response.status();
            let body = read_bounded_response_body(response).await?;
            if status.is_success() {
                let bounded_response: reqwest::Response = http::Response::new(body).into();
                let decoded: Resp = bounded_response
                    .json()
                    .await
                    .map_err(DagDbClientError::Decode)?;
                let actual = schema_of(&decoded);
                if actual != expected {
                    return Err(DagDbClientError::SchemaVersionMismatch {
                        expected,
                        actual: actual.to_owned(),
                    });
                }
                Ok(decoded)
            } else {
                Err(self.map_error(status, &body))
            }
        }

        /// Parse a non-2xx response into the governed error variant, falling
        /// back to [`DagDbClientError::UnexpectedStatus`] with the raw body when
        /// the envelope does not parse.
        fn map_error(&self, status: StatusCode, body: &[u8]) -> DagDbClientError {
            let code = status.as_u16();
            match serde_json::from_slice::<DagDbErrorEnvelope>(body) {
                Ok(envelope) => DagDbClientError::Server(DagDbServerError {
                    status: code,
                    error_code: envelope.error_code,
                    message: envelope.message,
                    receipt_hash: envelope.receipt_hash,
                    validation_report_id: envelope.validation_report_id,
                    requires_council_review: envelope.requires_council_review,
                }),
                Err(_) => DagDbClientError::UnexpectedStatus {
                    status: code,
                    body: String::from_utf8_lossy(body).into_owned(),
                },
            }
        }

        /// Assemble the gateway auth headers for `action` and optional
        /// per-request signature headers.
        ///
        /// Callers wanting a per-request deadline should build the
        /// `reqwest::Client` with [`reqwest::ClientBuilder::timeout`] and pass
        /// it to [`DagDbHttpClient::with_client`]; an elapsed deadline maps to
        /// [`DagDbClientError::Timeout`].
        fn auth_headers(
            &self,
            action: &str,
            signatures: Option<&DagDbSignatureHeaders>,
        ) -> Result<HeaderMap, DagDbClientError> {
            let mut headers = HeaderMap::with_capacity(if signatures.is_some() { 11 } else { 4 });
            headers.insert(
                AUTHORIZATION,
                header_value(
                    &format!("Bearer {}", self.auth.token.reveal()),
                    "authorization",
                )?,
            );
            headers.insert(
                HeaderName::from_static(TENANT_HEADER),
                header_value(&self.auth.tenant_id, TENANT_HEADER)?,
            );
            headers.insert(
                HeaderName::from_static(NAMESPACE_HEADER),
                header_value(&self.auth.namespace, NAMESPACE_HEADER)?,
            );
            headers.insert(
                HeaderName::from_static(AUTHORITY_SCOPE_HEADER),
                header_value(&self.auth.authority_scope(action), AUTHORITY_SCOPE_HEADER)?,
            );
            if let Some(signatures) = signatures {
                signatures.insert_into(&mut headers)?;
            }
            Ok(headers)
        }
    }

    fn oversized_response_error(status: StatusCode) -> DagDbClientError {
        DagDbClientError::UnexpectedStatus {
            status: status.as_u16(),
            body: OVERSIZED_RESPONSE_MESSAGE.to_owned(),
        }
    }

    /// Collect one response incrementally while enforcing the byte limit from
    /// actual chunks. Content-Length is only an early-rejection optimization;
    /// it is never trusted as the accounting boundary.
    pub(super) async fn read_bounded_response_body(
        mut response: reqwest::Response,
    ) -> Result<Vec<u8>, DagDbClientError> {
        let status = response.status();
        let max_bytes = u64::try_from(MAX_DAGDB_RESPONSE_BYTES)
            .map_err(|_| oversized_response_error(status))?;
        if response
            .content_length()
            .is_some_and(|content_length| content_length > max_bytes)
        {
            return Err(oversized_response_error(status));
        }

        let initial_capacity = response
            .content_length()
            .and_then(|content_length| usize::try_from(content_length).ok())
            .map_or(0, |content_length| {
                content_length.min(MAX_DAGDB_RESPONSE_BYTES)
            });
        let mut body = Vec::with_capacity(initial_capacity);
        loop {
            let chunk = match response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(error) if status.is_success() => {
                    return Err(DagDbClientError::Decode(error));
                }
                Err(error) => return Err(DagDbClientError::from_reqwest(error)),
            };
            let next_length = body
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| oversized_response_error(status))?;
            if next_length > MAX_DAGDB_RESPONSE_BYTES {
                return Err(oversized_response_error(status));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    fn trim_trailing_slash(mut base: String) -> String {
        while base.ends_with('/') {
            base.pop();
        }
        base
    }

    fn header_value(value: &str, header: &'static str) -> Result<HeaderValue, DagDbClientError> {
        HeaderValue::from_str(value).map_err(|_| DagDbClientError::InvalidAuthHeader { header })
    }

    fn signature_header_value(
        value: &str,
        header: &'static str,
    ) -> Result<HeaderValue, DagDbClientError> {
        HeaderValue::from_str(value)
            .map_err(|_| DagDbClientError::InvalidSignatureHeader { header })
    }

    fn require_signature_material(
        value: Option<&str>,
        header: &'static str,
    ) -> Result<(), DagDbClientError> {
        match value {
            Some(value) if !value.trim().is_empty() => Ok(()),
            _ => Err(DagDbClientError::MissingSignatureMaterial { header }),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Serialize, de::DeserializeOwned};

    use super::*;

    const ADVERSARIAL_TARGET_COMPONENT: &str = "Az09-._~/?&=#% \n雪";
    const ENCODED_ADVERSARIAL_TARGET_COMPONENT: &str = "Az09-._~%2F%3F%26%3D%23%25%20%0A%E9%9B%AA";

    #[test]
    fn dagdb_json_fixtures() {
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../exo-dag-db-api/fixtures/json/all_dto_fixtures.json"
        ))
        .expect("SDK parses complete DAG DB fixture set");

        assert_fixture::<DagDbIntakeRequest>(&fixtures, "requests", "intake");
        assert_fixture::<DagDbRouteRequest>(&fixtures, "requests", "route");
        assert_fixture::<DagDbContextPacketRequest>(&fixtures, "requests", "context_packet");
        assert_fixture::<DagDbValidateRequest>(&fixtures, "requests", "validate");
        assert_fixture::<DagDbWritebackRequest>(&fixtures, "requests", "writeback");
        assert_fixture::<DagDbTrustCheckRequest>(&fixtures, "requests", "trust_check");
        assert_fixture::<DagDbCouncilDecisionRequest>(&fixtures, "requests", "council_decision");
        assert_fixture::<DagDbReceiptLookupRequest>(&fixtures, "requests", "receipt_lookup");
        assert_fixture::<DagDbCatalogLookupRequest>(&fixtures, "requests", "catalog_lookup");
        assert_fixture::<DagDbRouteLookupRequest>(&fixtures, "requests", "route_lookup");

        assert_fixture::<DagDbIntakeResponse>(&fixtures, "responses", "intake");
        assert_fixture::<DagDbRouteResponse>(&fixtures, "responses", "route");
        assert_fixture::<DagDbContextPacketResponse>(&fixtures, "responses", "context_packet");
        assert_fixture::<DagDbValidateResponse>(&fixtures, "responses", "validate");
        assert_fixture::<DagDbWritebackResponse>(&fixtures, "responses", "writeback");
        assert_fixture::<DagDbImportResponse>(&fixtures, "responses", "import");
        assert_fixture::<DagDbExportResponse>(&fixtures, "responses", "export");
        assert_fixture::<DagDbTrustCheckResponse>(&fixtures, "responses", "trust_check");
        assert_fixture::<DagDbCouncilDecisionResponse>(&fixtures, "responses", "council_decision");
        assert_fixture::<DagDbReceiptLookupResponse>(&fixtures, "responses", "receipt_lookup");
        assert_fixture::<DagDbCatalogLookupResponse>(&fixtures, "responses", "catalog_lookup");
        assert_fixture::<DagDbRouteLookupResponse>(&fixtures, "responses", "route_lookup");

        assert_fixture::<DagDbErrorEnvelope>(&fixtures, "errors", "tenant_scope_mismatch");
    }

    #[test]
    fn dagdb_graph_json_fixtures() {
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../exo-dag-db-api/fixtures/json/all_dto_fixtures.json"
        ))
        .expect("SDK parses complete DAG DB fixture set");

        assert_fixture::<MemoryCandidate>(&fixtures, "graph", "memory_candidate");
        assert_fixture::<SimilarityResult>(&fixtures, "graph", "similarity_result");
        assert_fixture::<CanonicalizationDecision>(&fixtures, "graph", "canonicalization_decision");
        assert_fixture::<GraphView>(&fixtures, "graph", "graph_view");
        assert_fixture::<RouteInvalidationReceipt>(
            &fixtures,
            "graph",
            "route_invalidation_receipt",
        );
        assert_fixture::<PlacementResult>(&fixtures, "graph", "placement_result");
    }

    #[test]
    fn dagdb_sdk_helpers_cover_every_route_without_shape_drift() {
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../exo-dag-db-api/fixtures/json/all_dto_fixtures.json"
        ))
        .expect("SDK parses complete DAG DB fixture set");
        let client = DagDbClient::new();

        assert_post(
            client.intake(fixture(&fixtures, "requests", "intake")),
            "/api/v1/dag-db/intake",
        );
        assert_post(
            client.route(fixture(&fixtures, "requests", "route")),
            "/api/v1/dag-db/route",
        );
        assert_post(
            client.context_packet(fixture(&fixtures, "requests", "context_packet")),
            "/api/v1/dag-db/context-packet",
        );
        assert_post(
            client.validate(fixture(&fixtures, "requests", "validate")),
            "/api/v1/dag-db/validate",
        );
        assert_post(
            client.writeback(fixture(&fixtures, "requests", "writeback")),
            "/api/v1/dag-db/writeback",
        );
        assert_post(import_request(&client), "/api/v1/dag-db/import");
        assert_post(export_request(&client), "/api/v1/dag-db/export");
        assert_post(
            client.trust_check(fixture(&fixtures, "requests", "trust_check")),
            "/api/v1/dag-db/trust-check",
        );
        assert_post(
            client.council_decision(fixture(&fixtures, "requests", "council_decision")),
            "/api/v1/dag-db/council/decision",
        );
        assert_get(
            client.receipt_lookup(fixture(&fixtures, "requests", "receipt_lookup")),
            "/api/v1/dag-db/receipts/",
        );
        assert_get(
            client.catalog_lookup(fixture(&fixtures, "requests", "catalog_lookup")),
            "/api/v1/dag-db/catalog/",
        );
        assert_get(
            client.route_lookup(fixture(&fixtures, "requests", "route_lookup")),
            "/api/v1/dag-db/routes/",
        );
    }

    #[test]
    fn dagdb_lookup_request_specs_encode_every_caller_controlled_target_component() {
        let client = DagDbClient::new();

        let receipt = client.receipt_lookup(DagDbReceiptLookupRequest {
            receipt_hash: ADVERSARIAL_TARGET_COMPONENT.to_owned(),
            tenant_id: ADVERSARIAL_TARGET_COMPONENT.to_owned(),
            namespace: ADVERSARIAL_TARGET_COMPONENT.to_owned(),
            include_body: Some(true),
        });
        assert_eq!(
            receipt.path,
            format!(
                "/api/v1/dag-db/receipts/{0}?tenant_id={0}&namespace={0}&include_body=true",
                ENCODED_ADVERSARIAL_TARGET_COMPONENT
            )
        );

        let catalog = client.catalog_lookup(DagDbCatalogLookupRequest {
            catalog_id: ADVERSARIAL_TARGET_COMPONENT.to_owned(),
            tenant_id: ADVERSARIAL_TARGET_COMPONENT.to_owned(),
            namespace: ADVERSARIAL_TARGET_COMPONENT.to_owned(),
            include_children: Some(true),
            include_routes: Some(false),
        });
        assert_eq!(
            catalog.path,
            format!(
                "/api/v1/dag-db/catalog/{0}?tenant_id={0}&namespace={0}\
                 &include_children=true&include_routes=false",
                ENCODED_ADVERSARIAL_TARGET_COMPONENT
            )
        );

        let route = client.route_lookup(DagDbRouteLookupRequest {
            route_id: ADVERSARIAL_TARGET_COMPONENT.to_owned(),
            tenant_id: ADVERSARIAL_TARGET_COMPONENT.to_owned(),
            namespace: ADVERSARIAL_TARGET_COMPONENT.to_owned(),
            include_memory_refs: Some(false),
            include_validation: Some(true),
        });
        assert_eq!(
            route.path,
            format!(
                "/api/v1/dag-db/routes/{0}?tenant_id={0}&namespace={0}\
                 &include_memory_refs=false&include_validation=true",
                ENCODED_ADVERSARIAL_TARGET_COMPONENT
            )
        );
    }

    fn assert_fixture<T>(fixtures: &serde_json::Value, section: &str, name: &str)
    where
        T: DeserializeOwned + Serialize,
    {
        let fixture = fixtures
            .get(section)
            .and_then(|section| section.get(name))
            .unwrap_or_else(|| panic!("missing fixture {section}.{name}"));
        let parsed: T = serde_json::from_value(fixture.clone())
            .unwrap_or_else(|err| panic!("parse fixture {section}.{name}: {err}"));
        let serialized = serde_json::to_value(parsed)
            .unwrap_or_else(|err| panic!("serialize fixture {section}.{name}: {err}"));
        assert_eq!(serialized, *fixture, "fixture {section}.{name} drifted");
    }

    fn fixture<T>(fixtures: &serde_json::Value, section: &str, name: &str) -> T
    where
        T: DeserializeOwned,
    {
        serde_json::from_value(
            fixtures
                .get(section)
                .and_then(|section| section.get(name))
                .unwrap_or_else(|| panic!("missing fixture {section}.{name}"))
                .clone(),
        )
        .unwrap_or_else(|err| panic!("parse fixture {section}.{name}: {err}"))
    }

    fn assert_post<T>(spec: DagDbRequestSpec<T>, path: &str) {
        assert_eq!(spec.method, DagDbHttpMethod::Post);
        assert_eq!(spec.path, path);
        assert!(spec.body.is_some());
    }

    fn assert_get<T>(spec: DagDbRequestSpec<T>, path_prefix: &str) {
        assert_eq!(spec.method, DagDbHttpMethod::Get);
        assert!(
            spec.path.starts_with(path_prefix),
            "GET path `{}` must start with `{path_prefix}`",
            spec.path
        );
        assert!(spec.path.contains("tenant_id="));
        assert!(spec.path.contains("namespace="));
        assert!(spec.body.is_none());
    }

    fn import_request(client: &DagDbClient) -> DagDbRequestSpec<DagDbImportRequest> {
        client.dagdb_import(DagDbImportRequest {
            tenant_id: "tenant-a".to_owned(),
            namespace: "project_memory_v3".to_owned(),
            idempotency_key: "idem-import-1".to_owned(),
            db_set_version: "dag_db-project_memory_v3".to_owned(),
            source_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_owned(),
            requester_did: "did:exo:importer".to_owned(),
            import_report: serde_json::json!({
                "schema_version": "dagdb_kg_dry_run_import_report_v1",
                "source_candidates_schema_version": "dagdb_markdown_kg_import_candidates_v1",
                "graph_root": "KnowledgeGraphs/dag-db",
                "tenant_id": "tenant-a",
                "namespace": "project_memory_v3",
                "actor_did": "did:exo:kg-importer",
                "batch_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "dry_run_only": true,
                "postgres_writes": false,
                "raw_markdown_included": false,
                "proposed_memory_records": [],
                "proposed_catalog_entries": [],
                "proposed_graph_nodes": [],
                "proposed_graph_edges": [],
                "proposed_required_edges": [],
                "proposed_placement_decisions": [],
                "proposed_receipt_intents": [],
                "proposed_validation_reports": [],
                "proposed_governance_reviews": [],
                "proposed_graph_view_refreshes": [],
                "proposed_route_invalidations": [],
                "proposed_subdag_boundaries": [],
                "rollback_plan": {},
                "placement_governance_summary": {},
                "review_items": [],
                "warnings": []
            }),
        })
    }

    fn export_request(client: &DagDbClient) -> DagDbRequestSpec<DagDbExportRequest> {
        client.dagdb_export(DagDbExportRequest {
            tenant_id: "tenant-a".to_owned(),
            namespace: "project_memory_v3".to_owned(),
            idempotency_key: "idem-export-1".to_owned(),
            db_set_version: "dag_db-project_memory_v3".to_owned(),
            requester_did: "did:exo:exporter".to_owned(),
            included_memory_ids: vec![
                "2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
            ],
            included_graph_styles: Vec::new(),
            included_writeback_idempotency_keys: Vec::new(),
            source_commit_or_repo_ref: None,
            include_preview_context: false,
        })
    }
}

#[cfg(all(test, feature = "http-client"))]
mod transport_tests {
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
    };

    use super::{
        DagDbCatalogLookupRequest, DagDbContextPacketRequest, DagDbExportRequest,
        DagDbImportRequest, DagDbReceiptLookupRequest, DagDbRouteLookupRequest, DagDbRouteRequest,
        DagDbWritebackRequest,
        transport::{
            BearerToken, DagDbAuthConfig, DagDbClientError, DagDbHttpClient, DagDbSignatureHeaders,
            MAX_DAGDB_RESPONSE_BYTES, read_bounded_response_body,
        },
    };

    const ADVERSARIAL_PATH_COMPONENT: &str = "Az09-._~/?&=#% \n雪";
    const ENCODED_ADVERSARIAL_PATH_COMPONENT: &str = "Az09-._~%2F%3F%26%3D%23%25%20%0A%E9%9B%AA";
    const ADVERSARIAL_QUERY_COMPONENT: &str = "scope/?&=#% space";
    const ENCODED_ADVERSARIAL_QUERY_COMPONENT: &str = "scope%2F%3F%26%3D%23%25%20space";

    /// The raw HTTP request a [`TestServer`] captured from the SDK.
    struct CapturedRequest {
        request_line: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    /// Minimal in-process HTTP/1.1 server: accepts one connection, captures the
    /// request, writes a canned response, then hands the captured request back.
    /// No external mock-server crate is a workspace dependency, so this stands
    /// in for a live gateway using only `tokio`.
    struct TestServer {
        base_url: String,
        captured: oneshot::Receiver<CapturedRequest>,
    }

    impl TestServer {
        /// Spawn a server that replies with `status`/`body` and captures the request.
        async fn spawn(status_line: &'static str, body: impl Into<String>) -> Self {
            let body = body.into();
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test server");
            let addr = listener.local_addr().expect("server addr");
            let base_url = format!("http://{addr}");
            let (tx, captured) = oneshot::channel();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept connection");
                let request = read_request(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
                stream.flush().await.expect("flush response");
                let _ = tx.send(request);
            });
            Self { base_url, captured }
        }

        /// Spawn a server with a raw response so chunked and dishonest metadata
        /// boundaries can be exercised without a third-party mock server.
        async fn spawn_raw(response: Vec<u8>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind raw test server");
            let addr = listener.local_addr().expect("raw server addr");
            let base_url = format!("http://{addr}");
            let (tx, captured) = oneshot::channel();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept connection");
                let request = read_request(&mut stream).await;
                stream
                    .write_all(&response)
                    .await
                    .expect("write raw response");
                stream.flush().await.expect("flush raw response");
                let _ = tx.send(request);
            });
            Self { base_url, captured }
        }

        /// Spawn a server that accepts a connection but never replies, so the
        /// client's timeout fires.
        async fn spawn_silent() -> String {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind silent server");
            let addr = listener.local_addr().expect("silent addr");
            tokio::spawn(async move {
                let _conn = listener.accept().await;
                // Hold the connection open without responding.
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
            format!("http://{addr}")
        }

        async fn captured(self) -> CapturedRequest {
            self.captured.await.expect("server captured a request")
        }
    }

    /// Read one HTTP/1.1 request: request line, headers, and Content-Length body.
    async fn read_request(stream: &mut TcpStream) -> CapturedRequest {
        let mut buf = Vec::new();
        let header_end = loop {
            let mut chunk = [0_u8; 1024];
            let n = stream.read(&mut chunk).await.expect("read request bytes");
            assert!(n > 0, "connection closed before headers were complete");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos;
            }
        };
        let head = String::from_utf8(buf[..header_end].to_vec()).expect("utf8 request head");
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or_default().to_owned();
        let mut headers = Vec::new();
        let mut content_length = 0_usize;
        for line in lines {
            if let Some((key, value)) = line.split_once(": ") {
                if key.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
                headers.push((key.to_owned(), value.to_owned()));
            }
        }
        let mut body_bytes = buf[header_end + 4..].to_vec();
        while body_bytes.len() < content_length {
            let mut chunk = [0_u8; 1024];
            let n = stream.read(&mut chunk).await.expect("read body bytes");
            if n == 0 {
                break;
            }
            body_bytes.extend_from_slice(&chunk[..n]);
        }
        let body = String::from_utf8(body_bytes).expect("utf8 request body");
        CapturedRequest {
            request_line,
            headers,
            body,
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn auth() -> DagDbAuthConfig {
        DagDbAuthConfig::new("super-secret-token-value", "tenant-a", "primary")
    }

    fn fixtures() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../exo-dag-db-api/fixtures/json/all_dto_fixtures.json"
        ))
        .expect("parse fixture set")
    }

    fn fixture_request<T: serde::de::DeserializeOwned>(name: &str) -> T {
        serde_json::from_value(fixtures()["requests"][name].clone()).expect("parse request fixture")
    }

    fn route_request() -> DagDbRouteRequest {
        fixture_request("route")
    }

    fn context_packet_request() -> DagDbContextPacketRequest {
        fixture_request("context_packet")
    }

    fn writeback_request() -> DagDbWritebackRequest {
        fixture_request("writeback")
    }

    fn receipt_lookup_request() -> DagDbReceiptLookupRequest {
        fixture_request("receipt_lookup")
    }

    fn catalog_lookup_request() -> DagDbCatalogLookupRequest {
        fixture_request("catalog_lookup")
    }

    fn route_lookup_request() -> DagDbRouteLookupRequest {
        fixture_request("route_lookup")
    }

    fn import_request() -> DagDbImportRequest {
        DagDbImportRequest {
            tenant_id: "tenant-a".to_owned(),
            namespace: "primary".to_owned(),
            idempotency_key: "idem-import-1".to_owned(),
            db_set_version: "dag_db-project_memory_v3".to_owned(),
            source_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_owned(),
            requester_did: "did:exo:importer".to_owned(),
            import_report: serde_json::json!({
                "schema_version": "dagdb_kg_dry_run_import_report_v1",
                "source_candidates_schema_version": "dagdb_markdown_kg_import_candidates_v1",
                "graph_root": "KnowledgeGraphs/dag-db",
                "tenant_id": "tenant-a",
                "namespace": "primary",
                "actor_did": "did:exo:kg-importer",
                "batch_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "dry_run_only": true,
                "postgres_writes": false,
                "raw_markdown_included": false,
                "proposed_memory_records": [],
                "proposed_catalog_entries": [],
                "proposed_graph_nodes": [],
                "proposed_graph_edges": [],
                "proposed_required_edges": [],
                "proposed_placement_decisions": [],
                "proposed_receipt_intents": [],
                "proposed_validation_reports": [],
                "proposed_governance_reviews": [],
                "proposed_graph_view_refreshes": [],
                "proposed_route_invalidations": [],
                "proposed_subdag_boundaries": [],
                "rollback_plan": {},
                "placement_governance_summary": {},
                "review_items": [],
                "warnings": []
            }),
        }
    }

    fn export_request() -> DagDbExportRequest {
        DagDbExportRequest {
            tenant_id: "tenant-a".to_owned(),
            namespace: "primary".to_owned(),
            idempotency_key: "idem-export-1".to_owned(),
            db_set_version: "dag_db-project_memory_v3".to_owned(),
            requester_did: "did:exo:exporter".to_owned(),
            included_memory_ids: vec![
                "2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
            ],
            included_graph_styles: vec!["chronological".to_owned()],
            included_writeback_idempotency_keys: vec!["idem-writeback-1".to_owned()],
            source_commit_or_repo_ref: None,
            include_preview_context: false,
        }
    }

    fn signature_value(byte: char) -> String {
        byte.to_string().repeat(128)
    }

    fn approval_timestamp() -> &'static str {
        "2026-06-20T00:00:00Z"
    }

    fn route_signatures() -> DagDbSignatureHeaders {
        DagDbSignatureHeaders::default_route(
            signature_value('a'),
            signature_value('b'),
            "did:exo:route-authority",
            approval_timestamp(),
        )
    }

    fn context_packet_signatures() -> DagDbSignatureHeaders {
        DagDbSignatureHeaders::context_packet(
            signature_value('c'),
            signature_value('d'),
            "did:exo:context-authority",
            approval_timestamp(),
        )
    }

    fn writeback_signatures() -> DagDbSignatureHeaders {
        DagDbSignatureHeaders::writeback(
            signature_value('e'),
            signature_value('f'),
            signature_value('1'),
            "did:exo:lifecycle-authority",
            "did:exo:continuation-authority",
            approval_timestamp(),
            "2026-06-20T00:00:01Z",
        )
    }

    fn write_signature() -> DagDbSignatureHeaders {
        DagDbSignatureHeaders::write(signature_value('2'))
    }

    fn import_signatures() -> DagDbSignatureHeaders {
        DagDbSignatureHeaders::dagdb_import(
            signature_value('3'),
            signature_value('4'),
            "did:exo:import-authority",
            approval_timestamp(),
        )
    }

    fn export_signatures() -> DagDbSignatureHeaders {
        DagDbSignatureHeaders::dagdb_export(
            signature_value('5'),
            signature_value('6'),
            "did:exo:export-authority",
            approval_timestamp(),
        )
    }

    fn fixture_response(section: &str, name: &str) -> String {
        fixtures()
            .get(section)
            .and_then(|s| s.get(name))
            .expect("fixture exists")
            .to_string()
    }

    fn padded_route_response(byte_length: usize) -> String {
        let body = fixture_response("responses", "route");
        assert!(
            body.len() <= byte_length,
            "fixture exceeds requested byte length"
        );
        format!("{body}{}", " ".repeat(byte_length - body.len()))
    }

    fn chunked_json_response(status_line: &str, chunks: &[&[u8]]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        for chunk in chunks {
            response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            response.extend_from_slice(chunk);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        response
    }

    fn assert_response_too_large(err: DagDbClientError, expected_status: u16) {
        match err {
            DagDbClientError::UnexpectedStatus { status, body } => {
                assert_eq!(status, expected_status);
                assert_eq!(body, "response body exceeds the 1048576-byte limit");
            }
            other => panic!("expected bounded oversized response error, got {other:?}"),
        }
    }

    fn assert_local_signature_error(err: DagDbClientError, method: &str) {
        assert!(
            !matches!(
                err,
                DagDbClientError::Transport(_) | DagDbClientError::Timeout(_)
            ),
            "{method} should reject missing signatures before HTTP, got {err:?}"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains("signature"),
            "{method} should report missing signature material, got {rendered}"
        );
    }

    fn assert_scope_mismatch_error(err: DagDbClientError, method: &str) {
        assert!(
            !matches!(
                err,
                DagDbClientError::Transport(_) | DagDbClientError::Timeout(_)
            ),
            "{method} should reject tenant/namespace mismatch before HTTP, got {err:?}"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains("tenant") && rendered.contains("namespace"),
            "{method} should report tenant/namespace mismatch, got {rendered}"
        );
    }

    #[tokio::test]
    async fn unsigned_live_persistence_methods_fail_before_http_when_signatures_missing() {
        let client = DagDbHttpClient::new("http://127.0.0.1:9", auth()).expect("client");

        assert_local_signature_error(
            client
                .route(route_request())
                .await
                .expect_err("unsigned route must fail before HTTP"),
            "route",
        );
        assert_local_signature_error(
            client
                .context_packet(context_packet_request())
                .await
                .expect_err("unsigned context-packet must fail before HTTP"),
            "context_packet",
        );
        assert_local_signature_error(
            client
                .writeback(writeback_request())
                .await
                .expect_err("unsigned writeback must fail before HTTP"),
            "writeback",
        );
        assert_local_signature_error(
            client
                .dagdb_import(import_request())
                .await
                .expect_err("unsigned import must fail before HTTP"),
            "import",
        );
        assert_local_signature_error(
            client
                .dagdb_export(export_request())
                .await
                .expect_err("unsigned export must fail before HTTP"),
            "export",
        );
    }

    #[tokio::test]
    async fn incomplete_route_specific_signature_sets_fail_before_http() {
        let client = DagDbHttpClient::new("http://127.0.0.1:9", auth()).expect("client");

        assert_local_signature_error(
            client
                .route_with_signatures(route_request(), write_signature())
                .await
                .expect_err("route must require external approval signature material"),
            "route",
        );
        assert_local_signature_error(
            client
                .context_packet_with_signatures(context_packet_request(), write_signature())
                .await
                .expect_err("context-packet must require approval signature material"),
            "context_packet",
        );
        assert_local_signature_error(
            client
                .writeback_with_signatures(writeback_request(), write_signature())
                .await
                .expect_err("writeback must require lifecycle and continuation material"),
            "writeback",
        );
    }

    #[tokio::test]
    async fn import_export_require_independent_finality_signature_sets_before_http() {
        let client = DagDbHttpClient::new("http://127.0.0.1:9", auth()).expect("client");

        assert_local_signature_error(
            client
                .dagdb_import_with_signatures(import_request(), write_signature())
                .await
                .expect_err("import must require independent finality headers before HTTP"),
            "import",
        );
        assert_local_signature_error(
            client
                .dagdb_export_with_signatures(export_request(), write_signature())
                .await
                .expect_err("export must require independent finality headers before HTTP"),
            "export",
        );
    }

    #[tokio::test]
    async fn writeback_missing_approval_timestamps_fails_before_http() {
        let client = DagDbHttpClient::new("http://127.0.0.1:9", auth()).expect("client");

        assert_local_signature_error(
            client
                .writeback_with_signatures(
                    writeback_request(),
                    DagDbSignatureHeaders::writeback(
                        signature_value('a'),
                        signature_value('b'),
                        signature_value('c'),
                        "did:exo:finality-authority",
                        "did:exo:finality-authority",
                        "",
                        "2026-06-20T00:00:01Z",
                    ),
                )
                .await
                .expect_err("writeback must require lifecycle approval timestamp"),
            "writeback",
        );
    }

    #[tokio::test]
    async fn scoped_request_tenant_namespace_mismatch_fails_before_http() {
        let client = DagDbHttpClient::new("http://127.0.0.1:9", auth()).expect("client");

        let mut route = route_request();
        route.tenant_id = "tenant-b".to_owned();
        assert_scope_mismatch_error(
            client
                .route_with_signatures(route, route_signatures())
                .await
                .expect_err("route tenant mismatch must fail before HTTP"),
            "route",
        );

        let mut context_packet = context_packet_request();
        context_packet.namespace = "secondary".to_owned();
        assert_scope_mismatch_error(
            client
                .context_packet_with_signatures(context_packet, context_packet_signatures())
                .await
                .expect_err("context-packet namespace mismatch must fail before HTTP"),
            "context_packet",
        );

        let mut writeback = writeback_request();
        writeback.tenant_id = "tenant-b".to_owned();
        assert_scope_mismatch_error(
            client
                .writeback_with_signatures(writeback, writeback_signatures())
                .await
                .expect_err("writeback tenant mismatch must fail before HTTP"),
            "writeback",
        );

        let mut import = import_request();
        import.namespace = "secondary".to_owned();
        assert_scope_mismatch_error(
            client
                .dagdb_import_with_signatures(import, write_signature())
                .await
                .expect_err("import namespace mismatch must fail before HTTP"),
            "import",
        );

        let mut export = export_request();
        export.tenant_id = "tenant-b".to_owned();
        assert_scope_mismatch_error(
            client
                .dagdb_export_with_signatures(export, write_signature())
                .await
                .expect_err("export tenant mismatch must fail before HTTP"),
            "export",
        );
    }

    // (a) A POST builds the correct path + all four auth headers with the
    // correct `{action}:{tenant}:{namespace}` scope.
    #[tokio::test]
    async fn post_attaches_path_and_four_auth_headers_with_scope() {
        let body = fixture_response("responses", "route");
        let server = TestServer::spawn("200 OK", body).await;
        let client =
            DagDbHttpClient::new(format!("{}///", server.base_url), auth()).expect("client");

        let _ = client
            .route_with_signatures(route_request(), route_signatures())
            .await;
        let request = server.captured().await;

        assert!(
            request
                .request_line
                .starts_with("POST /api/v1/dag-db/route "),
            "request line was {:?}",
            request.request_line
        );
        assert_eq!(
            request.header("authorization"),
            Some("Bearer super-secret-token-value")
        );
        assert_eq!(request.header("x-exo-tenant-id"), Some("tenant-a"));
        assert_eq!(request.header("x-exo-namespace"), Some("primary"));
        assert_eq!(
            request.header("x-exo-authority-scope"),
            Some("dagdb:route:tenant-a:primary")
        );
        assert!(
            request
                .body
                .contains("\"idempotency_key\":\"idem-route-1\""),
            "body was {}",
            request.body
        );
    }

    #[tokio::test]
    async fn typed_methods_use_route_specific_paths_and_scopes() {
        macro_rules! assert_post_route {
            ($method:ident, $fixture:literal, $path:literal, $scope:literal, $signatures:expr) => {{
                let body = fixture_response("responses", $fixture);
                let server = TestServer::spawn("200 OK", body).await;
                let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

                let _ = client
                    .$method(fixture_request($fixture), $signatures)
                    .await
                    .expect("route response");
                let request = server.captured().await;

                assert!(
                    request
                        .request_line
                        .starts_with(concat!("POST ", $path, " ")),
                    "request line was {:?}",
                    request.request_line
                );
                assert_eq!(request.header("x-exo-authority-scope"), Some($scope));
                assert!(!request.body.is_empty(), "POST body should not be empty");
            }};
        }

        assert_post_route!(
            intake_with_signatures,
            "intake",
            "/api/v1/dag-db/intake",
            "dagdb:intake:tenant-a:primary",
            write_signature()
        );
        assert_post_route!(
            route_with_signatures,
            "route",
            "/api/v1/dag-db/route",
            "dagdb:route:tenant-a:primary",
            route_signatures()
        );
        assert_post_route!(
            context_packet_with_signatures,
            "context_packet",
            "/api/v1/dag-db/context-packet",
            "dagdb:context_packet:tenant-a:primary",
            context_packet_signatures()
        );
        assert_post_route!(
            validate_with_signatures,
            "validate",
            "/api/v1/dag-db/validate",
            "dagdb:validate:tenant-a:primary",
            write_signature()
        );
        assert_post_route!(
            writeback_with_signatures,
            "writeback",
            "/api/v1/dag-db/writeback",
            "dagdb:writeback:tenant-a:primary",
            writeback_signatures()
        );
        assert_post_route!(
            trust_check_with_signatures,
            "trust_check",
            "/api/v1/dag-db/trust-check",
            "dagdb:trust_check:tenant-a:primary",
            write_signature()
        );
        assert_post_route!(
            council_decision_with_signatures,
            "council_decision",
            "/api/v1/dag-db/council/decision",
            "dagdb:council_decision:tenant-a:primary",
            write_signature()
        );

        macro_rules! assert_get_route {
            ($method:ident, $request:expr, $fixture:literal, $path_prefix:literal, $scope:literal) => {{
                let body = fixture_response("responses", $fixture);
                let server = TestServer::spawn("200 OK", body).await;
                let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

                let _ = client.$method($request).await.expect("lookup response");
                let request = server.captured().await;

                assert!(
                    request
                        .request_line
                        .starts_with(concat!("GET ", $path_prefix)),
                    "request line was {:?}",
                    request.request_line
                );
                assert_eq!(request.header("x-exo-authority-scope"), Some($scope));
                assert!(request.body.is_empty(), "GET body should be empty");
            }};
        }

        assert_get_route!(
            receipt_lookup,
            receipt_lookup_request(),
            "receipt_lookup",
            "/api/v1/dag-db/receipts/",
            "dagdb:receipt_lookup:tenant-a:primary"
        );
        assert_get_route!(
            catalog_lookup,
            catalog_lookup_request(),
            "catalog_lookup",
            "/api/v1/dag-db/catalog/",
            "dagdb:catalog_lookup:tenant-a:primary"
        );
        assert_get_route!(
            route_lookup,
            route_lookup_request(),
            "route_lookup",
            "/api/v1/dag-db/routes/",
            "dagdb:route_lookup:tenant-a:primary"
        );
    }

    #[tokio::test]
    async fn dagdb_lookup_http_targets_preserve_components_without_target_injection() {
        macro_rules! assert_lookup_target {
            ($method:ident, $request:expr, $fixture:literal, $collection:literal, $flags:literal) => {{
                let body = fixture_response("responses", $fixture);
                let server = TestServer::spawn("200 OK", body).await;
                let auth = DagDbAuthConfig::new(
                    "super-secret-token-value",
                    ADVERSARIAL_QUERY_COMPONENT,
                    ADVERSARIAL_QUERY_COMPONENT,
                );
                let client = DagDbHttpClient::new(&server.base_url, auth).expect("client");

                let _ = client.$method($request).await.expect("lookup response");
                let request = server.captured().await;
                let expected = format!(
                    "GET /api/v1/dag-db/{collection}/{ENCODED_ADVERSARIAL_PATH_COMPONENT}\
                     ?tenant_id={query}&namespace={query}{flags} HTTP/1.1",
                    collection = $collection,
                    query = ENCODED_ADVERSARIAL_QUERY_COMPONENT,
                    flags = $flags,
                );
                assert_eq!(request.request_line, expected);
                assert_eq!(
                    request.header("x-exo-tenant-id"),
                    Some(ADVERSARIAL_QUERY_COMPONENT)
                );
                assert!(request.body.is_empty());
            }};
        }

        assert_lookup_target!(
            receipt_lookup,
            DagDbReceiptLookupRequest {
                receipt_hash: ADVERSARIAL_PATH_COMPONENT.to_owned(),
                tenant_id: ADVERSARIAL_QUERY_COMPONENT.to_owned(),
                namespace: ADVERSARIAL_QUERY_COMPONENT.to_owned(),
                include_body: Some(true),
            },
            "receipt_lookup",
            "receipts",
            "&include_body=true"
        );
        assert_lookup_target!(
            catalog_lookup,
            DagDbCatalogLookupRequest {
                catalog_id: ADVERSARIAL_PATH_COMPONENT.to_owned(),
                tenant_id: ADVERSARIAL_QUERY_COMPONENT.to_owned(),
                namespace: ADVERSARIAL_QUERY_COMPONENT.to_owned(),
                include_children: Some(true),
                include_routes: Some(false),
            },
            "catalog_lookup",
            "catalog",
            "&include_children=true&include_routes=false"
        );
        assert_lookup_target!(
            route_lookup,
            DagDbRouteLookupRequest {
                route_id: ADVERSARIAL_PATH_COMPONENT.to_owned(),
                tenant_id: ADVERSARIAL_QUERY_COMPONENT.to_owned(),
                namespace: ADVERSARIAL_QUERY_COMPONENT.to_owned(),
                include_memory_refs: Some(false),
                include_validation: Some(true),
            },
            "route_lookup",
            "routes",
            "&include_memory_refs=false&include_validation=true"
        );
    }

    #[tokio::test]
    async fn signed_writeback_attaches_all_gateway_signature_headers() {
        let body = fixture_response("responses", "writeback");
        let server = TestServer::spawn("200 OK", body).await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let _ = client
            .writeback_with_signatures(
                writeback_request(),
                DagDbSignatureHeaders::writeback(
                    signature_value('a'),
                    signature_value('b'),
                    signature_value('c'),
                    "did:exo:finality-authority",
                    "did:exo:finality-authority",
                    approval_timestamp(),
                    "2026-06-20T00:00:01Z",
                ),
            )
            .await;
        let request = server.captured().await;

        assert!(
            request
                .request_line
                .starts_with("POST /api/v1/dag-db/writeback "),
            "request line was {:?}",
            request.request_line
        );
        assert_eq!(
            request.header("x-exo-write-signature"),
            Some(signature_value('a').as_str())
        );
        assert_eq!(
            request.header("x-exo-lifecycle-signature"),
            Some(signature_value('b').as_str())
        );
        assert_eq!(
            request.header("x-exo-continuation-signature"),
            Some(signature_value('c').as_str())
        );
        assert_eq!(
            request.header("x-exo-lifecycle-approval-did"),
            Some("did:exo:finality-authority")
        );
        assert_eq!(
            request.header("x-exo-continuation-approval-did"),
            Some("did:exo:finality-authority")
        );
        assert_eq!(
            request.header("x-exo-lifecycle-approval-timestamp"),
            Some(approval_timestamp())
        );
        assert_eq!(
            request.header("x-exo-continuation-approval-timestamp"),
            Some("2026-06-20T00:00:01Z")
        );
    }

    #[tokio::test]
    async fn signed_route_attaches_default_route_approval_headers() {
        let body = fixture_response("responses", "route");
        let server = TestServer::spawn("200 OK", body).await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let _ = client
            .route_with_signatures(
                route_request(),
                DagDbSignatureHeaders::default_route(
                    signature_value('a'),
                    signature_value('b'),
                    "did:exo:route-authority",
                    approval_timestamp(),
                ),
            )
            .await;
        let request = server.captured().await;

        assert!(
            request
                .request_line
                .starts_with("POST /api/v1/dag-db/route "),
            "request line was {:?}",
            request.request_line
        );
        assert_eq!(
            request.header("x-exo-write-signature"),
            Some(signature_value('a').as_str())
        );
        assert_eq!(
            request.header("x-exo-default-route-approval-signature"),
            Some(signature_value('b').as_str())
        );
        assert_eq!(
            request.header("x-exo-default-route-approval-did"),
            Some("did:exo:route-authority")
        );
        assert_eq!(
            request.header("x-exo-default-route-approval-timestamp"),
            Some(approval_timestamp())
        );
        assert_eq!(
            request.header("x-exo-context-packet-approval-signature"),
            None
        );
        assert_eq!(request.header("x-exo-context-packet-approval-did"), None);
    }

    #[tokio::test]
    async fn signed_context_packet_attaches_write_and_approval_headers() {
        let body = fixture_response("responses", "context_packet");
        let server = TestServer::spawn("200 OK", body).await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let _ = client
            .context_packet_with_signatures(
                context_packet_request(),
                DagDbSignatureHeaders::context_packet(
                    signature_value('d'),
                    signature_value('e'),
                    "did:exo:context-authority",
                    approval_timestamp(),
                ),
            )
            .await;
        let request = server.captured().await;

        assert!(
            request
                .request_line
                .starts_with("POST /api/v1/dag-db/context-packet "),
            "request line was {:?}",
            request.request_line
        );
        assert_eq!(
            request.header("x-exo-write-signature"),
            Some(signature_value('d').as_str())
        );
        assert_eq!(
            request.header("x-exo-context-packet-approval-signature"),
            Some(signature_value('e').as_str())
        );
        assert_eq!(
            request.header("x-exo-context-packet-approval-did"),
            Some("did:exo:context-authority")
        );
        assert_eq!(
            request.header("x-exo-context-packet-approval-timestamp"),
            Some(approval_timestamp())
        );
        assert_eq!(
            request.header("x-exo-default-route-approval-signature"),
            None
        );
        assert_eq!(request.header("x-exo-default-route-approval-did"), None);
        assert_eq!(request.header("x-exo-lifecycle-signature"), None);
        assert_eq!(request.header("x-exo-continuation-signature"), None);
    }

    #[tokio::test]
    async fn signed_import_and_export_attach_write_signature_header() {
        for (response_fixture, path, scope, idempotency_key, call, approval_header) in [
            (
                "import",
                "/api/v1/dag-db/import",
                "dagdb:import:tenant-a:primary",
                "idem-import-1",
                0_u8,
                "x-exo-import-approval-signature",
            ),
            (
                "export",
                "/api/v1/dag-db/export",
                "dagdb:export:tenant-a:primary",
                "idem-export-1",
                1_u8,
                "x-exo-export-approval-signature",
            ),
        ] {
            let body = fixture_response("responses", response_fixture);
            let server = TestServer::spawn("200 OK", body).await;
            let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

            match call {
                0 => {
                    let _ = client
                        .dagdb_import_with_signatures(import_request(), import_signatures())
                        .await;
                }
                _ => {
                    let _ = client
                        .dagdb_export_with_signatures(export_request(), export_signatures())
                        .await;
                }
            }

            let request = server.captured().await;
            assert!(
                request.request_line.starts_with(&format!("POST {path} ")),
                "request line was {:?}",
                request.request_line
            );
            assert_eq!(request.header("x-exo-authority-scope"), Some(scope));
            assert!(request.header("x-exo-write-signature").is_some());
            assert_eq!(request.header("x-exo-lifecycle-signature"), None);
            assert_eq!(request.header("x-exo-continuation-signature"), None);
            assert!(request.header(approval_header).is_some());
            assert!(
                request
                    .body
                    .contains(&format!("\"idempotency_key\":\"{idempotency_key}\"")),
                "body was {}",
                request.body
            );
        }
    }

    // (b) A 2xx body deserializes into the right versioned DTO.
    #[tokio::test]
    async fn success_body_deserializes_into_versioned_dto() {
        let body = fixture_response("responses", "route");
        let server = TestServer::spawn("200 OK", body).await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let response = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect("2xx maps to DTO");
        assert_eq!(response.schema_version, "dagdb_route_response_v1");
        assert_eq!(response.tenant_id, "tenant-a");
        assert_eq!(response.idempotency_key, "idem-route-1");
    }

    #[tokio::test]
    async fn success_body_at_exact_response_limit_deserializes() {
        let body = padded_route_response(MAX_DAGDB_RESPONSE_BYTES);
        let server = TestServer::spawn("200 OK", body).await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let response = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect("exact-limit response maps to DTO");

        assert_eq!(response.schema_version, "dagdb_route_response_v1");
    }

    #[tokio::test]
    async fn chunked_body_without_content_length_at_limit_plus_one_is_rejected() {
        let body = padded_route_response(MAX_DAGDB_RESPONSE_BYTES + 1);
        let split = MAX_DAGDB_RESPONSE_BYTES;
        let raw = chunked_json_response(
            "200 OK",
            &[&body.as_bytes()[..split], &body.as_bytes()[split..]],
        );
        let server = TestServer::spawn_raw(raw).await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let err = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect_err("limit-plus-one chunked response must fail");

        assert_response_too_large(err, 200);
    }

    #[tokio::test]
    async fn chunked_body_without_content_length_within_limit_deserializes() {
        let body = fixture_response("responses", "route");
        let split = body.len() / 2;
        let raw = chunked_json_response(
            "200 OK",
            &[&body.as_bytes()[..split], &body.as_bytes()[split..]],
        );
        let server = TestServer::spawn_raw(raw).await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let response = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect("bounded chunked response maps to DTO");

        assert_eq!(response.schema_version, "dagdb_route_response_v1");
    }

    #[tokio::test]
    async fn dishonest_small_content_length_cannot_bypass_streamed_accounting() {
        let body = padded_route_response(MAX_DAGDB_RESPONSE_BYTES + 1).into_bytes();
        let mut raw_response = http::Response::new(reqwest::Body::from(body));
        raw_response.headers_mut().insert(
            reqwest::header::CONTENT_LENGTH,
            reqwest::header::HeaderValue::from_static("1"),
        );
        let response: reqwest::Response = raw_response.into();

        let err = read_bounded_response_body(response)
            .await
            .expect_err("dishonest Content-Length must not bypass actual byte accounting");

        assert_response_too_large(err, 200);
    }

    #[tokio::test]
    async fn dishonest_large_content_length_is_rejected_before_small_body_is_trusted() {
        let body = fixture_response("responses", "route");
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            MAX_DAGDB_RESPONSE_BYTES + 1
        )
        .into_bytes();
        let server = TestServer::spawn_raw(raw).await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let err = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect_err("oversized Content-Length must fail closed");

        assert_response_too_large(err, 200);
    }

    #[tokio::test]
    async fn malformed_success_body_maps_to_decode_error() {
        let server = TestServer::spawn("200 OK", "{\"schema_version\":").await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let err = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect_err("malformed 2xx body is an error");
        assert!(
            matches!(err, DagDbClientError::Decode(_)),
            "expected Decode, got {err:?}"
        );
    }

    // (c) A non-2xx body maps to the typed server error with error_code.
    #[tokio::test]
    async fn error_body_maps_to_typed_server_error() {
        let body = fixture_response("errors", "tenant_scope_mismatch");
        let server = TestServer::spawn("403 Forbidden", body).await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let err = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect_err("non-2xx is an error");
        match err {
            DagDbClientError::Server(server_err) => {
                assert_eq!(server_err.status, 403);
                assert_eq!(server_err.error_code, "tenant_scope_mismatch");
                assert_eq!(
                    server_err.message,
                    "tenant scope does not match authenticated identity"
                );
                assert_eq!(server_err.receipt_hash, None);
                assert_eq!(server_err.validation_report_id, None);
                assert!(!server_err.requires_council_review);
            }
            other => panic!("expected Server error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oversized_error_body_uses_the_same_bounded_stable_error() {
        let body = padded_route_response(MAX_DAGDB_RESPONSE_BYTES + 1);
        let raw = chunked_json_response("502 Bad Gateway", &[body.as_bytes()]);
        let server = TestServer::spawn_raw(raw).await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let err = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect_err("oversized non-2xx body must fail before parsing");

        assert_response_too_large(err, 502);
    }

    #[test]
    fn http_client_collects_bounded_bytes_before_json_deserialization() {
        assert_eq!(MAX_DAGDB_RESPONSE_BYTES, 1_048_576);
        let source = include_str!("dagdb.rs");
        let transport = source
            .split("mod transport {")
            .nth(1)
            .and_then(|section| {
                section
                    .split("#[cfg(all(test, feature = \"http-client\"))]")
                    .next()
            })
            .expect("transport production source");

        assert!(transport.contains("read_bounded_response_body(response).await"));
        assert!(!transport.contains("response.json().await"));
        assert!(!transport.contains("response.text().await"));
        assert!(!transport.contains("response.bytes().await"));
    }

    // (c') A non-2xx body that is NOT a valid envelope maps to UnexpectedStatus
    // carrying the raw body, never swallowed.
    #[tokio::test]
    async fn non_envelope_error_body_maps_to_unexpected_status() {
        let server = TestServer::spawn("502 Bad Gateway", "upstream exploded").await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let err = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect_err("non-2xx is an error");
        match err {
            DagDbClientError::UnexpectedStatus { status, body } => {
                assert_eq!(status, 502);
                assert_eq!(body, "upstream exploded");
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    // (d) A transport/timeout error maps to the Timeout variant.
    #[tokio::test]
    async fn timeout_maps_to_timeout_variant() {
        let base_url = TestServer::spawn_silent().await;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(150))
            .build()
            .expect("client with timeout");
        let client = DagDbHttpClient::with_client(&base_url, auth(), http);

        let err = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect_err("timeout is an error");
        assert!(
            matches!(err, DagDbClientError::Timeout(_)),
            "expected Timeout, got {err:?}"
        );
    }

    // (d') A connect failure (nothing listening) maps to the Transport variant.
    #[tokio::test]
    async fn connect_failure_maps_to_transport_variant() {
        // Reserve then drop a port so nothing is listening on it.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let client = DagDbHttpClient::new(format!("http://{addr}"), auth()).expect("client");

        let err = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect_err("connect failure is an error");
        assert!(
            matches!(err, DagDbClientError::Transport(_)),
            "expected Transport, got {err:?}"
        );
    }

    #[tokio::test]
    async fn invalid_auth_header_value_is_rejected_without_leaking_secret() {
        let auth = DagDbAuthConfig::new("super-secret-token-value\n", "tenant-a", "primary");
        let client = DagDbHttpClient::new("http://127.0.0.1:1", auth).expect("client");

        let err = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect_err("invalid auth header is rejected before send");
        match err {
            DagDbClientError::InvalidAuthHeader { header } => {
                assert_eq!(header, "authorization");
            }
            other => panic!("expected InvalidAuthHeader, got {other:?}"),
        }
        let rendered = format!("{err}");
        assert!(
            !rendered.contains("super-secret-token-value"),
            "auth error leaked token: {rendered}"
        );
    }

    #[tokio::test]
    async fn invalid_signature_header_value_is_rejected_without_leaking_secret() {
        let client = DagDbHttpClient::new("http://127.0.0.1:1", auth()).expect("client");

        let err = client
            .context_packet_with_signatures(
                context_packet_request(),
                DagDbSignatureHeaders::context_packet(
                    "signature-secret\nvalue",
                    signature_value('a'),
                    "did:exo:context-authority",
                    approval_timestamp(),
                ),
            )
            .await
            .expect_err("invalid signature header is rejected before send");
        match err {
            DagDbClientError::InvalidSignatureHeader { header } => {
                assert_eq!(header, "x-exo-write-signature");
            }
            other => panic!("expected InvalidSignatureHeader, got {other:?}"),
        }
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("signature-secret"),
            "signature error leaked signature: {rendered}"
        );
    }

    // (d'') A 2xx body whose schema_version mismatches the SDK constant is
    // surfaced, not silently accepted.
    #[tokio::test]
    async fn schema_version_mismatch_is_surfaced() {
        let mut route = fixtures()["responses"]["route"].clone();
        route["schema_version"] = serde_json::Value::String("dagdb_route_response_v999".to_owned());
        let body = route.to_string();
        let server = TestServer::spawn("200 OK", body).await;
        let client = DagDbHttpClient::new(&server.base_url, auth()).expect("client");

        let err = client
            .route_with_signatures(route_request(), route_signatures())
            .await
            .expect_err("mismatch is an error");
        match err {
            DagDbClientError::SchemaVersionMismatch { expected, actual } => {
                assert_eq!(expected, "dagdb_route_response_v1");
                assert_eq!(actual, "dagdb_route_response_v999");
            }
            other => panic!("expected SchemaVersionMismatch, got {other:?}"),
        }
    }

    // (e) The bearer token is never exposed through Debug.
    #[tokio::test]
    async fn bearer_token_is_redacted_in_debug() {
        let config = auth();
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("super-secret-token-value"),
            "auth config Debug leaked the token: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "expected redaction marker: {rendered}"
        );
    }

    #[tokio::test]
    async fn bearer_token_constructors_and_display_are_redacted() {
        let token = BearerToken::new("constructor-secret");
        let from_string: BearerToken = String::from("string-secret").into();

        assert_eq!(format!("{token}"), "<redacted>");
        assert_eq!(format!("{from_string}"), "<redacted>");
        assert_eq!(format!("{token:?}"), "BearerToken(<redacted>)");
        assert!(
            !format!("{from_string:?}").contains("string-secret"),
            "BearerToken Debug leaked string constructor value"
        );
    }

    #[tokio::test]
    async fn signature_headers_are_redacted_in_debug() {
        let signatures = DagDbSignatureHeaders::writeback(
            "write-signature-secret",
            "lifecycle-signature-secret",
            "continuation-signature-secret",
            "did:exo:lifecycle-finality",
            "did:exo:continuation-finality",
            "2026-06-20T00:00:00Z",
            "2026-06-20T00:00:01Z",
        );

        let rendered = format!("{signatures:?}");
        assert!(
            !rendered.contains("write-signature-secret"),
            "signature Debug leaked write signature: {rendered}"
        );
        assert!(
            !rendered.contains("lifecycle-signature-secret"),
            "signature Debug leaked lifecycle signature: {rendered}"
        );
        assert!(
            !rendered.contains("continuation-signature-secret"),
            "signature Debug leaked continuation signature: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "expected redaction marker: {rendered}"
        );
    }
}
