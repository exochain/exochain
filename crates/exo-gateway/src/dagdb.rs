//! Additive DAG DB gateway scaffolding and narrow council ingress.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};

use axum::{
    Json, Router,
    extract::{Extension, Path, Query, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, post},
};
// `ConsentPurpose` is consumed only by the production-db consent verification and
// the `#[cfg(debug_assertions)]` dev gatekeeper profile; gate it to those
// configurations to avoid an unused-import warning in a release build without
// `production-db`.
#[cfg(any(feature = "production-db", debug_assertions))]
use exo_api::dagdb::ConsentPurpose;
// `DagDbWritebackResponse` is constructed only by the production-db persisted
// writeback path and the `#[cfg(test)]` response-shape builder; gate the import
// to those configurations so the default build is unused-import clean.
#[cfg(any(test, feature = "production-db"))]
use exo_api::dagdb::{
    CatalogEntryResponse, CouncilDecisionStatus, CredentialStatus, DagDbCatalogLookupRequest,
    DagDbCatalogLookupResponse, DagDbCouncilDecisionResponse, DagDbIntakeResponse,
    DagDbReceiptLookupRequest, DagDbReceiptLookupResponse, DagDbRouteLookupRequest,
    DagDbRouteLookupResponse, DagDbRouteResponse, DagDbTrustCheckResponse, DagDbValidateResponse,
    DagDbWritebackResponse, ValidationDecision,
};
use exo_api::dagdb::{
    ContextPacketLayerBudgetReport, ContextPacketLayerEdgeRef, ContextPacketLayerRef,
    ContextPacketMemoryRef, CouncilReviewStatus, DagDbContextPacketRequest,
    DagDbContextPacketResponse, DagDbCouncilDecisionRequest, DagDbErrorEnvelope,
    DagDbExportRequest, DagDbImportRequest, DagDbIntakeRequest, DagDbRouteRequest,
    DagDbTrustCheckRequest, DagDbValidateRequest, DagDbWritebackRequest, DagFinalityStatus,
    RiskClass, RouteStatus, SafeMetadata, ValidationStatus,
};
#[cfg(feature = "production-db")]
use exo_api::dagdb::{DagDbExportResponse, DagDbImportResponse};
#[cfg(feature = "production-db")]
use exo_api::dagdb::{
    DagDbGraphContextPacketBuildRequest, DagDbGraphContextSelectionRequest,
    DagDbGraphContextSelectionResponse,
};
#[cfg(any(test, feature = "production-db"))]
use exo_api::dagdb::{ReceiptEventType, SubjectKind};
use exo_core::Hash256;
#[cfg(feature = "production-db")]
use exo_core::Timestamp;
use exo_dag_db_core::{
    hash::RequestHashMaterial,
    metadata::{MetadataField, sanitize_keywords, sanitize_runtime_metadata},
};
#[cfg(test)]
use exo_dag_db_domain::council::CouncilError;
#[cfg(feature = "production-db")]
use exo_dag_db_domain::scoring::DomainError;
#[cfg(feature = "production-db")]
use exo_dag_db_domain::{
    context_packet_persistence::{
        CONTEXT_PACKET_FINALITY_PURPOSE, ContextPacketAcceptanceEvidence, ContextPacketRecord,
        ContextPacketRequest, ContextPacketRouteBinding, DefaultContextQuality,
        PacketFreshnessStatus, PacketPersistenceStatus, PacketValidationStatus,
        accept_context_packet_record, build_context_packet_record,
        canonical_context_packet_approval_payload_hash,
    },
    continuation_persistence::{
        ContinuationRecord, ContinuationRetrievalStatus, PRD17_CONTINUATION_RECORD_SCHEMA,
    },
    default_route::{
        DEFAULT_ROUTE_FINALITY_PURPOSE, DEFAULT_ROUTE_SCHEMA_VERSION,
        DefaultRouteAcceptanceEvidence, DefaultRouteMemoryRef, DefaultRouteRecord,
        DefaultRouteSource, DefaultRouteStatus, RouteFreshnessStatus, accept_default_route_record,
        canonical_default_route_approval_payload_hash,
    },
    lifecycle_action::{
        CONTINUATION_FINALITY_PURPOSE, LifecycleAction, LifecycleActionType, LifecycleEvidenceRef,
        LifecycleMemoryRef, LifecycleRollbackRef, LifecycleTerminalState,
        PRD17_LIFECYCLE_ACTION_SCHEMA, PRODUCTION_LIFECYCLE_APPROVAL_EVIDENCE_PREFIX,
        ProductionLifecycleApproval, ProductionLifecycleApprovalEvidence,
        canonical_continuation_approval_payload_hash, canonical_lifecycle_approval_payload_hash,
    },
};
#[cfg(feature = "production-db")]
use exo_dag_db_exchange::{kg_export::KgExportError, kg_import::KgImportError};
use exo_dag_db_exchange::{kg_export::KgExportScope, kg_import::KgImportDryRunReport};
#[cfg(feature = "production-db")]
use exo_dag_db_postgres::{
    ReceiptHashMaterial,
    persistent_context::{
        PersistentGraphContextPacket, build_persistent_graph_context_selection,
        build_persistent_graph_context_selection_with_layered_drilldown,
    },
    postgres::{
        begin_tenant_transaction,
        kg_context_selection_write::{DbWriteSummary, UsageEventMemoryMetadata},
        kg_import::KgImportPersistenceError,
    },
};
// `DagDbConsentRecord`/`BailmentState` are consumed only by the production-db DB
// resolver and the `#[cfg(debug_assertions)]` dev gatekeeper profile; gate the
// import to those configurations so a release build without `production-db` does
// not warn on unused imports (T1 gated the dev profile out of release).
#[cfg(feature = "production-db")]
use exo_gatekeeper::invariants::InvariantContext;
use exo_gatekeeper::{ConsentEngine, IdentityRegistry};
#[cfg(any(feature = "production-db", debug_assertions))]
use exo_gatekeeper::{DagDbConsentRecord, types::BailmentState};
#[cfg(feature = "production-db")]
use exo_gatekeeper::{
    DagDbGatekeeperService, GatekeeperError,
    types::{DAGDB_WRITEBACK_SCOPE, GovernmentBranch, Role},
};
#[cfg(feature = "production-db")]
use exo_gatekeeper::{usage_event_payload_hash, verify_write_consent, verify_write_signature};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(feature = "production-db")]
use sqlx::{Postgres, Row, Transaction};
#[cfg(any(feature = "production-db", debug_assertions))]
use tracing::info;
use tracing::warn;

/// Public REST prefix reserved for ExoChain DAG DB.
pub const DAGDB_REST_PREFIX: &str = "/api/v1/dag-db";

const TENANT_HEADER: &str = "x-exo-tenant-id";
const NAMESPACE_HEADER: &str = "x-exo-namespace";
const AUTHORITY_SCOPE_HEADER: &str = "x-exo-authority-scope";
#[cfg(feature = "production-db")]
const WRITE_SIGNATURE_HEADER: &str = "x-exo-write-signature";
#[cfg(feature = "production-db")]
const DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER: &str = "x-exo-default-route-approval-signature";
#[cfg(feature = "production-db")]
const DEFAULT_ROUTE_APPROVAL_DID_HEADER: &str = "x-exo-default-route-approval-did";
#[cfg(feature = "production-db")]
const DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-default-route-approval-timestamp";
#[cfg(feature = "production-db")]
const CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER: &str = "x-exo-context-packet-approval-signature";
#[cfg(feature = "production-db")]
const CONTEXT_PACKET_APPROVAL_DID_HEADER: &str = "x-exo-context-packet-approval-did";
#[cfg(feature = "production-db")]
const CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-context-packet-approval-timestamp";
#[cfg(feature = "production-db")]
const LIFECYCLE_SIGNATURE_HEADER: &str = "x-exo-lifecycle-signature";
#[cfg(feature = "production-db")]
const CONTINUATION_SIGNATURE_HEADER: &str = "x-exo-continuation-signature";
#[cfg(feature = "production-db")]
const LIFECYCLE_APPROVAL_DID_HEADER: &str = "x-exo-lifecycle-approval-did";
#[cfg(feature = "production-db")]
const CONTINUATION_APPROVAL_DID_HEADER: &str = "x-exo-continuation-approval-did";
#[cfg(feature = "production-db")]
const LIFECYCLE_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-lifecycle-approval-timestamp";
#[cfg(feature = "production-db")]
const CONTINUATION_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-continuation-approval-timestamp";
#[cfg(feature = "production-db")]
const WRITEBACK_CONTINUATION_EXPIRY_EPOCH_SECONDS: u64 = 4_102_444_800;
#[cfg(feature = "production-db")]
const INTAKE_ROUTE_IDEMPOTENCY_NAME: &str = "dagdb.intake";
#[cfg(feature = "production-db")]
const VALIDATE_ROUTE_IDEMPOTENCY_NAME: &str = "dagdb.validate";
#[cfg(feature = "production-db")]
const TRUST_CHECK_ROUTE_IDEMPOTENCY_NAME: &str = "dagdb.trust_check";
#[cfg(feature = "production-db")]
const COUNCIL_DECISION_ROUTE_IDEMPOTENCY_NAME: &str = "dagdb.council_decision";
#[cfg(feature = "production-db")]
const IMPORT_ROUTE_IDEMPOTENCY_NAME: &str = "dagdb.import";
#[cfg(feature = "production-db")]
const EXPORT_ROUTE_IDEMPOTENCY_NAME: &str = "dagdb.export";
#[cfg(feature = "production-db")]
const IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER: &str = "x-exo-import-approval-signature";
#[cfg(feature = "production-db")]
const IMPORT_FINALITY_APPROVAL_DID_HEADER: &str = "x-exo-import-approval-did";
#[cfg(feature = "production-db")]
const IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-import-approval-timestamp";
#[cfg(feature = "production-db")]
const EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER: &str = "x-exo-export-approval-signature";
#[cfg(feature = "production-db")]
const EXPORT_FINALITY_APPROVAL_DID_HEADER: &str = "x-exo-export-approval-did";
#[cfg(feature = "production-db")]
const EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER: &str = "x-exo-export-approval-timestamp";
#[cfg(feature = "production-db")]
const RESERVED_IDEMPOTENCY_BODY_STATUS: &str = "reserved";
#[cfg(feature = "production-db")]
const STORED_IDEMPOTENCY_BODY_STATUS: &str = "stored";
#[cfg(feature = "production-db")]
const REPLAYED_IDEMPOTENCY_BODY_STATUS: &str = "replayed";
#[cfg(feature = "production-db")]
const GATEWAY_IDEMPOTENCY_RESERVATION_TTL_MS: i64 = 86_400_000;
#[cfg(feature = "production-db")]
const GATEWAY_AUTHORIZATION_PAYLOAD_HASH_FIELD: &str = "_gateway_authorization_payload_hash";
const GATEWAY_OPERATIONAL_AUDIT_ACTOR: &str = "did:exo:dagdb-gateway";
#[cfg(feature = "production-db")]
const GATEWAY_OPERATIONAL_AUDIT_SOURCE: &str = "dagdb_gateway_mounted_route";
/// Environment variable that enables the repository local-dev gatekeeper profile.
///
/// Only consulted by the `#[cfg(debug_assertions)]` dev-profile mount; the
/// constant itself is retained unconditionally so the binary and tooling can
/// name it, but a release build never reads it because the mount is compiled out.
pub const LOCAL_DEV_GATEKEEPER_ENV: &str = "DAGDB_LOCAL_DEV_GATEKEEPER";
#[cfg(debug_assertions)]
const LOCAL_DEV_AGENT_DID: &str = "did:exo:cursor-mcp-agent";
// Canonical local-dev tenant/namespace sourced from the single DAG DB constant
// so the gateway can never diverge from the runtime's tenant identity (GAP-012
// P1-E).
#[cfg(debug_assertions)]
const LOCAL_DEV_TENANT_ID: &str = exo_dag_db_core::tenant::LOCAL_DEV_TENANT_ID;
#[cfg(debug_assertions)]
const LOCAL_DEV_NAMESPACE: &str = exo_dag_db_core::tenant::LOCAL_DEV_NAMESPACE;
#[cfg_attr(not(any(test, feature = "production-db")), allow(dead_code))]
const DAGDB_LAYERED_MODES: &[&str] = &["off", "auto", "required"];
#[cfg_attr(not(any(test, feature = "production-db")), allow(dead_code))]
const DAGDB_MAX_LAYER_DEPTH: u32 = 8;
// D1-S4 gateway bound for the depth-on-demand reserve, in basis points. Mirrors
// the runtime's `LAYERED_DRILLDOWN_MAX_RESERVE_BP` (the breadth pass always keeps
// a majority share). Defined locally so the validator compiles without the
// production-db feature, which gates the exo-dag-db import.
// Consumed only by `validate_drilldown_reserve_bp`, itself reached solely from
// the production-db persisted context-packet path, so gate it identically.
#[cfg(feature = "production-db")]
const DAGDB_MAX_DRILLDOWN_RESERVE_BP: u32 = 5_000;
/// Allowed typed-knowledge classes for a writeback. The list is closed: any
/// other value is rejected (fail closed). The class describes WHAT the memory
/// is; it never influences deterministic placement/organization.
const DAGDB_KNOWLEDGE_CLASSES: &[&str] = &["decision", "finding", "fix", "constraint", "handoff"];
#[cfg(feature = "production-db")]
const DAGDB_WRITEBACK_SIGNED_TASK_HASH_DOMAIN: &str =
    "exo.dagdb.gateway.writeback.signed_task_hash.v2";
#[cfg(debug_assertions)]
const LOCAL_DEV_KEY_SEED_REL: &str = "crates/exo-gatekeeper/tests/fixtures/dev_private_key.seed";
#[cfg(debug_assertions)]
const LOCAL_DEV_KEY_SOURCE_EXPLICIT_SEED: &str = "explicit_seed_file";
#[cfg(debug_assertions)]
const LOCAL_DEV_KEY_SOURCE_DETERMINISTIC_FALLBACK: &str = "deterministic_local_dev_fallback";

type QueryParams = BTreeMap<String, String>;

/// Route-scoped DAG DB dependencies injected by the gateway server merge.
#[derive(Clone)]
pub struct DagDbRouteContext {
    pub pool: Option<sqlx::PgPool>,
    /// Explicitly-installed in-memory gatekeeper profile.
    ///
    /// `None` is the default production posture: the write gate hydrates its
    /// consent/identity state from the live database per request (see
    /// [`resolve_gatekeeper_service_from_db`]). A `Some(_)` profile is installed
    /// ONLY by integration tests (`install_gatekeeper_profile`) or the explicit
    /// repository dev profile (`install_local_dev_gatekeeper_profile`, gated on
    /// `DAGDB_LOCAL_DEV_GATEKEEPER`); when present it overrides the DB resolver.
    /// Ticket T1 will gate/remove the dev fallback.
    gatekeeper: Arc<RwLock<Option<DagDbGatekeeperProfile>>>,
}

#[derive(Clone)]
struct DagDbGatekeeperProfile {
    // Constructed in every build (the dev/test profile installer compiles in the
    // default build) but read only on the production-db gatekeeper_service path;
    // suppress the not-read warning without gating the field, which would split
    // its constructor across configs.
    #[cfg_attr(not(feature = "production-db"), allow(dead_code))]
    consent_engine: Arc<ConsentEngine>,
    #[cfg_attr(not(feature = "production-db"), allow(dead_code))]
    identity_registry: Arc<IdentityRegistry>,
}

impl DagDbRouteContext {
    /// Build route context from the gateway application pool.
    #[must_use]
    pub fn from_pool(pool: Option<sqlx::PgPool>) -> Self {
        Self {
            pool,
            gatekeeper: Arc::new(RwLock::new(None)),
        }
    }

    /// Install in-memory consent and identity registries for integration tests.
    pub fn install_gatekeeper_profile(
        &self,
        consent_engine: ConsentEngine,
        identity_registry: IdentityRegistry,
    ) {
        if let Ok(mut profile) = self.gatekeeper.write() {
            *profile = Some(DagDbGatekeeperProfile {
                consent_engine: Arc::new(consent_engine),
                identity_registry: Arc::new(identity_registry),
            });
        }
    }

    /// Install local-dev consent and identity for repository MCP writeback dogfood.
    ///
    /// Gated on `#[cfg(debug_assertions)]` so it is never compiled into a release
    /// binary (T1). In release the write gate reaches `gatekeeper_service` with
    /// no installed profile and authorizes only via the live DB resolver
    /// (`resolve_gatekeeper_service_from_db`) or fails closed; there is no
    /// fabricated dev identity in the shipping path.
    #[cfg(debug_assertions)]
    pub fn install_local_dev_gatekeeper_profile(&self) {
        self.install_local_dev_gatekeeper_profile_from_seed_path(&local_dev_key_seed_path());
    }

    #[cfg(debug_assertions)]
    fn install_local_dev_gatekeeper_profile_from_seed_path(&self, seed_path: &str) {
        let Ok(local_keypair) = load_local_dev_keypair_from_seed_path(seed_path) else {
            return;
        };
        let keypair = local_keypair.keypair;
        let Ok(bailor) = exo_core::Did::new("did:exo:local-dev-bailor")
            .or_else(|_| exo_core::Did::new("did:exo:bailor"))
        else {
            return;
        };
        let bailee = exo_core::Did::new(LOCAL_DEV_AGENT_DID).unwrap_or_else(|_| bailor.clone());
        let consent_engine = ConsentEngine::default()
            .with_bailment(
                LOCAL_DEV_TENANT_ID,
                BailmentState::Active {
                    bailor,
                    bailee,
                    scope: "dag-db:writeback".into(),
                },
            )
            .with_consent_record(DagDbConsentRecord {
                tenant_id: LOCAL_DEV_TENANT_ID.to_owned(),
                agent_did: LOCAL_DEV_AGENT_DID.to_owned(),
                purpose: ConsentPurpose::Writeback,
                active: true,
            });
        let identity_registry = IdentityRegistry::default()
            .with_public_key(LOCAL_DEV_AGENT_DID, *keypair.public_key().as_bytes());
        self.install_gatekeeper_profile(consent_engine, identity_registry);
        info!(
            tenant_id = LOCAL_DEV_TENANT_ID,
            namespace = LOCAL_DEV_NAMESPACE,
            agent_did = LOCAL_DEV_AGENT_DID,
            key_source = local_keypair.source,
            "Installed local dev DAG DB gatekeeper profile"
        );
    }

    /// Snapshot the explicitly-installed gatekeeper profile, if any.
    ///
    /// Returns `None` both when no profile was installed AND when the lock is
    /// poisoned. A poisoned lock is treated as "no installed profile" so the
    /// caller falls through to the DB resolver (fail-closed real authorization)
    /// rather than to a silently-empty default that would deny-all and mask the
    /// fault. This replaces the prior `.unwrap_or_default()` poisoned-lock
    /// silent-empty fallback.
    #[cfg(feature = "production-db")]
    fn installed_gatekeeper_profile(&self) -> Option<DagDbGatekeeperProfile> {
        self.gatekeeper.read().ok().and_then(|guard| guard.clone())
    }

    /// Resolve the gatekeeper service that authorizes a single write.
    ///
    /// When an in-memory profile is explicitly installed (integration tests or
    /// the gated repository dev profile) it is used directly. Otherwise — the
    /// default production posture — the service is hydrated from live database
    /// state for `(agent_did, tenant_id)` via [`resolve_gatekeeper_service_from_db`].
    ///
    /// Fails closed with [`GatekeeperError::AuthorityResolverUnavailable`] when
    /// the DB resolver cannot establish authorization state (query failure). It
    /// NEVER falls back to empty registries.
    #[cfg(feature = "production-db")]
    async fn gatekeeper_service(
        &self,
        pool: &sqlx::PgPool,
        agent_did: &str,
        tenant_id: &str,
        namespace: &str,
        extra_identity_dids: &[&str],
    ) -> Result<DagDbGatekeeperService, GatekeeperError> {
        if let Some(profile) = self.installed_gatekeeper_profile() {
            return Ok(DagDbGatekeeperService::new(
                pool.clone(),
                profile.consent_engine,
                profile.identity_registry,
            ));
        }
        resolve_gatekeeper_service_from_db(
            pool,
            agent_did,
            tenant_id,
            namespace,
            extra_identity_dids,
        )
        .await
    }
}

/// Hydrate a [`DagDbGatekeeperService`] from live ExoChain consent/identity
/// database state for a single `(agent_did, tenant_id)` write authorization.
///
/// This is the default production authority resolver: it translates the
/// gateway-owned, DB-backed `consent_records` rows and the agent's DID document
/// into the gate's in-memory [`ConsentEngine`]/[`IdentityRegistry`] shapes. The
/// row→gate-type translation lives here in the gateway crate so `exo-gatekeeper`
/// stays database-free.
///
/// ## Tenant-qualified scope convention
///
/// `consent_records` has no tenant column, so the tenant is encoded into the
/// existing `scope` string. A writeback grant for `tenant_id` is stored as
/// [`tenant_writeback_scope`]'s `dag-db:writeback:{tenant_id}`. The resolver
/// filters the loaded rows on that exact scope string, so a grant scoped to a
/// different tenant cannot authorize this tenant's writeback. Import/export
/// grants include the namespace as `dag-db:import:{tenant_id}:{namespace}` and
/// `dag-db:export:{tenant_id}:{namespace}`. The gate's own bailment uses the
/// canonical [`DAGDB_WRITEBACK_SCOPE`] (`dag-db:writeback`), which is what
/// `BailmentState::authorizes_writeback` checks; tenant/namespace qualification
/// is enforced by the row filter, not the bailment scope.
///
/// ## Fail-closed contract
///
/// Returns [`GatekeeperError::AuthorityResolverUnavailable`] when a database
/// query fails (consent load, trusted-clock lookup, or DID-document lookup) or
/// when a registered DID document carries no trustable Ed25519 key. It never
/// returns a service backed by empty registries on error — an empty registry
/// silently denies-all and masks misconfiguration, so it is reserved for the
/// genuinely-unregistered agent (no rows), which then fails closed inside the
/// gate's consent/provenance checks with a policy denial.
#[cfg(feature = "production-db")]
async fn resolve_gatekeeper_service_from_db(
    pool: &sqlx::PgPool,
    agent_did: &str,
    tenant_id: &str,
    namespace: &str,
    extra_identity_dids: &[&str],
) -> Result<DagDbGatekeeperService, GatekeeperError> {
    let now_ms = trusted_resolver_epoch_ms(pool).await?;
    let expected_writeback_scope = tenant_writeback_scope(tenant_id);
    let expected_import_scope = tenant_namespace_consent_scope("import", tenant_id, namespace);
    let expected_export_scope = tenant_namespace_consent_scope("export", tenant_id, namespace);

    let mut consent_engine = ConsentEngine::default();
    let consent_rows = crate::db::load_consent_records(pool, agent_did, now_ms)
        .await
        .map_err(|error| {
            GatekeeperError::AuthorityResolverUnavailable(format!(
                "consent records lookup failed: {error}"
            ))
        })?;
    for row in consent_rows {
        let purpose = if row.scope == expected_writeback_scope {
            ConsentPurpose::Writeback
        } else if row.scope == expected_import_scope {
            ConsentPurpose::Import
        } else if row.scope == expected_export_scope {
            ConsentPurpose::Export
        } else {
            continue;
        };
        // The bailor (subject) entrusts the acting agent (bailee) with the
        // canonical writeback scope. `authorizes_writeback` checks the bailee
        // equals the agent and the scope equals `DAGDB_WRITEBACK_SCOPE`; the
        // tenant/namespace qualification has already been enforced by the row
        // filter above.
        let Ok(bailor) = exo_core::Did::new(&row.subject_did) else {
            continue;
        };
        let Ok(bailee) = exo_core::Did::new(agent_did) else {
            continue;
        };
        consent_engine = consent_engine
            .with_bailment(
                tenant_id,
                BailmentState::Active {
                    bailor,
                    bailee,
                    scope: DAGDB_WRITEBACK_SCOPE.to_owned(),
                },
            )
            .with_consent_record(DagDbConsentRecord {
                tenant_id: tenant_id.to_owned(),
                agent_did: agent_did.to_owned(),
                purpose,
                active: true,
            });
    }

    let mut identity_registry = IdentityRegistry::default();
    let mut identity_dids = BTreeSet::new();
    identity_dids.insert(agent_did.to_owned());
    for did in extra_identity_dids {
        if !did.is_empty() {
            identity_dids.insert((*did).to_owned());
        }
    }
    for identity_did in identity_dids {
        if let Some(doc) = crate::db::find_did_document(pool, &identity_did)
            .await
            .map_err(|error| {
                GatekeeperError::AuthorityResolverUnavailable(format!(
                    "DID document lookup failed: {error}"
                ))
            })?
        {
            let keys =
                crate::server::active_did_document_ed25519_keys(&doc, "dag-db writeback authority")
                    .map_err(|error| {
                        GatekeeperError::AuthorityResolverUnavailable(format!(
                            "DID document key validation failed: {error}"
                        ))
                    })?;
            for key in keys {
                let Ok(key_bytes) = <[u8; 32]>::try_from(key.as_slice()) else {
                    continue;
                };
                identity_registry = identity_registry.with_public_key(&identity_did, key_bytes);
            }
        }
        identity_registry =
            register_governed_roles_from_db(identity_registry, pool, &identity_did, now_ms).await?;
    }

    Ok(DagDbGatekeeperService::new(
        pool.clone(),
        Arc::new(consent_engine),
        Arc::new(identity_registry),
    ))
}

#[cfg(feature = "production-db")]
async fn register_governed_roles_from_db(
    mut identity_registry: IdentityRegistry,
    pool: &sqlx::PgPool,
    identity_did: &str,
    now_ms: i64,
) -> Result<IdentityRegistry, GatekeeperError> {
    let role_rows = crate::db::load_agent_roles(pool, identity_did, now_ms)
        .await
        .map_err(|error| {
            GatekeeperError::AuthorityResolverUnavailable(format!(
                "agent role lookup failed: {error}"
            ))
        })?;
    for row in role_rows {
        let branch = gateway_government_branch(&row.branch)?;
        let role = Role::try_new(row.role, branch).map_err(|error| {
            GatekeeperError::AuthorityResolverUnavailable(format!(
                "agent role validation failed: {error}"
            ))
        })?;
        identity_registry = identity_registry.with_role(identity_did, role);
    }
    Ok(identity_registry)
}

#[cfg(feature = "production-db")]
fn gateway_government_branch(branch: &str) -> Result<GovernmentBranch, GatekeeperError> {
    match branch {
        "executive" => Ok(GovernmentBranch::Executive),
        "legislative" => Ok(GovernmentBranch::Legislative),
        "judicial" => Ok(GovernmentBranch::Judicial),
        _ => Err(GatekeeperError::AuthorityResolverUnavailable(
            "agent role branch is not governed".to_owned(),
        )),
    }
}

/// Canonical tenant-qualified DAG DB writeback scope string used as the
/// `consent_records.scope` filter value.
///
/// `consent_records` has no tenant column; the tenant is encoded into the scope
/// so a grant cannot be replayed across tenants. Built from the gate's canonical
/// [`DAGDB_WRITEBACK_SCOPE`] (`dag-db:writeback`) as `dag-db:writeback:{tenant_id}`.
#[cfg(feature = "production-db")]
fn tenant_writeback_scope(tenant_id: &str) -> String {
    format!("{DAGDB_WRITEBACK_SCOPE}:{tenant_id}")
}

#[cfg(feature = "production-db")]
fn tenant_namespace_consent_scope(operation: &str, tenant_id: &str, namespace: &str) -> String {
    format!("dag-db:{operation}:{tenant_id}:{namespace}")
}

/// Trusted current-time milliseconds from the database clock for the resolver's
/// active/non-expired consent filter. Never caller time; fails closed on error.
#[cfg(feature = "production-db")]
async fn trusted_resolver_epoch_ms(pool: &sqlx::PgPool) -> Result<i64, GatekeeperError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| {
        GatekeeperError::AuthorityResolverUnavailable(format!(
            "resolver clock lookup failed: {error}"
        ))
    })
}

static ROUTE_CONTEXT_OVERRIDE: std::sync::OnceLock<Arc<DagDbRouteContext>> =
    std::sync::OnceLock::new();

/// Override the route context used by DAG DB handlers (integration tests only).
pub fn set_route_context_for_integration_tests(ctx: Arc<DagDbRouteContext>) {
    let _ = ROUTE_CONTEXT_OVERRIDE.set(ctx);
}

fn resolve_route_context(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
) -> Arc<DagDbRouteContext> {
    if let Some(ctx) = ROUTE_CONTEXT_OVERRIDE.get() {
        return ctx.clone();
    }
    extension
        .map(|Extension(ctx)| ctx)
        .unwrap_or_else(|| Arc::new(DagDbRouteContext::from_pool(None)))
}

/// Build the additive public ExoChain DAG DB router.
pub fn dagdb_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let routes: [(&str, MethodRouter<S>); 12] = [
        ("/api/v1/dag-db/intake", post(handle_dagdb_intake)),
        ("/api/v1/dag-db/route", post(handle_dagdb_route)),
        (
            "/api/v1/dag-db/context-packet",
            post(handle_dagdb_context_packet),
        ),
        ("/api/v1/dag-db/validate", post(handle_dagdb_validate)),
        ("/api/v1/dag-db/writeback", post(handle_dagdb_writeback)),
        ("/api/v1/dag-db/import", post(handle_dagdb_import)),
        ("/api/v1/dag-db/export", post(handle_dagdb_export)),
        ("/api/v1/dag-db/trust-check", post(handle_dagdb_trust_check)),
        (
            "/api/v1/dag-db/council/decision",
            post(handle_dagdb_council_decision),
        ),
        (
            "/api/v1/dag-db/receipts/:receipt_hash",
            get(handle_dagdb_receipt_lookup),
        ),
        (
            "/api/v1/dag-db/catalog/:catalog_id",
            get(handle_dagdb_catalog_lookup),
        ),
        (
            "/api/v1/dag-db/routes/:route_id",
            get(handle_dagdb_route_lookup),
        ),
    ];
    routes
        .into_iter()
        .fold(Router::new(), |router, (path, route)| {
            router.route(path, route)
        })
}

async fn handle_dagdb_intake(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    Json(request): Json<DagDbIntakeRequest>,
) -> Response {
    if let Some(denied) = verify_dagdb_authority(
        &headers,
        &request.tenant_id,
        &request.namespace,
        "dagdb:intake",
    ) {
        return denied;
    }
    let ctx = resolve_route_context(extension);
    #[cfg(feature = "production-db")]
    if let Err(denied) =
        verify_dagdb_session_authority(&ctx, &headers, "dagdb.intake", &request.tenant_id).await
    {
        return denied;
    }
    intake_handler(&ctx, request).await
}

async fn handle_dagdb_route(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    Json(request): Json<DagDbRouteRequest>,
) -> Response {
    if let Some(denied) = verify_dagdb_authority(
        &headers,
        &request.tenant_id,
        &request.namespace,
        "dagdb:route",
    ) {
        return denied;
    }
    let ctx = resolve_route_context(extension);
    #[cfg(feature = "production-db")]
    if let Err(denied) =
        verify_dagdb_session_authority(&ctx, &headers, "dagdb.route", &request.tenant_id).await
    {
        return denied;
    }
    route_handler(&ctx, &headers, request).await
}

async fn handle_dagdb_context_packet(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    Json(request): Json<DagDbContextPacketRequest>,
) -> Response {
    if let Some(denied) = verify_dagdb_authority(
        &headers,
        &request.tenant_id,
        &request.namespace,
        "dagdb:context_packet",
    ) {
        return denied;
    }
    let ctx = resolve_route_context(extension);
    #[cfg(feature = "production-db")]
    if let Err(denied) =
        verify_dagdb_session_authority(&ctx, &headers, "dagdb.context_packet", &request.tenant_id)
            .await
    {
        return denied;
    }
    gated_context_packet_handler(&ctx, &headers, request).await
}

async fn handle_dagdb_validate(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    Json(request): Json<DagDbValidateRequest>,
) -> Response {
    if let Some(denied) = verify_dagdb_authority(
        &headers,
        &request.tenant_id,
        &request.namespace,
        "dagdb:validate",
    ) {
        return denied;
    }
    let ctx = resolve_route_context(extension);
    #[cfg(feature = "production-db")]
    if let Err(denied) =
        verify_dagdb_session_authority(&ctx, &headers, "dagdb.validate", &request.tenant_id).await
    {
        return denied;
    }
    validate_handler(&ctx, request).await
}

async fn handle_dagdb_writeback(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    Json(request): Json<DagDbWritebackRequest>,
) -> Response {
    if let Some(denied) = verify_dagdb_authority(
        &headers,
        &request.tenant_id,
        &request.namespace,
        "dagdb:writeback",
    ) {
        return denied;
    }
    let ctx = resolve_route_context(extension);
    #[cfg(feature = "production-db")]
    if let Err(denied) =
        verify_dagdb_session_authority(&ctx, &headers, "dagdb.writeback", &request.tenant_id).await
    {
        return denied;
    }
    writeback_handler(&ctx, &headers, request).await
}

async fn handle_dagdb_import(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    request: Result<Json<DagDbImportRequest>, JsonRejection>,
) -> Response {
    let request = match request {
        Ok(Json(request)) => request,
        Err(rejection) => {
            return dagdb_invalid_json_request_response("dagdb.import", &rejection);
        }
    };
    let ctx = resolve_route_context(extension);
    if let Some(denial) = dagdb_authority_denial(
        &headers,
        &request.tenant_id,
        &request.namespace,
        "dagdb:import",
    ) {
        log_dagdb_authority_denial(
            "dagdb.import",
            &headers,
            &request.tenant_id,
            &request.namespace,
            "dagdb:import",
        );
        #[cfg(feature = "production-db")]
        if let Some(pool) = &ctx.pool {
            let receipt_tenant = mounted_audit_tenant_id(&headers, &request.tenant_id);
            let receipt_namespace = mounted_audit_namespace(&headers, &request.namespace);
            let request_hash = import_route_request_hash(&request).ok();
            if let Err(error) = insert_gateway_operational_receipt_for_error(
                pool,
                &receipt_tenant,
                &receipt_namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                "import",
                gateway_operational_actor(&request.requester_did),
                &request.idempotency_key,
                request_hash,
                denial.status,
                denial.error_code,
            )
            .await
            {
                return *error;
            }
        }
        let denied = dagdb_authority_denial_response(denial, false);
        return denied;
    }
    #[cfg(feature = "production-db")]
    {
        let session_actor = match verify_dagdb_session_authority(
            &ctx,
            &headers,
            "dagdb.import",
            &request.tenant_id,
        )
        .await
        {
            Ok(actor) => actor,
            Err(denied) => return denied,
        };
        if let Err(denied) = bind_requester_to_session_actor(
            &session_actor,
            "dagdb.import",
            &request.tenant_id,
            &request.requester_did,
        ) {
            return *denied;
        }
    }
    import_handler(&ctx, &headers, request).await
}

async fn handle_dagdb_export(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    request: Result<Json<DagDbExportRequest>, JsonRejection>,
) -> Response {
    let request = match request {
        Ok(Json(request)) => request,
        Err(rejection) => {
            return dagdb_invalid_json_request_response("dagdb.export", &rejection);
        }
    };
    let ctx = resolve_route_context(extension);
    if let Some(denial) = dagdb_authority_denial(
        &headers,
        &request.tenant_id,
        &request.namespace,
        "dagdb:export",
    ) {
        log_dagdb_authority_denial(
            "dagdb.export",
            &headers,
            &request.tenant_id,
            &request.namespace,
            "dagdb:export",
        );
        #[cfg(feature = "production-db")]
        if let Some(pool) = &ctx.pool {
            let receipt_tenant = mounted_audit_tenant_id(&headers, &request.tenant_id);
            let receipt_namespace = mounted_audit_namespace(&headers, &request.namespace);
            let request_hash = export_route_request_hash(&request).ok();
            if let Err(error) = insert_gateway_operational_receipt_for_error(
                pool,
                &receipt_tenant,
                &receipt_namespace,
                EXPORT_ROUTE_IDEMPOTENCY_NAME,
                "export",
                gateway_operational_actor(&request.requester_did),
                &request.idempotency_key,
                request_hash,
                denial.status,
                denial.error_code,
            )
            .await
            {
                return *error;
            }
        }
        let denied = dagdb_authority_denial_response(denial, false);
        return denied;
    }
    #[cfg(feature = "production-db")]
    {
        let session_actor = match verify_dagdb_session_authority(
            &ctx,
            &headers,
            "dagdb.export",
            &request.tenant_id,
        )
        .await
        {
            Ok(actor) => actor,
            Err(denied) => return denied,
        };
        if let Err(denied) = bind_requester_to_session_actor(
            &session_actor,
            "dagdb.export",
            &request.tenant_id,
            &request.requester_did,
        ) {
            return *denied;
        }
    }
    export_handler(&ctx, &headers, request).await
}

async fn handle_dagdb_trust_check(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    Json(request): Json<DagDbTrustCheckRequest>,
) -> Response {
    if let Some(denied) = verify_dagdb_authority(
        &headers,
        &request.tenant_id,
        &request.namespace,
        "dagdb:trust_check",
    ) {
        return denied;
    }
    let ctx = resolve_route_context(extension);
    #[cfg(feature = "production-db")]
    if let Err(denied) =
        verify_dagdb_session_authority(&ctx, &headers, "dagdb.trust_check", &request.tenant_id)
            .await
    {
        return denied;
    }
    trust_check_handler(&ctx, request).await
}

async fn handle_dagdb_council_decision(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    Json(request): Json<DagDbCouncilDecisionRequest>,
) -> Response {
    if let Some(denied) = verify_council_authority(&headers, &request) {
        return denied;
    }
    let ctx = resolve_route_context(extension);
    #[cfg(feature = "production-db")]
    if let Err(denied) =
        verify_dagdb_session_authority(&ctx, &headers, "dagdb.council_decision", &request.tenant_id)
            .await
    {
        return denied;
    }
    council_decision_handler(&ctx, request).await
}

async fn handle_dagdb_receipt_lookup(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    Path(receipt_hash): Path<String>,
    Query(query): Query<QueryParams>,
) -> Response {
    let tenant_id = required_query_text(&query, "tenant_id");
    let namespace = required_query_text(&query, "namespace");
    if let Some(denied) =
        verify_dagdb_authority(&headers, &tenant_id, &namespace, "dagdb:receipt_lookup")
    {
        return denied;
    }
    let ctx = resolve_route_context(extension);
    #[cfg(feature = "production-db")]
    if let Err(denied) =
        verify_dagdb_session_authority(&ctx, &headers, "dagdb.receipt_lookup", &tenant_id).await
    {
        return denied;
    }
    receipt_lookup_handler(
        &ctx,
        DagDbReceiptLookupRequest {
            receipt_hash,
            tenant_id,
            namespace,
            include_body: optional_query_bool(&query, "include_body"),
        },
    )
    .await
}

async fn handle_dagdb_catalog_lookup(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    Path(catalog_id): Path<String>,
    Query(query): Query<QueryParams>,
) -> Response {
    let tenant_id = required_query_text(&query, "tenant_id");
    let namespace = required_query_text(&query, "namespace");
    if let Some(denied) =
        verify_dagdb_authority(&headers, &tenant_id, &namespace, "dagdb:catalog_lookup")
    {
        return denied;
    }
    let ctx = resolve_route_context(extension);
    #[cfg(feature = "production-db")]
    if let Err(denied) =
        verify_dagdb_session_authority(&ctx, &headers, "dagdb.catalog_lookup", &tenant_id).await
    {
        return denied;
    }
    catalog_lookup_handler(
        &ctx,
        DagDbCatalogLookupRequest {
            catalog_id,
            tenant_id,
            namespace,
            include_children: optional_query_bool(&query, "include_children"),
            include_routes: optional_query_bool(&query, "include_routes"),
        },
    )
    .await
}

async fn handle_dagdb_route_lookup(
    extension: Option<Extension<Arc<DagDbRouteContext>>>,
    headers: HeaderMap,
    Path(route_id): Path<String>,
    Query(query): Query<QueryParams>,
) -> Response {
    let tenant_id = required_query_text(&query, "tenant_id");
    let namespace = required_query_text(&query, "namespace");
    if let Some(denied) =
        verify_dagdb_authority(&headers, &tenant_id, &namespace, "dagdb:route_lookup")
    {
        return denied;
    }
    let ctx = resolve_route_context(extension);
    #[cfg(feature = "production-db")]
    if let Err(denied) =
        verify_dagdb_session_authority(&ctx, &headers, "dagdb.route_lookup", &tenant_id).await
    {
        return denied;
    }
    route_lookup_handler(
        &ctx,
        DagDbRouteLookupRequest {
            route_id,
            tenant_id,
            namespace,
            include_memory_refs: optional_query_bool(&query, "include_memory_refs"),
            include_validation: optional_query_bool(&query, "include_validation"),
        },
    )
    .await
}

async fn intake_handler(ctx: &DagDbRouteContext, request: DagDbIntakeRequest) -> Response {
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        return persist_idempotent_intake_response(pool, request).await;
    }
    #[cfg(not(feature = "production-db"))]
    let _ = (ctx, &request);
    warn!(
        route = "dagdb.intake",
        status = 503,
        tenant_id = %request.tenant_id,
        namespace = %request.namespace,
        "DAG DB intake rejected because no production database pool is configured"
    );
    dagdb_route_database_unavailable_response("dagdb.intake")
}

async fn validate_handler(ctx: &DagDbRouteContext, request: DagDbValidateRequest) -> Response {
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        return persist_idempotent_validate_response(pool, request).await;
    }
    #[cfg(not(feature = "production-db"))]
    let _ = (ctx, &request);
    warn!(
        route = "dagdb.validate",
        status = 503,
        tenant_id = %request.tenant_id,
        namespace = %request.namespace,
        "DAG DB validate rejected because no production database pool is configured"
    );
    dagdb_route_database_unavailable_response("dagdb.validate")
}

async fn trust_check_handler(ctx: &DagDbRouteContext, request: DagDbTrustCheckRequest) -> Response {
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        return persist_idempotent_trust_check_response(pool, request).await;
    }
    #[cfg(not(feature = "production-db"))]
    let _ = (ctx, &request);
    warn!(
        route = "dagdb.trust_check",
        status = 503,
        tenant_id = %request.tenant_id,
        namespace = %request.namespace,
        "DAG DB trust-check rejected because no production database pool is configured"
    );
    dagdb_route_database_unavailable_response("dagdb.trust_check")
}

async fn council_decision_handler(
    ctx: &DagDbRouteContext,
    request: DagDbCouncilDecisionRequest,
) -> Response {
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        return persist_idempotent_council_decision_response(pool, request).await;
    }
    #[cfg(not(feature = "production-db"))]
    let _ = (ctx, &request);
    warn!(
        route = "dagdb.council_decision",
        status = 503,
        tenant_id = %request.tenant_id,
        namespace = %request.namespace,
        "DAG DB council decision rejected because no production database pool is configured"
    );
    dagdb_route_database_unavailable_response("dagdb.council_decision")
}

async fn receipt_lookup_handler(
    ctx: &DagDbRouteContext,
    request: DagDbReceiptLookupRequest,
) -> Response {
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        return match load_receipt_lookup_response(pool, request).await {
            Ok(response) => (StatusCode::OK, Json(response)).into_response(),
            Err(response) => *response,
        };
    }
    #[cfg(not(feature = "production-db"))]
    let _ = (ctx, &request);
    warn!(
        route = "dagdb.receipt_lookup",
        status = 503,
        tenant_id = %request.tenant_id,
        namespace = %request.namespace,
        "DAG DB receipt lookup rejected because no production database pool is configured"
    );
    dagdb_route_database_unavailable_response("dagdb.receipt_lookup")
}

async fn catalog_lookup_handler(
    ctx: &DagDbRouteContext,
    request: DagDbCatalogLookupRequest,
) -> Response {
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        return match load_catalog_lookup_response(pool, request).await {
            Ok(response) => (StatusCode::OK, Json(response)).into_response(),
            Err(response) => *response,
        };
    }
    #[cfg(not(feature = "production-db"))]
    let _ = (ctx, &request);
    warn!(
        route = "dagdb.catalog_lookup",
        status = 503,
        tenant_id = %request.tenant_id,
        namespace = %request.namespace,
        "DAG DB catalog lookup rejected because no production database pool is configured"
    );
    dagdb_route_database_unavailable_response("dagdb.catalog_lookup")
}

async fn route_lookup_handler(
    ctx: &DagDbRouteContext,
    request: DagDbRouteLookupRequest,
) -> Response {
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        return match load_route_lookup_response(pool, request).await {
            Ok(response) => (StatusCode::OK, Json(response)).into_response(),
            Err(response) => *response,
        };
    }
    #[cfg(not(feature = "production-db"))]
    let _ = (ctx, &request);
    warn!(
        route = "dagdb.route_lookup",
        status = 503,
        tenant_id = %request.tenant_id,
        namespace = %request.namespace,
        "DAG DB route lookup rejected because no production database pool is configured"
    );
    dagdb_route_database_unavailable_response("dagdb.route_lookup")
}

async fn route_handler(
    ctx: &DagDbRouteContext,
    headers: &HeaderMap,
    request: DagDbRouteRequest,
) -> Response {
    #[cfg(not(feature = "production-db"))]
    let _ = ctx;
    #[cfg(not(feature = "production-db"))]
    let _ = headers;
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        let request_hash = request_hash(
            "dagdb.route",
            &request.tenant_id,
            &request.namespace,
            &request,
        )
        .ok();
        let signature = match header_text(headers, WRITE_SIGNATURE_HEADER) {
            Some(signature) => signature.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.route",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "write_signature_required",
                    "DAG DB route persistence requires x-exo-write-signature header",
                    false,
                )
                .await;
            }
        };
        let default_route_approval_signature = match header_text(
            headers,
            DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER,
        ) {
            Some(signature) => signature.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.route",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "default_route_approval_signature_required",
                    "DAG DB default route finality requires x-exo-default-route-approval-signature header",
                    false,
                )
                .await;
            }
        };
        let default_route_approval_did = match header_text(
            headers,
            DEFAULT_ROUTE_APPROVAL_DID_HEADER,
        ) {
            Some(did) => did.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.route",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "default_route_approval_authority_required",
                    "DAG DB default route finality requires x-exo-default-route-approval-did header",
                    false,
                )
                .await;
            }
        };
        let default_route_approval_timestamp = match header_text(
            headers,
            DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER,
        ) {
            Some(timestamp) => timestamp.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.route",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "default_route_approval_timestamp_required",
                    "DAG DB default route finality requires x-exo-default-route-approval-timestamp header",
                    false,
                )
                .await;
            }
        };
        let service = match ctx
            .gatekeeper_service(
                pool,
                &request.requesting_agent_did,
                &request.tenant_id,
                &request.namespace,
                &[&default_route_approval_did],
            )
            .await
        {
            Ok(service) => service,
            Err(error) => {
                let handler_error = DagDbHandlerError::from_gatekeeper(error);
                warn!(
                    route = "dagdb.route",
                    status = handler_error.status().as_u16(),
                    error_code = %handler_error.error_code(),
                    gatekeeper_error_class = %handler_error.class(),
                    "DAG DB default route authority resolver failed closed"
                );
                return handler_error.into_response();
            }
        };
        match gated_route_response(
            &service,
            &request,
            &signature,
            &default_route_approval_signature,
            &default_route_approval_did,
            &default_route_approval_timestamp,
        )
        .await
        {
            Ok(response) => {
                info!(
                    route = "dagdb.route",
                    status = 201,
                    tenant_id = %response.tenant_id,
                    namespace = %response.namespace,
                    route_id = %response.route_id,
                    "DAG DB default route persisted"
                );
                return (StatusCode::CREATED, Json(response)).into_response();
            }
            Err(error) => {
                warn!(
                    route = "dagdb.route",
                    status = error.status().as_u16(),
                    error_code = %error.error_code(),
                    gatekeeper_error_class = %error.class(),
                    "DAG DB default route persistence failed closed"
                );
                return error.into_response();
            }
        }
    }
    #[cfg(not(feature = "production-db"))]
    let _ = &request;
    warn!(
        route = "dagdb.route",
        status = 503,
        "DAG DB default route rejected because no governed route persistence is configured"
    );
    dagdb_route_database_unavailable_response("dagdb.route")
}

async fn gated_context_packet_handler(
    ctx: &DagDbRouteContext,
    headers: &HeaderMap,
    request: DagDbContextPacketRequest,
) -> Response {
    #[cfg(not(feature = "production-db"))]
    let _ = headers;
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        let request_hash = request_hash(
            "dagdb.context_packet",
            &request.tenant_id,
            &request.namespace,
            &request,
        )
        .ok();
        let signature = match header_text(headers, WRITE_SIGNATURE_HEADER) {
            Some(signature) => signature.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.context_packet",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "write_signature_required",
                    "DAG DB context packet persistence requires x-exo-write-signature header",
                    false,
                )
                .await;
            }
        };
        let context_packet_approval_signature = match header_text(
            headers,
            CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER,
        ) {
            Some(signature) => signature.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.context_packet",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "context_packet_approval_signature_required",
                    "DAG DB context packet finality requires x-exo-context-packet-approval-signature header",
                    false,
                )
                .await;
            }
        };
        let context_packet_approval_did = match header_text(
            headers,
            CONTEXT_PACKET_APPROVAL_DID_HEADER,
        ) {
            Some(did) => did.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.context_packet",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "context_packet_approval_authority_required",
                    "DAG DB context packet finality requires x-exo-context-packet-approval-did header",
                    false,
                )
                .await;
            }
        };
        let context_packet_approval_timestamp = match header_text(
            headers,
            CONTEXT_PACKET_APPROVAL_TIMESTAMP_HEADER,
        ) {
            Some(timestamp) => timestamp.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.context_packet",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "context_packet_approval_timestamp_required",
                    "DAG DB context packet finality requires x-exo-context-packet-approval-timestamp header",
                    false,
                )
                .await;
            }
        };
        let service = match ctx
            .gatekeeper_service(
                pool,
                &request.requesting_agent_did,
                &request.tenant_id,
                &request.namespace,
                &[&context_packet_approval_did],
            )
            .await
        {
            Ok(service) => service,
            Err(error) => {
                let handler_error = DagDbHandlerError::from_gatekeeper(error);
                warn!(
                    route = "dagdb.context_packet",
                    status = handler_error.status().as_u16(),
                    error_code = %handler_error.error_code(),
                    gatekeeper_error_class = %handler_error.class(),
                    "DAG DB context packet authority resolver failed closed"
                );
                return handler_error.into_response();
            }
        };
        match gated_context_packet_response(
            &service,
            pool,
            &request,
            &signature,
            &context_packet_approval_signature,
            &context_packet_approval_did,
            &context_packet_approval_timestamp,
        )
        .await
        {
            Ok(response) => {
                info!(
                    route = "dagdb.context_packet",
                    status = 200,
                    tenant_id = %response.tenant_id,
                    namespace = %response.namespace,
                    context_packet_id = %response.context_packet_id,
                    "DAG DB context packet persisted"
                );
                return (StatusCode::OK, Json(response)).into_response();
            }
            Err(error) => {
                warn!(
                    route = "dagdb.context_packet",
                    status = error.status().as_u16(),
                    error_code = %error.error_code(),
                    gatekeeper_error_class = %error.class(),
                    "DAG DB context packet persistence failed closed"
                );
                return error.into_response();
            }
        }
    }
    context_packet_handler(ctx, request).await
}

async fn context_packet_handler(
    ctx: &DagDbRouteContext,
    request: DagDbContextPacketRequest,
) -> Response {
    #[cfg(feature = "production-db")]
    {
        if let Some(pool) = &ctx.pool {
            match persistent_context_packet_response(pool, &request).await {
                Ok(response) => {
                    let mode = response
                        .context_packet_mode
                        .clone()
                        .unwrap_or_else(|| "database".to_owned());
                    if response.memory_refs.is_empty() {
                        info!(
                            route = "dagdb.context_packet",
                            status = 200,
                            mode = %mode,
                            tenant_id = %response.tenant_id,
                            namespace = %response.namespace,
                            "DAG DB context packet served with empty selection"
                        );
                    } else {
                        info!(
                            route = "dagdb.context_packet",
                            status = 200,
                            mode = %mode,
                            tenant_id = %response.tenant_id,
                            namespace = %response.namespace,
                            memory_ref_count = response.memory_refs.len(),
                            token_estimate = response.token_estimate,
                            "DAG DB context packet served from database"
                        );
                    }
                    return (StatusCode::OK, Json(response)).into_response();
                }
                Err(error) => {
                    warn!(
                        route = "dagdb.context_packet",
                        status = error.status().as_u16(),
                        error_code = %error.error_code(),
                        "DAG DB context packet database path failed closed"
                    );
                    return error.into_response();
                }
            }
        }
    }
    let _ = ctx;
    if let Err(response) = context_packet_layered_fields(&request, 0, false) {
        return *response;
    }
    warn!(
        route = "dagdb.context_packet",
        status = 503,
        "DAG DB context packet rejected because no governed database pool is configured"
    );
    dagdb_route_database_unavailable_response("dagdb.context_packet")
}

async fn writeback_handler(
    ctx: &DagDbRouteContext,
    headers: &HeaderMap,
    request: DagDbWritebackRequest,
) -> Response {
    // Fail closed on the optional typed-knowledge class before any persistence
    // or signature handling, identically in the production-db and scaffold
    // paths. A classless writeback is unchanged telemetry.
    if let Err(response) = validate_writeback_knowledge_class(&request) {
        return *response;
    }
    #[cfg(not(feature = "production-db"))]
    let _ = (ctx, headers);
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        let request_hash = request_hash(
            "dagdb.writeback",
            &request.tenant_id,
            &request.namespace,
            &request,
        )
        .ok();
        let signature = match header_text(headers, WRITE_SIGNATURE_HEADER) {
            Some(signature) => signature.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.writeback",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "write_signature_required",
                    "DAG DB writeback requires x-exo-write-signature header",
                    false,
                )
                .await;
            }
        };
        let lifecycle_signature = match header_text(headers, LIFECYCLE_SIGNATURE_HEADER) {
            Some(signature) => signature.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.writeback",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "lifecycle_signature_required",
                    "DAG DB writeback lifecycle persistence requires x-exo-lifecycle-signature header",
                    false,
                )
                .await;
            }
        };
        let continuation_signature = match header_text(headers, CONTINUATION_SIGNATURE_HEADER) {
            Some(signature) => signature.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.writeback",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "continuation_signature_required",
                    "DAG DB writeback continuation persistence requires x-exo-continuation-signature header",
                    false,
                )
                .await;
            }
        };
        let lifecycle_approval_did = match header_text(headers, LIFECYCLE_APPROVAL_DID_HEADER) {
            Some(did) => did.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.writeback",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "lifecycle_approval_authority_required",
                    "DAG DB writeback lifecycle finality requires x-exo-lifecycle-approval-did header",
                    true,
                )
                .await;
            }
        };
        let continuation_approval_did = match header_text(headers, CONTINUATION_APPROVAL_DID_HEADER)
        {
            Some(did) => did.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    "dagdb.writeback",
                    &request.idempotency_key,
                    &request.requesting_agent_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "continuation_approval_authority_required",
                    "DAG DB writeback continuation finality requires x-exo-continuation-approval-did header",
                    true,
                )
                .await;
            }
        };
        let lifecycle_approval_timestamp = match header_text(
            headers,
            LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
        ) {
            Some(timestamp) => timestamp.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                        pool,
                        &request.tenant_id,
                        &request.namespace,
                        "dagdb.writeback",
                        &request.idempotency_key,
                        &request.requesting_agent_did,
                        request_hash,
                        StatusCode::BAD_REQUEST,
                        "lifecycle_approval_timestamp_required",
                        "DAG DB writeback lifecycle finality requires x-exo-lifecycle-approval-timestamp header",
                        false,
                    )
                    .await;
            }
        };
        let continuation_approval_timestamp = match header_text(
            headers,
            CONTINUATION_APPROVAL_TIMESTAMP_HEADER,
        ) {
            Some(timestamp) => timestamp.to_owned(),
            None => {
                return mounted_dagdb_operational_error_response(
                        pool,
                        &request.tenant_id,
                        &request.namespace,
                        "dagdb.writeback",
                        &request.idempotency_key,
                        &request.requesting_agent_did,
                        request_hash,
                        StatusCode::BAD_REQUEST,
                        "continuation_approval_timestamp_required",
                        "DAG DB writeback continuation finality requires x-exo-continuation-approval-timestamp header",
                        false,
                    )
                    .await;
            }
        };
        let service = match ctx
            .gatekeeper_service(
                pool,
                &request.requesting_agent_did,
                &request.tenant_id,
                &request.namespace,
                &[&lifecycle_approval_did, &continuation_approval_did],
            )
            .await
        {
            Ok(service) => service,
            Err(error) => {
                let handler_error = DagDbHandlerError::from_gatekeeper(error);
                warn!(
                    route = "dagdb.writeback",
                    status = handler_error.status().as_u16(),
                    error_code = %handler_error.error_code(),
                    gatekeeper_error_class = %handler_error.class(),
                    "DAG DB writeback authority resolver failed closed"
                );
                return handler_error.into_response();
            }
        };
        match gated_writeback_response(
            &service,
            pool,
            &request,
            &signature,
            &lifecycle_signature,
            &continuation_signature,
            &lifecycle_approval_did,
            &continuation_approval_did,
            &lifecycle_approval_timestamp,
            &continuation_approval_timestamp,
        )
        .await
        {
            Ok(response) => {
                info!(
                    route = "dagdb.writeback",
                    status = 200,
                    tenant_id = %response.tenant_id,
                    namespace = %response.namespace,
                    receipt_hash = %response.receipt_hash,
                    "DAG DB writeback persisted"
                );
                return (StatusCode::OK, Json(response)).into_response();
            }
            Err(error) => {
                warn!(
                    route = "dagdb.writeback",
                    status = error.status().as_u16(),
                    error_code = %error.error_code(),
                    gatekeeper_error_class = %error.class(),
                    "DAG DB writeback gate failed closed"
                );
                return error.into_response();
            }
        }
    }
    // Fail closed when no production database pool is configured: a writeback is
    // a governed graph mutation and must never return a synthetic success or a
    // fabricated receipt. This matches the import/export no-pool behavior (503,
    // `database_unavailable`) so all three mutation surfaces are uniformly
    // fail-closed off the production-db path.
    #[cfg(not(feature = "production-db"))]
    let _ = &request;
    warn!(
        route = "dagdb.writeback",
        status = 503,
        "DAG DB writeback rejected because no production database pool is configured"
    );
    dagdb_runtime_database_unavailable_response("writeback")
}

async fn import_handler(
    ctx: &DagDbRouteContext,
    headers: &HeaderMap,
    request: DagDbImportRequest,
) -> Response {
    #[cfg(not(feature = "production-db"))]
    let _ = (ctx, headers);
    let report_json = match validated_import_report_json(&request) {
        Ok(report_json) => report_json,
        Err(response) => return *response,
    };
    #[cfg(feature = "production-db")]
    let request_hash = match import_route_request_hash(&request) {
        Ok(request_hash) => request_hash,
        Err(response) => return *response,
    };
    #[cfg(not(feature = "production-db"))]
    let _ = &report_json;
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        let signature = match header_text(headers, WRITE_SIGNATURE_HEADER) {
            Some(signature) => signature.to_owned(),
            None => {
                warn!(
                    route = "dagdb.import",
                    status = 400,
                    error_code = "write_signature_required",
                    tenant_id = %request.tenant_id,
                    namespace = %request.namespace,
                    "DAG DB import rejected because write signature is missing"
                );
                return dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    IMPORT_ROUTE_IDEMPOTENCY_NAME,
                    &request.idempotency_key,
                    &request.requester_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "write_signature_required",
                    "DAG DB import requires x-exo-write-signature header",
                    false,
                )
                .await;
            }
        };
        let replayed_response = match reserve_gateway_idempotency_key(
            pool,
            &request.tenant_id,
            &request.namespace,
            IMPORT_ROUTE_IDEMPOTENCY_NAME,
            &request.idempotency_key,
            request_hash,
            &request.requester_did,
            "import",
        )
        .await
        {
            Ok(GatewayIdempotencyDecision::Reserved) => None,
            Ok(GatewayIdempotencyDecision::Replayed(response)) => Some(response),
            Ok(GatewayIdempotencyDecision::Failed(response)) => return *response,
            Err(response) => return *response,
        };
        let finality_approval = match require_operation_finality_approval(
            headers,
            "import",
            IMPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
            IMPORT_FINALITY_APPROVAL_DID_HEADER,
            IMPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
        ) {
            Ok(approval) => approval,
            Err(error) => {
                if replayed_response.is_none() {
                    if let Err(cleanup_error) =
                        cleanup_gateway_idempotency_reservation(pool, &request, request_hash).await
                    {
                        return *cleanup_error;
                    }
                }
                return handler_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    IMPORT_ROUTE_IDEMPOTENCY_NAME,
                    &request.idempotency_key,
                    &request.requester_did,
                    request_hash,
                    error,
                )
                .await;
            }
        };
        let service = match ctx
            .gatekeeper_service(
                pool,
                &request.requester_did,
                &request.tenant_id,
                &request.namespace,
                &[&finality_approval.authority_did],
            )
            .await
        {
            Ok(service) => service,
            Err(error) => {
                if replayed_response.is_none() {
                    if let Err(cleanup_error) =
                        cleanup_gateway_idempotency_reservation(pool, &request, request_hash).await
                    {
                        return *cleanup_error;
                    }
                }
                let handler_error = DagDbHandlerError::from_gatekeeper(error);
                warn!(
                    route = "dagdb.import",
                    status = handler_error.status().as_u16(),
                    error_code = %handler_error.error_code(),
                    gatekeeper_error_class = %handler_error.class(),
                    tenant_id = %request.tenant_id,
                    namespace = %request.namespace,
                    "DAG DB import authority resolver failed closed"
                );
                return handler_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    IMPORT_ROUTE_IDEMPOTENCY_NAME,
                    &request.idempotency_key,
                    &request.requester_did,
                    request_hash,
                    handler_error,
                )
                .await;
            }
        };
        let authorization_payload_hash = match gated_import_authorization(
            &service,
            pool,
            &request,
            &signature,
            replayed_response.is_none(),
            replayed_response
                .as_ref()
                .and_then(|response| response.authorization_payload_hash),
        )
        .await
        {
            Ok(authorization_payload_hash) => authorization_payload_hash,
            Err(error) => {
                if replayed_response.is_none() {
                    if let Err(cleanup_error) =
                        cleanup_gateway_idempotency_reservation(pool, &request, request_hash).await
                    {
                        return *cleanup_error;
                    }
                }
                warn!(
                    route = "dagdb.import",
                    status = error.status().as_u16(),
                    error_code = %error.error_code(),
                    gatekeeper_error_class = %error.class(),
                    tenant_id = %request.tenant_id,
                    namespace = %request.namespace,
                    "DAG DB import gate failed closed"
                );
                return handler_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    IMPORT_ROUTE_IDEMPOTENCY_NAME,
                    &request.idempotency_key,
                    &request.requester_did,
                    request_hash,
                    error,
                )
                .await;
            }
        };
        if let Err(error) = validate_import_finality_approval(
            &service,
            &request,
            authorization_payload_hash,
            &finality_approval,
        ) {
            if replayed_response.is_none() {
                if let Err(cleanup_error) =
                    cleanup_gateway_idempotency_reservation(pool, &request, request_hash).await
                {
                    return *cleanup_error;
                }
            }
            warn!(
                route = "dagdb.import",
                status = error.status().as_u16(),
                error_code = %error.error_code(),
                gatekeeper_error_class = %error.class(),
                tenant_id = %request.tenant_id,
                namespace = %request.namespace,
                "DAG DB import finality gate failed closed"
            );
            return handler_operational_error_response(
                pool,
                &request.tenant_id,
                &request.namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                &request.idempotency_key,
                &request.requester_did,
                request_hash,
                error,
            )
            .await;
        }
        if let Some(response) = replayed_response {
            return response.response;
        }
        match exo_dag_db_postgres::postgres::kg_import::persist_kg_import_report(pool, &report_json)
            .await
        {
            Ok(summary) => {
                let status = if summary.replayed {
                    "replayed"
                } else {
                    "persisted"
                };
                match import_response_from_summary(request.clone(), summary, status) {
                    Ok(response) => {
                        if let Err(error) = store_gateway_idempotency_response(
                            pool,
                            &request.tenant_id,
                            &request.namespace,
                            IMPORT_ROUTE_IDEMPOTENCY_NAME,
                            &request.idempotency_key,
                            request_hash,
                            StatusCode::OK,
                            serde_json::to_value(&response)
                                .map_err(|_| import_idempotency_unavailable_response()),
                            Some(authorization_payload_hash),
                            "import",
                        )
                        .await
                        {
                            return *error;
                        }
                        info!(
                            route = "dagdb.import",
                            status = 200,
                            tenant_id = %response.tenant_id,
                            namespace = %response.namespace,
                            import_status = %response.import_status,
                            "DAG DB import persisted"
                        );
                        return (StatusCode::OK, Json(response)).into_response();
                    }
                    Err(response) => {
                        if let Err(cleanup_error) =
                            cleanup_gateway_idempotency_reservation(pool, &request, request_hash)
                                .await
                        {
                            return *cleanup_error;
                        }
                        return *response;
                    }
                }
            }
            Err(error) => {
                if let Err(cleanup_error) =
                    cleanup_gateway_idempotency_reservation(pool, &request, request_hash).await
                {
                    return *cleanup_error;
                }
                return dagdb_import_adapter_error_response(&request, &error);
            }
        }
    }
    warn!(
        route = "dagdb.import",
        status = 503,
        "DAG DB import rejected because no production database pool is configured"
    );
    dagdb_runtime_database_unavailable_response("import")
}

async fn export_handler(
    ctx: &DagDbRouteContext,
    headers: &HeaderMap,
    request: DagDbExportRequest,
) -> Response {
    #[cfg(not(feature = "production-db"))]
    let _ = (ctx, headers);
    let scope = match export_scope_from_request(&request) {
        Ok(scope) => scope,
        Err(response) => return *response,
    };
    #[cfg(not(feature = "production-db"))]
    let _ = &scope;
    #[cfg(feature = "production-db")]
    if let Some(pool) = &ctx.pool {
        let request_hash = match export_route_request_hash(&request) {
            Ok(request_hash) => request_hash,
            Err(response) => return *response,
        };
        let signature = match header_text(headers, WRITE_SIGNATURE_HEADER) {
            Some(signature) => signature.to_owned(),
            None => {
                warn!(
                    route = "dagdb.export",
                    status = 400,
                    error_code = "write_signature_required",
                    tenant_id = %request.tenant_id,
                    namespace = %request.namespace,
                    "DAG DB export rejected because write signature is missing"
                );
                return dagdb_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    EXPORT_ROUTE_IDEMPOTENCY_NAME,
                    &request.idempotency_key,
                    &request.requester_did,
                    request_hash,
                    StatusCode::BAD_REQUEST,
                    "write_signature_required",
                    "DAG DB export requires x-exo-write-signature header",
                    false,
                )
                .await;
            }
        };
        let replayed_response = match reserve_gateway_idempotency_key(
            pool,
            &request.tenant_id,
            &request.namespace,
            EXPORT_ROUTE_IDEMPOTENCY_NAME,
            &request.idempotency_key,
            request_hash,
            &request.requester_did,
            "export",
        )
        .await
        {
            Ok(GatewayIdempotencyDecision::Reserved) => None,
            Ok(GatewayIdempotencyDecision::Replayed(response)) => Some(response),
            Ok(GatewayIdempotencyDecision::Failed(response)) => return *response,
            Err(response) => return *response,
        };
        let finality_approval = match require_operation_finality_approval(
            headers,
            "export",
            EXPORT_FINALITY_APPROVAL_SIGNATURE_HEADER,
            EXPORT_FINALITY_APPROVAL_DID_HEADER,
            EXPORT_FINALITY_APPROVAL_TIMESTAMP_HEADER,
        ) {
            Ok(approval) => approval,
            Err(error) => {
                if replayed_response.is_none() {
                    if let Err(cleanup_error) =
                        cleanup_export_idempotency_reservation(pool, &request, request_hash).await
                    {
                        return *cleanup_error;
                    }
                }
                return handler_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    EXPORT_ROUTE_IDEMPOTENCY_NAME,
                    &request.idempotency_key,
                    &request.requester_did,
                    request_hash,
                    error,
                )
                .await;
            }
        };
        let service = match ctx
            .gatekeeper_service(
                pool,
                &request.requester_did,
                &request.tenant_id,
                &request.namespace,
                &[&finality_approval.authority_did],
            )
            .await
        {
            Ok(service) => service,
            Err(error) => {
                if replayed_response.is_none() {
                    if let Err(cleanup_error) =
                        cleanup_export_idempotency_reservation(pool, &request, request_hash).await
                    {
                        return *cleanup_error;
                    }
                }
                let handler_error = DagDbHandlerError::from_gatekeeper(error);
                warn!(
                    route = "dagdb.export",
                    status = handler_error.status().as_u16(),
                    error_code = %handler_error.error_code(),
                    gatekeeper_error_class = %handler_error.class(),
                    tenant_id = %request.tenant_id,
                    namespace = %request.namespace,
                    "DAG DB export authority resolver failed closed"
                );
                return handler_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    EXPORT_ROUTE_IDEMPOTENCY_NAME,
                    &request.idempotency_key,
                    &request.requester_did,
                    request_hash,
                    handler_error,
                )
                .await;
            }
        };
        let authorization_payload_hash = match gated_export_authorization(
            &service,
            pool,
            &request,
            request_hash,
            &signature,
            replayed_response.is_none(),
            replayed_response
                .as_ref()
                .and_then(|response| response.authorization_payload_hash),
        )
        .await
        {
            Ok(authorization_payload_hash) => authorization_payload_hash,
            Err(error) => {
                if replayed_response.is_none() {
                    if let Err(cleanup_error) =
                        cleanup_export_idempotency_reservation(pool, &request, request_hash).await
                    {
                        return *cleanup_error;
                    }
                }
                warn!(
                    route = "dagdb.export",
                    status = error.status().as_u16(),
                    error_code = %error.error_code(),
                    gatekeeper_error_class = %error.class(),
                    tenant_id = %request.tenant_id,
                    namespace = %request.namespace,
                    "DAG DB export gate failed closed"
                );
                return handler_operational_error_response(
                    pool,
                    &request.tenant_id,
                    &request.namespace,
                    EXPORT_ROUTE_IDEMPOTENCY_NAME,
                    &request.idempotency_key,
                    &request.requester_did,
                    request_hash,
                    error,
                )
                .await;
            }
        };
        if let Err(error) = validate_export_finality_approval(
            &service,
            &request,
            authorization_payload_hash,
            &finality_approval,
        ) {
            if replayed_response.is_none() {
                if let Err(cleanup_error) =
                    cleanup_export_idempotency_reservation(pool, &request, request_hash).await
                {
                    return *cleanup_error;
                }
            }
            warn!(
                route = "dagdb.export",
                status = error.status().as_u16(),
                error_code = %error.error_code(),
                gatekeeper_error_class = %error.class(),
                tenant_id = %request.tenant_id,
                namespace = %request.namespace,
                "DAG DB export finality gate failed closed"
            );
            return handler_operational_error_response(
                pool,
                &request.tenant_id,
                &request.namespace,
                EXPORT_ROUTE_IDEMPOTENCY_NAME,
                &request.idempotency_key,
                &request.requester_did,
                request_hash,
                error,
            )
            .await;
        }
        if let Some(response) = replayed_response {
            return response.response;
        }
        match exo_dag_db_postgres::postgres::kg_export::build_kg_portable_export(pool, &scope, &[])
            .await
        {
            Ok(export) => {
                if let Err(error) =
                    exo_dag_db_postgres::postgres::kg_export::persist_kg_portable_export_with_idempotency_key(
                        pool,
                        &export,
                        &request.requester_did,
                        &request.idempotency_key,
                    )
                    .await
                {
                    if let Err(cleanup_error) =
                        cleanup_export_idempotency_reservation(pool, &request, request_hash).await
                    {
                        return *cleanup_error;
                    }
                    return dagdb_export_adapter_error_response(&request, &error);
                }
                match export_response_from_portable(request.clone(), export) {
                    Ok(response) => {
                        if let Err(error) = store_gateway_idempotency_response(
                            pool,
                            &response.tenant_id,
                            &response.namespace,
                            EXPORT_ROUTE_IDEMPOTENCY_NAME,
                            &response.idempotency_key,
                            request_hash,
                            StatusCode::OK,
                            serde_json::to_value(&response)
                                .map_err(|_| export_idempotency_unavailable_response()),
                            Some(authorization_payload_hash),
                            "export",
                        )
                        .await
                        {
                            return *error;
                        }
                        info!(
                            route = "dagdb.export",
                            status = 200,
                            tenant_id = %response.tenant_id,
                            namespace = %response.namespace,
                            export_status = %response.export_status,
                            "DAG DB export built from database"
                        );
                        return (StatusCode::OK, Json(response)).into_response();
                    }
                    Err(response) => {
                        if let Err(cleanup_error) =
                            cleanup_export_idempotency_reservation(pool, &request, request_hash)
                                .await
                        {
                            return *cleanup_error;
                        }
                        return *response;
                    }
                }
            }
            Err(error) => {
                if let Err(cleanup_error) =
                    cleanup_export_idempotency_reservation(pool, &request, request_hash).await
                {
                    return *cleanup_error;
                }
                return dagdb_export_adapter_error_response(&request, &error);
            }
        }
    }
    warn!(
        route = "dagdb.export",
        status = 503,
        "DAG DB export rejected because no production database pool is configured"
    );
    dagdb_runtime_database_unavailable_response("export")
}

#[cfg(feature = "production-db")]
async fn persistent_context_packet_response(
    pool: &sqlx::PgPool,
    request: &DagDbContextPacketRequest,
) -> Result<DagDbContextPacketResponse, DagDbHandlerError> {
    // D1-S4: validate the layered mode and the depth reserve the same way the
    // depth param is validated, then dispatch. When `layered_mode != off` the
    // handler calls the membership-triggered DRILLDOWN entrypoint with the
    // reserve; off-mode stays on the breadth-only path and is byte-identical.
    let mode = layered_mode_value(&request.layered_mode)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    let max_layer_depth = validate_max_layer_depth(request.max_layer_depth)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    let drilldown_reserve_bp = validate_drilldown_reserve_bp(request.drilldown_reserve_bp)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;

    let selection_request = graph_context_selection_request_from_packet(request);
    let persistent_selection = if mode == "off" {
        build_persistent_graph_context_selection(pool, &selection_request)
            .await
            .map_err(DagDbHandlerError::from_domain)?
    } else {
        build_persistent_graph_context_selection_with_layered_drilldown(
            pool,
            &selection_request,
            Some(mode),
            Some(max_layer_depth),
            drilldown_reserve_bp,
        )
        .await
        .map_err(DagDbHandlerError::from_domain)?
    };
    if persistent_selection
        .selection
        .selected_memory_refs
        .is_empty()
    {
        return Err(DagDbHandlerError::from_response(
            *d5_record_rejected_response(
                "context packet",
                "selected memory refs are required for live context-packet persistence",
            ),
        ));
    }

    let build_request =
        graph_context_packet_build_request(request, persistent_selection.selection.clone());
    let packet = exo_dag_db_postgres::build_graph_context_packet(&build_request)
        .map_err(DagDbHandlerError::from_domain)?;
    let persistent = PersistentGraphContextPacket {
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        boundary_warnings: persistent_selection.boundary_warnings.clone(),
        selection: persistent_selection,
        packet,
    };
    context_packet_response_from_persistent(request, &persistent)
        .map_err(|response| DagDbHandlerError::from_response(*response))
}

#[cfg(feature = "production-db")]
async fn gated_route_response(
    service: &DagDbGatekeeperService,
    request: &DagDbRouteRequest,
    signature: &str,
    approval_signature: &str,
    approval_authority_did: &str,
    approval_timestamp: &str,
) -> Result<DagDbRouteResponse, DagDbHandlerError> {
    let response = route_response_from_request(request.clone(), "dagdb.route")
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    let proposed = default_route_candidate_from_response(request, &response)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    let approval_payload_hash_hex = canonical_default_route_approval_payload_hash(
        &proposed,
        &request.requesting_agent_did,
        &request.idempotency_key,
        approval_authority_did,
        DEFAULT_ROUTE_FINALITY_PURPOSE,
        approval_timestamp,
    )
    .map_err(|response| {
        DagDbHandlerError::from_response(*d5_record_rejected_response("default route", response))
    })?;
    let approval_payload_hash = decode_canonical_approval_hash(&approval_payload_hash_hex)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    validate_gateway_approval_payload(
        service,
        &request.requesting_agent_did,
        approval_authority_did,
        &approval_payload_hash,
        approval_signature,
    )?;
    let record = default_route_record_from_response(
        request,
        &response,
        approval_authority_did,
        approval_signature,
        approval_timestamp,
        &approval_payload_hash_hex,
    )
    .map_err(|response| DagDbHandlerError::from_response(*response))?;
    let write_payload_hash = exo_gatekeeper::dagdb_gate::default_route_payload_hash(&record)
        .map_err(DagDbHandlerError::from_gatekeeper)?;
    validate_gateway_write_payload(
        service,
        &record.tenant_id,
        &request.requesting_agent_did,
        &write_payload_hash,
        signature,
    )?;
    let invariant_context =
        service.dagdb_invariant_context(&request.tenant_id, &request.requesting_agent_did);
    service
        .persist_default_route(
            &record,
            &request.requesting_agent_did,
            signature,
            invariant_context.as_ref(),
        )
        .await
        .map_err(DagDbHandlerError::from_gatekeeper)?;
    Ok(response)
}

#[cfg(feature = "production-db")]
async fn gated_context_packet_response(
    service: &DagDbGatekeeperService,
    pool: &sqlx::PgPool,
    request: &DagDbContextPacketRequest,
    signature: &str,
    approval_signature: &str,
    approval_authority_did: &str,
    approval_timestamp: &str,
) -> Result<DagDbContextPacketResponse, DagDbHandlerError> {
    let response = persistent_context_packet_response(pool, request).await?;
    let proposed = context_packet_candidate_from_response(request, &response)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    let approval_payload_hash_hex = canonical_context_packet_approval_payload_hash(
        &proposed,
        &request.requesting_agent_did,
        &proposed.idempotency_key,
        approval_authority_did,
        CONTEXT_PACKET_FINALITY_PURPOSE,
        approval_timestamp,
    )
    .map_err(|response| {
        DagDbHandlerError::from_response(*d5_record_rejected_response("context packet", response))
    })?;
    let approval_payload_hash = decode_canonical_approval_hash(&approval_payload_hash_hex)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    validate_gateway_approval_payload(
        service,
        &request.requesting_agent_did,
        approval_authority_did,
        &approval_payload_hash,
        approval_signature,
    )?;
    let record = context_packet_record_from_response(
        request,
        &response,
        approval_authority_did,
        approval_signature,
        approval_timestamp,
        &approval_payload_hash_hex,
    )
    .map_err(|response| DagDbHandlerError::from_response(*response))?;
    let write_payload_hash =
        exo_gatekeeper::dagdb_gate::context_packet_record_payload_hash(&record)
            .map_err(DagDbHandlerError::from_gatekeeper)?;
    validate_gateway_write_payload(
        service,
        &record.tenant_id,
        &request.requesting_agent_did,
        &write_payload_hash,
        signature,
    )?;
    let invariant_context =
        service.dagdb_invariant_context(&request.tenant_id, &request.requesting_agent_did);
    service
        .persist_context_packet_record(
            &record,
            &request.requesting_agent_did,
            signature,
            invariant_context.as_ref(),
        )
        .await
        .map_err(DagDbHandlerError::from_gatekeeper)?;
    Ok(response)
}

#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
async fn gated_writeback_response(
    service: &DagDbGatekeeperService,
    pool: &sqlx::PgPool,
    request: &DagDbWritebackRequest,
    signature: &str,
    lifecycle_signature: &str,
    continuation_signature: &str,
    lifecycle_approval_did: &str,
    continuation_approval_did: &str,
    lifecycle_approval_timestamp: &str,
    continuation_approval_timestamp: &str,
) -> Result<DagDbWritebackResponse, DagDbHandlerError> {
    let selection_request = selection_request_from_writeback(request).map_err(|error| {
        DagDbHandlerError::from_domain(DomainError::HashMaterial {
            reason: error.to_string(),
        })
    })?;
    let selection = build_persistent_graph_context_selection(pool, &selection_request)
        .await
        .map_err(DagDbHandlerError::from_domain)?;
    let memory_metadata = writeback_usage_event_metadata(request);
    let invariant_context = service.dagdb_invariant_context(
        &selection.selection.tenant_id,
        &request.requesting_agent_did,
    );
    let lifecycle_base = lifecycle_action_from_writeback(request)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    let continuation_base = continuation_record_from_writeback(request)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    prevalidate_writeback_d5_gates(
        service,
        &selection.selection,
        &request.requesting_agent_did,
        &lifecycle_base,
        &continuation_base,
        signature,
        lifecycle_signature,
        continuation_signature,
        lifecycle_approval_did,
        continuation_approval_did,
        lifecycle_approval_timestamp,
        continuation_approval_timestamp,
        invariant_context.as_ref(),
    )?;
    let lifecycle = lifecycle_action_finalization_from_writeback(
        request,
        lifecycle_base,
        lifecycle_signature,
        lifecycle_approval_did,
        lifecycle_approval_timestamp,
    )
    .map_err(|response| DagDbHandlerError::from_response(*response))?;
    let continuation = continuation_record_finalization_from_writeback(
        request,
        continuation_base,
        continuation_signature,
        continuation_approval_did,
        continuation_approval_timestamp,
    )
    .map_err(|response| DagDbHandlerError::from_response(*response))?;
    prevalidate_writeback_response_metadata(request)?;
    let now_epoch_seconds = trusted_gateway_epoch_seconds(pool).await?;
    let summary = persist_writeback_surfaces_atomically(
        pool,
        &selection.selection,
        &memory_metadata,
        WritebackD5Surfaces {
            lifecycle_action: &lifecycle.base,
            lifecycle_approval: &lifecycle.approval,
            continuation: &continuation.base,
            continuation_approval: &continuation.approval,
        },
        now_epoch_seconds,
    )
    .await?;
    match writeback_response_from_persisted(request, &summary, !summary.replayed) {
        Ok(response) => Ok(response),
        Err(response) => Err(DagDbHandlerError::from_response(*response)),
    }
}

#[cfg(feature = "production-db")]
fn prevalidate_writeback_response_metadata(
    request: &DagDbWritebackRequest,
) -> Result<(), DagDbHandlerError> {
    if let Some(summary_text) = request.summary_text.as_deref() {
        sanitize_metadata(MetadataField::Summary, summary_text)
            .map_err(|response| DagDbHandlerError::from_response(*response))?;
    }
    if let Some(keyword_texts) = request.keyword_texts.as_deref() {
        sanitize_keyword_texts(Some(keyword_texts))
            .map_err(|response| DagDbHandlerError::from_response(*response))?;
    }
    writeback_layered_fields(request)
        .map(|_| ())
        .map_err(|response| DagDbHandlerError::from_response(*response))
}

#[cfg(feature = "production-db")]
struct WritebackD5Surfaces<'a> {
    lifecycle_action: &'a LifecycleAction,
    lifecycle_approval: &'a ProductionLifecycleApprovalEvidence,
    continuation: &'a ContinuationRecord,
    continuation_approval: &'a ProductionLifecycleApprovalEvidence,
}

#[cfg(feature = "production-db")]
async fn persist_writeback_surfaces_atomically(
    pool: &sqlx::PgPool,
    selection: &DagDbGraphContextSelectionResponse,
    metadata: &UsageEventMemoryMetadata,
    surfaces: WritebackD5Surfaces<'_>,
    now_epoch_seconds: u64,
) -> Result<DbWriteSummary, DagDbHandlerError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| DagDbHandlerError::from_d5_postgres("writeback transaction", &error))?;
    let result = persist_writeback_surfaces_in_transaction(
        &mut tx,
        selection,
        metadata,
        surfaces,
        now_epoch_seconds,
    )
    .await;
    match result {
        Ok(summary) => {
            tx.commit()
                .await
                .map_err(|error| DagDbHandlerError::from_d5_postgres("writeback commit", &error))?;
            Ok(summary)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                warn!(
                    operation = "persist_writeback_surfaces_atomically",
                    tenant_id = %selection.tenant_id,
                    namespace = %selection.namespace,
                    request_id = %selection.request_id,
                    error = %rollback_error,
                    "failed to rollback transaction after atomic writeback persistence error"
                );
            }
            Err(error)
        }
    }
}

#[cfg(feature = "production-db")]
async fn persist_writeback_surfaces_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    selection: &DagDbGraphContextSelectionResponse,
    metadata: &UsageEventMemoryMetadata,
    surfaces: WritebackD5Surfaces<'_>,
    now_epoch_seconds: u64,
) -> Result<DbWriteSummary, DagDbHandlerError> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut **tx)
        .await
        .map_err(|error| DagDbHandlerError::from_d5_postgres("writeback transaction", &error))?;
    let summary = exo_dag_db_postgres::postgres::kg_context_selection_write::persist_usage_event_to_db_with_metadata_in_transaction(
        tx,
        selection,
        Some(metadata),
    )
    .await
    .map_err(DagDbHandlerError::from_domain)?;

    exo_dag_db_postgres::postgres::lifecycle_action::persist_approved_lifecycle_action_in_transaction(
        tx,
        surfaces.lifecycle_action,
        surfaces.lifecycle_approval,
    )
    .await
    .map_err(|error| DagDbHandlerError::from_d5_postgres("lifecycle action", &error))?;

    exo_dag_db_postgres::postgres::continuation_persistence::persist_approved_continuation_record_in_transaction(
        tx,
        surfaces.continuation,
        surfaces.continuation_approval,
        now_epoch_seconds,
    )
    .await
    .map_err(|error| DagDbHandlerError::from_d5_postgres("continuation", &error))?;
    Ok(summary)
}

#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
fn prevalidate_writeback_d5_gates(
    service: &DagDbGatekeeperService,
    selection: &DagDbGraphContextSelectionResponse,
    agent_did: &str,
    lifecycle_action: &LifecycleAction,
    continuation: &ContinuationRecord,
    signature: &str,
    lifecycle_signature: &str,
    continuation_signature: &str,
    lifecycle_approval_did: &str,
    continuation_approval_did: &str,
    lifecycle_approval_timestamp: &str,
    continuation_approval_timestamp: &str,
    invariant_context: Option<&InvariantContext>,
) -> Result<(), DagDbHandlerError> {
    validate_external_finality_authority(agent_did, lifecycle_approval_did)?;
    validate_external_finality_authority(agent_did, continuation_approval_did)?;

    service
        .validate_usage_event_write(selection, agent_did, signature, invariant_context)
        .map_err(DagDbHandlerError::from_gatekeeper)?;

    let lifecycle_payload_hash_hex = canonical_lifecycle_approval_payload_hash(
        lifecycle_action,
        lifecycle_approval_did,
        lifecycle_action.action_type.as_str(),
        lifecycle_approval_timestamp,
    )
    .map_err(|response| {
        DagDbHandlerError::from_response(*d5_record_rejected_response("lifecycle action", response))
    })?;
    let lifecycle_payload_hash = decode_canonical_approval_hash(&lifecycle_payload_hash_hex)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    validate_gateway_signature_for_registered_did(
        service,
        agent_did,
        lifecycle_approval_did,
        &lifecycle_payload_hash,
        lifecycle_signature,
    )?;

    let continuation_payload_hash_hex = canonical_continuation_approval_payload_hash(
        continuation,
        continuation_approval_did,
        CONTINUATION_FINALITY_PURPOSE,
        continuation_approval_timestamp,
    )
    .map_err(|response| {
        DagDbHandlerError::from_response(*d5_record_rejected_response("continuation", response))
    })?;
    let continuation_payload_hash = decode_canonical_approval_hash(&continuation_payload_hash_hex)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    validate_gateway_signature_for_registered_did(
        service,
        agent_did,
        continuation_approval_did,
        &continuation_payload_hash,
        continuation_signature,
    )
}

#[cfg(feature = "production-db")]
fn validate_gateway_write_payload(
    service: &DagDbGatekeeperService,
    tenant_id: &str,
    agent_did: &str,
    payload_hash: &[u8; 32],
    signature: &str,
) -> Result<(), DagDbHandlerError> {
    validate_gateway_write_payload_for_purpose(
        service,
        tenant_id,
        agent_did,
        ConsentPurpose::Writeback,
        payload_hash,
        signature,
    )
}

#[cfg(feature = "production-db")]
fn validate_gateway_approval_payload(
    service: &DagDbGatekeeperService,
    requesting_agent_did: &str,
    approval_authority_did: &str,
    payload_hash: &[u8; 32],
    signature: &str,
) -> Result<(), DagDbHandlerError> {
    validate_external_finality_authority(requesting_agent_did, approval_authority_did)?;
    validate_gateway_signature_for_registered_did(
        service,
        requesting_agent_did,
        approval_authority_did,
        payload_hash,
        signature,
    )
}

#[cfg(feature = "production-db")]
fn validate_external_finality_authority(
    requesting_agent_did: &str,
    approval_authority_did: &str,
) -> Result<(), DagDbHandlerError> {
    if approval_authority_did.is_empty() || approval_authority_did == requesting_agent_did {
        return Err(DagDbHandlerError::external_finality_denied());
    }
    if exo_core::Did::new(approval_authority_did).is_err() {
        return Err(DagDbHandlerError::external_finality_denied());
    }
    Ok(())
}

#[cfg(feature = "production-db")]
fn validate_gateway_signature_for_registered_did(
    service: &DagDbGatekeeperService,
    requesting_agent_did: &str,
    authority_did: &str,
    payload_hash: &[u8; 32],
    signature: &str,
) -> Result<(), DagDbHandlerError> {
    match exo_gatekeeper::dagdb_gate::verify_production_finality_authority(
        service.identity_registry.as_ref(),
        requesting_agent_did,
        authority_did,
        payload_hash,
        signature,
    ) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(DagDbHandlerError::external_finality_denied()),
    }
}

#[cfg(feature = "production-db")]
fn validate_gateway_write_payload_for_purpose(
    service: &DagDbGatekeeperService,
    tenant_id: &str,
    agent_did: &str,
    purpose: ConsentPurpose,
    payload_hash: &[u8; 32],
    signature: &str,
) -> Result<(), DagDbHandlerError> {
    match verify_write_consent(
        service.consent_engine.as_ref(),
        tenant_id,
        agent_did,
        purpose,
    ) {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            return Err(DagDbHandlerError::from_gatekeeper(
                GatekeeperError::InvariantViolation("ConsentRequired".to_owned()),
            ));
        }
    }

    match verify_write_signature(
        service.identity_registry.as_ref(),
        payload_hash,
        signature,
        agent_did,
    ) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(DagDbHandlerError::from_gatekeeper(
            GatekeeperError::InvariantViolation("ProvenanceVerifiable".to_owned()),
        )),
    }
}

#[cfg(feature = "production-db")]
async fn gated_import_authorization(
    service: &DagDbGatekeeperService,
    pool: &sqlx::PgPool,
    request: &DagDbImportRequest,
    signature: &str,
    persist_usage_event: bool,
    replay_authorization_payload_hash: Option<Hash256>,
) -> Result<Hash256, DagDbHandlerError> {
    let authorization_payload_hash = import_authorization_payload_hash(
        pool,
        request,
        persist_usage_event,
        replay_authorization_payload_hash,
    )
    .await?;
    validate_gateway_write_payload_for_purpose(
        service,
        &request.tenant_id,
        &request.requester_did,
        ConsentPurpose::Import,
        authorization_payload_hash.as_bytes(),
        signature,
    )?;
    Ok(authorization_payload_hash)
}

#[cfg(feature = "production-db")]
async fn gated_export_authorization(
    service: &DagDbGatekeeperService,
    pool: &sqlx::PgPool,
    request: &DagDbExportRequest,
    request_hash: Hash256,
    signature: &str,
    persist_usage_event: bool,
    replay_authorization_payload_hash: Option<Hash256>,
) -> Result<Hash256, DagDbHandlerError> {
    let authorization_payload_hash = export_authorization_payload_hash(
        pool,
        request,
        request_hash,
        persist_usage_event,
        replay_authorization_payload_hash,
    )
    .await?;
    validate_gateway_write_payload_for_purpose(
        service,
        &request.tenant_id,
        &request.requester_did,
        ConsentPurpose::Export,
        authorization_payload_hash.as_bytes(),
        signature,
    )?;
    Ok(authorization_payload_hash)
}

#[cfg(feature = "production-db")]
struct OperationFinalityApproval {
    signature: String,
    authority_did: String,
    timestamp: String,
}

#[cfg(feature = "production-db")]
fn require_operation_finality_approval(
    headers: &HeaderMap,
    operation: &'static str,
    signature_header: &'static str,
    authority_header: &'static str,
    timestamp_header: &'static str,
) -> Result<OperationFinalityApproval, DagDbHandlerError> {
    let signature = required_nonempty_header(headers, signature_header, operation)?;
    let authority_did = required_nonempty_header(headers, authority_header, operation)?;
    let timestamp = required_nonempty_header(headers, timestamp_header, operation)?;
    Ok(OperationFinalityApproval {
        signature,
        authority_did,
        timestamp,
    })
}

#[cfg(feature = "production-db")]
fn required_nonempty_header(
    headers: &HeaderMap,
    header_name: &'static str,
    operation: &'static str,
) -> Result<String, DagDbHandlerError> {
    match header_text(headers, header_name) {
        Some(value) if !value.trim().is_empty() => Ok(value.to_owned()),
        _ => Err(DagDbHandlerError::finality_approval_required(format!(
            "DAG DB {operation} finality requires {header_name} header"
        ))),
    }
}

#[cfg(feature = "production-db")]
fn validate_import_finality_approval(
    service: &DagDbGatekeeperService,
    request: &DagDbImportRequest,
    authorization_payload_hash: Hash256,
    approval: &OperationFinalityApproval,
) -> Result<(), DagDbHandlerError> {
    let finality_payload_hash = import_finality_payload_hash(
        request,
        authorization_payload_hash,
        &approval.authority_did,
        &approval.timestamp,
    )?;
    validate_gateway_approval_payload(
        service,
        &request.requester_did,
        &approval.authority_did,
        finality_payload_hash.as_bytes(),
        &approval.signature,
    )
}

#[cfg(feature = "production-db")]
fn validate_export_finality_approval(
    service: &DagDbGatekeeperService,
    request: &DagDbExportRequest,
    authorization_payload_hash: Hash256,
    approval: &OperationFinalityApproval,
) -> Result<(), DagDbHandlerError> {
    let finality_payload_hash = export_finality_payload_hash(
        request,
        authorization_payload_hash,
        &approval.authority_did,
        &approval.timestamp,
    )?;
    validate_gateway_approval_payload(
        service,
        &request.requester_did,
        &approval.authority_did,
        finality_payload_hash.as_bytes(),
        &approval.signature,
    )
}

#[cfg(feature = "production-db")]
fn import_finality_payload_hash(
    request: &DagDbImportRequest,
    authorization_payload_hash: Hash256,
    approval_authority_did: &str,
    approval_timestamp: &str,
) -> Result<Hash256, DagDbHandlerError> {
    validate_external_finality_authority(&request.requester_did, approval_authority_did)?;
    let request_hash = import_route_request_hash(request).map_err(|response| {
        DagDbHandlerError::from_response(*d5_record_rejected_response(
            "import finality approval",
            format!(
                "import request hash could not be computed: {:?}",
                response.status()
            ),
        ))
    })?;
    operation_finality_payload_hash(
        "dagdb.gateway.import.external_finality",
        &(
            &request.tenant_id,
            &request.namespace,
            &request.requester_did,
            &request.idempotency_key,
            &request.db_set_version,
            &request.source_hash,
            request_hash.to_string(),
            authorization_payload_hash.to_string(),
            approval_authority_did,
            approval_timestamp,
        ),
    )
}

#[cfg(feature = "production-db")]
fn export_finality_payload_hash(
    request: &DagDbExportRequest,
    authorization_payload_hash: Hash256,
    approval_authority_did: &str,
    approval_timestamp: &str,
) -> Result<Hash256, DagDbHandlerError> {
    validate_external_finality_authority(&request.requester_did, approval_authority_did)?;
    let request_body = request_json(request).map_err(|response| {
        DagDbHandlerError::from_response(*d5_record_rejected_response(
            "export finality approval",
            format!(
                "export request could not be canonicalized: {:?}",
                response.status()
            ),
        ))
    })?;
    let request_hash = request_hash(
        EXPORT_ROUTE_IDEMPOTENCY_NAME,
        &request.tenant_id,
        &request.namespace,
        &request_body,
    )
    .map_err(|response| {
        DagDbHandlerError::from_response(*d5_record_rejected_response(
            "export finality approval",
            format!(
                "export request hash could not be computed: {:?}",
                response.status()
            ),
        ))
    })?;
    operation_finality_payload_hash(
        "dagdb.gateway.export.external_finality",
        &(
            &request.tenant_id,
            &request.namespace,
            &request.requester_did,
            &request.idempotency_key,
            &request.db_set_version,
            request_hash.to_string(),
            authorization_payload_hash.to_string(),
            approval_authority_did,
            approval_timestamp,
        ),
    )
}

#[cfg(feature = "production-db")]
fn operation_finality_payload_hash<T>(
    domain: &str,
    material: &T,
) -> Result<Hash256, DagDbHandlerError>
where
    T: Serialize,
{
    let hash_hex = hash_hex(domain, material)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    let hash_bytes = decode_canonical_approval_hash(&hash_hex)
        .map_err(|response| DagDbHandlerError::from_response(*response))?;
    Ok(Hash256::from_bytes(hash_bytes))
}

#[cfg(feature = "production-db")]
fn validate_council_decision_finality(
    request: &DagDbCouncilDecisionRequest,
) -> Result<(), DagDbHandlerError> {
    if request.decision_status == CouncilDecisionStatus::Approved
        && request.subject_id == request.approver_did
    {
        return Err(DagDbHandlerError::external_finality_denied());
    }
    Ok(())
}

#[cfg(feature = "production-db")]
async fn import_authorization_payload_hash(
    pool: &sqlx::PgPool,
    request: &DagDbImportRequest,
    persist_usage_event: bool,
    replay_authorization_payload_hash: Option<Hash256>,
) -> Result<Hash256, DagDbHandlerError> {
    if !persist_usage_event {
        if let Some(payload_hash) = replay_authorization_payload_hash {
            return Ok(payload_hash);
        }
    }
    let selection_request = selection_request_from_import(request);
    let selection = build_persistent_graph_context_selection(pool, &selection_request)
        .await
        .map_err(DagDbHandlerError::from_domain)?;
    let payload_hash = usage_event_payload_hash(&selection.selection)
        .map_err(DagDbHandlerError::from_gatekeeper)?;
    Ok(Hash256::from_bytes(payload_hash))
}

#[cfg(feature = "production-db")]
async fn export_authorization_payload_hash(
    pool: &sqlx::PgPool,
    request: &DagDbExportRequest,
    request_hash: Hash256,
    persist_usage_event: bool,
    replay_authorization_payload_hash: Option<Hash256>,
) -> Result<Hash256, DagDbHandlerError> {
    if !persist_usage_event {
        if let Some(payload_hash) = replay_authorization_payload_hash {
            return Ok(payload_hash);
        }
    }
    let selection_request = selection_request_from_export(request, request_hash);
    let selection = build_persistent_graph_context_selection(pool, &selection_request)
        .await
        .map_err(DagDbHandlerError::from_domain)?;
    let payload_hash = usage_event_payload_hash(&selection.selection)
        .map_err(DagDbHandlerError::from_gatekeeper)?;
    Ok(Hash256::from_bytes(payload_hash))
}

#[cfg(feature = "production-db")]
fn selection_request_from_import(
    request: &DagDbImportRequest,
) -> DagDbGraphContextSelectionRequest {
    DagDbGraphContextSelectionRequest {
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        request_id: request.idempotency_key.clone(),
        task: format!("import:{}", request.source_hash),
        task_hash: request.source_hash.clone(),
        token_budget: 2_048,
        max_memory_refs: 1,
        catalog_hints: Vec::new(),
        requested_memory_ids: Vec::new(),
        force_revalidate: false,
    }
}

#[cfg(feature = "production-db")]
fn selection_request_from_export(
    request: &DagDbExportRequest,
    request_hash: Hash256,
) -> DagDbGraphContextSelectionRequest {
    let max_memory_refs = u32::try_from(request.included_memory_ids.len())
        .unwrap_or(u32::MAX)
        .clamp(1, 64);
    DagDbGraphContextSelectionRequest {
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        request_id: request.idempotency_key.clone(),
        task: format!("export:{}", request.db_set_version),
        task_hash: request_hash.to_string(),
        token_budget: 2_048,
        max_memory_refs,
        catalog_hints: request.included_graph_styles.clone(),
        requested_memory_ids: request.included_memory_ids.clone(),
        force_revalidate: false,
    }
}

#[cfg(feature = "production-db")]
fn graph_context_selection_request_from_packet(
    request: &DagDbContextPacketRequest,
) -> DagDbGraphContextSelectionRequest {
    let task = graph_context_packet_task(request);
    let class_budget = exo_dag_db_postgres::graph_context_selection::task_budget_tokens(&task);
    let token_budget = if request.token_budget == 0 {
        class_budget
    } else {
        request.token_budget
    };
    DagDbGraphContextSelectionRequest {
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        request_id: request.request_id.clone(),
        task,
        task_hash: request.task_hash.clone(),
        token_budget,
        max_memory_refs: token_budget.min(64),
        catalog_hints: Vec::new(),
        requested_memory_ids: Vec::new(),
        force_revalidate: false,
    }
}

#[cfg(feature = "production-db")]
fn graph_context_packet_build_request(
    request: &DagDbContextPacketRequest,
    selection: DagDbGraphContextSelectionResponse,
) -> DagDbGraphContextPacketBuildRequest {
    DagDbGraphContextPacketBuildRequest {
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        request_id: request.request_id.clone(),
        task: graph_context_packet_task(request),
        task_hash: request.task_hash.clone(),
        audit_id: request.idempotency_key.clone(),
        token_budget: selection.token_budget,
        selection,
        import_tracking_status: None,
    }
}

#[cfg(feature = "production-db")]
fn graph_context_packet_task(request: &DagDbContextPacketRequest) -> String {
    request
        .task
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("route:{}", request.route_id))
}

/// Derive the selection task hash signed for a DAG DB writeback usage event.
///
/// Flat legacy writebacks with no searchable metadata sign the raw
/// `answer_hash`. When searchable metadata (`summary_text`, `knowledge_class`)
/// or any layered writeback field is present, all optional metadata and layer
/// fields are bound into the signed material with explicit absent/present
/// encoding so a relayed signature cannot be replayed with mutated searchable
/// metadata or a mutated layer target.
#[cfg(feature = "production-db")]
pub fn writeback_signed_task_hash(
    request: &DagDbWritebackRequest,
) -> Result<String, KgImportError> {
    let metadata_fields_present =
        request.summary_text.is_some() || request.knowledge_class.is_some();
    let layer_fields_present = request.layered_mode.is_some()
        || request.target_layer_path.is_some()
        || request.target_layer_depth.is_some()
        || request.target_layer_reason.is_some();
    if !metadata_fields_present && !layer_fields_present {
        return Ok(request.answer_hash.clone());
    }
    let summary_text =
        writeback_signed_task_hash_part("summary_text", request.summary_text.as_deref());
    let knowledge_class =
        writeback_signed_task_hash_part("knowledge_class", request.knowledge_class.as_deref());
    let layered_mode =
        writeback_signed_task_hash_part("layered_mode", request.layered_mode.as_deref());
    let target_layer_path =
        writeback_signed_task_hash_part("target_layer_path", request.target_layer_path.as_deref());
    let target_layer_depth_value = request.target_layer_depth.map(|depth| depth.to_string());
    let target_layer_depth =
        writeback_signed_task_hash_part("target_layer_depth", target_layer_depth_value.as_deref());
    let target_layer_reason = writeback_signed_task_hash_part(
        "target_layer_reason",
        request.target_layer_reason.as_deref(),
    );
    Ok(exo_dag_db_exchange::kg_import::stable_hash(
        DAGDB_WRITEBACK_SIGNED_TASK_HASH_DOMAIN,
        &[
            &request.answer_hash,
            &summary_text,
            &knowledge_class,
            &layered_mode,
            &target_layer_path,
            &target_layer_depth,
            &target_layer_reason,
        ],
    )?
    .to_string())
}

/// Encode an optional writeback signing field so absent and empty values bind
/// to distinct signed material.
#[cfg(feature = "production-db")]
fn writeback_signed_task_hash_part(field: &str, value: Option<&str>) -> String {
    match value {
        Some(value) => format!("{field}:present:{value}"),
        None => format!("{field}:absent"),
    }
}

/// Build the graph-context selection request whose persisted selection forms
/// the signed payload for a DAG DB writeback.
///
/// Shared with the `dagdb_writeback_sign` binary so the signer and the gateway
/// derive identical signing material, including searchable metadata and layered
/// target binding.
#[cfg(feature = "production-db")]
pub fn selection_request_from_writeback(
    request: &DagDbWritebackRequest,
) -> Result<DagDbGraphContextSelectionRequest, KgImportError> {
    let max_memory_refs = u32::try_from(request.parent_memory_ids.len())
        .unwrap_or(u32::MAX)
        .clamp(1, 64);
    Ok(DagDbGraphContextSelectionRequest {
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        request_id: request.idempotency_key.clone(),
        task: format!("writeback:{}", request.context_packet_id),
        task_hash: writeback_signed_task_hash(request)?,
        token_budget: 2_048,
        max_memory_refs,
        catalog_hints: Vec::new(),
        requested_memory_ids: request.parent_memory_ids.clone(),
        force_revalidate: false,
    })
}

#[cfg(feature = "production-db")]
pub fn writeback_lifecycle_payload_hash(
    request: &DagDbWritebackRequest,
) -> Result<[u8; 32], String> {
    let action = lifecycle_action_from_writeback(request)
        .map_err(|_| "lifecycle action request rejected".to_owned())?;
    exo_gatekeeper::dagdb_gate::lifecycle_action_payload_hash(&action)
        .map_err(|error| error.to_string())
}

#[cfg(feature = "production-db")]
pub fn writeback_continuation_payload_hash(
    request: &DagDbWritebackRequest,
) -> Result<[u8; 32], String> {
    let record = continuation_record_from_writeback(request)
        .map_err(|_| "continuation request rejected".to_owned())?;
    exo_gatekeeper::dagdb_gate::continuation_record_payload_hash(&record)
        .map_err(|error| error.to_string())
}

#[cfg(feature = "production-db")]
pub fn writeback_lifecycle_approval_payload_hash(
    request: &DagDbWritebackRequest,
    approval_authority_did: &str,
    approved_at: &str,
) -> Result<[u8; 32], String> {
    let action = lifecycle_action_from_writeback(request)
        .map_err(|_| "lifecycle action request rejected".to_owned())?;
    let payload_hash = canonical_lifecycle_approval_payload_hash(
        &action,
        approval_authority_did,
        action.action_type.as_str(),
        approved_at,
    )
    .map_err(|error| error.to_string())?;
    approval_hash_hex_to_bytes(&payload_hash)
}

#[cfg(feature = "production-db")]
pub fn writeback_continuation_approval_payload_hash(
    request: &DagDbWritebackRequest,
    approval_authority_did: &str,
    approved_at: &str,
) -> Result<[u8; 32], String> {
    let record = continuation_record_from_writeback(request)
        .map_err(|_| "continuation request rejected".to_owned())?;
    let payload_hash = canonical_continuation_approval_payload_hash(
        &record,
        approval_authority_did,
        CONTINUATION_FINALITY_PURPOSE,
        approved_at,
    )
    .map_err(|error| error.to_string())?;
    approval_hash_hex_to_bytes(&payload_hash)
}

#[cfg(feature = "production-db")]
fn approval_hash_hex_to_bytes(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value)
        .map_err(|error| format!("canonical approval hash must be hex: {error}"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "canonical approval hash must be 32 bytes, got {}",
            bytes.len()
        )
    })
}

#[cfg(feature = "production-db")]
fn default_route_candidate_from_response(
    request: &DagDbRouteRequest,
    response: &DagDbRouteResponse,
) -> Result<DefaultRouteRecord, Box<Response>> {
    let memory_ids = request.requested_memory_ids.clone().unwrap_or_default();
    if memory_ids.is_empty() {
        return Err(d5_record_rejected_response(
            "default route",
            "selected memory refs are required for default-route persistence",
        ));
    }
    let selected_memory_refs = sorted_strings(memory_ids)
        .into_iter()
        .map(|memory_id| {
            Ok(DefaultRouteMemoryRef {
                latest_receipt_hash: hash_hex(
                    "dagdb.gateway.default_route.memory_receipt",
                    &(&response.route_id, &memory_id),
                )?,
                citation_ref: hash_hex(
                    "dagdb.gateway.default_route.citation",
                    &(&response.route_id, &memory_id),
                )?,
                validation_status: "passed".to_owned(),
                memory_id,
            })
        })
        .collect::<Result<Vec<_>, Box<Response>>>()?;
    let created_at = gateway_record_stamp("dagdb.route.created_at", &request.idempotency_key)?;
    let updated_at = gateway_record_stamp("dagdb.route.updated_at", &request.idempotency_key)?;
    Ok(DefaultRouteRecord {
        schema_version: DEFAULT_ROUTE_SCHEMA_VERSION.to_owned(),
        route_id: response.route_id.clone(),
        request_id: request.idempotency_key.clone(),
        tenant_id: request.tenant_id.clone(),
        project_id: gateway_project_id(&request.namespace),
        memory_namespace: request.namespace.clone(),
        status: DefaultRouteStatus::Active,
        route_source: DefaultRouteSource::Persisted,
        policy_ref: request.approved_scope_hash.clone(),
        freshness_ref: request.task_signature_hash.clone(),
        policy_allowed: true,
        freshness_status: RouteFreshnessStatus::Current,
        invalidated: false,
        production_default_route_approval_status: "operator_deferred".to_owned(),
        packet_quality_review_status: "operator_deferred".to_owned(),
        selected_memory_refs,
        created_at,
        updated_at: updated_at.clone(),
    })
}

#[cfg(feature = "production-db")]
fn default_route_record_from_response(
    request: &DagDbRouteRequest,
    response: &DagDbRouteResponse,
    approval_authority_did: &str,
    approval_signature: &str,
    approval_timestamp: &str,
    approval_payload_hash_hex: &str,
) -> Result<DefaultRouteRecord, Box<Response>> {
    let route = default_route_candidate_from_response(request, response)?;
    let updated_at = route.updated_at.clone();
    accept_default_route_record(
        &route,
        &default_route_acceptance_evidence(
            request,
            response,
            approval_authority_did,
            approval_signature,
            approval_timestamp,
            approval_payload_hash_hex,
        )?,
        updated_at,
    )
    .map_err(|error| d5_record_rejected_response("default route", error))
}

#[cfg(feature = "production-db")]
fn context_packet_candidate_from_response(
    request: &DagDbContextPacketRequest,
    response: &DagDbContextPacketResponse,
) -> Result<ContextPacketRecord, Box<Response>> {
    let selected_memory_ids = sorted_strings(
        response
            .memory_refs
            .iter()
            .map(|memory_ref| memory_ref.memory_id.clone())
            .collect(),
    );
    let selected_edge_ids = sorted_strings(
        response
            .selected_graph_edges
            .iter()
            .map(|edge| edge.graph_edge_id.clone())
            .collect(),
    );
    let source_proof_refs = sorted_strings(
        response
            .memory_refs
            .iter()
            .map(|memory_ref| memory_ref.latest_receipt_hash.clone())
            .collect(),
    );
    let binding = ContextPacketRouteBinding {
        route_id: response.route_id.clone(),
        tenant_id: response.tenant_id.clone(),
        project_id: gateway_project_id(&response.namespace),
        memory_namespace: response.namespace.clone(),
        production_default_route_approval_status: "operator_deferred".to_owned(),
        packet_quality_review_status: "operator_deferred".to_owned(),
        route_freshness_status: PacketFreshnessStatus::Current,
    };
    let validation_passed = response.validation_status == ValidationStatus::Passed;
    let packet_request = ContextPacketRequest {
        packet_id: response.context_packet_id.clone(),
        query_hash: request.task_hash.clone(),
        selected_memory_ids,
        selected_edge_ids,
        token_budget: response.token_budget,
        token_estimate: response.token_estimate,
        citation_coverage_bp: if validation_passed { 10_000 } else { 0 },
        validation_coverage_bp: if validation_passed { 10_000 } else { 0 },
        source_proof_refs,
        context_quality: if response.memory_refs.is_empty() {
            DefaultContextQuality::EmptyContext
        } else {
            DefaultContextQuality::UsableContext
        },
        freshness_status: PacketFreshnessStatus::Current,
        validation_status: if validation_passed {
            PacketValidationStatus::Passed
        } else {
            PacketValidationStatus::Failed
        },
        persistence_status: PacketPersistenceStatus::ProofBound,
        fallback_reason: response.selection_warning.clone(),
        raw_body_present: false,
        created_at: gateway_record_stamp(
            "dagdb.context_packet.created_at",
            &request.idempotency_key,
        )?,
    };
    build_context_packet_record(&binding, packet_request)
        .map_err(|error| d5_record_rejected_response("context packet", error))
}

#[cfg(feature = "production-db")]
fn context_packet_record_from_response(
    request: &DagDbContextPacketRequest,
    response: &DagDbContextPacketResponse,
    approval_authority_did: &str,
    approval_signature: &str,
    approval_timestamp: &str,
    approval_payload_hash_hex: &str,
) -> Result<ContextPacketRecord, Box<Response>> {
    let record = context_packet_candidate_from_response(request, response)?;
    accept_context_packet_record(
        &record,
        &context_packet_acceptance_evidence(
            request,
            response,
            &record,
            approval_authority_did,
            approval_signature,
            approval_timestamp,
            approval_payload_hash_hex,
        )?,
    )
    .map_err(|error| d5_record_rejected_response("context packet", error))
}

#[cfg(feature = "production-db")]
fn default_route_acceptance_evidence(
    request: &DagDbRouteRequest,
    response: &DagDbRouteResponse,
    approval_authority_did: &str,
    approval_signature: &str,
    approval_timestamp: &str,
    approval_payload_hash_hex: &str,
) -> Result<DefaultRouteAcceptanceEvidence, Box<Response>> {
    let approved_at = approval_timestamp.to_owned();
    Ok(DefaultRouteAcceptanceEvidence {
        production_default_route_approval_ref: format!(
            "external-production-approval:{}",
            hash_hex(
                "dagdb.gateway.default_route.external_production_approval",
                &(
                    &request.tenant_id,
                    &request.namespace,
                    &request.requesting_agent_did,
                    &response.route_id,
                    &request.idempotency_key,
                    approval_authority_did,
                    approval_payload_hash_hex,
                    approval_signature,
                    &approved_at,
                ),
            )?
        ),
        packet_quality_review_ref: format!(
            "external-packet-quality-review:{}",
            hash_hex(
                "dagdb.gateway.default_route.packet_quality",
                &(
                    &request.tenant_id,
                    &request.namespace,
                    &response.route_id,
                    &request.task_signature_hash,
                    approval_authority_did,
                    approval_payload_hash_hex,
                ),
            )?
        ),
        finality_ref: format!(
            "external-finality:{}",
            hash_hex(
                "dagdb.gateway.default_route.external_finality",
                &(
                    &response.receipt_hash,
                    &request.idempotency_key,
                    approval_authority_did,
                    approval_signature,
                    approval_payload_hash_hex,
                    &approved_at,
                ),
            )?
        ),
        tenant_id: request.tenant_id.clone(),
        memory_namespace: request.namespace.clone(),
        actor_id: request.requesting_agent_did.clone(),
        route_id: response.route_id.clone(),
        route_purpose: DEFAULT_ROUTE_FINALITY_PURPOSE.to_owned(),
        request_id: request.idempotency_key.clone(),
        payload_hash: approval_payload_hash_hex.to_owned(),
        receipt_payload_hash: approval_payload_hash_hex.to_owned(),
        authority_did: approval_authority_did.to_owned(),
        authority_signature: approval_signature.to_owned(),
        approved_at,
    })
}

#[cfg(feature = "production-db")]
fn context_packet_acceptance_evidence(
    request: &DagDbContextPacketRequest,
    response: &DagDbContextPacketResponse,
    record: &ContextPacketRecord,
    approval_authority_did: &str,
    approval_signature: &str,
    approval_timestamp: &str,
    approval_payload_hash_hex: &str,
) -> Result<ContextPacketAcceptanceEvidence, Box<Response>> {
    let approved_at = approval_timestamp.to_owned();
    Ok(ContextPacketAcceptanceEvidence {
        production_default_route_approval_ref: format!(
            "external-production-approval:{}",
            hash_hex(
                "dagdb.gateway.context_packet.external_production_approval",
                &(
                    &request.tenant_id,
                    &request.namespace,
                    &request.requesting_agent_did,
                    &response.route_id,
                    &response.context_packet_id,
                    &request.request_id,
                    approval_authority_did,
                    approval_payload_hash_hex,
                    approval_signature,
                    &approved_at,
                ),
            )?
        ),
        packet_quality_review_ref: format!(
            "external-packet-quality-review:{}",
            hash_hex(
                "dagdb.gateway.context_packet.quality_review",
                &(
                    &request.tenant_id,
                    &request.namespace,
                    &response.context_packet_id,
                    &response.packet_hash,
                    approval_authority_did,
                    approval_payload_hash_hex,
                ),
            )?
        ),
        finality_ref: format!(
            "external-finality:{}",
            hash_hex(
                "dagdb.gateway.context_packet.external_finality",
                &(
                    &response.receipt_hash,
                    &request.idempotency_key,
                    approval_authority_did,
                    approval_signature,
                    approval_payload_hash_hex,
                    &approved_at,
                ),
            )?
        ),
        tenant_id: request.tenant_id.clone(),
        memory_namespace: request.namespace.clone(),
        actor_id: request.requesting_agent_did.clone(),
        route_id: response.route_id.clone(),
        packet_id: response.context_packet_id.clone(),
        route_purpose: CONTEXT_PACKET_FINALITY_PURPOSE.to_owned(),
        request_id: record.idempotency_key.clone(),
        payload_hash: approval_payload_hash_hex.to_owned(),
        receipt_payload_hash: approval_payload_hash_hex.to_owned(),
        authority_did: approval_authority_did.to_owned(),
        authority_signature: approval_signature.to_owned(),
        approved_at,
    })
}

#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
fn production_lifecycle_approval_evidence_from_writeback(
    request: &DagDbWritebackRequest,
    subject_id: &str,
    request_id: &str,
    payload_hash: String,
    authority_did: &str,
    authority_signature: &str,
    route_purpose: &str,
    approved_at: &str,
) -> Result<ProductionLifecycleApprovalEvidence, Box<Response>> {
    let signature_hash = Hash256::digest(authority_signature.as_bytes()).to_string();
    let approval_ref = hash_hex(
        "dagdb.gateway.lifecycle.external_production_approval",
        &(
            &request.tenant_id,
            &request.namespace,
            &request.requesting_agent_did,
            authority_did,
            &request.route_id,
            route_purpose,
            request_id,
            &payload_hash,
            &signature_hash,
            subject_id,
            approved_at,
        ),
    )?;
    Ok(ProductionLifecycleApprovalEvidence {
        evidence_ref: LifecycleEvidenceRef {
            evidence_id: format!("{PRODUCTION_LIFECYCLE_APPROVAL_EVIDENCE_PREFIX}{approval_ref}"),
            receipt_id: hash_hex(
                "dagdb.gateway.lifecycle.external_production_receipt",
                &(
                    &request.validation_report_id,
                    &request.route_id,
                    route_purpose,
                    &signature_hash,
                    approved_at,
                ),
            )?,
            digest: payload_hash.clone(),
            summary_ref: hash_hex(
                "dagdb.gateway.lifecycle.external_production_summary",
                &(
                    &request.idempotency_key,
                    &request.answer_hash,
                    &signature_hash,
                ),
            )?,
            preserved: true,
        },
        tenant_id: request.tenant_id.clone(),
        memory_namespace: request.namespace.clone(),
        actor_id: request.requesting_agent_did.clone(),
        route_id: request.route_id.clone(),
        route_purpose: route_purpose.to_owned(),
        request_id: request_id.to_owned(),
        payload_hash,
        authority_did: authority_did.to_owned(),
        authority_signature: authority_signature.to_owned(),
        approved_at: approved_at.to_owned(),
    })
}

#[cfg(feature = "production-db")]
struct LifecycleActionFinalization {
    base: LifecycleAction,
    approval: ProductionLifecycleApprovalEvidence,
}

#[cfg(feature = "production-db")]
struct ContinuationRecordFinalization {
    base: ContinuationRecord,
    approval: ProductionLifecycleApprovalEvidence,
}

#[cfg(feature = "production-db")]
fn lifecycle_action_finalization_from_writeback(
    request: &DagDbWritebackRequest,
    base: LifecycleAction,
    lifecycle_signature: &str,
    lifecycle_approval_did: &str,
    approved_at: &str,
) -> Result<LifecycleActionFinalization, Box<Response>> {
    let route_purpose = base.action_type.as_str();
    let payload_hash = canonical_lifecycle_approval_payload_hash(
        &base,
        lifecycle_approval_did,
        route_purpose,
        approved_at,
    )
    .map_err(|error| d5_record_rejected_response("lifecycle action", error))?;
    let approval = production_lifecycle_approval_evidence_from_writeback(
        request,
        &base.action_id,
        &base.source_packet_id,
        payload_hash,
        lifecycle_approval_did,
        lifecycle_signature,
        route_purpose,
        approved_at,
    )?;
    approval
        .validate_for_lifecycle_action(&base)
        .map_err(|error| d5_record_rejected_response("lifecycle action", error))?;
    let accepted = base
        .approved_with_evidence(&approval)
        .map_err(|error| d5_record_rejected_response("lifecycle action", error))?;
    accepted
        .validate()
        .map_err(|error| d5_record_rejected_response("lifecycle action", error))?;
    Ok(LifecycleActionFinalization { base, approval })
}

#[cfg(feature = "production-db")]
fn lifecycle_action_from_writeback(
    request: &DagDbWritebackRequest,
) -> Result<LifecycleAction, Box<Response>> {
    let parent_memory_ids = sorted_strings(request.parent_memory_ids.clone());
    if parent_memory_ids.is_empty() {
        return Err(d5_record_rejected_response(
            "lifecycle action",
            "parent memory refs are required for lifecycle persistence",
        ));
    }
    let parent_memory_refs =
        lifecycle_refs_from_memory_ids(&request.tenant_id, &request.namespace, parent_memory_ids);
    let target_memory_id = writeback_target_memory_id(request)?;
    let target_memory_refs = lifecycle_refs_from_memory_ids(
        &request.tenant_id,
        &request.namespace,
        vec![target_memory_id.clone()],
    );
    let action_id = hash_hex(
        "dagdb.gateway.lifecycle_action",
        &(&request.idempotency_key, &request.answer_hash),
    )?;
    let base = LifecycleAction {
        schema_version: PRD17_LIFECYCLE_ACTION_SCHEMA.to_owned(),
        action_id: action_id.clone(),
        action_type: LifecycleActionType::Writeback,
        tenant_id: request.tenant_id.clone(),
        project_id: gateway_project_id(&request.namespace),
        memory_namespace: request.namespace.clone(),
        actor_id: request.requesting_agent_did.clone(),
        source_packet_id: request.context_packet_id.clone(),
        source_receipt_id: request.validation_report_id.clone(),
        parent_memory_ids: parent_memory_refs.clone(),
        target_memory_ids: target_memory_refs.clone(),
        validation_report_id: request.validation_report_id.clone(),
        policy_ref: request.route_id.clone(),
        rollback_ref: LifecycleRollbackRef {
            rollback_id: hash_hex("dagdb.gateway.lifecycle.rollback", &action_id)?,
            action_id: action_id.clone(),
            inverse_action_type: LifecycleActionType::Archive,
            before_refs: parent_memory_refs,
            after_refs: target_memory_refs,
            validation_ref: request.validation_report_id.clone(),
            operator_required: true,
        },
        route_invalidation_event_ids: vec![hash_hex(
            "dagdb.gateway.lifecycle.route_invalidation",
            &(&request.route_id, &request.context_packet_id),
        )?],
        evidence_refs: vec![LifecycleEvidenceRef {
            evidence_id: hash_hex("dagdb.gateway.lifecycle.evidence", &request.answer_hash)?,
            receipt_id: request.validation_report_id.clone(),
            digest: request.answer_hash.clone(),
            summary_ref: hash_hex(
                "dagdb.gateway.lifecycle.summary_ref",
                &(&request.idempotency_key, &target_memory_id),
            )?,
            preserved: true,
        }],
        terminal_state: production_lifecycle_pending_terminal_state()
            .map_err(|error| d5_record_rejected_response("lifecycle action", error))?,
        production_lifecycle_approval: production_lifecycle_pending_approval()
            .map_err(|error| d5_record_rejected_response("lifecycle action", error))?,
        created_at: gateway_record_stamp(
            "dagdb.lifecycle_action.created_at",
            &request.idempotency_key,
        )?,
    };
    base.validate()
        .map_err(|error| d5_record_rejected_response("lifecycle action", error))?;
    Ok(base)
}

#[cfg(feature = "production-db")]
fn continuation_record_finalization_from_writeback(
    request: &DagDbWritebackRequest,
    base: ContinuationRecord,
    continuation_signature: &str,
    continuation_approval_did: &str,
    approved_at: &str,
) -> Result<ContinuationRecordFinalization, Box<Response>> {
    let payload_hash = canonical_continuation_approval_payload_hash(
        &base,
        continuation_approval_did,
        CONTINUATION_FINALITY_PURPOSE,
        approved_at,
    )
    .map_err(|error| d5_record_rejected_response("continuation", error))?;
    let approval = production_lifecycle_approval_evidence_from_writeback(
        request,
        &base.continuation_id,
        &base.task_id,
        payload_hash,
        continuation_approval_did,
        continuation_signature,
        CONTINUATION_FINALITY_PURPOSE,
        approved_at,
    )?;
    approval
        .validate_for_continuation_record(&base)
        .map_err(|error| d5_record_rejected_response("continuation", error))?;
    let accepted = base
        .approved_with_evidence(&approval, 0)
        .map_err(|error| d5_record_rejected_response("continuation", error))?;
    accepted
        .validate(0)
        .map_err(|error| d5_record_rejected_response("continuation", error))?;
    Ok(ContinuationRecordFinalization { base, approval })
}

#[cfg(feature = "production-db")]
fn continuation_record_from_writeback(
    request: &DagDbWritebackRequest,
) -> Result<ContinuationRecord, Box<Response>> {
    let mut memory_ids = request.parent_memory_ids.clone();
    memory_ids.push(writeback_target_memory_id(request)?);
    let memory_refs = lifecycle_refs_from_memory_ids(
        &request.tenant_id,
        &request.namespace,
        sorted_strings(memory_ids),
    );
    let base = ContinuationRecord {
        schema_version: PRD17_CONTINUATION_RECORD_SCHEMA.to_owned(),
        continuation_id: hash_hex(
            "dagdb.gateway.continuation",
            &(&request.idempotency_key, &request.context_packet_id),
        )?,
        task_id: request.idempotency_key.clone(),
        tenant_id: request.tenant_id.clone(),
        project_id: gateway_project_id(&request.namespace),
        memory_namespace: request.namespace.clone(),
        actor_id: request.requesting_agent_did.clone(),
        route_id: request.route_id.clone(),
        summary_ref: writeback_target_memory_id(request)?,
        memory_refs,
        blocker_refs: vec!["production_lifecycle_approval_approved".to_owned()],
        validation_refs: vec![request.validation_report_id.clone()],
        expiry_epoch_seconds: WRITEBACK_CONTINUATION_EXPIRY_EPOCH_SECONDS,
        later_retrieval_status: ContinuationRetrievalStatus::Pending,
        production_lifecycle_approval: production_lifecycle_pending_approval()
            .map_err(|error| d5_record_rejected_response("continuation", error))?,
        created_at: gateway_record_stamp(
            "dagdb.continuation.created_at",
            &request.idempotency_key,
        )?,
    };
    base.validate(0)
        .map_err(|error| d5_record_rejected_response("continuation", error))?;
    Ok(base)
}

#[cfg(feature = "production-db")]
async fn trusted_gateway_epoch_seconds(pool: &sqlx::PgPool) -> Result<u64, DagDbHandlerError> {
    let seconds =
        sqlx::query_scalar::<_, i64>("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT")
            .fetch_one(pool)
            .await
            .map_err(|_| DagDbHandlerError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                error_code: "database_unavailable",
                class: "database",
                message: "DAG DB database operation failed".to_owned(),
                requires_council_review: false,
            })?;
    u64::try_from(seconds).map_err(|_| DagDbHandlerError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        error_code: "database_unavailable",
        class: "database",
        message: "DAG DB database operation failed".to_owned(),
        requires_council_review: false,
    })
}

#[cfg(feature = "production-db")]
fn writeback_target_memory_id(request: &DagDbWritebackRequest) -> Result<String, Box<Response>> {
    hash_hex(
        "dagdb.gateway.writeback.target_memory",
        &(&request.idempotency_key, &request.answer_hash),
    )
}

#[cfg(feature = "production-db")]
fn lifecycle_refs_from_memory_ids(
    tenant_id: &str,
    namespace: &str,
    memory_ids: Vec<String>,
) -> Vec<LifecycleMemoryRef> {
    memory_ids
        .into_iter()
        .map(|memory_id| LifecycleMemoryRef {
            tenant_id: tenant_id.to_owned(),
            project_id: gateway_project_id(namespace),
            memory_namespace: namespace.to_owned(),
            memory_id,
        })
        .collect()
}

#[cfg(feature = "production-db")]
fn production_lifecycle_pending_terminal_state() -> Result<LifecycleTerminalState, serde_json::Error>
{
    serde_json::from_value(json!("operator_deferred"))
}

#[cfg(feature = "production-db")]
fn production_lifecycle_pending_approval() -> Result<ProductionLifecycleApproval, serde_json::Error>
{
    serde_json::from_value(json!("operator_deferred"))
}

#[cfg(feature = "production-db")]
fn gateway_project_id(namespace: &str) -> String {
    namespace.to_owned()
}

#[cfg(feature = "production-db")]
fn gateway_record_stamp(domain: &str, idempotency_key: &str) -> Result<String, Box<Response>> {
    hash_hex(domain, &idempotency_key)
}

#[cfg(feature = "production-db")]
fn decode_canonical_approval_hash(value: &str) -> Result<[u8; 32], Box<Response>> {
    let bytes = hex::decode(value).map_err(|error| {
        d5_record_rejected_response(
            "external finality approval",
            format!("canonical approval hash must be hex: {error}"),
        )
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        d5_record_rejected_response(
            "external finality approval",
            format!(
                "canonical approval hash must be 32 bytes, got {}",
                bytes.len()
            ),
        )
    })
}

#[cfg(feature = "production-db")]
fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

#[cfg(feature = "production-db")]
fn d5_record_rejected_response(
    surface: &'static str,
    detail: impl std::fmt::Display,
) -> Box<Response> {
    Box::new(dagdb_error_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        "metadata_rejected",
        format!("DAG DB {surface} persistence request was rejected: {detail}"),
        true,
    ))
}

#[cfg(feature = "production-db")]
fn writeback_usage_event_metadata(request: &DagDbWritebackRequest) -> UsageEventMemoryMetadata {
    UsageEventMemoryMetadata {
        summary_text: request.summary_text.clone(),
        knowledge_class: request.knowledge_class.clone(),
    }
}

#[cfg(feature = "production-db")]
fn context_packet_response_from_persistent(
    request: &DagDbContextPacketRequest,
    persistent: &exo_dag_db_postgres::persistent_context::PersistentGraphContextPacket,
) -> Result<DagDbContextPacketResponse, Box<Response>> {
    let memory_refs: Vec<ContextPacketMemoryRef> = persistent
        .packet
        .selected_memory_refs
        .iter()
        .map(|memory_ref| ContextPacketMemoryRef {
            memory_id: memory_ref.memory_id.clone(),
            title: memory_ref.title.clone(),
            summary: memory_ref.summary.clone(),
            keywords: Vec::new(),
            latest_receipt_hash: persistent
                .selection
                .selected_memory_receipt_hashes
                .get(&memory_ref.memory_id)
                .cloned()
                .unwrap_or_else(|| Hash256::ZERO.to_string()),
        })
        .collect();
    let token_estimate = persistent.packet.packet_metrics.selected_token_estimate;
    let zero_receipt_hash = Hash256::ZERO.to_string();
    let missing_selected_receipt_hash = !memory_refs.is_empty()
        && memory_refs
            .iter()
            .any(|memory_ref| memory_ref.latest_receipt_hash == zero_receipt_hash);
    let (context_packet_mode, selection_warning) = if memory_refs.is_empty() {
        (
            Some("empty_selection".to_owned()),
            Some("no memory references selected for this task and database state".to_owned()),
        )
    } else if missing_selected_receipt_hash {
        (
            Some("database".to_owned()),
            Some(
                "selected memory reference receipt hash unavailable; validation failed closed"
                    .to_owned(),
            ),
        )
    } else {
        (Some("database".to_owned()), None)
    };
    let layered = context_packet_layered_fields(request, memory_refs.len(), false)?;
    Ok(DagDbContextPacketResponse {
        schema_version: exo_api::dagdb::DAGDB_CONTEXT_PACKET_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        idempotency_key: request.idempotency_key.clone(),
        context_packet_id: persistent.packet.packet_hash.clone(),
        route_id: request.route_id.clone(),
        receipt_hash: hash_hex(
            "dagdb.gateway.receipt",
            &(
                "dagdb.context_packet",
                persistent.packet.packet_hash.as_str(),
            ),
        )
        .unwrap_or_else(|_| Hash256::ZERO.to_string()),
        validation_status: if missing_selected_receipt_hash {
            ValidationStatus::Failed
        } else {
            ValidationStatus::Passed
        },
        council_status: CouncilReviewStatus::NotRequired,
        dag_finality_status: DagFinalityStatus::Pending,
        memory_refs,
        packet_hash: persistent.packet.packet_hash.clone(),
        token_budget: request.token_budget,
        token_estimate,
        created_new: true,
        validation_report_id: None,
        council_decision_id: None,
        context_packet_mode,
        selection_warning,
        layered_mode: layered.layered_mode,
        selected_layers: layered.selected_layers,
        selected_layer_edges: layered.selected_layer_edges,
        layer_budget_report: layered.layer_budget_report,
        flat_fallback_used: layered.flat_fallback_used,
        layered_status: layered.layered_status,
        selected_graph_edges: persistent.packet.selected_graph_edges.clone(),
        citation_refs: persistent.packet.citation_refs.clone(),
        packet_metrics: Some(persistent.packet.packet_metrics.clone()),
        boundaries: Some(persistent.packet.boundaries.clone()),
        packet_markdown: Some(persistent.packet.markdown.clone()),
    })
}

#[cfg(feature = "production-db")]
fn writeback_response_from_persisted(
    request: &DagDbWritebackRequest,
    summary: &exo_dag_db_postgres::postgres::kg_context_selection_write::DbWriteSummary,
    created_new: bool,
) -> Result<DagDbWritebackResponse, Box<Response>> {
    let summary_meta = request
        .summary_text
        .as_deref()
        .map(|text| sanitize_metadata(MetadataField::Summary, text))
        .transpose()?;
    let keywords = request
        .keyword_texts
        .as_deref()
        .map(|texts| sanitize_keyword_texts(Some(texts)))
        .transpose()?;
    let layered = writeback_layered_fields(request)?;
    Ok(DagDbWritebackResponse {
        schema_version: exo_api::dagdb::DAGDB_WRITEBACK_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        idempotency_key: request.idempotency_key.clone(),
        memory_id: hash_hex(
            "dagdb.gateway.writeback.memory",
            &(summary.receipt_hash.as_str(), request.answer_hash.as_str()),
        )?,
        receipt_hash: summary.receipt_hash.clone(),
        validation_status: ValidationStatus::Passed,
        council_status: CouncilReviewStatus::NotRequired,
        dag_finality_status: DagFinalityStatus::Pending,
        risk_class: RiskClass::R1,
        risk_bp: 1_000,
        created_new,
        validation_report_id: Some(request.validation_report_id.clone()),
        council_decision_id: None,
        summary: summary_meta,
        keywords,
        target_layer_path: layered.target_layer_path,
        target_layer_depth: layered.target_layer_depth,
        target_layer_reason: layered.target_layer_reason,
        created_child_layer_id: layered.created_child_layer_id,
        layered_writeback_status: layered.layered_writeback_status,
    })
}

#[cfg(feature = "production-db")]
struct DagDbHandlerError {
    status: StatusCode,
    error_code: &'static str,
    class: &'static str,
    message: String,
    requires_council_review: bool,
}

#[cfg(feature = "production-db")]
impl DagDbHandlerError {
    fn from_domain(error: DomainError) -> Self {
        let (status, error_code, message, requires_council_review) = match &error {
            DomainError::TenantScopeMismatch { .. } => (
                StatusCode::FORBIDDEN,
                "tenant_scope_mismatch",
                error.to_string(),
                false,
            ),
            DomainError::Metadata(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "metadata_rejected",
                error.to_string(),
                true,
            ),
            DomainError::HashMaterial { .. } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB database operation failed".into(),
                false,
            ),
            _ => (
                StatusCode::BAD_REQUEST,
                "invalid_request_shape",
                error.to_string(),
                false,
            ),
        };
        Self {
            status,
            error_code,
            class: "domain",
            message,
            requires_council_review,
        }
    }

    fn from_gatekeeper(error: GatekeeperError) -> Self {
        let failure = GatekeeperFailure::from_error(&error);
        Self {
            status: failure.status,
            error_code: failure.error_code,
            class: failure.class,
            message: failure.message.to_owned(),
            requires_council_review: failure.requires_council_review,
        }
    }

    fn from_response(response: Response) -> Self {
        let status = response.status();
        let (error_code, requires_council_review) = if status == StatusCode::UNPROCESSABLE_ENTITY {
            ("metadata_rejected", true)
        } else {
            ("invalid_request_shape", false)
        };
        Self {
            status,
            error_code,
            class: "response",
            message: "DAG DB writeback request was rejected".into(),
            requires_council_review,
        }
    }

    fn from_d5_postgres(_surface: &'static str, error: &(dyn std::error::Error + 'static)) -> Self {
        if error_source_is_sqlx(error) {
            Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                error_code: "database_unavailable",
                class: "database",
                message: "DAG DB database operation failed".to_owned(),
                requires_council_review: false,
            }
        } else {
            Self {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                error_code: "metadata_rejected",
                class: "metadata",
                message: "DAG DB writeback metadata was rejected".to_owned(),
                requires_council_review: true,
            }
        }
    }

    #[cfg(feature = "production-db")]
    fn external_finality_denied() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error_code: "approval_denied",
            class: "approval",
            message: "DAG DB writeback finality approval was denied".to_owned(),
            requires_council_review: true,
        }
    }

    fn finality_approval_required(message: String) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error_code: "finality_approval_required",
            class: "approval",
            message,
            requires_council_review: true,
        }
    }

    fn status(&self) -> StatusCode {
        self.status
    }

    fn error_code(&self) -> &str {
        self.error_code
    }

    fn class(&self) -> &str {
        self.class
    }

    fn into_response(self) -> Response {
        dagdb_error_response(
            self.status,
            self.error_code,
            &self.message,
            self.requires_council_review,
        )
    }
}

#[cfg(feature = "production-db")]
fn error_source_is_sqlx(mut error: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if error.is::<sqlx::Error>() {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

#[cfg(feature = "production-db")]
struct GatekeeperFailure {
    status: StatusCode,
    error_code: &'static str,
    class: &'static str,
    message: &'static str,
    requires_council_review: bool,
}

#[cfg(feature = "production-db")]
impl GatekeeperFailure {
    fn from_error(error: &GatekeeperError) -> Self {
        match error {
            GatekeeperError::InvariantViolation(detail) if detail.contains("ConsentRequired") => {
                Self {
                    status: StatusCode::FORBIDDEN,
                    error_code: "consent_denied",
                    class: "consent",
                    message: "DAG DB writeback consent was denied",
                    requires_council_review: true,
                }
            }
            GatekeeperError::InvariantViolation(detail)
                if detail.contains("ProvenanceVerifiable") =>
            {
                Self {
                    status: StatusCode::FORBIDDEN,
                    error_code: "provenance_denied",
                    class: "provenance",
                    message: "DAG DB writeback provenance could not be verified",
                    requires_council_review: true,
                }
            }
            GatekeeperError::McpTypedSignatureEncodingFailed { .. } => Self {
                status: StatusCode::FORBIDDEN,
                error_code: "provenance_denied",
                class: "provenance",
                message: "DAG DB writeback provenance could not be verified",
                requires_council_review: true,
            },
            // Metadata sanitization rejections surface inside hash-material
            // assembly; classify them before the database-failure arm so a
            // policy rejection is never reported as database unavailability.
            GatekeeperError::InvariantViolation(detail) if detail.contains("metadata rejected") => {
                Self {
                    status: StatusCode::UNPROCESSABLE_ENTITY,
                    error_code: "metadata_rejected",
                    class: "metadata",
                    message: "DAG DB writeback metadata was rejected",
                    requires_council_review: true,
                }
            }
            GatekeeperError::InvariantViolation(detail)
                if is_gatekeeper_database_failure(detail) =>
            {
                Self {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    error_code: "database_unavailable",
                    class: "database",
                    message: "DAG DB database operation failed",
                    requires_council_review: false,
                }
            }
            GatekeeperError::CapabilityDenied(_) => Self {
                status: StatusCode::FORBIDDEN,
                error_code: "writeback_denied",
                class: "capability",
                message: "DAG DB writeback was denied",
                requires_council_review: true,
            },
            GatekeeperError::InvariantViolation(_) => Self {
                status: StatusCode::FORBIDDEN,
                error_code: "writeback_denied",
                class: "invariant",
                message: "DAG DB writeback was denied",
                requires_council_review: true,
            },
            GatekeeperError::Timeout(_) => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                error_code: "database_unavailable",
                class: "runtime",
                message: "DAG DB database operation failed",
                requires_council_review: false,
            },
            // The authority resolver could not establish consent/identity state
            // (pool absent or a resolver query failed). This is an availability
            // /misconfiguration fault, not a policy denial: surface 5xx so the
            // caller retries rather than treating it as a hard deny.
            GatekeeperError::AuthorityResolverUnavailable(_) => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                error_code: "database_unavailable",
                class: "resolver",
                message: "DAG DB authorization state is unavailable",
                requires_council_review: false,
            },
            GatekeeperError::KernelIntegrityFailure { .. }
            | GatekeeperError::CombinatorError(_)
            | GatekeeperError::HolonError(_)
            | GatekeeperError::McpViolation(_)
            | GatekeeperError::TeeError(_)
            | GatekeeperError::CheckpointError(_)
            | GatekeeperError::Core(_)
            | GatekeeperError::McpAuditChainBroken { .. }
            | GatekeeperError::McpAuditInvalidRecord { .. }
            | GatekeeperError::McpAuditHashEncodingFailed { .. } => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                error_code: "database_unavailable",
                class: "runtime",
                message: "DAG DB database operation failed",
                requires_council_review: false,
            },
        }
    }
}

#[cfg(feature = "production-db")]
fn is_gatekeeper_database_failure(detail: &str) -> bool {
    detail.contains("dagdb write blocked")
        && (detail.contains("hash_material_failed")
            || detail.contains("graph_context_selection_write_postgres")
            // PRD-D5: the four lifecycle/persistence surfaces emit this marker
            // when their backing transaction fails, so a DB outage on those
            // surfaces is classified 503 rather than a policy rejection.
            || detail.contains("surface_database_unavailable"))
}

fn verify_council_authority(
    headers: &HeaderMap,
    request: &DagDbCouncilDecisionRequest,
) -> Option<Response> {
    let Some(auth) = header_text(headers, header::AUTHORIZATION.as_str()) else {
        return Some(council_unauthenticated_response());
    };
    if !auth.starts_with("Bearer ") {
        return Some(council_unauthenticated_response());
    }

    let Some(tenant) = header_text(headers, TENANT_HEADER) else {
        return Some(council_tenant_scope_mismatch_response());
    };
    let Some(namespace) = header_text(headers, NAMESPACE_HEADER) else {
        return Some(council_tenant_scope_mismatch_response());
    };
    if tenant != request.tenant_id || namespace != request.namespace {
        return Some(council_tenant_scope_mismatch_response());
    }

    let required_scope = format!(
        "dagdb:council_decision:{}:{}",
        request.tenant_id, request.namespace
    );
    let has_scope = header_text(headers, AUTHORITY_SCOPE_HEADER)
        .map(|value| value.split([',', ' ']).any(|scope| scope == required_scope))
        .unwrap_or(false);
    if !has_scope {
        return Some(council_authority_required_response());
    }

    None
}

fn verify_dagdb_authority(
    headers: &HeaderMap,
    tenant_id: &str,
    namespace: &str,
    action: &str,
) -> Option<Response> {
    let denial = dagdb_authority_denial(headers, tenant_id, namespace, action)?;
    Some(dagdb_authority_denial_response(denial, false))
}

fn dagdb_authority_denial_response(
    denial: DagDbAuthorityDenial,
    requires_council_review: bool,
) -> Response {
    match denial.error_code {
        "unauthenticated" => dagdb_unauthenticated_response(false),
        "tenant_scope_mismatch" => dagdb_tenant_scope_mismatch_response(requires_council_review),
        "authority_denied" => dagdb_authority_required_response(requires_council_review),
        _ => dagdb_authority_required_response(requires_council_review),
    }
}

/// Identity established by binding a bearer token to a live DB-backed session.
///
/// `NoPool` means no pool is configured, so there is no persisted actor to bind
/// to. Callers must still fail closed before returning any claim-producing
/// response. `Authenticated(actor_did)` is the cryptographically-established
/// session actor that downstream authorization must bind request-supplied
/// identity and scope against.
#[cfg(feature = "production-db")]
enum DagDbSessionActor {
    /// No pool configured; no persisted session identity exists.
    NoPool,
    /// Bearer token resolved to a live session owned by this actor DID.
    Authenticated(String),
}

/// Bind the bearer token to a live DB-backed session whose user owns the
/// requested tenant. The header-shape gate alone accepts any `Bearer` string;
/// whenever a pool is configured (persisted tenant data is reachable), the
/// token must resolve to an unrevoked, unexpired `sessions` row whose user
/// profile matches the requested `tenant_id`. Session expiry is judged by the
/// trusted database clock, never caller time. Fails closed on lookup errors.
///
/// On success returns the session's authenticated `actor_did` so callers can
/// bind request-supplied identity (`requester_did`) and capability scope to the
/// principal that actually holds the session, instead of trusting
/// caller-controlled request fields or headers.
#[cfg(feature = "production-db")]
async fn verify_dagdb_session_authority(
    ctx: &DagDbRouteContext,
    headers: &HeaderMap,
    route_name: &'static str,
    tenant_id: &str,
) -> Result<DagDbSessionActor, Response> {
    let Some(pool) = ctx.pool.as_ref() else {
        return Ok(DagDbSessionActor::NoPool);
    };
    let token = header_text(headers, header::AUTHORIZATION.as_str())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let Some(token) = token else {
        warn!(
            route = route_name,
            tenant_id = %tenant_id,
            "DAG DB session binding failed closed: empty bearer token"
        );
        return Err(dagdb_unauthenticated_response(false));
    };
    let row = sqlx::query(
        "SELECT s.actor_did, u.tenant_id AS user_tenant_id \
         FROM sessions s \
         LEFT JOIN users u ON u.did = s.actor_did \
         WHERE s.token = $1 \
           AND s.revoked = FALSE \
           AND s.expires_at > FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT",
    )
    .bind(token)
    .fetch_optional(pool)
    .await;
    match row {
        Err(_) => {
            warn!(
                route = route_name,
                tenant_id = %tenant_id,
                "DAG DB session binding failed closed: session lookup unavailable"
            );
            Err(dagdb_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "session_lookup_unavailable",
                "DAG DB session validation is unavailable",
                false,
            ))
        }
        Ok(None) => {
            warn!(
                route = route_name,
                tenant_id = %tenant_id,
                "DAG DB session binding failed closed: no live session for bearer token"
            );
            Err(dagdb_unauthenticated_response(false))
        }
        Ok(Some(row)) => {
            let user_tenant: Option<String> = row.try_get("user_tenant_id").ok();
            if user_tenant.as_deref() != Some(tenant_id) {
                warn!(
                    route = route_name,
                    tenant_id = %tenant_id,
                    "DAG DB session binding failed closed: session user tenant mismatch"
                );
                return Err(dagdb_tenant_scope_mismatch_response(false));
            }
            let actor_did: Option<String> = row.try_get("actor_did").ok();
            match actor_did.filter(|did| !did.is_empty()) {
                Some(actor_did) => Ok(DagDbSessionActor::Authenticated(actor_did)),
                None => {
                    warn!(
                        route = route_name,
                        tenant_id = %tenant_id,
                        "DAG DB session binding failed closed: session row missing actor_did"
                    );
                    Err(dagdb_unauthenticated_response(false))
                }
            }
        }
    }
}

/// Reject when the request-supplied `requester_did` does not match the
/// cryptographically-established session actor. The session actor (not a
/// caller-controlled request field or `x-exo-authority-scope` header) is the
/// only trusted principal; a writeback-authorized agent must not be able to
/// self-assert another `requester_did` to reach the import/export adapters.
///
/// When no pool is configured there is no persisted session identity to bind
/// against. The caller must still reject before returning any claim-producing
/// response from the no-pool path.
#[cfg(feature = "production-db")]
fn bind_requester_to_session_actor(
    session_actor: &DagDbSessionActor,
    route_name: &'static str,
    tenant_id: &str,
    requester_did: &str,
) -> Result<(), Box<Response>> {
    let DagDbSessionActor::Authenticated(actor_did) = session_actor else {
        return Ok(());
    };
    // Shape validation precedes authorization: a malformed requester_did is a
    // bad request (400 invalid_request_shape from the handler's own
    // validation), not a forbidden actor mismatch. Skip the actor binding for
    // a requester_did that is not a well-formed DID and let the downstream
    // handler reject it; a well-formed DID that does not match the session
    // actor is still bound/denied below.
    if exo_core::Did::new(requester_did).is_err() {
        return Ok(());
    }
    if actor_did == requester_did {
        return Ok(());
    }
    warn!(
        route = route_name,
        tenant_id = %tenant_id,
        "DAG DB authority failed closed: requester_did does not match session actor"
    );
    Err(Box::new(dagdb_error_response(
        StatusCode::FORBIDDEN,
        "requester_actor_mismatch",
        "DAG DB requester_did does not match the authenticated session actor",
        false,
    )))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DagDbAuthorityDenial {
    status: StatusCode,
    error_code: &'static str,
}

fn dagdb_authority_denial(
    headers: &HeaderMap,
    tenant_id: &str,
    namespace: &str,
    action: &str,
) -> Option<DagDbAuthorityDenial> {
    let Some(auth) = header_text(headers, header::AUTHORIZATION.as_str()) else {
        return Some(DagDbAuthorityDenial {
            status: StatusCode::UNAUTHORIZED,
            error_code: "unauthenticated",
        });
    };
    if !auth.starts_with("Bearer ") {
        return Some(DagDbAuthorityDenial {
            status: StatusCode::UNAUTHORIZED,
            error_code: "unauthenticated",
        });
    }

    let Some(tenant) = header_text(headers, TENANT_HEADER) else {
        return Some(DagDbAuthorityDenial {
            status: StatusCode::FORBIDDEN,
            error_code: "tenant_scope_mismatch",
        });
    };
    let Some(header_namespace) = header_text(headers, NAMESPACE_HEADER) else {
        return Some(DagDbAuthorityDenial {
            status: StatusCode::FORBIDDEN,
            error_code: "tenant_scope_mismatch",
        });
    };
    if tenant != tenant_id || header_namespace != namespace {
        return Some(DagDbAuthorityDenial {
            status: StatusCode::FORBIDDEN,
            error_code: "tenant_scope_mismatch",
        });
    }

    let required_scope = format!("{action}:{tenant_id}:{namespace}");
    let has_scope = header_text(headers, AUTHORITY_SCOPE_HEADER)
        .map(|value| value.split([',', ' ']).any(|scope| scope == required_scope))
        .unwrap_or(false);
    if !has_scope {
        return Some(DagDbAuthorityDenial {
            status: StatusCode::FORBIDDEN,
            error_code: "authority_denied",
        });
    }

    None
}

fn log_dagdb_authority_denial(
    route_name: &'static str,
    headers: &HeaderMap,
    tenant_id: &str,
    namespace: &str,
    action: &str,
) {
    if let Some(denial) = dagdb_authority_denial(headers, tenant_id, namespace, action) {
        warn!(
            route = route_name,
            status = denial.status.as_u16(),
            error_code = denial.error_code,
            tenant_id = %tenant_id,
            namespace = %namespace,
            "DAG DB authority check failed closed"
        );
    }
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn required_query_text(query: &QueryParams, name: &str) -> String {
    query.get(name).cloned().unwrap_or_default()
}

fn optional_query_bool(query: &QueryParams, name: &str) -> Option<bool> {
    query.get(name).map(|value| value == "true")
}

fn dagdb_unauthenticated_response(requires_council_review: bool) -> Response {
    dagdb_error_response(
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "DAG DB route requires bearer authentication",
        requires_council_review,
    )
}

fn dagdb_tenant_scope_mismatch_response(requires_council_review: bool) -> Response {
    dagdb_error_response(
        StatusCode::FORBIDDEN,
        "tenant_scope_mismatch",
        "DAG DB tenant or namespace does not match the authorized scope",
        requires_council_review,
    )
}

fn dagdb_authority_required_response(requires_council_review: bool) -> Response {
    dagdb_error_response(
        StatusCode::FORBIDDEN,
        "authority_denied",
        "DAG DB route requires matching authority scope",
        requires_council_review,
    )
}

fn dagdb_invalid_json_request_response(
    route_name: &'static str,
    rejection: &JsonRejection,
) -> Response {
    warn!(
        route = route_name,
        status = 400,
        error_code = "invalid_request_shape",
        rejection_category = dagdb_json_rejection_category(rejection),
        "DAG DB JSON request rejected"
    );
    dagdb_error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request_shape",
        "DAG DB request JSON body is malformed or contains unsupported fields",
        false,
    )
}

fn dagdb_json_rejection_category(rejection: &JsonRejection) -> &'static str {
    match rejection {
        JsonRejection::JsonDataError(_) => "json_data_error",
        JsonRejection::JsonSyntaxError(_) => "json_syntax_error",
        JsonRejection::MissingJsonContentType(_) => "missing_json_content_type",
        JsonRejection::BytesRejection(_) => "bytes_rejection",
        _ => "json_rejection",
    }
}

fn intake_response_from_request(
    request: DagDbIntakeRequest,
    route_name: &str,
) -> Result<DagDbIntakeResponse, Box<Response>> {
    let title = sanitize_metadata(MetadataField::Title, &request.title_text)?;
    let summary = sanitize_metadata(MetadataField::Summary, &request.summary_text)?;
    let keywords = sanitize_keyword_texts(request.keyword_texts.as_deref())?;
    let mut redacted_body = request_json(&request)?;
    replace_metadata(
        &mut redacted_body,
        "title_text",
        "title",
        request_json(&title)?,
    )?;
    replace_metadata(
        &mut redacted_body,
        "summary_text",
        "summary",
        request_json(&summary)?,
    )?;
    replace_metadata(
        &mut redacted_body,
        "keyword_texts",
        "keywords",
        request_json(&keywords)?,
    )?;
    let request_hash = request_hash(
        route_name,
        &request.tenant_id,
        &request.namespace,
        &redacted_body,
    )?;
    let memory_id = hash_hex(
        "dagdb.gateway.memory",
        &(&request_hash, &request.payload_hash),
    )?;
    Ok(DagDbIntakeResponse {
        schema_version: exo_api::dagdb::DAGDB_INTAKE_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        idempotency_key: request.idempotency_key,
        memory_id,
        receipt_hash: receipt_hash(route_name, request_hash)?,
        validation_status: ValidationStatus::Pending,
        council_status: CouncilReviewStatus::NotRequired,
        dag_finality_status: DagFinalityStatus::Pending,
        risk_class: RiskClass::R1,
        risk_bp: 1_000,
        created_new: true,
        title,
        summary,
        keywords,
        validation_report_id: None,
        council_decision_id: None,
        duplicate_of_memory_id: None,
    })
}

#[cfg(any(feature = "production-db", test))]
fn route_response_from_request(
    request: DagDbRouteRequest,
    route_name: &str,
) -> Result<DagDbRouteResponse, Box<Response>> {
    let redacted_body = request_json(&request)?;
    let request_hash = request_hash(
        route_name,
        &request.tenant_id,
        &request.namespace,
        &redacted_body,
    )?;
    let selected_memory_ids = request.requested_memory_ids.clone().unwrap_or_default();
    Ok(DagDbRouteResponse {
        schema_version: exo_api::dagdb::DAGDB_ROUTE_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        idempotency_key: request.idempotency_key,
        route_id: hash_hex(
            "dagdb.gateway.route",
            &(&request_hash, &request.task_signature_hash),
        )?,
        receipt_hash: receipt_hash(route_name, request_hash)?,
        validation_status: ValidationStatus::Passed,
        council_status: CouncilReviewStatus::NotRequired,
        route_status: RouteStatus::Active,
        dag_finality_status: DagFinalityStatus::Pending,
        selected_memory_ids,
        route_score_bp: 0,
        token_budget: request.token_budget,
        token_estimate: 0,
        stale_at: "86400000:0".to_owned(),
        created_new: true,
        validation_report_id: None,
        council_decision_id: None,
        rejected_memory_ids: Some(Vec::new()),
    })
}

#[cfg_attr(not(any(test, feature = "production-db")), allow(dead_code))]
struct LayeredContextFields {
    layered_mode: Option<String>,
    selected_layers: Option<Vec<ContextPacketLayerRef>>,
    selected_layer_edges: Option<Vec<ContextPacketLayerEdgeRef>>,
    layer_budget_report: Option<ContextPacketLayerBudgetReport>,
    flat_fallback_used: Option<bool>,
    layered_status: Option<String>,
}

#[cfg(any(test, feature = "production-db"))]
struct LayeredWritebackFields {
    target_layer_path: Option<String>,
    target_layer_depth: Option<u32>,
    target_layer_reason: Option<String>,
    created_child_layer_id: Option<String>,
    layered_writeback_status: Option<String>,
}

#[cfg_attr(not(any(test, feature = "production-db")), allow(dead_code))]
fn no_layered_context_fields() -> LayeredContextFields {
    LayeredContextFields {
        layered_mode: None,
        selected_layers: None,
        selected_layer_edges: None,
        layer_budget_report: None,
        flat_fallback_used: None,
        layered_status: None,
    }
}

#[cfg(any(test, feature = "production-db"))]
fn no_layered_writeback_fields() -> LayeredWritebackFields {
    LayeredWritebackFields {
        target_layer_path: None,
        target_layer_depth: None,
        target_layer_reason: None,
        created_child_layer_id: None,
        layered_writeback_status: None,
    }
}

#[cfg_attr(not(any(test, feature = "production-db")), allow(dead_code))]
fn invalid_layered_request(error_code: &'static str, message: &'static str) -> Box<Response> {
    Box::new(dagdb_error_response(
        StatusCode::BAD_REQUEST,
        error_code,
        message,
        false,
    ))
}

/// Validate the optional typed-knowledge class on a writeback, failing closed.
///
/// A writeback with no `knowledge_class` is plain usage-event telemetry and is
/// accepted unchanged. When a class is present it must be one of the closed
/// `DAGDB_KNOWLEDGE_CLASSES` set and the writeback must carry a non-empty
/// `summary_text` (knowledge writebacks must be content-bearing). The class
/// describes WHAT the memory is and never influences placement/organization.
fn validate_writeback_knowledge_class(
    request: &DagDbWritebackRequest,
) -> Result<(), Box<Response>> {
    let Some(class) = request.knowledge_class.as_deref() else {
        return Ok(());
    };
    if !DAGDB_KNOWLEDGE_CLASSES.contains(&class) {
        return Err(Box::new(dagdb_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_knowledge_class",
            "DAG DB knowledge_class must be one of decision, finding, fix, constraint, handoff",
            false,
        )));
    }
    let summary_is_content_bearing = request
        .summary_text
        .as_deref()
        .map(|text| !text.trim().is_empty())
        .unwrap_or(false);
    if !summary_is_content_bearing {
        return Err(Box::new(dagdb_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "knowledge_class_requires_summary",
            "DAG DB knowledge writebacks require a non-empty summary_text",
            false,
        )));
    }
    Ok(())
}

#[cfg_attr(not(any(test, feature = "production-db")), allow(dead_code))]
fn layered_mode_value(layered_mode: &Option<String>) -> Result<&str, Box<Response>> {
    let mode = layered_mode.as_deref().unwrap_or("off");
    if DAGDB_LAYERED_MODES.contains(&mode) {
        Ok(mode)
    } else {
        Err(invalid_layered_request(
            "invalid_layered_mode",
            "DAG DB layered_mode must be off, auto, or required",
        ))
    }
}

#[cfg_attr(not(any(test, feature = "production-db")), allow(dead_code))]
fn validate_max_layer_depth(max_layer_depth: Option<u32>) -> Result<u32, Box<Response>> {
    let depth = max_layer_depth.unwrap_or(2);
    if depth <= DAGDB_MAX_LAYER_DEPTH {
        Ok(depth)
    } else {
        Err(invalid_layered_request(
            "invalid_request_shape",
            "DAG DB max_layer_depth exceeds gateway limit",
        ))
    }
}

/// Validate the depth-on-demand reserve (D1-S4), like the depth param.
///
/// Absent defaults to `0` (no reserve, byte-identical to the leftover-budget
/// path). A reserve above the runtime's half-budget bound fails closed so the
/// breadth pass always keeps a majority of the token budget.
#[cfg(feature = "production-db")]
fn validate_drilldown_reserve_bp(drilldown_reserve_bp: Option<u32>) -> Result<u32, Box<Response>> {
    let reserve = drilldown_reserve_bp.unwrap_or(0);
    if reserve <= DAGDB_MAX_DRILLDOWN_RESERVE_BP {
        Ok(reserve)
    } else {
        Err(invalid_layered_request(
            "invalid_request_shape",
            "DAG DB drilldown_reserve_bp exceeds gateway limit",
        ))
    }
}

#[cfg_attr(not(any(test, feature = "production-db")), allow(dead_code))]
fn layer_path_depth(layer_path: &str) -> Result<u32, Box<Response>> {
    validate_layer_path(layer_path)?;
    u32::try_from(layer_path.split('/').count().saturating_sub(1)).map_err(|_| {
        invalid_layered_request(
            "invalid_layer_path_depth",
            "DAG DB layer_path depth exceeds gateway limit",
        )
    })
}

#[cfg_attr(not(any(test, feature = "production-db")), allow(dead_code))]
fn validate_layer_path(layer_path: &str) -> Result<(), Box<Response>> {
    if layer_path.is_empty()
        || layer_path.starts_with('/')
        || layer_path.ends_with('/')
        || layer_path.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.chars().any(|character| {
                    character.is_control() || character.is_whitespace() || character == '\\'
                })
        })
    {
        return Err(invalid_layered_request(
            "invalid_request_shape",
            "DAG DB target_layer_path must be a relative layer path",
        ));
    }
    Ok(())
}

#[cfg(any(test, feature = "production-db"))]
fn validate_layer_reason(reason: &str) -> Result<(), Box<Response>> {
    if reason.trim().is_empty()
        || reason.len() > 128
        || reason.chars().any(|character| character.is_control())
    {
        return Err(invalid_layered_request(
            "invalid_request_shape",
            "DAG DB target_layer_reason must be a bounded non-empty reason",
        ));
    }
    Ok(())
}

#[cfg_attr(not(any(test, feature = "production-db")), allow(dead_code))]
fn context_packet_layered_fields(
    request: &DagDbContextPacketRequest,
    selected_ref_count: usize,
    verified_layer_evidence: bool,
) -> Result<LayeredContextFields, Box<Response>> {
    let explicit_layer_request = request.layered_mode.is_some()
        || request.max_layer_depth.is_some()
        || request.require_layer_evidence.unwrap_or(false);
    if !explicit_layer_request {
        return Ok(no_layered_context_fields());
    }

    let mode = layered_mode_value(&request.layered_mode)?;
    let max_layer_depth = validate_max_layer_depth(request.max_layer_depth)?;
    let require_layer_evidence =
        request.require_layer_evidence.unwrap_or(false) || mode == "required";
    if mode == "off" {
        if require_layer_evidence {
            return Err(invalid_layered_request(
                "invalid_request_shape",
                "DAG DB required layer evidence conflicts with layered_mode off",
            ));
        }
        return Ok(LayeredContextFields {
            layered_mode: Some("off".to_owned()),
            selected_layers: Some(Vec::new()),
            selected_layer_edges: Some(Vec::new()),
            layer_budget_report: Some(ContextPacketLayerBudgetReport {
                layered_mode: "off".to_owned(),
                max_layer_depth,
                required_layer_evidence: false,
                budget_status: "not_requested".to_owned(),
            }),
            flat_fallback_used: Some(false),
            layered_status: Some("off".to_owned()),
        });
    }

    if selected_ref_count == 0 || !verified_layer_evidence {
        if require_layer_evidence {
            return Err(invalid_layered_request(
                "required_layer_evidence_missing",
                "DAG DB required layered context requires selected layer evidence",
            ));
        }
        return Ok(LayeredContextFields {
            layered_mode: Some(mode.to_owned()),
            selected_layers: Some(Vec::new()),
            selected_layer_edges: Some(Vec::new()),
            layer_budget_report: Some(ContextPacketLayerBudgetReport {
                layered_mode: mode.to_owned(),
                max_layer_depth,
                required_layer_evidence: false,
                budget_status: "flat_fallback_no_layer_evidence".to_owned(),
            }),
            flat_fallback_used: Some(true),
            layered_status: Some("flat_fallback_no_layer_evidence".to_owned()),
        });
    }

    let root_path = "root".to_owned();
    let child_path = format!("root/context-packet/{}", request.route_id);
    let child_depth = layer_path_depth(&child_path)?;
    if child_depth > max_layer_depth {
        return Err(invalid_layered_request(
            "invalid_request_shape",
            "DAG DB layered context exceeds max_layer_depth",
        ));
    }
    let root_layer_id = hash_hex("dagdb.gateway.layer", &root_path)?;
    let child_layer_id = hash_hex("dagdb.gateway.layer", &child_path)?;
    let layer_edge_id = hash_hex(
        "dagdb.gateway.layer_edge",
        &(&root_layer_id, &child_layer_id, "contains_subgraph"),
    )?;
    let selected_ref_count = u32::try_from(selected_ref_count).unwrap_or(u32::MAX);
    Ok(LayeredContextFields {
        layered_mode: Some(mode.to_owned()),
        selected_layers: Some(vec![
            ContextPacketLayerRef {
                layer_id: root_layer_id.clone(),
                layer_path: root_path,
                layer_depth: 0,
                layer_kind: "root".to_owned(),
                selected_ref_count,
            },
            ContextPacketLayerRef {
                layer_id: child_layer_id.clone(),
                layer_path: child_path,
                layer_depth: child_depth,
                layer_kind: "context_packet".to_owned(),
                selected_ref_count,
            },
        ]),
        selected_layer_edges: Some(vec![ContextPacketLayerEdgeRef {
            layer_edge_id,
            from_layer_id: root_layer_id,
            to_layer_id: child_layer_id,
            edge_kind: "contains_subgraph".to_owned(),
        }]),
        layer_budget_report: Some(ContextPacketLayerBudgetReport {
            layered_mode: mode.to_owned(),
            max_layer_depth,
            required_layer_evidence: require_layer_evidence,
            budget_status: "within_layer_budget".to_owned(),
        }),
        flat_fallback_used: Some(false),
        layered_status: Some("layered_evidence_selected".to_owned()),
    })
}

#[cfg(any(test, feature = "production-db"))]
fn writeback_layered_fields(
    request: &DagDbWritebackRequest,
) -> Result<LayeredWritebackFields, Box<Response>> {
    let explicit_layer_request = request.layered_mode.is_some()
        || request.target_layer_path.is_some()
        || request.target_layer_depth.is_some()
        || request.target_layer_reason.is_some();
    if !explicit_layer_request {
        return Ok(no_layered_writeback_fields());
    }

    let mode = layered_mode_value(&request.layered_mode)?;
    let target_present = request.target_layer_path.is_some()
        || request.target_layer_depth.is_some()
        || request.target_layer_reason.is_some();
    if mode == "off" {
        if target_present {
            return Err(invalid_layered_request(
                "invalid_request_shape",
                "DAG DB target layer fields require layered_mode auto or required",
            ));
        }
        return Ok(no_layered_writeback_fields());
    }

    let Some(target_layer_path) = request.target_layer_path.as_deref() else {
        return Err(invalid_layered_request(
            "invalid_request_shape",
            "DAG DB layered writeback requires target_layer_path",
        ));
    };
    let Some(target_layer_depth) = request.target_layer_depth else {
        return Err(invalid_layered_request(
            "invalid_request_shape",
            "DAG DB layered writeback requires target_layer_depth",
        ));
    };
    let Some(target_layer_reason) = request.target_layer_reason.as_deref() else {
        return Err(invalid_layered_request(
            "invalid_request_shape",
            "DAG DB layered writeback requires target_layer_reason",
        ));
    };

    let calculated_depth = layer_path_depth(target_layer_path)?;
    if calculated_depth != target_layer_depth || target_layer_depth > DAGDB_MAX_LAYER_DEPTH {
        return Err(invalid_layered_request(
            "invalid_request_shape",
            "DAG DB target_layer_depth must match target_layer_path",
        ));
    }
    validate_layer_reason(target_layer_reason)?;

    Ok(LayeredWritebackFields {
        target_layer_path: Some(target_layer_path.to_owned()),
        target_layer_depth: Some(target_layer_depth),
        target_layer_reason: Some(target_layer_reason.to_owned()),
        created_child_layer_id: Some(hash_hex(
            "dagdb.gateway.writeback.layer",
            &target_layer_path,
        )?),
        layered_writeback_status: Some("layer_target_recorded".to_owned()),
    })
}

#[allow(dead_code)]
fn context_packet_response_from_request(
    request: DagDbContextPacketRequest,
    route_name: &str,
) -> Result<DagDbContextPacketResponse, Box<Response>> {
    let layered = context_packet_layered_fields(&request, 0, false)?;
    let redacted_body = request_json(&request)?;
    let request_hash = request_hash(
        route_name,
        &request.tenant_id,
        &request.namespace,
        &redacted_body,
    )?;
    Ok(DagDbContextPacketResponse {
        schema_version: exo_api::dagdb::DAGDB_CONTEXT_PACKET_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        idempotency_key: request.idempotency_key,
        context_packet_id: hash_hex(
            "dagdb.gateway.context_packet",
            &(&request_hash, &request.route_id),
        )?,
        route_id: request.route_id,
        receipt_hash: receipt_hash(route_name, request_hash)?,
        validation_status: ValidationStatus::Pending,
        council_status: CouncilReviewStatus::NotRequired,
        dag_finality_status: DagFinalityStatus::Pending,
        memory_refs: Vec::new(),
        packet_hash: hash_hex("dagdb.gateway.packet", &request_hash)?,
        token_budget: request.token_budget,
        token_estimate: 0,
        created_new: true,
        validation_report_id: None,
        council_decision_id: None,
        context_packet_mode: Some("scaffold".to_owned()),
        selection_warning: Some(
            "gateway database mode unavailable; scaffold packet has no selected memory refs"
                .to_owned(),
        ),
        layered_mode: layered.layered_mode,
        selected_layers: layered.selected_layers,
        selected_layer_edges: layered.selected_layer_edges,
        layer_budget_report: layered.layer_budget_report,
        flat_fallback_used: layered.flat_fallback_used,
        layered_status: layered.layered_status,
        selected_graph_edges: Vec::new(),
        citation_refs: Vec::new(),
        packet_metrics: None,
        boundaries: None,
        packet_markdown: None,
    })
}

fn validate_response_from_request(
    request: DagDbValidateRequest,
    route_name: &str,
) -> Result<DagDbValidateResponse, Box<Response>> {
    let notes = sanitize_optional_metadata(
        MetadataField::ValidationNotes,
        request.validation_notes_text.as_deref(),
    )?;
    let mut redacted_body = request_json(&request)?;
    replace_metadata(
        &mut redacted_body,
        "validation_notes_text",
        "validation_notes",
        request_json(&notes)?,
    )?;
    let request_hash = request_hash(
        route_name,
        &request.tenant_id,
        &request.namespace,
        &redacted_body,
    )?;
    Ok(DagDbValidateResponse {
        schema_version: exo_api::dagdb::DAGDB_VALIDATE_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        idempotency_key: request.idempotency_key,
        validation_report_id: hash_hex(
            "dagdb.gateway.validation",
            &(&request_hash, &request.subject_id),
        )?,
        subject_kind: request.subject_kind,
        subject_id: request.subject_id,
        receipt_hash: receipt_hash(route_name, request_hash)?,
        validation_status: request.requested_status.unwrap_or(ValidationStatus::Passed),
        council_status: CouncilReviewStatus::NotRequired,
        risk_class: RiskClass::R1,
        risk_bp: 1_000,
        decision: ValidationDecision::Allow,
        created_new: true,
        council_decision_id: request.council_decision_id,
        contradictory_report_ids: Some(Vec::new()),
        notes,
    })
}

#[cfg(feature = "production-db")]
async fn persist_idempotent_intake_response(
    pool: &sqlx::PgPool,
    request: DagDbIntakeRequest,
) -> Response {
    let response_seed =
        match intake_response_from_request(request.clone(), INTAKE_ROUTE_IDEMPOTENCY_NAME) {
            Ok(response) => response,
            Err(response) => return *response,
        };
    let redacted_body = match intake_redacted_body(&request, &response_seed) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request_hash = match request_hash(
        INTAKE_ROUTE_IDEMPOTENCY_NAME,
        &request.tenant_id,
        &request.namespace,
        &redacted_body,
    ) {
        Ok(request_hash) => request_hash,
        Err(response) => return *response,
    };
    match reserve_gateway_idempotency_key(
        pool,
        &request.tenant_id,
        &request.namespace,
        INTAKE_ROUTE_IDEMPOTENCY_NAME,
        &request.idempotency_key,
        request_hash,
        &request.submitted_by_did,
        "intake",
    )
    .await
    {
        Ok(GatewayIdempotencyDecision::Reserved) => {}
        Ok(GatewayIdempotencyDecision::Replayed(response)) => return response.response,
        Ok(GatewayIdempotencyDecision::Failed(response)) | Err(response) => return *response,
    }
    match persist_intake_response(pool, request.clone()).await {
        Ok(response) => {
            if let Err(error) = store_gateway_idempotency_response(
                pool,
                &request.tenant_id,
                &request.namespace,
                INTAKE_ROUTE_IDEMPOTENCY_NAME,
                &request.idempotency_key,
                request_hash,
                StatusCode::CREATED,
                serde_json::to_value(&response)
                    .map_err(|_| idempotency_unavailable_response("intake")),
                None,
                "intake",
            )
            .await
            {
                return *error;
            }
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(error) => {
            if let Err(cleanup_error) = cleanup_gateway_idempotency_reservation_for_route(
                pool,
                &request.tenant_id,
                &request.namespace,
                INTAKE_ROUTE_IDEMPOTENCY_NAME,
                &request.idempotency_key,
                request_hash,
                "intake",
            )
            .await
            {
                return *cleanup_error;
            }
            *error
        }
    }
}

#[cfg(feature = "production-db")]
async fn persist_idempotent_validate_response(
    pool: &sqlx::PgPool,
    request: DagDbValidateRequest,
) -> Response {
    let response_seed =
        match validate_response_from_request(request.clone(), VALIDATE_ROUTE_IDEMPOTENCY_NAME) {
            Ok(response) => response,
            Err(response) => return *response,
        };
    let redacted_body = match validate_redacted_body(&request, &response_seed) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request_hash = match request_hash(
        VALIDATE_ROUTE_IDEMPOTENCY_NAME,
        &request.tenant_id,
        &request.namespace,
        &redacted_body,
    ) {
        Ok(request_hash) => request_hash,
        Err(response) => return *response,
    };
    match reserve_gateway_idempotency_key(
        pool,
        &request.tenant_id,
        &request.namespace,
        VALIDATE_ROUTE_IDEMPOTENCY_NAME,
        &request.idempotency_key,
        request_hash,
        &request.validator_did,
        "validate",
    )
    .await
    {
        Ok(GatewayIdempotencyDecision::Reserved) => {}
        Ok(GatewayIdempotencyDecision::Replayed(response)) => return response.response,
        Ok(GatewayIdempotencyDecision::Failed(response)) | Err(response) => return *response,
    }
    match persist_validate_response(pool, request.clone()).await {
        Ok(response) => {
            if let Err(error) = store_gateway_idempotency_response(
                pool,
                &request.tenant_id,
                &request.namespace,
                VALIDATE_ROUTE_IDEMPOTENCY_NAME,
                &request.idempotency_key,
                request_hash,
                StatusCode::CREATED,
                serde_json::to_value(&response)
                    .map_err(|_| idempotency_unavailable_response("validate")),
                None,
                "validate",
            )
            .await
            {
                return *error;
            }
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(error) => {
            if let Err(cleanup_error) = cleanup_gateway_idempotency_reservation_for_route(
                pool,
                &request.tenant_id,
                &request.namespace,
                VALIDATE_ROUTE_IDEMPOTENCY_NAME,
                &request.idempotency_key,
                request_hash,
                "validate",
            )
            .await
            {
                return *cleanup_error;
            }
            *error
        }
    }
}

#[cfg(feature = "production-db")]
async fn persist_idempotent_trust_check_response(
    pool: &sqlx::PgPool,
    request: DagDbTrustCheckRequest,
) -> Response {
    let request_body = match request_json(&request) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request_hash = match request_hash(
        TRUST_CHECK_ROUTE_IDEMPOTENCY_NAME,
        &request.tenant_id,
        &request.namespace,
        &request_body,
    ) {
        Ok(request_hash) => request_hash,
        Err(response) => return *response,
    };
    match reserve_gateway_idempotency_key(
        pool,
        &request.tenant_id,
        &request.namespace,
        TRUST_CHECK_ROUTE_IDEMPOTENCY_NAME,
        &request.idempotency_key,
        request_hash,
        &request.operator_did,
        "trust-check",
    )
    .await
    {
        Ok(GatewayIdempotencyDecision::Reserved) => {}
        Ok(GatewayIdempotencyDecision::Replayed(response)) => return response.response,
        Ok(GatewayIdempotencyDecision::Failed(response)) | Err(response) => return *response,
    }
    match persist_trust_check_response(pool, request.clone()).await {
        Ok(response) => {
            if let Err(error) = store_gateway_idempotency_response(
                pool,
                &request.tenant_id,
                &request.namespace,
                TRUST_CHECK_ROUTE_IDEMPOTENCY_NAME,
                &request.idempotency_key,
                request_hash,
                StatusCode::CREATED,
                serde_json::to_value(&response)
                    .map_err(|_| idempotency_unavailable_response("trust-check")),
                None,
                "trust-check",
            )
            .await
            {
                return *error;
            }
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(error) => {
            if let Err(cleanup_error) = cleanup_gateway_idempotency_reservation_for_route(
                pool,
                &request.tenant_id,
                &request.namespace,
                TRUST_CHECK_ROUTE_IDEMPOTENCY_NAME,
                &request.idempotency_key,
                request_hash,
                "trust-check",
            )
            .await
            {
                return *cleanup_error;
            }
            *error
        }
    }
}

#[cfg(feature = "production-db")]
async fn persist_idempotent_council_decision_response(
    pool: &sqlx::PgPool,
    request: DagDbCouncilDecisionRequest,
) -> Response {
    if let Err(error) = validate_council_decision_finality(&request) {
        return error.into_response();
    }
    let request_body = match request_json(&request) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request_hash = match request_hash(
        COUNCIL_DECISION_ROUTE_IDEMPOTENCY_NAME,
        &request.tenant_id,
        &request.namespace,
        &request_body,
    ) {
        Ok(request_hash) => request_hash,
        Err(response) => return *response,
    };
    match reserve_gateway_idempotency_key(
        pool,
        &request.tenant_id,
        &request.namespace,
        COUNCIL_DECISION_ROUTE_IDEMPOTENCY_NAME,
        &request.idempotency_key,
        request_hash,
        &request.approver_did,
        "council decision",
    )
    .await
    {
        Ok(GatewayIdempotencyDecision::Reserved) => {}
        Ok(GatewayIdempotencyDecision::Replayed(response)) => return response.response,
        Ok(GatewayIdempotencyDecision::Failed(response)) | Err(response) => return *response,
    }
    match persist_council_decision_response(pool, request.clone()).await {
        Ok(response) => {
            if let Err(error) = store_gateway_idempotency_response(
                pool,
                &request.tenant_id,
                &request.namespace,
                COUNCIL_DECISION_ROUTE_IDEMPOTENCY_NAME,
                &request.idempotency_key,
                request_hash,
                StatusCode::CREATED,
                serde_json::to_value(&response)
                    .map_err(|_| idempotency_unavailable_response("council decision")),
                None,
                "council decision",
            )
            .await
            {
                return *error;
            }
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(error) => {
            if let Err(cleanup_error) = cleanup_gateway_idempotency_reservation_for_route(
                pool,
                &request.tenant_id,
                &request.namespace,
                COUNCIL_DECISION_ROUTE_IDEMPOTENCY_NAME,
                &request.idempotency_key,
                request_hash,
                "council decision",
            )
            .await
            {
                return *cleanup_error;
            }
            *error
        }
    }
}

#[cfg(feature = "production-db")]
async fn persist_intake_response(
    pool: &sqlx::PgPool,
    request: DagDbIntakeRequest,
) -> Result<DagDbIntakeResponse, Box<Response>> {
    let mut response = intake_response_from_request(request.clone(), "dagdb.intake")?;
    let redacted_body = intake_redacted_body(&request, &response)?;
    let request_hash = request_hash(
        "dagdb.intake",
        &request.tenant_id,
        &request.namespace,
        &redacted_body,
    )?;
    let memory_id = hash_from_hex_for_route("dagdb.intake", "memory_id", &response.memory_id)?;
    let source_hash = hash_from_hex_for_route("dagdb.intake", "source_hash", &request.source_hash)?;
    let payload_hash =
        hash_from_hex_for_route("dagdb.intake", "payload_hash", &request.payload_hash)?;
    let payload_uri_hash = optional_hash_from_hex_for_route(
        "dagdb.intake",
        "payload_uri_hash",
        request.payload_uri_hash.as_deref(),
    )?;
    let access_policy_hash = optional_hash_from_hex_for_route(
        "dagdb.intake",
        "access_policy_hash",
        request.access_policy_hash.as_deref(),
    )?;
    let declared_rights_hash = optional_hash_from_hex_for_route(
        "dagdb.intake",
        "declared_rights_hash",
        request.declared_rights_hash.as_deref(),
    )?;
    let title = json_value_for_route("dagdb.intake", &response.title)?;
    let summary = json_value_for_route("dagdb.intake", &response.summary)?;
    let keywords = json_value_for_route("dagdb.intake", &response.keywords)?;
    let source_type = enum_sql_for_route("dagdb.intake", &request.source_type)?;
    let consent_purpose = enum_sql_for_route("dagdb.intake", &request.consent_purpose)?;
    let risk_class = enum_sql_for_route("dagdb.intake", &response.risk_class)?;
    let validation_status = enum_sql_for_route("dagdb.intake", &response.validation_status)?;
    let council_status = enum_sql_for_route("dagdb.intake", &response.council_status)?;
    let dag_finality_status = enum_sql_for_route("dagdb.intake", &response.dag_finality_status)?;
    let mut tx = begin_tenant_transaction(pool, &request.tenant_id)
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.intake"))?;
    let receipt_hash = insert_gateway_subject_receipt_in_transaction(
        &mut tx,
        GatewaySubjectReceipt {
            tenant_id: &request.tenant_id,
            namespace: &request.namespace,
            subject_kind: SubjectKind::Memory,
            subject_id: memory_id,
            event_type: ReceiptEventType::IntakeCreated,
            actor_did: &request.submitted_by_did,
            route_name: "dagdb.intake",
            receipt_body: json!({
                "route": "dagdb.intake",
                "idempotency_ref": idempotency_ref(&request.idempotency_key),
                "request_hash": request_hash.to_string(),
                "memory_id": response.memory_id,
                "requested_action": request.requested_action,
            }),
        },
    )
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO dagdb_memory_objects \
         (memory_id, tenant_id, namespace, node_type, source_type, consent_purpose, payload_hash, \
          source_hash, payload_uri_hash, owner_did, controller_did, submitted_by_did, \
          access_policy_hash, declared_rights_hash, title, summary, keywords, risk_class, risk_bp, \
          status, validation_status, council_status, dag_finality_status, latest_receipt_hash, \
          created_at_physical_ms, created_at_logical, updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, 'source', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                 $16, $17, $18, 'pending', $19, $20, $21, $22, 1, 0, 1, 0) \
         ON CONFLICT DO NOTHING",
    )
    .bind(hash_bytes(memory_id))
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(source_type)
    .bind(consent_purpose)
    .bind(hash_bytes(payload_hash))
    .bind(hash_bytes(source_hash))
    .bind(optional_hash_bytes(payload_uri_hash))
    .bind(&request.owner_did)
    .bind(&request.controller_did)
    .bind(&request.submitted_by_did)
    .bind(optional_hash_bytes(access_policy_hash))
    .bind(optional_hash_bytes(declared_rights_hash))
    .bind(title)
    .bind(summary)
    .bind(keywords)
    .bind(risk_class)
    .bind(i32::from(response.risk_bp))
    .bind(validation_status)
    .bind(council_status)
    .bind(dag_finality_status)
    .bind(hash_bytes(receipt_hash))
    .execute(&mut *tx)
    .await
    .map_err(|_| route_database_unavailable_box("dagdb.intake"))?;
    persist_intake_parent_edges(&mut tx, &request, memory_id).await?;
    tx.commit()
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.intake"))?;
    response.receipt_hash = receipt_hash.to_string();
    response.created_new = inserted.rows_affected() == 1;
    Ok(response)
}

#[cfg(feature = "production-db")]
async fn persist_validate_response(
    pool: &sqlx::PgPool,
    request: DagDbValidateRequest,
) -> Result<DagDbValidateResponse, Box<Response>> {
    let mut response = validate_response_from_request(request.clone(), "dagdb.validate")?;
    let redacted_body = validate_redacted_body(&request, &response)?;
    let request_hash = request_hash(
        "dagdb.validate",
        &request.tenant_id,
        &request.namespace,
        &redacted_body,
    )?;
    let validation_report_id = hash_from_hex_for_route(
        "dagdb.validate",
        "validation_report_id",
        &response.validation_report_id,
    )?;
    let subject_id = hash_from_hex_for_route("dagdb.validate", "subject_id", &request.subject_id)?;
    let council_decision_id = optional_hash_from_hex_for_route(
        "dagdb.validate",
        "council_decision_id",
        request.council_decision_id.as_deref(),
    )?;
    let policy_hash = hash_hex("dagdb.gateway.validation.policy", &request.requested_status)
        .and_then(|value| hash_from_hex_for_route("dagdb.validate", "policy_hash", &value))?;
    let notes = json_value_for_route("dagdb.validate", &response.notes)?;
    let contradictory_report_ids =
        json_value_for_route("dagdb.validate", &response.contradictory_report_ids)?;
    let subject_kind = enum_sql_for_route("dagdb.validate", &request.subject_kind)?;
    let validation_status = enum_sql_for_route("dagdb.validate", &response.validation_status)?;
    let risk_class = enum_sql_for_route("dagdb.validate", &response.risk_class)?;
    let decision = enum_sql_for_route("dagdb.validate", &response.decision)?;
    let mut tx = begin_tenant_transaction(pool, &request.tenant_id)
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.validate"))?;
    let receipt_hash = insert_gateway_subject_receipt_in_transaction(
        &mut tx,
        GatewaySubjectReceipt {
            tenant_id: &request.tenant_id,
            namespace: &request.namespace,
            subject_kind: SubjectKind::ValidationReport,
            subject_id: validation_report_id,
            event_type: validation_receipt_event_type(response.validation_status),
            actor_did: &request.validator_did,
            route_name: "dagdb.validate",
            receipt_body: json!({
                "route": "dagdb.validate",
                "idempotency_ref": idempotency_ref(&request.idempotency_key),
                "request_hash": request_hash.to_string(),
                "subject_kind": subject_kind,
                "subject_id": request.subject_id,
                "validation_status": validation_status,
            }),
        },
    )
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO dagdb_validation_reports \
         (validation_report_id, tenant_id, namespace, subject_kind, subject_id, validator_did, \
          input_hash, policy_hash, validation_status, risk_class, risk_bp, decision, notes, \
          contradictory_report_ids, council_decision_id, latest_receipt_hash, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 1, 0) \
         ON CONFLICT DO NOTHING",
    )
    .bind(hash_bytes(validation_report_id))
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(subject_kind)
    .bind(hash_bytes(subject_id))
    .bind(&request.validator_did)
    .bind(hash_bytes(request_hash))
    .bind(hash_bytes(policy_hash))
    .bind(validation_status)
    .bind(risk_class)
    .bind(i32::from(response.risk_bp))
    .bind(decision)
    .bind(notes)
    .bind(contradictory_report_ids)
    .bind(optional_hash_bytes(council_decision_id))
    .bind(hash_bytes(receipt_hash))
    .execute(&mut *tx)
    .await
    .map_err(|_| route_database_unavailable_box("dagdb.validate"))?;
    tx.commit()
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.validate"))?;
    response.receipt_hash = receipt_hash.to_string();
    response.created_new = inserted.rows_affected() == 1;
    Ok(response)
}

#[cfg(feature = "production-db")]
async fn persist_trust_check_response(
    pool: &sqlx::PgPool,
    request: DagDbTrustCheckRequest,
) -> Result<DagDbTrustCheckResponse, Box<Response>> {
    let request_body = request_json(&request)?;
    let request_hash = request_hash(
        "dagdb.trust_check",
        &request.tenant_id,
        &request.namespace,
        &request_body,
    )?;
    let credential_id = hash_hex(
        "dagdb.gateway.trust.credential",
        &(&request_hash, &request.agent_did, &request.nonce),
    )
    .and_then(|value| hash_from_hex_for_route("dagdb.trust_check", "credential_id", &value))?;
    let safety_score_id = hash_hex(
        "dagdb.gateway.trust.safety_score",
        &(&request_hash, &request.agent_did, &request.operator_did),
    )
    .and_then(|value| hash_from_hex_for_route("dagdb.trust_check", "safety_score_id", &value))?;
    let requested_scope_hash = hash_from_hex_for_route(
        "dagdb.trust_check",
        "requested_scope_hash",
        &request.requested_scope_hash,
    )?;
    let checkpoint_hash = optional_hash_from_hex_for_route(
        "dagdb.trust_check",
        "checkpoint_hash",
        request.checkpoint_hash.as_deref(),
    )?;
    let attestation_hash = optional_hash_from_hex_for_route(
        "dagdb.trust_check",
        "attestation_hash",
        request.attestation_hash.as_deref(),
    )?;
    let prior_trust_receipt_hash = optional_hash_from_hex_for_route(
        "dagdb.trust_check",
        "prior_trust_receipt_hash",
        request.prior_trust_receipt_hash.as_deref(),
    )?;
    let evidence_hash = hash_hex(
        "dagdb.gateway.trust.evidence",
        &request.evidence_receipt_hashes,
    )
    .and_then(|value| hash_from_hex_for_route("dagdb.trust_check", "evidence_hash", &value))?;
    let signature_hash = Hash256::digest(request.signature.as_bytes());
    let expires_at = parse_hlc_for_route("dagdb.trust_check", "expires_at", &request.expires_at)?;
    let purpose = enum_sql_for_route("dagdb.trust_check", &request.purpose)?;
    let credential_status = enum_sql_for_route("dagdb.trust_check", &CredentialStatus::Active)?;
    let validation_status = enum_sql_for_route("dagdb.trust_check", &ValidationStatus::Passed)?;
    let council_status =
        enum_sql_for_route("dagdb.trust_check", &CouncilReviewStatus::NotRequired)?;
    let mut tx = begin_tenant_transaction(pool, &request.tenant_id)
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.trust_check"))?;
    let credential_receipt_hash = insert_gateway_subject_receipt_in_transaction(
        &mut tx,
        GatewaySubjectReceipt {
            tenant_id: &request.tenant_id,
            namespace: &request.namespace,
            subject_kind: SubjectKind::InboundAgentCredential,
            subject_id: credential_id,
            event_type: ReceiptEventType::TrustCheckCreated,
            actor_did: &request.operator_did,
            route_name: "dagdb.trust_check",
            receipt_body: json!({
                "route": "dagdb.trust_check",
                "idempotency_ref": idempotency_ref(&request.idempotency_key),
                "request_hash": request_hash.to_string(),
                "credential_id": credential_id.to_string(),
                "safety_score_id": safety_score_id.to_string(),
            }),
        },
    )
    .await?;
    let safety_receipt_hash = insert_gateway_subject_receipt_in_transaction(
        &mut tx,
        GatewaySubjectReceipt {
            tenant_id: &request.tenant_id,
            namespace: &request.namespace,
            subject_kind: SubjectKind::AgentSafetyScore,
            subject_id: safety_score_id,
            event_type: ReceiptEventType::TrustCheckCreated,
            actor_did: &request.operator_did,
            route_name: "dagdb.trust_check",
            receipt_body: json!({
                "route": "dagdb.trust_check",
                "idempotency_ref": idempotency_ref(&request.idempotency_key),
                "request_hash": request_hash.to_string(),
                "credential_id": credential_id.to_string(),
                "safety_score_id": safety_score_id.to_string(),
            }),
        },
    )
    .await?;
    let credential_inserted = sqlx::query(
        "INSERT INTO dagdb_inbound_agent_credentials \
         (credential_id, tenant_id, namespace, agent_did, operator_did, model_name, model_version, \
          provider_or_builder, requested_action, requested_scope_hash, purpose, autonomy_level, \
          nonce, expires_at_physical_ms, expires_at_logical, signature_hash, credential_status, \
          checkpoint_hash, attestation_hash, prior_trust_receipt_hash, created_at_physical_ms, \
          created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
                 $18, $19, $20, 1, 0) \
         ON CONFLICT DO NOTHING",
    )
    .bind(hash_bytes(credential_id))
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(&request.agent_did)
    .bind(&request.operator_did)
    .bind(&request.model_name)
    .bind(&request.model_version)
    .bind(&request.provider_or_builder)
    .bind(&request.requested_action)
    .bind(hash_bytes(requested_scope_hash))
    .bind(purpose)
    .bind(&request.autonomy_level)
    .bind(&request.nonce)
    .bind(timestamp_physical_i64("dagdb.trust_check", expires_at)?)
    .bind(timestamp_logical_i32("dagdb.trust_check", expires_at)?)
    .bind(hash_bytes(signature_hash))
    .bind(credential_status)
    .bind(optional_hash_bytes(checkpoint_hash))
    .bind(optional_hash_bytes(attestation_hash))
    .bind(optional_hash_bytes(prior_trust_receipt_hash))
    .execute(&mut *tx)
    .await
    .map_err(|_| route_database_unavailable_box("dagdb.trust_check"))?;
    sqlx::query(
        "INSERT INTO dagdb_agent_safety_scores \
         (safety_score_id, tenant_id, namespace, agent_did, operator_did, window_start_physical_ms, \
          window_start_logical, window_end_physical_ms, window_end_logical, evidence_hash, \
          identity_bp, authority_bp, consent_bp, provenance_bp, validation_bp, recency_bp, \
          revocation_bp, route_quality_bp, incident_penalty_bp, total_score_bp, validation_status, \
          council_status, latest_receipt_hash, created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, 1, 0, $6, $7, $8, 9000, 9000, 9000, 9000, 9000, 9000, \
                 9000, 9000, 0, 9000, $9, $10, $11, 1, 0) \
         ON CONFLICT DO NOTHING",
    )
    .bind(hash_bytes(safety_score_id))
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(&request.agent_did)
    .bind(&request.operator_did)
    .bind(timestamp_physical_i64("dagdb.trust_check", expires_at)?)
    .bind(timestamp_logical_i32("dagdb.trust_check", expires_at)?)
    .bind(hash_bytes(evidence_hash))
    .bind(validation_status)
    .bind(council_status)
    .bind(hash_bytes(safety_receipt_hash))
    .execute(&mut *tx)
    .await
    .map_err(|_| route_database_unavailable_box("dagdb.trust_check"))?;
    tx.commit()
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.trust_check"))?;
    Ok(DagDbTrustCheckResponse {
        schema_version: exo_api::dagdb::DAGDB_TRUST_CHECK_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        idempotency_key: request.idempotency_key,
        credential_id: credential_id.to_string(),
        safety_score_id: safety_score_id.to_string(),
        receipt_hash: credential_receipt_hash.to_string(),
        validation_status: ValidationStatus::Passed,
        council_status: CouncilReviewStatus::NotRequired,
        credential_status: CredentialStatus::Active,
        total_score_bp: 9_000,
        created_new: credential_inserted.rows_affected() == 1,
        block_reason: None,
        expires_at: Some(request.expires_at),
    })
}

#[cfg(feature = "production-db")]
async fn persist_council_decision_response(
    pool: &sqlx::PgPool,
    request: DagDbCouncilDecisionRequest,
) -> Result<DagDbCouncilDecisionResponse, Box<Response>> {
    validate_council_decision_finality(&request)
        .map_err(|error| Box::new(error.into_response()))?;
    let notes = sanitize_optional_metadata(
        MetadataField::ValidationNotes,
        request.notes_text.as_deref(),
    )?;
    let request_body = request_json(&request)?;
    let request_hash = request_hash(
        "dagdb.council_decision",
        &request.tenant_id,
        &request.namespace,
        &request_body,
    )?;
    let decision_id = hash_hex(
        "dagdb.gateway.council_decision",
        &(&request_hash, &request.subject_id, &request.approver_did),
    )
    .and_then(|value| hash_from_hex_for_route("dagdb.council_decision", "decision_id", &value))?;
    let subject_id =
        hash_from_hex_for_route("dagdb.council_decision", "subject_id", &request.subject_id)?;
    let approved_scope_hash = hash_from_hex_for_route(
        "dagdb.council_decision",
        "approved_scope_hash",
        &request.approved_scope_hash,
    )?;
    let validation_report_id = optional_hash_from_hex_for_route(
        "dagdb.council_decision",
        "validation_report_id",
        request.validation_report_id.as_deref(),
    )?;
    let route_id = optional_hash_from_hex_for_route(
        "dagdb.council_decision",
        "route_id",
        request.route_id.as_deref(),
    )?;
    let context_packet_id = optional_hash_from_hex_for_route(
        "dagdb.council_decision",
        "context_packet_id",
        request.context_packet_id.as_deref(),
    )?;
    let created_at =
        parse_hlc_for_route("dagdb.council_decision", "created_at", &request.created_at)?;
    let expires_at =
        parse_hlc_for_route("dagdb.council_decision", "expires_at", &request.expires_at)?;
    if expires_at <= created_at {
        return Err(Box::new(dagdb_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
            "DAG DB council decision expires_at must be after created_at",
            false,
        )));
    }
    let subject_kind = enum_sql_for_route("dagdb.council_decision", &request.subject_kind)?;
    let decision_source = enum_sql_for_route("dagdb.council_decision", &request.decision_source)?;
    let decision_status = enum_sql_for_route("dagdb.council_decision", &request.decision_status)?;
    let risk_class = enum_sql_for_route("dagdb.council_decision", &request.risk_class)?;
    let notes_json = json_value_for_route("dagdb.council_decision", &notes)?;
    let mut tx = begin_tenant_transaction(pool, &request.tenant_id)
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.council_decision"))?;
    let receipt_hash = insert_gateway_subject_receipt_in_transaction(
        &mut tx,
        GatewaySubjectReceipt {
            tenant_id: &request.tenant_id,
            namespace: &request.namespace,
            subject_kind: SubjectKind::CouncilDecision,
            subject_id: decision_id,
            event_type: ReceiptEventType::CouncilDecisionRecorded,
            actor_did: &request.approver_did,
            route_name: "dagdb.council_decision",
            receipt_body: json!({
                "route": "dagdb.council_decision",
                "idempotency_ref": idempotency_ref(&request.idempotency_key),
                "request_hash": request_hash.to_string(),
                "decision_id": decision_id.to_string(),
                "subject_id": request.subject_id,
                "decision_status": decision_status,
            }),
        },
    )
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO dagdb_council_decisions \
         (decision_id, tenant_id, namespace, subject_kind, subject_id, requested_action, \
          approved_scope_hash, risk_class, approver_did, decision_source, decision_status, \
          reason_code, validation_report_id, route_id, context_packet_id, notes, \
          created_at_physical_ms, created_at_logical, expires_at_physical_ms, expires_at_logical, \
          receipt_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
                 $17, $18, $19, $20, $21) \
         ON CONFLICT DO NOTHING",
    )
    .bind(hash_bytes(decision_id))
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .bind(subject_kind)
    .bind(hash_bytes(subject_id))
    .bind(&request.requested_action)
    .bind(hash_bytes(approved_scope_hash))
    .bind(risk_class)
    .bind(&request.approver_did)
    .bind(decision_source)
    .bind(decision_status)
    .bind(&request.reason_code)
    .bind(optional_hash_bytes(validation_report_id))
    .bind(optional_hash_bytes(route_id))
    .bind(optional_hash_bytes(context_packet_id))
    .bind(notes_json)
    .bind(timestamp_physical_i64(
        "dagdb.council_decision",
        created_at,
    )?)
    .bind(timestamp_logical_i32("dagdb.council_decision", created_at)?)
    .bind(timestamp_physical_i64(
        "dagdb.council_decision",
        expires_at,
    )?)
    .bind(timestamp_logical_i32("dagdb.council_decision", expires_at)?)
    .bind(hash_bytes(receipt_hash))
    .execute(&mut *tx)
    .await
    .map_err(|_| route_database_unavailable_box("dagdb.council_decision"))?;
    tx.commit()
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.council_decision"))?;
    Ok(DagDbCouncilDecisionResponse {
        schema_version: exo_api::dagdb::DAGDB_COUNCIL_DECISION_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        idempotency_key: request.idempotency_key,
        decision_id: decision_id.to_string(),
        subject_kind: request.subject_kind,
        subject_id: request.subject_id,
        receipt_hash: receipt_hash.to_string(),
        validation_status: ValidationStatus::NotRequired,
        council_status: council_status_from_decision(request.decision_status),
        decision_status: request.decision_status,
        approved_scope_hash: request.approved_scope_hash,
        risk_class: request.risk_class,
        expires_at: request.expires_at,
        created_new: inserted.rows_affected() == 1,
        validation_report_id: request.validation_report_id,
        route_id: request.route_id,
        context_packet_id: request.context_packet_id,
        notes,
    })
}

#[cfg(feature = "production-db")]
async fn load_receipt_lookup_response(
    pool: &sqlx::PgPool,
    request: DagDbReceiptLookupRequest,
) -> Result<DagDbReceiptLookupResponse, Box<Response>> {
    let receipt_hash = hash_from_hex_for_route(
        "dagdb.receipt_lookup",
        "receipt_hash",
        &request.receipt_hash,
    )?;
    let mut tx = begin_tenant_transaction(pool, &request.tenant_id)
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?;
    let row = sqlx::query(
        "SELECT subject_kind, encode(subject_id, 'hex') AS subject_id, \
                encode(prev_receipt_hash, 'hex') AS prev_receipt_hash, seq, event_type, actor_did, \
                event_hlc_physical_ms, event_hlc_logical, created_at_physical_ms, \
                created_at_logical, receipt_body \
         FROM dagdb_receipts \
         WHERE receipt_hash = $1 AND tenant_id = $2 AND namespace = $3",
    )
    .bind(hash_bytes(receipt_hash))
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?;
    tx.commit()
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?;
    let row =
        row.ok_or_else(|| route_not_found_box("dagdb.receipt_lookup", "receipt not found"))?;
    let receipt_body: Value = row
        .try_get("receipt_body")
        .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?;
    Ok(DagDbReceiptLookupResponse {
        schema_version: exo_api::dagdb::DAGDB_RECEIPT_LOOKUP_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        receipt_hash: request.receipt_hash,
        subject_kind: enum_from_sql_for_route(
            "dagdb.receipt_lookup",
            row.try_get("subject_kind")
                .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?,
        )?,
        subject_id: row
            .try_get("subject_id")
            .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?,
        prev_receipt_hash: row
            .try_get("prev_receipt_hash")
            .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?,
        seq: u64_from_i64_for_route(
            "dagdb.receipt_lookup",
            row.try_get("seq")
                .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?,
        )?,
        event_type: enum_from_sql_for_route(
            "dagdb.receipt_lookup",
            row.try_get("event_type")
                .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?,
        )?,
        actor_did: row
            .try_get("actor_did")
            .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?,
        event_hlc: hlc_text(
            row.try_get("event_hlc_physical_ms")
                .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?,
            row.try_get("event_hlc_logical")
                .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?,
        )?,
        created_at: hlc_text(
            row.try_get("created_at_physical_ms")
                .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?,
            row.try_get("created_at_logical")
                .map_err(|_| route_database_unavailable_box("dagdb.receipt_lookup"))?,
        )?,
        receipt_body: request
            .include_body
            .unwrap_or(false)
            .then_some(receipt_body),
        validation_report_id: None,
    })
}

#[cfg(feature = "production-db")]
async fn load_catalog_lookup_response(
    pool: &sqlx::PgPool,
    request: DagDbCatalogLookupRequest,
) -> Result<DagDbCatalogLookupResponse, Box<Response>> {
    let catalog_id =
        hash_from_hex_for_route("dagdb.catalog_lookup", "catalog_id", &request.catalog_id)?;
    let mut tx = begin_tenant_transaction(pool, &request.tenant_id)
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?;
    let row = sqlx::query(
        "SELECT encode(catalog_id, 'hex') AS catalog_id, encode(memory_id, 'hex') AS memory_id, \
                encode(parent_catalog_id, 'hex') AS parent_catalog_id, catalog_level, title, \
                summary, keywords, status, validation_status, council_status, \
                dag_finality_status, encode(latest_receipt_hash, 'hex') AS latest_receipt_hash \
         FROM dagdb_catalog_entries \
         WHERE catalog_id = $1 AND tenant_id = $2 AND namespace = $3",
    )
    .bind(hash_bytes(catalog_id))
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?;
    let Some(row) = row else {
        tx.commit()
            .await
            .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?;
        return Err(route_not_found_box(
            "dagdb.catalog_lookup",
            "catalog entry not found",
        ));
    };
    let children = if request.include_children.unwrap_or(false) {
        Some(
            load_catalog_children(&mut tx, &request.tenant_id, &request.namespace, catalog_id)
                .await?,
        )
    } else {
        None
    };
    let routes = if request.include_routes.unwrap_or(false) {
        Some(load_catalog_route_ids(&mut tx, &request.tenant_id, &request.namespace).await?)
    } else {
        None
    };
    tx.commit()
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?;
    Ok(DagDbCatalogLookupResponse {
        schema_version: exo_api::dagdb::DAGDB_CATALOG_LOOKUP_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        catalog_id: row
            .try_get("catalog_id")
            .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?,
        catalog_level: u32_from_i32_for_route(
            "dagdb.catalog_lookup",
            row.try_get("catalog_level")
                .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?,
        )?,
        title: json_column_for_route("dagdb.catalog_lookup", &row, "title")?,
        summary: json_column_for_route("dagdb.catalog_lookup", &row, "summary")?,
        keywords: json_column_for_route("dagdb.catalog_lookup", &row, "keywords")?,
        status: enum_from_sql_for_route(
            "dagdb.catalog_lookup",
            row.try_get("status")
                .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?,
        )?,
        validation_status: enum_from_sql_for_route(
            "dagdb.catalog_lookup",
            row.try_get("validation_status")
                .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?,
        )?,
        council_status: enum_from_sql_for_route(
            "dagdb.catalog_lookup",
            row.try_get("council_status")
                .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?,
        )?,
        dag_finality_status: enum_from_sql_for_route(
            "dagdb.catalog_lookup",
            row.try_get("dag_finality_status")
                .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?,
        )?,
        latest_receipt_hash: row
            .try_get("latest_receipt_hash")
            .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?,
        memory_id: row
            .try_get("memory_id")
            .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?,
        parent_catalog_id: row
            .try_get("parent_catalog_id")
            .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?,
        children,
        routes,
    })
}

#[cfg(feature = "production-db")]
async fn load_route_lookup_response(
    pool: &sqlx::PgPool,
    request: DagDbRouteLookupRequest,
) -> Result<DagDbRouteLookupResponse, Box<Response>> {
    let route_id = hash_from_hex_for_route("dagdb.route_lookup", "route_id", &request.route_id)?;
    let mut tx = begin_tenant_transaction(pool, &request.tenant_id)
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?;
    let row = sqlx::query(
        "SELECT encode(route_id, 'hex') AS route_id, selected_memory_ids, route_score_bp, \
                token_budget, token_estimate, status, validation_status, council_status, \
                dag_finality_status, stale_at_physical_ms, stale_at_logical, \
                encode(latest_receipt_hash, 'hex') AS latest_receipt_hash \
         FROM dagdb_route_receipts \
         WHERE route_id = $1 AND tenant_id = $2 AND namespace = $3",
    )
    .bind(hash_bytes(route_id))
    .bind(&request.tenant_id)
    .bind(&request.namespace)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?;
    tx.commit()
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?;
    let row = row.ok_or_else(|| route_not_found_box("dagdb.route_lookup", "route not found"))?;
    Ok(DagDbRouteLookupResponse {
        schema_version: exo_api::dagdb::DAGDB_ROUTE_LOOKUP_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        route_id: row
            .try_get("route_id")
            .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?,
        route_status: enum_from_sql_for_route(
            "dagdb.route_lookup",
            row.try_get("status")
                .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?,
        )?,
        validation_status: enum_from_sql_for_route(
            "dagdb.route_lookup",
            row.try_get("validation_status")
                .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?,
        )?,
        council_status: enum_from_sql_for_route(
            "dagdb.route_lookup",
            row.try_get("council_status")
                .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?,
        )?,
        dag_finality_status: enum_from_sql_for_route(
            "dagdb.route_lookup",
            row.try_get("dag_finality_status")
                .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?,
        )?,
        selected_memory_ids: json_column_for_route(
            "dagdb.route_lookup",
            &row,
            "selected_memory_ids",
        )?,
        route_score_bp: u16_from_i32_for_route(
            "dagdb.route_lookup",
            row.try_get("route_score_bp")
                .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?,
        )?,
        token_budget: u32_from_i32_for_route(
            "dagdb.route_lookup",
            row.try_get("token_budget")
                .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?,
        )?,
        token_estimate: u32_from_i32_for_route(
            "dagdb.route_lookup",
            row.try_get("token_estimate")
                .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?,
        )?,
        stale_at: hlc_text(
            row.try_get("stale_at_physical_ms")
                .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?,
            row.try_get("stale_at_logical")
                .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?,
        )?,
        latest_receipt_hash: row
            .try_get("latest_receipt_hash")
            .map_err(|_| route_database_unavailable_box("dagdb.route_lookup"))?,
        memory_refs: request.include_memory_refs.unwrap_or(false).then(Vec::new),
        validation_report: None,
    })
}

// Builds the synthetic writeback response shape. The runtime no-pool path now
// fails closed (503) instead of returning this scaffold, so this builder is
// retained only for the response-shape unit tests that assert its layered /
// metadata handling.
#[cfg(test)]
fn writeback_response_from_request(
    request: DagDbWritebackRequest,
    route_name: &str,
) -> Result<DagDbWritebackResponse, Box<Response>> {
    let layered = writeback_layered_fields(&request)?;
    let summary =
        sanitize_optional_metadata(MetadataField::Summary, request.summary_text.as_deref())?;
    let keywords = request
        .keyword_texts
        .as_deref()
        .map(|texts| sanitize_keyword_texts(Some(texts)))
        .transpose()?;
    let mut redacted_body = request_json(&request)?;
    replace_metadata(
        &mut redacted_body,
        "summary_text",
        "summary",
        request_json(&summary)?,
    )?;
    replace_metadata(
        &mut redacted_body,
        "keyword_texts",
        "keywords",
        request_json(&keywords)?,
    )?;
    let request_hash = request_hash(
        route_name,
        &request.tenant_id,
        &request.namespace,
        &redacted_body,
    )?;
    Ok(DagDbWritebackResponse {
        schema_version: exo_api::dagdb::DAGDB_WRITEBACK_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        idempotency_key: request.idempotency_key,
        memory_id: hash_hex(
            "dagdb.gateway.writeback",
            &(&request_hash, &request.answer_hash),
        )?,
        receipt_hash: receipt_hash(route_name, request_hash)?,
        validation_status: ValidationStatus::Pending,
        council_status: CouncilReviewStatus::NotRequired,
        dag_finality_status: DagFinalityStatus::Pending,
        risk_class: RiskClass::R1,
        risk_bp: 1_000,
        created_new: true,
        validation_report_id: Some(request.validation_report_id),
        council_decision_id: None,
        summary,
        keywords,
        target_layer_path: layered.target_layer_path,
        target_layer_depth: layered.target_layer_depth,
        target_layer_reason: layered.target_layer_reason,
        created_child_layer_id: layered.created_child_layer_id,
        layered_writeback_status: layered.layered_writeback_status,
    })
}

fn validated_import_report_json(request: &DagDbImportRequest) -> Result<String, Box<Response>> {
    validate_runtime_request_basics(
        "dagdb.import",
        &request.tenant_id,
        &request.namespace,
        &request.idempotency_key,
        &request.db_set_version,
        &request.requester_did,
    )?;
    exo_dag_db_exchange::kg_import::hash_from_hex("source_hash", &request.source_hash).map_err(
        |_| {
            invalid_runtime_request(
                "dagdb.import",
                "import_source_hash_invalid",
                "DAG DB import source_hash must be 64-character hex",
            )
        },
    )?;
    let report_json = serde_json::to_string(&request.import_report).map_err(|_| {
        invalid_runtime_request(
            "dagdb.import",
            "import_report_encode_failed",
            "DAG DB import report could not be encoded as JSON",
        )
    })?;
    let report = KgImportDryRunReport::parse_json(&report_json).map_err(|_| {
        invalid_runtime_request(
            "dagdb.import",
            "import_report_invalid_or_unsafe",
            "DAG DB import report is invalid or unsafe",
        )
    })?;
    if report.tenant_id != request.tenant_id || report.namespace != request.namespace {
        return Err(invalid_runtime_request(
            "dagdb.import",
            "import_report_scope_mismatch",
            "DAG DB import report tenant or namespace does not match request scope",
        ));
    }
    // Persisted receipts derive their actor from the report, and every receipt
    // intent must match the report actor; bind that declared actor to the
    // signature-verified requester so an import cannot attribute receipts to a
    // principal that never signed the request.
    if report.actor_did != request.requester_did {
        return Err(invalid_runtime_request(
            "dagdb.import",
            "import_report_actor_mismatch",
            "DAG DB import report actor_did does not match the requester",
        ));
    }
    Ok(report_json)
}

#[cfg(feature = "production-db")]
fn import_route_request_hash(request: &DagDbImportRequest) -> Result<Hash256, Box<Response>> {
    let body = request_json(request)?;
    request_hash(
        IMPORT_ROUTE_IDEMPOTENCY_NAME,
        &request.tenant_id,
        &request.namespace,
        &body,
    )
}

#[cfg(feature = "production-db")]
fn export_route_request_hash(request: &DagDbExportRequest) -> Result<Hash256, Box<Response>> {
    let body = request_json(request)?;
    request_hash(
        EXPORT_ROUTE_IDEMPOTENCY_NAME,
        &request.tenant_id,
        &request.namespace,
        &body,
    )
}

#[cfg(feature = "production-db")]
enum GatewayIdempotencyDecision {
    Reserved,
    Replayed(CachedGatewayIdempotencyResponse),
    Failed(Box<Response>),
}

#[cfg(feature = "production-db")]
struct CachedGatewayIdempotencyResponse {
    response: Response,
    authorization_payload_hash: Option<Hash256>,
}

#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
async fn reserve_gateway_idempotency_key(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    namespace: &str,
    route_name: &'static str,
    idempotency_key: &str,
    request_hash: Hash256,
    actor_did: &str,
    operation: &'static str,
) -> Result<GatewayIdempotencyDecision, Box<Response>> {
    let response_body = json!({
        "idempotency_status": RESERVED_IDEMPOTENCY_BODY_STATUS,
        "route_name": route_name,
    });
    let response_hash = gateway_idempotency_response_hash(
        &response_body,
        route_name,
        "reserve",
        operation,
        tenant_id,
        namespace,
        idempotency_key,
    )?;
    let mut tx = begin_gateway_idempotency_transaction(
        pool,
        tenant_id,
        namespace,
        route_name,
        idempotency_key,
        "reserve",
        operation,
    )
    .await?;
    let reserved = insert_gateway_idempotency_reservation(
        &mut tx,
        tenant_id,
        namespace,
        route_name,
        idempotency_key,
        request_hash,
        response_hash,
        &response_body,
        operation,
    )
    .await?
        || (reclaim_expired_gateway_idempotency_reservation(
            &mut tx,
            tenant_id,
            namespace,
            route_name,
            idempotency_key,
            request_hash,
            operation,
        )
        .await?
            && insert_gateway_idempotency_reservation(
                &mut tx,
                tenant_id,
                namespace,
                route_name,
                idempotency_key,
                request_hash,
                response_hash,
                &response_body,
                operation,
            )
            .await?);
    let decision = if reserved {
        GatewayIdempotencyDecision::Reserved
    } else {
        replay_gateway_idempotency_response_in_transaction(
            &mut tx,
            tenant_id,
            namespace,
            route_name,
            idempotency_key,
            request_hash,
            actor_did,
            operation,
        )
        .await?
    };
    commit_gateway_idempotency_transaction(
        tx,
        tenant_id,
        namespace,
        route_name,
        idempotency_key,
        "reserve",
        operation,
    )
    .await?;
    match decision {
        GatewayIdempotencyDecision::Failed(response) => Err(response),
        decision => Ok(decision),
    }
}

#[cfg(feature = "production-db")]
async fn begin_gateway_idempotency_transaction<'a>(
    pool: &'a sqlx::PgPool,
    tenant_id: &str,
    namespace: &str,
    route_name: &str,
    idempotency_key: &str,
    phase: &'static str,
    operation: &'static str,
) -> Result<Transaction<'a, Postgres>, Box<Response>> {
    begin_tenant_transaction(pool, tenant_id)
        .await
        .map_err(|_| {
            idempotency_unavailable_response_logged(
                route_name,
                phase,
                operation,
                tenant_id,
                namespace,
                idempotency_key,
            )
        })
}

#[cfg(feature = "production-db")]
async fn commit_gateway_idempotency_transaction(
    tx: Transaction<'_, Postgres>,
    tenant_id: &str,
    namespace: &str,
    route_name: &str,
    idempotency_key: &str,
    phase: &'static str,
    operation: &'static str,
) -> Result<(), Box<Response>> {
    tx.commit().await.map_err(|_| {
        idempotency_unavailable_response_logged(
            route_name,
            phase,
            operation,
            tenant_id,
            namespace,
            idempotency_key,
        )
    })
}

#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
async fn dagdb_operational_error_response(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    namespace: &str,
    route_name: &'static str,
    idempotency_key: &str,
    actor_did: &str,
    request_hash: Hash256,
    status: StatusCode,
    error_code: &str,
    message: impl Into<String>,
    requires_council_review: bool,
) -> Response {
    let message = message.into();
    let _ = insert_gateway_operational_receipt_for_error(
        pool,
        tenant_id,
        namespace,
        route_name,
        gateway_operation_from_route_name(route_name),
        gateway_operational_actor(actor_did),
        idempotency_key,
        Some(request_hash),
        status,
        error_code,
    )
    .await;
    dagdb_error_response(status, error_code, message, requires_council_review)
}

#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
async fn handler_operational_error_response(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    namespace: &str,
    route_name: &'static str,
    idempotency_key: &str,
    actor_did: &str,
    request_hash: Hash256,
    error: DagDbHandlerError,
) -> Response {
    if let Err(audit_error) = insert_gateway_operational_receipt_for_error(
        pool,
        tenant_id,
        namespace,
        route_name,
        gateway_operation_from_route_name(route_name),
        gateway_operational_actor(actor_did),
        idempotency_key,
        Some(request_hash),
        error.status(),
        error.error_code(),
    )
    .await
    {
        return *audit_error;
    }
    error.into_response()
}

#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
async fn mounted_dagdb_operational_error_response(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    namespace: &str,
    route_name: &'static str,
    idempotency_key: &str,
    actor_did: &str,
    request_hash: Option<Hash256>,
    status: StatusCode,
    error_code: &str,
    message: impl Into<String>,
    requires_council_review: bool,
) -> Response {
    let message = message.into();
    let _ = insert_gateway_operational_receipt_for_error(
        pool,
        tenant_id,
        namespace,
        route_name,
        gateway_operation_from_route_name(route_name),
        gateway_operational_actor(actor_did),
        idempotency_key,
        request_hash,
        status,
        error_code,
    )
    .await;
    dagdb_error_response(status, error_code, message, requires_council_review)
}

#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
async fn insert_gateway_operational_receipt_for_error(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    namespace: &str,
    route_name: &'static str,
    operation: &'static str,
    actor_did: &str,
    idempotency_key: &str,
    request_hash: Option<Hash256>,
    status: StatusCode,
    error_code: &str,
) -> Result<(), Box<Response>> {
    let Some(event_type) = receipt_event_type_for_error_code(error_code) else {
        return Ok(());
    };
    insert_gateway_operational_receipt(
        pool,
        GatewayOperationalReceipt {
            tenant_id,
            namespace,
            route_name,
            operation,
            actor_did,
            idempotency_key,
            request_hash,
            event_type,
            status,
            error_code: Some(error_code),
        },
    )
    .await
}

#[cfg(feature = "production-db")]
#[derive(Clone, Copy)]
struct GatewayOperationalReceipt<'a> {
    tenant_id: &'a str,
    namespace: &'a str,
    route_name: &'static str,
    operation: &'static str,
    actor_did: &'a str,
    idempotency_key: &'a str,
    request_hash: Option<Hash256>,
    event_type: ReceiptEventType,
    status: StatusCode,
    error_code: Option<&'a str>,
}

#[cfg(feature = "production-db")]
async fn insert_gateway_operational_receipt(
    pool: &sqlx::PgPool,
    receipt: GatewayOperationalReceipt<'_>,
) -> Result<(), Box<Response>> {
    let mut tx = match begin_tenant_transaction(pool, receipt.tenant_id).await {
        Ok(tx) => tx,
        Err(_) => return Err(operational_audit_unavailable_response(receipt)),
    };
    if let Err(error) = insert_gateway_operational_receipt_in_transaction(&mut tx, receipt).await {
        let _ = tx.rollback().await;
        return Err(error);
    }
    tx.commit()
        .await
        .map_err(|_| operational_audit_unavailable_response(receipt))?;
    Ok(())
}

#[cfg(feature = "production-db")]
async fn insert_gateway_operational_receipt_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    receipt: GatewayOperationalReceipt<'_>,
) -> Result<u64, Box<Response>> {
    let idempotency_ref = idempotency_ref(receipt.idempotency_key);
    let request_hash = receipt.request_hash.map(|hash| hash.to_string());
    let event_type = receipt_event_type_name(receipt.event_type);
    let attempt_ordinal = next_gateway_operational_attempt_ordinal(
        tx,
        receipt,
        &idempotency_ref,
        request_hash.as_deref(),
    )
    .await?;
    let receipt_body = json!({
        "route": receipt.route_name,
        "operation": receipt.operation,
        "tenant_id": receipt.tenant_id,
        "namespace": receipt.namespace,
        "idempotency_ref": idempotency_ref,
        "request_hash": request_hash,
        "status": receipt.status.as_u16(),
        "error_code": receipt.error_code,
        "event_type": event_type,
        "actor_did": receipt.actor_did,
        "attempt_ordinal": attempt_ordinal,
        "source": GATEWAY_OPERATIONAL_AUDIT_SOURCE,
    });
    let event_body_hash = gateway_operational_event_body_hash(&receipt_body)
        .map_err(|_| operational_audit_unavailable_response(receipt))?;
    let subject_ref = format!(
        "{}:{}:{}:{}:{}:{}",
        receipt.route_name,
        event_type,
        idempotency_ref,
        request_hash.as_deref().unwrap_or(""),
        receipt.error_code.unwrap_or(""),
        attempt_ordinal
    );
    let event_hlc = gateway_operational_event_hlc(receipt, attempt_ordinal)?;
    exo_dag_db_postgres::receipt::insert_operational_receipt_in_transaction(
        tx,
        exo_dag_db_postgres::receipt::OperationalReceiptInsert {
            tenant_id: receipt.tenant_id,
            namespace: receipt.namespace,
            subject_kind: SubjectKind::Route,
            subject_id: exo_dag_db_postgres::receipt::operational_receipt_subject_id(
                receipt.route_name,
                &subject_ref,
                receipt.event_type,
            ),
            event_type: receipt.event_type,
            actor_did: receipt.actor_did,
            event_hlc,
            event_body_hash,
            receipt_body,
        },
    )
    .await
    .map_err(|_| operational_audit_unavailable_response(receipt))
}

#[cfg(feature = "production-db")]
fn gateway_operational_event_body_hash<T: Serialize>(
    body: &T,
) -> Result<Hash256, ciborium::ser::Error<std::io::Error>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&("dagdb.gateway.operational_receipt", body), &mut bytes)?;
    Ok(Hash256::digest(&bytes))
}

#[cfg(feature = "production-db")]
async fn next_gateway_operational_attempt_ordinal(
    tx: &mut Transaction<'_, Postgres>,
    receipt: GatewayOperationalReceipt<'_>,
    idempotency_ref: &str,
    request_hash: Option<&str>,
) -> Result<i64, Box<Response>> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dagdb_receipts \
         WHERE tenant_id = $1 AND namespace = $2 AND event_type = $3 \
           AND receipt_body->>'route' = $4 \
           AND COALESCE(receipt_body->>'idempotency_ref', '') = $5 \
           AND COALESCE(receipt_body->>'request_hash', '') = $6 \
           AND COALESCE(receipt_body->>'error_code', '') = $7",
    )
    .bind(receipt.tenant_id)
    .bind(receipt.namespace)
    .bind(receipt_event_type_name(receipt.event_type))
    .bind(receipt.route_name)
    .bind(idempotency_ref)
    .bind(request_hash.unwrap_or(""))
    .bind(receipt.error_code.unwrap_or(""))
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| operational_audit_unavailable_response(receipt))?;
    Ok(count + 1)
}

#[cfg(feature = "production-db")]
fn gateway_operational_event_hlc(
    receipt: GatewayOperationalReceipt<'_>,
    attempt_ordinal: i64,
) -> Result<Timestamp, Box<Response>> {
    let logical = u32::try_from(attempt_ordinal)
        .map_err(|_| operational_audit_unavailable_response(receipt))?;
    Ok(Timestamp::new(1, logical))
}

#[cfg(feature = "production-db")]
fn operational_audit_unavailable_response(receipt: GatewayOperationalReceipt<'_>) -> Box<Response> {
    warn!(
        route = receipt.route_name,
        status = StatusCode::SERVICE_UNAVAILABLE.as_u16(),
        tenant_id = %receipt.tenant_id,
        namespace = %receipt.namespace,
        idempotency_ref = %idempotency_ref(receipt.idempotency_key),
        "DAG DB operational receipt persistence failed closed"
    );
    Box::new(dagdb_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
        format!(
            "DAG DB {} operational audit could not be persisted",
            receipt.operation
        ),
        false,
    ))
}

#[cfg(feature = "production-db")]
fn gateway_operational_actor(actor_did: &str) -> &str {
    if actor_did.trim().is_empty() {
        GATEWAY_OPERATIONAL_AUDIT_ACTOR
    } else {
        actor_did
    }
}

#[cfg(feature = "production-db")]
fn gateway_operation_from_route_name(route_name: &str) -> &'static str {
    match route_name {
        INTAKE_ROUTE_IDEMPOTENCY_NAME => "intake",
        VALIDATE_ROUTE_IDEMPOTENCY_NAME => "validate",
        TRUST_CHECK_ROUTE_IDEMPOTENCY_NAME => "trust-check",
        COUNCIL_DECISION_ROUTE_IDEMPOTENCY_NAME => "council decision",
        IMPORT_ROUTE_IDEMPOTENCY_NAME => "import",
        EXPORT_ROUTE_IDEMPOTENCY_NAME => "export",
        "dagdb.route" => "route",
        "dagdb.context_packet" => "context_packet",
        "dagdb.writeback" => "writeback",
        _ => "dagdb",
    }
}

#[cfg(feature = "production-db")]
fn receipt_event_type_name(event_type: ReceiptEventType) -> &'static str {
    match event_type {
        ReceiptEventType::DagdbApprovalDenied => "dagdb_approval_denied",
        ReceiptEventType::DagdbReplayDetected => "dagdb_replay_detected",
        ReceiptEventType::DagdbIdempotencyConflict => "dagdb_idempotency_conflict",
        ReceiptEventType::DagdbRlsTenantViolation => "dagdb_rls_tenant_violation",
        ReceiptEventType::DagdbSignatureFailure => "dagdb_signature_failure",
        _ => "dagdb_operational_event",
    }
}

#[cfg(feature = "production-db")]
fn mounted_audit_tenant_id(_headers: &HeaderMap, request_tenant_id: &str) -> String {
    request_tenant_id.to_owned()
}

#[cfg(feature = "production-db")]
fn mounted_audit_namespace(_headers: &HeaderMap, request_namespace: &str) -> String {
    request_namespace.to_owned()
}

/// Insert a gateway idempotency reservation stamped by the trusted database
/// clock (the gateway's approved DB-backed time source; AGENTS.md forbids
/// `SystemTime` in production code).
#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
async fn insert_gateway_idempotency_reservation(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    namespace: &str,
    route_name: &'static str,
    idempotency_key: &str,
    request_hash: Hash256,
    response_hash: Hash256,
    response_body: &Value,
    operation: &'static str,
) -> Result<bool, Box<Response>> {
    let inserted = sqlx::query(
        "INSERT INTO dagdb_idempotency_keys \
         (tenant_id, namespace, route_name, idempotency_key, request_hash, response_hash, response_body, \
          status_code, cached_failure, created_at_physical_ms, created_at_logical, \
          expires_at_physical_ms, expires_at_logical) \
         SELECT $1, $2, $3, $4, $5, $6, $7, 202, false, trusted_now.now_ms, 0, \
                trusted_now.now_ms + $8, 0 \
         FROM (SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT AS now_ms) \
              AS trusted_now \
         ON CONFLICT (tenant_id, namespace, route_name, idempotency_key) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(namespace)
    .bind(route_name)
    .bind(idempotency_key)
    .bind(request_hash.as_bytes().to_vec())
    .bind(response_hash.as_bytes().to_vec())
    .bind(response_body.clone())
    .bind(GATEWAY_IDEMPOTENCY_RESERVATION_TTL_MS)
    .execute(&mut **tx)
    .await
    .map_err(|_| {
        idempotency_unavailable_response_logged(
            route_name,
            "reserve",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
        )
    })?;
    Ok(inserted.rows_affected() == 1)
}

/// Delete an expired reserved row for the same request hash so the retry can
/// re-reserve; completed responses and foreign-request reservations are never
/// touched.
#[cfg(feature = "production-db")]
async fn reclaim_expired_gateway_idempotency_reservation(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    namespace: &str,
    route_name: &'static str,
    idempotency_key: &str,
    request_hash: Hash256,
    operation: &'static str,
) -> Result<bool, Box<Response>> {
    let reclaimed = sqlx::query(
        "DELETE FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3 AND idempotency_key = $4 \
           AND request_hash = $5 \
           AND response_body->>'idempotency_status' = $6 \
           AND expires_at_physical_ms < FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT",
    )
    .bind(tenant_id)
    .bind(namespace)
    .bind(route_name)
    .bind(idempotency_key)
    .bind(request_hash.as_bytes().to_vec())
    .bind(RESERVED_IDEMPOTENCY_BODY_STATUS)
    .execute(&mut **tx)
    .await
    .map_err(|_| {
        idempotency_unavailable_response_logged(
            route_name,
            "reserve",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
        )
    })?;
    Ok(reclaimed.rows_affected() == 1)
}

#[cfg(feature = "production-db")]
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn replay_gateway_idempotency_response(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    namespace: &str,
    route_name: &'static str,
    idempotency_key: &str,
    request_hash: Hash256,
    actor_did: &str,
    operation: &'static str,
) -> Result<GatewayIdempotencyDecision, Box<Response>> {
    let mut tx = begin_gateway_idempotency_transaction(
        pool,
        tenant_id,
        namespace,
        route_name,
        idempotency_key,
        "replay",
        operation,
    )
    .await?;
    let decision = replay_gateway_idempotency_response_in_transaction(
        &mut tx,
        tenant_id,
        namespace,
        route_name,
        idempotency_key,
        request_hash,
        actor_did,
        operation,
    )
    .await?;
    commit_gateway_idempotency_transaction(
        tx,
        tenant_id,
        namespace,
        route_name,
        idempotency_key,
        "replay",
        operation,
    )
    .await?;
    match decision {
        GatewayIdempotencyDecision::Failed(response) => Err(response),
        decision => Ok(decision),
    }
}

#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
async fn replay_gateway_idempotency_response_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    namespace: &str,
    route_name: &'static str,
    idempotency_key: &str,
    request_hash: Hash256,
    actor_did: &str,
    operation: &'static str,
) -> Result<GatewayIdempotencyDecision, Box<Response>> {
    let unavailable = || {
        idempotency_unavailable_response_logged(
            route_name,
            "replay",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
        )
    };
    let row = sqlx::query(
        "SELECT request_hash, response_body, status_code FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3 AND idempotency_key = $4",
    )
    .bind(tenant_id)
    .bind(namespace)
    .bind(route_name)
    .bind(idempotency_key)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| unavailable())?;

    let existing_hash = hash_from_idempotency_row(
        row.try_get("request_hash").map_err(|_| unavailable())?,
        operation,
    )
    .inspect_err(|_| {
        log_idempotency_failure(
            route_name,
            "replay",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
            StatusCode::SERVICE_UNAVAILABLE,
        );
    })?;
    if existing_hash != request_hash {
        insert_gateway_operational_receipt_in_transaction(
            tx,
            GatewayOperationalReceipt {
                tenant_id,
                namespace,
                route_name,
                operation,
                actor_did: gateway_operational_actor(actor_did),
                idempotency_key,
                request_hash: Some(request_hash),
                event_type: ReceiptEventType::DagdbIdempotencyConflict,
                status: StatusCode::CONFLICT,
                error_code: Some("idempotency_key_conflict"),
            },
        )
        .await
        .map_err(|_| unavailable())?;
        return Ok(GatewayIdempotencyDecision::Failed(
            idempotency_conflict_response(operation),
        ));
    }

    let mut body: Value = row.try_get("response_body").map_err(|_| unavailable())?;
    if body.get("idempotency_status").and_then(Value::as_str)
        == Some(RESERVED_IDEMPOTENCY_BODY_STATUS)
    {
        return Ok(GatewayIdempotencyDecision::Failed(
            idempotency_in_progress_response(operation),
        ));
    }
    let authorization_payload_hash = gateway_authorization_payload_hash_from_cached_body(
        route_name,
        operation,
        tenant_id,
        namespace,
        idempotency_key,
        &mut body,
    )?;
    mark_gateway_idempotency_replay_status(
        &mut body,
        route_name,
        operation,
        tenant_id,
        namespace,
        idempotency_key,
    )?;

    let status = status_from_idempotency_row(
        row.try_get("status_code").map_err(|_| unavailable())?,
        operation,
    )
    .inspect_err(|_| {
        log_idempotency_failure(
            route_name,
            "replay",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
            StatusCode::SERVICE_UNAVAILABLE,
        );
    })?;
    insert_gateway_operational_receipt_in_transaction(
        tx,
        GatewayOperationalReceipt {
            tenant_id,
            namespace,
            route_name,
            operation,
            actor_did: gateway_operational_actor(actor_did),
            idempotency_key,
            request_hash: Some(request_hash),
            event_type: ReceiptEventType::DagdbReplayDetected,
            status,
            error_code: None,
        },
    )
    .await
    .map_err(|_| unavailable())?;
    Ok(GatewayIdempotencyDecision::Replayed(
        CachedGatewayIdempotencyResponse {
            response: (status, Json(body)).into_response(),
            authorization_payload_hash,
        },
    ))
}

#[cfg(feature = "production-db")]
fn gateway_authorization_payload_hash_from_cached_body(
    route_name: &str,
    operation: &'static str,
    tenant_id: &str,
    namespace: &str,
    idempotency_key: &str,
    body: &mut Value,
) -> Result<Option<Hash256>, Box<Response>> {
    let Some(value) = body.get(GATEWAY_AUTHORIZATION_PAYLOAD_HASH_FIELD) else {
        return Ok(None);
    };
    let Some(hash_hex) = value.as_str() else {
        log_idempotency_failure(
            route_name,
            "replay",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
            StatusCode::SERVICE_UNAVAILABLE,
        );
        return Err(idempotency_unavailable_response(operation));
    };
    let authorization_payload_hash = exo_dag_db_exchange::kg_import::hash_from_hex(
        GATEWAY_AUTHORIZATION_PAYLOAD_HASH_FIELD,
        hash_hex,
    )
    .map_err(|_| {
        log_idempotency_failure(
            route_name,
            "replay",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
            StatusCode::SERVICE_UNAVAILABLE,
        );
        idempotency_unavailable_response(operation)
    })?;
    if let Value::Object(fields) = body {
        fields.remove(GATEWAY_AUTHORIZATION_PAYLOAD_HASH_FIELD);
    }
    Ok(Some(authorization_payload_hash))
}

#[cfg(feature = "production-db")]
fn mark_gateway_idempotency_replay_status(
    body: &mut Value,
    route_name: &str,
    operation: &'static str,
    tenant_id: &str,
    namespace: &str,
    idempotency_key: &str,
) -> Result<(), Box<Response>> {
    let Value::Object(fields) = body else {
        log_idempotency_failure(
            route_name,
            "replay",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
            StatusCode::SERVICE_UNAVAILABLE,
        );
        return Err(idempotency_unavailable_response(operation));
    };
    fields.insert(
        "idempotency_status".to_owned(),
        json!(REPLAYED_IDEMPOTENCY_BODY_STATUS),
    );
    Ok(())
}

#[cfg(feature = "production-db")]
fn insert_gateway_authorization_payload_hash(
    response_body: &mut Value,
    authorization_payload_hash: Option<Hash256>,
    route_name: &str,
    operation: &'static str,
    tenant_id: &str,
    namespace: &str,
    idempotency_key: &str,
) -> Result<(), Box<Response>> {
    let Some(authorization_payload_hash) = authorization_payload_hash else {
        return Ok(());
    };
    let Value::Object(fields) = response_body else {
        log_idempotency_failure(
            route_name,
            "store",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
            StatusCode::SERVICE_UNAVAILABLE,
        );
        return Err(idempotency_unavailable_response(operation));
    };
    fields.insert(
        GATEWAY_AUTHORIZATION_PAYLOAD_HASH_FIELD.to_owned(),
        json!(authorization_payload_hash.to_string()),
    );
    Ok(())
}

#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
async fn store_gateway_idempotency_response(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    namespace: &str,
    route_name: &str,
    idempotency_key: &str,
    request_hash: Hash256,
    status: StatusCode,
    response_body: Result<Value, Box<Response>>,
    authorization_payload_hash: Option<Hash256>,
    operation: &'static str,
) -> Result<(), Box<Response>> {
    let mut response_body = response_body.inspect_err(|_| {
        log_idempotency_failure(
            route_name,
            "store",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
            StatusCode::SERVICE_UNAVAILABLE,
        );
    })?;
    insert_gateway_authorization_payload_hash(
        &mut response_body,
        authorization_payload_hash,
        route_name,
        operation,
        tenant_id,
        namespace,
        idempotency_key,
    )?;
    let response_hash = gateway_idempotency_response_hash(
        &response_body,
        route_name,
        "store",
        operation,
        tenant_id,
        namespace,
        idempotency_key,
    )?;
    let mut tx = begin_gateway_idempotency_transaction(
        pool,
        tenant_id,
        namespace,
        route_name,
        idempotency_key,
        "store",
        operation,
    )
    .await?;
    let updated = sqlx::query(
        "UPDATE dagdb_idempotency_keys \
         SET response_hash = $5, response_body = $6, status_code = $7, cached_failure = false \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3 AND idempotency_key = $4 \
           AND request_hash = $8",
    )
    .bind(tenant_id)
    .bind(namespace)
    .bind(route_name)
    .bind(idempotency_key)
    .bind(response_hash.as_bytes().to_vec())
    .bind(response_body)
    .bind(i32::from(status.as_u16()))
    .bind(request_hash.as_bytes().to_vec())
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        idempotency_unavailable_response_logged(
            route_name,
            "store",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
        )
    })?;

    if updated.rows_affected() == 1 {
        commit_gateway_idempotency_transaction(
            tx,
            tenant_id,
            namespace,
            route_name,
            idempotency_key,
            "store",
            operation,
        )
        .await
    } else {
        Err(idempotency_unavailable_response_logged(
            route_name,
            "store",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
        ))
    }
}

#[cfg(feature = "production-db")]
async fn delete_gateway_idempotency_reservation(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    namespace: &str,
    route_name: &str,
    idempotency_key: &str,
    request_hash: Hash256,
) -> Result<u64, sqlx::Error> {
    let mut tx = begin_tenant_transaction(pool, tenant_id).await?;
    let rows_affected = delete_gateway_idempotency_reservation_in_transaction(
        &mut tx,
        tenant_id,
        namespace,
        route_name,
        idempotency_key,
        request_hash,
    )
    .await?;
    tx.commit().await?;
    Ok(rows_affected)
}

#[cfg(feature = "production-db")]
async fn delete_gateway_idempotency_reservation_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    namespace: &str,
    route_name: &str,
    idempotency_key: &str,
    request_hash: Hash256,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "DELETE FROM dagdb_idempotency_keys \
         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3 AND idempotency_key = $4 \
           AND request_hash = $5 \
           AND response_body->>'idempotency_status' = $6",
    )
    .bind(tenant_id)
    .bind(namespace)
    .bind(route_name)
    .bind(idempotency_key)
    .bind(request_hash.as_bytes().to_vec())
    .bind(RESERVED_IDEMPOTENCY_BODY_STATUS)
    .execute(&mut **tx)
    .await
    .map(|result| result.rows_affected())
}

#[cfg(feature = "production-db")]
async fn cleanup_gateway_idempotency_reservation(
    pool: &sqlx::PgPool,
    request: &DagDbImportRequest,
    request_hash: Hash256,
) -> Result<(), Box<Response>> {
    match delete_gateway_idempotency_reservation(
        pool,
        &request.tenant_id,
        &request.namespace,
        IMPORT_ROUTE_IDEMPOTENCY_NAME,
        &request.idempotency_key,
        request_hash,
    )
    .await
    {
        Ok(rows_affected) if idempotency_reservation_cleanup_removed(rows_affected) => Ok(()),
        Ok(rows_affected) => {
            log_idempotency_cleanup_row_mismatch(
                "dagdb.import",
                "import",
                &request.tenant_id,
                &request.namespace,
                &request.idempotency_key,
                rows_affected,
            );
            Err(idempotency_unavailable_response("import"))
        }
        Err(_) => Err(idempotency_unavailable_response_logged(
            "dagdb.import",
            "cleanup",
            "import",
            &request.tenant_id,
            &request.namespace,
            &request.idempotency_key,
        )),
    }
}

#[cfg(feature = "production-db")]
async fn cleanup_export_idempotency_reservation(
    pool: &sqlx::PgPool,
    request: &DagDbExportRequest,
    request_hash: Hash256,
) -> Result<(), Box<Response>> {
    match delete_gateway_idempotency_reservation(
        pool,
        &request.tenant_id,
        &request.namespace,
        EXPORT_ROUTE_IDEMPOTENCY_NAME,
        &request.idempotency_key,
        request_hash,
    )
    .await
    {
        Ok(rows_affected) if idempotency_reservation_cleanup_removed(rows_affected) => Ok(()),
        Ok(rows_affected) => {
            log_idempotency_cleanup_row_mismatch(
                "dagdb.export",
                "export",
                &request.tenant_id,
                &request.namespace,
                &request.idempotency_key,
                rows_affected,
            );
            Err(idempotency_unavailable_response("export"))
        }
        Err(_) => Err(idempotency_unavailable_response_logged(
            "dagdb.export",
            "cleanup",
            "export",
            &request.tenant_id,
            &request.namespace,
            &request.idempotency_key,
        )),
    }
}

#[cfg(feature = "production-db")]
#[allow(clippy::too_many_arguments)]
async fn cleanup_gateway_idempotency_reservation_for_route(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    namespace: &str,
    route_name: &'static str,
    idempotency_key: &str,
    request_hash: Hash256,
    operation: &'static str,
) -> Result<(), Box<Response>> {
    match delete_gateway_idempotency_reservation(
        pool,
        tenant_id,
        namespace,
        route_name,
        idempotency_key,
        request_hash,
    )
    .await
    {
        Ok(rows_affected) if idempotency_reservation_cleanup_removed(rows_affected) => Ok(()),
        Ok(rows_affected) => {
            log_idempotency_cleanup_row_mismatch(
                route_name,
                operation,
                tenant_id,
                namespace,
                idempotency_key,
                rows_affected,
            );
            Err(idempotency_unavailable_response(operation))
        }
        Err(_) => Err(idempotency_unavailable_response_logged(
            route_name,
            "cleanup",
            operation,
            tenant_id,
            namespace,
            idempotency_key,
        )),
    }
}

#[cfg(feature = "production-db")]
fn idempotency_unavailable_response_logged(
    route_name: &str,
    stage: &'static str,
    operation: &'static str,
    tenant_id: &str,
    namespace: &str,
    idempotency_key: &str,
) -> Box<Response> {
    log_idempotency_failure(
        route_name,
        stage,
        operation,
        tenant_id,
        namespace,
        idempotency_key,
        StatusCode::SERVICE_UNAVAILABLE,
    );
    idempotency_unavailable_response(operation)
}

#[cfg(feature = "production-db")]
fn log_idempotency_failure(
    route_name: &str,
    stage: &'static str,
    operation: &'static str,
    tenant_id: &str,
    namespace: &str,
    idempotency_key: &str,
    status: StatusCode,
) {
    warn!(
        route = route_name,
        status = status.as_u16(),
        stage,
        operation,
        tenant_id = %tenant_id,
        namespace = %namespace,
        idempotency_ref = %idempotency_ref(idempotency_key),
        "DAG DB idempotency guard failed closed"
    );
}

#[cfg(feature = "production-db")]
fn log_idempotency_cleanup_row_mismatch(
    route_name: &str,
    operation: &'static str,
    tenant_id: &str,
    namespace: &str,
    idempotency_key: &str,
    rows_affected: u64,
) {
    warn!(
        route = route_name,
        status = StatusCode::SERVICE_UNAVAILABLE.as_u16(),
        stage = "cleanup",
        operation,
        tenant_id = %tenant_id,
        namespace = %namespace,
        idempotency_ref = %idempotency_ref(idempotency_key),
        rows_affected,
        "DAG DB idempotency reservation cleanup removed unexpected row count"
    );
}

#[cfg(feature = "production-db")]
fn idempotency_reservation_cleanup_removed(rows_affected: u64) -> bool {
    rows_affected == 1
}

#[cfg(feature = "production-db")]
fn idempotency_ref(idempotency_key: &str) -> String {
    Hash256::digest(idempotency_key.as_bytes()).to_string()
}

#[cfg(feature = "production-db")]
fn hash_from_idempotency_row(
    bytes: Vec<u8>,
    operation: &'static str,
) -> Result<Hash256, Box<Response>> {
    let Ok(bytes) = <[u8; 32]>::try_from(bytes) else {
        return Err(idempotency_unavailable_response(operation));
    };
    Ok(Hash256::from_bytes(bytes))
}

#[cfg(feature = "production-db")]
fn status_from_idempotency_row(
    status_code: i32,
    operation: &'static str,
) -> Result<StatusCode, Box<Response>> {
    let Ok(status_code) = u16::try_from(status_code) else {
        return Err(idempotency_unavailable_response(operation));
    };
    StatusCode::from_u16(status_code).map_err(|_| idempotency_unavailable_response(operation))
}

#[cfg(feature = "production-db")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdapterFailure {
    status: StatusCode,
    error_code: &'static str,
    class: &'static str,
    message: &'static str,
}

#[cfg(feature = "production-db")]
fn import_adapter_failure(error: &KgImportPersistenceError) -> AdapterFailure {
    match error {
        KgImportPersistenceError::Report(report_error) => match report_error {
            KgImportError::InvalidJson { .. }
            | KgImportError::InvalidReport { .. }
            | KgImportError::InvalidHash { .. } => AdapterFailure {
                status: StatusCode::BAD_REQUEST,
                error_code: "import_rejected",
                class: "validation",
                message: "DAG DB import request was rejected by the import adapter",
            },
            KgImportError::Hash { .. } => import_runtime_adapter_failure("runtime"),
        },
        KgImportPersistenceError::Conflict { .. } => AdapterFailure {
            status: StatusCode::CONFLICT,
            error_code: "import_rejected",
            class: "conflict",
            message: "DAG DB import request conflicted with existing adapter state",
        },
        KgImportPersistenceError::UnsupportedSection { .. } => AdapterFailure {
            status: StatusCode::BAD_REQUEST,
            error_code: "import_rejected",
            class: "unsupported",
            message: "DAG DB import request used an unsupported adapter section",
        },
        // PRD-D2 (D2-S3): the import-time aggregate distillation rejected a layer
        // member (e.g. forbidden material), so the request content is rejected —
        // a validation failure, not a runtime fault.
        KgImportPersistenceError::LayerAggregate { .. } => AdapterFailure {
            status: StatusCode::BAD_REQUEST,
            error_code: "import_rejected",
            class: "validation",
            message: "DAG DB import request was rejected by the layer aggregate distiller",
        },
        KgImportPersistenceError::Postgres { .. } => import_runtime_adapter_failure("postgres"),
        KgImportPersistenceError::MissingDatabaseUrl { .. }
        | KgImportPersistenceError::Init { .. }
        | KgImportPersistenceError::Json { .. }
        | KgImportPersistenceError::TimestampOutOfRange
        | KgImportPersistenceError::CountOutOfRange
        | KgImportPersistenceError::Hash { .. } => import_runtime_adapter_failure("runtime"),
    }
}

#[cfg(feature = "production-db")]
fn import_runtime_adapter_failure(class: &'static str) -> AdapterFailure {
    AdapterFailure {
        status: StatusCode::SERVICE_UNAVAILABLE,
        error_code: "database_unavailable",
        class,
        message: "DAG DB import adapter is temporarily unavailable",
    }
}

#[cfg(feature = "production-db")]
fn export_adapter_failure(error: &KgExportError) -> AdapterFailure {
    match error {
        KgExportError::InvalidScope { .. } | KgExportError::ForbiddenMaterial { .. } => {
            AdapterFailure {
                status: StatusCode::BAD_REQUEST,
                error_code: "export_rejected",
                class: "validation",
                message: "DAG DB export request was rejected by the export adapter",
            }
        }
        KgExportError::ImportHash(import_error) => match import_error {
            KgImportError::InvalidJson { .. }
            | KgImportError::InvalidReport { .. }
            | KgImportError::InvalidHash { .. } => AdapterFailure {
                status: StatusCode::BAD_REQUEST,
                error_code: "export_rejected",
                class: "validation",
                message: "DAG DB export request was rejected by the export adapter",
            },
            KgImportError::Hash { .. } => export_runtime_adapter_failure("runtime"),
        },
        KgExportError::Conflict { .. } | KgExportError::IncompatibleCachedResponse { .. } => {
            AdapterFailure {
                status: StatusCode::CONFLICT,
                error_code: "export_rejected",
                class: "conflict",
                message: "DAG DB export request conflicted with existing adapter state",
            }
        }
        KgExportError::UnsupportedPersistenceTarget { .. } => AdapterFailure {
            status: StatusCode::BAD_REQUEST,
            error_code: "export_rejected",
            class: "unsupported",
            message: "DAG DB export request used an unsupported adapter target",
        },
        KgExportError::Postgres { .. } => export_runtime_adapter_failure("postgres"),
        KgExportError::MissingDatabaseUrl { .. }
        | KgExportError::TimestampOutOfRange
        | KgExportError::CountOutOfRange
        | KgExportError::Hash { .. }
        | KgExportError::Io { .. }
        | KgExportError::Json { .. }
        | KgExportError::Init { .. } => export_runtime_adapter_failure("runtime"),
    }
}

#[cfg(feature = "production-db")]
fn export_runtime_adapter_failure(class: &'static str) -> AdapterFailure {
    AdapterFailure {
        status: StatusCode::SERVICE_UNAVAILABLE,
        error_code: "database_unavailable",
        class,
        message: "DAG DB export adapter is temporarily unavailable",
    }
}

#[cfg(feature = "production-db")]
fn dagdb_import_adapter_error_response(
    request: &DagDbImportRequest,
    error: &KgImportPersistenceError,
) -> Response {
    let failure = import_adapter_failure(error);
    warn!(
        route = "dagdb.import",
        status = failure.status.as_u16(),
        error_code = failure.error_code,
        adapter_error_class = failure.class,
        tenant_id = %request.tenant_id,
        namespace = %request.namespace,
        "DAG DB import adapter failed closed"
    );
    dagdb_error_response(failure.status, failure.error_code, failure.message, false)
}

#[cfg(feature = "production-db")]
fn dagdb_export_adapter_error_response(
    request: &DagDbExportRequest,
    error: &KgExportError,
) -> Response {
    let failure = export_adapter_failure(error);
    warn!(
        route = "dagdb.export",
        status = failure.status.as_u16(),
        error_code = failure.error_code,
        adapter_error_class = failure.class,
        tenant_id = %request.tenant_id,
        namespace = %request.namespace,
        "DAG DB export adapter failed closed"
    );
    dagdb_error_response(failure.status, failure.error_code, failure.message, false)
}

#[cfg(feature = "production-db")]
fn idempotency_conflict_response(operation: &'static str) -> Box<Response> {
    Box::new(dagdb_error_response(
        StatusCode::CONFLICT,
        "idempotency_key_conflict",
        idempotency_message(
            operation,
            "idempotency key was already used with a different request body",
        ),
        false,
    ))
}

#[cfg(feature = "production-db")]
fn idempotency_in_progress_response(operation: &'static str) -> Box<Response> {
    Box::new(dagdb_error_response(
        StatusCode::CONFLICT,
        "idempotency_key_in_progress",
        idempotency_message(operation, "idempotency key is currently being processed"),
        false,
    ))
}

#[cfg(feature = "production-db")]
fn idempotency_unavailable_response(operation: &'static str) -> Box<Response> {
    Box::new(dagdb_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
        idempotency_message(operation, "idempotency guard could not be checked"),
        false,
    ))
}

#[cfg(feature = "production-db")]
fn import_idempotency_unavailable_response() -> Box<Response> {
    idempotency_unavailable_response("import")
}

#[cfg(feature = "production-db")]
fn export_idempotency_unavailable_response() -> Box<Response> {
    idempotency_unavailable_response("export")
}

fn dagdb_runtime_database_unavailable_response(operation: &'static str) -> Response {
    dagdb_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
        idempotency_message(operation, "requires a configured production database"),
        false,
    )
}

fn dagdb_route_database_unavailable_response(route_name: &'static str) -> Response {
    let operation = route_name.strip_prefix("dagdb.").unwrap_or(route_name);
    dagdb_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "database_unavailable",
        format!("DAG DB {operation} requires a configured production database"),
        false,
    )
}

fn idempotency_message(operation: &'static str, detail: &str) -> String {
    format!("DAG DB {operation} {detail}")
}

#[cfg(feature = "production-db")]
fn import_response_from_summary(
    request: DagDbImportRequest,
    summary: exo_dag_db_exchange::kg_import::KgImportPersistedSummary,
    import_status: &str,
) -> Result<DagDbImportResponse, Box<Response>> {
    let imported_record_count = summary
        .inserted_memory_count
        .saturating_add(summary.inserted_catalog_count)
        .saturating_add(summary.inserted_graph_node_count)
        .saturating_add(summary.inserted_graph_edge_count)
        .saturating_add(summary.inserted_layer_count)
        .saturating_add(summary.inserted_layer_membership_count)
        .saturating_add(summary.inserted_layer_edge_count)
        .saturating_add(summary.inserted_validation_report_count)
        .saturating_add(summary.inserted_placement_decision_count)
        .saturating_add(summary.inserted_placement_trace_count)
        .saturating_add(summary.inserted_receipt_count);
    Ok(DagDbImportResponse {
        schema_version: exo_api::dagdb::DAGDB_IMPORT_RESPONSE_SCHEMA_VERSION.to_owned(),
        operation_id: runtime_operation_id(
            "dagdb.gateway.import.operation",
            &request.tenant_id,
            &request.namespace,
            &request.idempotency_key,
            &request.db_set_version,
            &request.source_hash,
        )?,
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        idempotency_key: request.idempotency_key,
        db_set_version: request.db_set_version,
        import_status: import_status.to_owned(),
        import_receipt_id: Some(summary.idempotency_key),
        source_hash: request.source_hash,
        imported_record_count,
        receipt_path: None,
        non_claims: runtime_non_claims(),
        idempotency_status: Some(
            if summary.replayed {
                REPLAYED_IDEMPOTENCY_BODY_STATUS
            } else {
                STORED_IDEMPOTENCY_BODY_STATUS
            }
            .to_owned(),
        ),
    })
}

fn export_scope_from_request(request: &DagDbExportRequest) -> Result<KgExportScope, Box<Response>> {
    validate_runtime_request_basics(
        "dagdb.export",
        &request.tenant_id,
        &request.namespace,
        &request.idempotency_key,
        &request.db_set_version,
        &request.requester_did,
    )?;
    for memory_id in &request.included_memory_ids {
        exo_dag_db_exchange::kg_import::hash_from_hex("included_memory_ids", memory_id).map_err(
            |_| {
                invalid_runtime_request(
                    "dagdb.export",
                    "export_included_memory_id_invalid",
                    "DAG DB export included_memory_ids entries must be 64-character hex hashes",
                )
            },
        )?;
    }
    let scope = KgExportScope {
        tenant_id: request.tenant_id.clone(),
        namespace: request.namespace.clone(),
        included_memory_ids: request.included_memory_ids.clone(),
        included_graph_styles: request.included_graph_styles.clone(),
        included_writeback_idempotency_keys: request.included_writeback_idempotency_keys.clone(),
        source_commit_or_repo_ref: request.source_commit_or_repo_ref.clone(),
        include_preview_context: request.include_preview_context,
    };
    scope.validate().map_err(|_| {
        invalid_runtime_request(
            "dagdb.export",
            "export_scope_invalid_or_unsafe",
            "DAG DB export scope is invalid or unsafe",
        )
    })?;
    Ok(scope)
}

#[cfg(feature = "production-db")]
fn export_response_from_portable(
    request: DagDbExportRequest,
    export: exo_dag_db_exchange::kg_export::KgPortableExport,
) -> Result<DagDbExportResponse, Box<Response>> {
    let exported_record_count = export_record_count(&export);
    Ok(DagDbExportResponse {
        schema_version: exo_api::dagdb::DAGDB_EXPORT_RESPONSE_SCHEMA_VERSION.to_owned(),
        operation_id: runtime_operation_id(
            "dagdb.gateway.export.operation",
            &request.tenant_id,
            &request.namespace,
            &request.idempotency_key,
            &request.db_set_version,
            export.hashes.whole_export_hash.as_str(),
        )?,
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        idempotency_key: request.idempotency_key,
        db_set_version: request.db_set_version,
        export_status: "built".to_owned(),
        export_artifact_id: Some(export.export_id),
        export_hash: Some(export.hashes.whole_export_hash),
        exported_record_count,
        report_path: None,
        non_claims: runtime_non_claims(),
        idempotency_status: Some(STORED_IDEMPOTENCY_BODY_STATUS.to_owned()),
    })
}

fn validate_runtime_request_basics(
    route_name: &'static str,
    tenant_id: &str,
    namespace: &str,
    idempotency_key: &str,
    db_set_version: &str,
    requester_did: &str,
) -> Result<(), Box<Response>> {
    for (field, value) in [
        ("tenant_id", tenant_id),
        ("namespace", namespace),
        ("idempotency_key", idempotency_key),
        ("db_set_version", db_set_version),
        ("requester_did", requester_did),
    ] {
        if value.trim().is_empty() {
            return Err(invalid_runtime_request(
                route_name,
                "runtime_required_field_empty",
                "DAG DB runtime request fields must not be empty",
            ));
        }
        exo_dag_db_exchange::kg_export::reject_forbidden_string(field, value).map_err(|_| {
            invalid_runtime_request(
                route_name,
                "runtime_field_unsafe",
                "DAG DB runtime request field is unsafe",
            )
        })?;
    }
    if !requester_did.starts_with("did:") {
        return Err(invalid_runtime_request(
            route_name,
            "runtime_requester_did_invalid",
            "DAG DB runtime requester_did must be a DID",
        ));
    }
    Ok(())
}

#[cfg(feature = "production-db")]
fn runtime_operation_id(
    domain: &str,
    tenant_id: &str,
    namespace: &str,
    idempotency_key: &str,
    db_set_version: &str,
    material_hash: &str,
) -> Result<String, Box<Response>> {
    hash_hex(
        domain,
        &(
            tenant_id,
            namespace,
            idempotency_key,
            db_set_version,
            material_hash,
        ),
    )
}

#[cfg(feature = "production-db")]
fn runtime_non_claims() -> Vec<String> {
    vec![
        "m60_not_approved".to_owned(),
        "operator_runtime_approval_not_present".to_owned(),
        "not_final_evidence".to_owned(),
    ]
}

#[cfg(feature = "production-db")]
fn export_record_count(export: &exo_dag_db_exchange::kg_export::KgPortableExport) -> u32 {
    [
        export.memory_records.len(),
        export.catalog_entries.len(),
        export.graph_nodes.len(),
        export.graph_edges.len(),
        export.similarity_results.len(),
        export.canonicalization_decisions.len(),
        export.placement_traces.len(),
        export.validation_reports.len(),
        export.receipts.len(),
        export.subject_receipt_heads.len(),
        export.context_packet_previews.len(),
        export.context_packet_records.len(),
        export.route_receipts.len(),
        export.writeback_summaries.len(),
        export.idempotency_references.len(),
        export.citation_index.len(),
        export.provenance_index.len(),
    ]
    .into_iter()
    .fold(0_u32, |total, count| {
        total.saturating_add(u32::try_from(count).unwrap_or(u32::MAX))
    })
}

fn invalid_runtime_request(
    route_name: &'static str,
    category: &'static str,
    message: &'static str,
) -> Box<Response> {
    warn!(
        route = route_name,
        status = 400,
        error_code = "invalid_request_shape",
        category,
        "DAG DB runtime request rejected"
    );
    Box::new(dagdb_error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request_shape",
        message,
        false,
    ))
}

#[cfg(test)]
fn receipt_lookup_response(request: DagDbReceiptLookupRequest) -> DagDbReceiptLookupResponse {
    DagDbReceiptLookupResponse {
        schema_version: exo_api::dagdb::DAGDB_RECEIPT_LOOKUP_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        receipt_hash: request.receipt_hash,
        subject_kind: SubjectKind::Memory,
        subject_id: Hash256::ZERO.to_string(),
        prev_receipt_hash: Hash256::ZERO.to_string(),
        seq: 1,
        event_type: ReceiptEventType::IntakeCreated,
        actor_did: "did:exo:gateway".to_owned(),
        event_hlc: "0:0".to_owned(),
        created_at: "0:0".to_owned(),
        receipt_body: request.include_body.unwrap_or(false).then(|| {
            json!({
                "summary": safe_gateway_metadata("receipt lookup body")
            })
        }),
        validation_report_id: None,
    }
}

#[cfg(test)]
fn catalog_lookup_response(request: DagDbCatalogLookupRequest) -> DagDbCatalogLookupResponse {
    let title = safe_gateway_metadata("catalog");
    let summary = safe_gateway_metadata("catalog summary");
    DagDbCatalogLookupResponse {
        schema_version: exo_api::dagdb::DAGDB_CATALOG_LOOKUP_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        catalog_id: request.catalog_id,
        catalog_level: 0,
        title: title.clone(),
        summary: summary.clone(),
        keywords: Vec::new(),
        status: exo_api::dagdb::MemoryStatus::Routable,
        validation_status: ValidationStatus::Passed,
        council_status: CouncilReviewStatus::NotRequired,
        dag_finality_status: DagFinalityStatus::Committed,
        latest_receipt_hash: Hash256::ZERO.to_string(),
        memory_id: None,
        parent_catalog_id: None,
        children: request.include_children.unwrap_or(false).then(|| {
            vec![CatalogEntryResponse {
                catalog_id: Hash256::digest(b"child-catalog").to_string(),
                title,
                summary,
            }]
        }),
        routes: request
            .include_routes
            .unwrap_or(false)
            .then(|| vec![Hash256::digest(b"catalog-route").to_string()]),
    }
}

#[cfg(test)]
fn route_lookup_response(request: DagDbRouteLookupRequest) -> DagDbRouteLookupResponse {
    DagDbRouteLookupResponse {
        schema_version: exo_api::dagdb::DAGDB_ROUTE_LOOKUP_RESPONSE_SCHEMA_VERSION.to_owned(),
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        route_id: request.route_id,
        route_status: RouteStatus::Active,
        validation_status: ValidationStatus::Passed,
        council_status: CouncilReviewStatus::NotRequired,
        dag_finality_status: DagFinalityStatus::Committed,
        selected_memory_ids: Vec::new(),
        route_score_bp: 0,
        token_budget: 0,
        token_estimate: 0,
        stale_at: "86400000:0".to_owned(),
        latest_receipt_hash: Hash256::ZERO.to_string(),
        memory_refs: request.include_memory_refs.unwrap_or(false).then(|| {
            vec![ContextPacketMemoryRef {
                memory_id: Hash256::digest(b"route-memory").to_string(),
                title: safe_gateway_metadata("memory"),
                summary: safe_gateway_metadata("memory summary"),
                keywords: Vec::new(),
                latest_receipt_hash: Hash256::ZERO.to_string(),
            }]
        }),
        validation_report: None,
    }
}

fn sanitize_metadata(field: MetadataField, text: &str) -> Result<SafeMetadata, Box<Response>> {
    sanitize_runtime_metadata(field, text).map_err(|_| {
        Box::new(dagdb_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "metadata_rejected",
            "DAG DB metadata was rejected",
            true,
        ))
    })
}

fn sanitize_optional_metadata(
    field: MetadataField,
    text: Option<&str>,
) -> Result<Option<SafeMetadata>, Box<Response>> {
    text.map(|value| sanitize_metadata(field, value))
        .transpose()
}

fn sanitize_keyword_texts(texts: Option<&[String]>) -> Result<Vec<SafeMetadata>, Box<Response>> {
    let empty = Vec::new();
    let keyword_texts = texts.unwrap_or(&empty);
    sanitize_keywords(keyword_texts).map_err(|_| {
        Box::new(dagdb_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "metadata_rejected",
            "DAG DB keyword metadata was rejected",
            true,
        ))
    })
}

fn request_json<T: Serialize>(request: &T) -> Result<Value, Box<Response>> {
    serde_json::to_value(request).map_err(|_| {
        Box::new(dagdb_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
            "DAG DB request could not be canonicalized",
            false,
        ))
    })
}

fn replace_metadata(
    body: &mut Value,
    inbound_field: &str,
    stored_field: &str,
    value: Value,
) -> Result<(), Box<Response>> {
    let Some(object) = body.as_object_mut() else {
        return Err(Box::new(dagdb_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
            "DAG DB request body must be a JSON object",
            false,
        )));
    };
    object.remove(inbound_field);
    object.insert(stored_field.to_owned(), value);
    Ok(())
}

fn request_hash<T: Serialize>(
    route_name: &str,
    tenant_id: &str,
    namespace: &str,
    redacted_body: &T,
) -> Result<Hash256, Box<Response>> {
    let mut canonical_body = Vec::new();
    ciborium::ser::into_writer(redacted_body, &mut canonical_body).map_err(|_| {
        Box::new(dagdb_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
            "DAG DB request body could not be encoded canonically",
            false,
        ))
    })?;
    RequestHashMaterial {
        route_name: route_name.to_owned(),
        tenant_id: tenant_id.to_owned(),
        namespace: namespace.to_owned(),
        canonical_redacted_request_body: canonical_body,
    }
    .hash()
    .map_err(|_| {
        Box::new(dagdb_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
            "DAG DB request hash could not be computed",
            false,
        ))
    })
}

fn hash_hex<T: Serialize>(domain: &str, value: &T) -> Result<String, Box<Response>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&(domain, value), &mut bytes).map_err(|_| {
        Box::new(dagdb_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
            "DAG DB response hash could not be computed",
            false,
        ))
    })?;
    Ok(Hash256::digest(&bytes).to_string())
}

#[cfg(feature = "production-db")]
fn gateway_idempotency_response_hash<T: Serialize>(
    response_body: &T,
    route_name: &str,
    stage: &'static str,
    operation: &'static str,
    tenant_id: &str,
    namespace: &str,
    idempotency_key: &str,
) -> Result<Hash256, Box<Response>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(
        &("dagdb.gateway.idempotency_response", response_body),
        &mut bytes,
    )
    .map_err(|_| {
        idempotency_unavailable_response_logged(
            route_name,
            stage,
            operation,
            tenant_id,
            namespace,
            idempotency_key,
        )
    })?;
    Ok(Hash256::digest(&bytes))
}

fn receipt_hash(route_name: &str, request_hash: Hash256) -> Result<String, Box<Response>> {
    hash_hex("dagdb.gateway.receipt", &(route_name, request_hash))
}

#[cfg(feature = "production-db")]
fn route_database_unavailable_box(route_name: &'static str) -> Box<Response> {
    Box::new(dagdb_route_database_unavailable_response(route_name))
}

#[cfg(feature = "production-db")]
fn route_not_found_box(route_name: &'static str, message: &'static str) -> Box<Response> {
    Box::new(dagdb_error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("DAG DB {route_name} {message}"),
        false,
    ))
}

#[cfg(feature = "production-db")]
fn hash_from_hex_for_route(
    route_name: &'static str,
    field: &'static str,
    value: &str,
) -> Result<Hash256, Box<Response>> {
    exo_dag_db_exchange::kg_import::hash_from_hex(field, value).map_err(|_| {
        Box::new(dagdb_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
            format!("DAG DB {route_name} requires {field} to be a 64-character hex hash"),
            false,
        ))
    })
}

#[cfg(feature = "production-db")]
fn optional_hash_from_hex_for_route(
    route_name: &'static str,
    field: &'static str,
    value: Option<&str>,
) -> Result<Option<Hash256>, Box<Response>> {
    value
        .map(|value| hash_from_hex_for_route(route_name, field, value))
        .transpose()
}

#[cfg(feature = "production-db")]
fn hash_bytes(hash: Hash256) -> Vec<u8> {
    hash.as_bytes().to_vec()
}

#[cfg(feature = "production-db")]
fn optional_hash_bytes(hash: Option<Hash256>) -> Option<Vec<u8>> {
    hash.map(hash_bytes)
}

#[cfg(feature = "production-db")]
fn enum_sql_for_route<T: Serialize>(
    route_name: &'static str,
    value: &T,
) -> Result<String, Box<Response>> {
    match serde_json::to_value(value).map_err(|_| route_database_unavailable_box(route_name))? {
        Value::String(value) => Ok(value),
        _ => Err(route_database_unavailable_box(route_name)),
    }
}

#[cfg(feature = "production-db")]
fn enum_from_sql_for_route<T>(route_name: &'static str, value: String) -> Result<T, Box<Response>>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(Value::String(value))
        .map_err(|_| route_database_unavailable_box(route_name))
}

#[cfg(feature = "production-db")]
fn json_value_for_route<T: Serialize>(
    route_name: &'static str,
    value: &T,
) -> Result<Value, Box<Response>> {
    serde_json::to_value(value).map_err(|_| route_database_unavailable_box(route_name))
}

#[cfg(feature = "production-db")]
fn json_column_for_route<T>(
    route_name: &'static str,
    row: &sqlx::postgres::PgRow,
    name: &'static str,
) -> Result<T, Box<Response>>
where
    T: for<'de> Deserialize<'de>,
{
    let value: Value = row
        .try_get(name)
        .map_err(|_| route_database_unavailable_box(route_name))?;
    serde_json::from_value(value).map_err(|_| route_database_unavailable_box(route_name))
}

#[cfg(feature = "production-db")]
fn parse_hlc_for_route(
    route_name: &'static str,
    field: &'static str,
    value: &str,
) -> Result<Timestamp, Box<Response>> {
    let Some((physical, logical)) = value.split_once(':') else {
        return Err(Box::new(dagdb_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
            format!("DAG DB {route_name} requires {field} to be an HLC timestamp"),
            false,
        )));
    };
    let physical_ms = physical.parse::<u64>().map_err(|_| {
        Box::new(dagdb_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
            format!("DAG DB {route_name} requires {field} physical_ms to be an integer"),
            false,
        ))
    })?;
    let logical = logical.parse::<u32>().map_err(|_| {
        Box::new(dagdb_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
            format!("DAG DB {route_name} requires {field} logical to be an integer"),
            false,
        ))
    })?;
    Ok(Timestamp::new(physical_ms, logical))
}

#[cfg(feature = "production-db")]
fn timestamp_physical_i64(
    route_name: &'static str,
    timestamp: Timestamp,
) -> Result<i64, Box<Response>> {
    i64::try_from(timestamp.physical_ms).map_err(|_| route_database_unavailable_box(route_name))
}

#[cfg(feature = "production-db")]
fn timestamp_logical_i32(
    route_name: &'static str,
    timestamp: Timestamp,
) -> Result<i32, Box<Response>> {
    i32::try_from(timestamp.logical).map_err(|_| route_database_unavailable_box(route_name))
}

#[cfg(feature = "production-db")]
fn u64_from_i64_for_route(route_name: &'static str, value: i64) -> Result<u64, Box<Response>> {
    u64::try_from(value).map_err(|_| route_database_unavailable_box(route_name))
}

#[cfg(feature = "production-db")]
fn u32_from_i32_for_route(route_name: &'static str, value: i32) -> Result<u32, Box<Response>> {
    u32::try_from(value).map_err(|_| route_database_unavailable_box(route_name))
}

#[cfg(feature = "production-db")]
fn u16_from_i32_for_route(route_name: &'static str, value: i32) -> Result<u16, Box<Response>> {
    u16::try_from(value).map_err(|_| route_database_unavailable_box(route_name))
}

#[cfg(feature = "production-db")]
fn hlc_text(physical_ms: i64, logical: i32) -> Result<String, Box<Response>> {
    let physical_ms =
        u64::try_from(physical_ms).map_err(|_| route_database_unavailable_box("dagdb.lookup"))?;
    let logical =
        u32::try_from(logical).map_err(|_| route_database_unavailable_box("dagdb.lookup"))?;
    Ok(format!("{physical_ms}:{logical}"))
}

#[cfg(feature = "production-db")]
fn intake_redacted_body(
    request: &DagDbIntakeRequest,
    response: &DagDbIntakeResponse,
) -> Result<Value, Box<Response>> {
    let mut redacted_body = request_json(request)?;
    replace_metadata(
        &mut redacted_body,
        "title_text",
        "title",
        request_json(&response.title)?,
    )?;
    replace_metadata(
        &mut redacted_body,
        "summary_text",
        "summary",
        request_json(&response.summary)?,
    )?;
    replace_metadata(
        &mut redacted_body,
        "keyword_texts",
        "keywords",
        request_json(&response.keywords)?,
    )?;
    Ok(redacted_body)
}

#[cfg(feature = "production-db")]
fn validate_redacted_body(
    request: &DagDbValidateRequest,
    response: &DagDbValidateResponse,
) -> Result<Value, Box<Response>> {
    let mut redacted_body = request_json(request)?;
    replace_metadata(
        &mut redacted_body,
        "validation_notes_text",
        "validation_notes",
        request_json(&response.notes)?,
    )?;
    Ok(redacted_body)
}

#[cfg(feature = "production-db")]
fn validation_receipt_event_type(status: ValidationStatus) -> ReceiptEventType {
    match status {
        ValidationStatus::Passed => ReceiptEventType::ValidationPassed,
        ValidationStatus::Failed | ValidationStatus::Contradictory => {
            ReceiptEventType::ValidationFailed
        }
        _ => ReceiptEventType::ValidationCreated,
    }
}

#[cfg(feature = "production-db")]
fn council_status_from_decision(status: CouncilDecisionStatus) -> CouncilReviewStatus {
    match status {
        CouncilDecisionStatus::Approved => CouncilReviewStatus::Approved,
        CouncilDecisionStatus::Denied | CouncilDecisionStatus::Revoked => {
            CouncilReviewStatus::Denied
        }
        CouncilDecisionStatus::Expired => CouncilReviewStatus::Expired,
        CouncilDecisionStatus::Escalated => CouncilReviewStatus::Escalated,
    }
}

#[cfg(feature = "production-db")]
struct GatewaySubjectReceipt<'a> {
    tenant_id: &'a str,
    namespace: &'a str,
    subject_kind: SubjectKind,
    subject_id: Hash256,
    event_type: ReceiptEventType,
    actor_did: &'a str,
    route_name: &'static str,
    receipt_body: Value,
}

#[cfg(feature = "production-db")]
async fn insert_gateway_subject_receipt_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    receipt: GatewaySubjectReceipt<'_>,
) -> Result<Hash256, Box<Response>> {
    let event_hlc = Timestamp::new(1, 1);
    let event_body_hash = gateway_operational_event_body_hash(&receipt.receipt_body)
        .map_err(|_| route_database_unavailable_box(receipt.route_name))?;
    let receipt_hash = ReceiptHashMaterial {
        tenant_id: receipt.tenant_id.to_owned(),
        namespace: receipt.namespace.to_owned(),
        subject_kind: receipt.subject_kind,
        subject_id: receipt.subject_id,
        prev_receipt_hash: Hash256::ZERO,
        seq: 1,
        event_type: receipt.event_type,
        actor_did: receipt.actor_did.to_owned(),
        event_hlc,
        event_body_hash,
    }
    .hash()
    .map_err(|_| route_database_unavailable_box(receipt.route_name))?;
    sqlx::query(
        "INSERT INTO dagdb_receipts \
         (receipt_hash, tenant_id, namespace, subject_kind, subject_id, prev_receipt_hash, seq, \
          event_type, actor_did, event_hlc_physical_ms, event_hlc_logical, event_hash, receipt_body, \
          created_at_physical_ms, created_at_logical) \
         VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8, 1, 1, $9, $10, 1, 1) \
         ON CONFLICT (receipt_hash) DO NOTHING",
    )
    .bind(hash_bytes(receipt_hash))
    .bind(receipt.tenant_id)
    .bind(receipt.namespace)
    .bind(enum_sql_for_route(receipt.route_name, &receipt.subject_kind)?)
    .bind(hash_bytes(receipt.subject_id))
    .bind(hash_bytes(Hash256::ZERO))
    .bind(enum_sql_for_route(receipt.route_name, &receipt.event_type)?)
    .bind(receipt.actor_did)
    .bind(hash_bytes(event_body_hash))
    .bind(receipt.receipt_body)
    .execute(&mut **tx)
    .await
    .map_err(|_| route_database_unavailable_box(receipt.route_name))?;
    sqlx::query(
        "INSERT INTO dagdb_subject_receipt_heads \
         (tenant_id, namespace, subject_kind, subject_id, latest_receipt_hash, latest_seq, \
          updated_at_physical_ms, updated_at_logical) \
         VALUES ($1, $2, $3, $4, $5, 1, 1, 1) \
         ON CONFLICT DO NOTHING",
    )
    .bind(receipt.tenant_id)
    .bind(receipt.namespace)
    .bind(enum_sql_for_route(
        receipt.route_name,
        &receipt.subject_kind,
    )?)
    .bind(hash_bytes(receipt.subject_id))
    .bind(hash_bytes(receipt_hash))
    .execute(&mut **tx)
    .await
    .map_err(|_| route_database_unavailable_box(receipt.route_name))?;
    Ok(receipt_hash)
}

#[cfg(feature = "production-db")]
async fn persist_intake_parent_edges(
    tx: &mut Transaction<'_, Postgres>,
    request: &DagDbIntakeRequest,
    memory_id: Hash256,
) -> Result<(), Box<Response>> {
    let Some(parent_memory_ids) = request.parent_memory_ids.as_deref() else {
        return Ok(());
    };
    let edge_types = request.edge_types.as_deref().unwrap_or(&[]);
    for (index, parent_memory_id) in parent_memory_ids.iter().enumerate() {
        let parent_hash =
            hash_from_hex_for_route("dagdb.intake", "parent_memory_id", parent_memory_id)?;
        let edge_type = edge_types
            .get(index)
            .map(|edge_type| enum_sql_for_route("dagdb.intake", edge_type))
            .transpose()?
            .unwrap_or_else(|| "parent".to_owned());
        sqlx::query(
            "INSERT INTO dagdb_memory_edges \
             (tenant_id, namespace, from_memory_id, to_memory_id, edge_type, \
              created_at_physical_ms, created_at_logical) \
             SELECT $1, $2, $3, $4, $5, 1, 0 \
             WHERE EXISTS (SELECT 1 FROM dagdb_memory_objects WHERE memory_id = $4) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&request.tenant_id)
        .bind(&request.namespace)
        .bind(hash_bytes(memory_id))
        .bind(hash_bytes(parent_hash))
        .bind(edge_type)
        .execute(&mut **tx)
        .await
        .map_err(|_| route_database_unavailable_box("dagdb.intake"))?;
    }
    Ok(())
}

#[cfg(feature = "production-db")]
async fn load_catalog_children(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    namespace: &str,
    catalog_id: Hash256,
) -> Result<Vec<CatalogEntryResponse>, Box<Response>> {
    let rows = sqlx::query(
        "SELECT encode(catalog_id, 'hex') AS catalog_id, title, summary \
         FROM dagdb_catalog_entries \
         WHERE tenant_id = $1 AND namespace = $2 AND parent_catalog_id = $3 \
         ORDER BY catalog_level ASC, catalog_id ASC LIMIT 100",
    )
    .bind(tenant_id)
    .bind(namespace)
    .bind(hash_bytes(catalog_id))
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?;
    rows.into_iter()
        .map(|row| {
            Ok(CatalogEntryResponse {
                catalog_id: row
                    .try_get("catalog_id")
                    .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?,
                title: json_column_for_route("dagdb.catalog_lookup", &row, "title")?,
                summary: json_column_for_route("dagdb.catalog_lookup", &row, "summary")?,
            })
        })
        .collect()
}

#[cfg(feature = "production-db")]
async fn load_catalog_route_ids(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    namespace: &str,
) -> Result<Vec<String>, Box<Response>> {
    let rows = sqlx::query(
        "SELECT encode(route_id, 'hex') AS route_id \
         FROM dagdb_route_receipts \
         WHERE tenant_id = $1 AND namespace = $2 \
         ORDER BY route_id ASC LIMIT 100",
    )
    .bind(tenant_id)
    .bind(namespace)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))?;
    rows.into_iter()
        .map(|row| {
            row.try_get("route_id")
                .map_err(|_| route_database_unavailable_box("dagdb.catalog_lookup"))
        })
        .collect()
}

#[cfg(test)]
fn safe_gateway_metadata(text: &str) -> SafeMetadata {
    SafeMetadata {
        decision: exo_api::dagdb::SafeMetadataDecision::Allow,
        text: text.to_owned(),
        redaction_codes: Vec::new(),
        original_hash: Hash256::digest(text.as_bytes()).to_string(),
        truncated: false,
        byte_len: u32::try_from(text.len()).unwrap_or(u32::MAX),
    }
}

fn council_unauthenticated_response() -> Response {
    dagdb_error_response(
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "DAG DB council decision requires bearer authentication",
        false,
    )
}

fn council_tenant_scope_mismatch_response() -> Response {
    dagdb_error_response(
        StatusCode::FORBIDDEN,
        "tenant_scope_mismatch",
        "DAG DB tenant or namespace does not match the authorized scope",
        false,
    )
}

fn council_authority_required_response() -> Response {
    dagdb_error_response(
        StatusCode::FORBIDDEN,
        "council_authority_required",
        "DAG DB council decision requires council authority scope",
        true,
    )
}

#[cfg(test)]
fn council_error_response(error: CouncilError) -> Response {
    match error {
        CouncilError::InvalidRequestShape(_) | CouncilError::Hash(_) => dagdb_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
            "DAG DB council decision request is invalid",
            false,
        ),
        CouncilError::Metadata(_) => dagdb_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "metadata_rejected",
            "DAG DB council decision metadata was rejected",
            true,
        ),
        CouncilError::ApprovalScopeMismatch => dagdb_error_response(
            StatusCode::CONFLICT,
            "approval_scope_mismatch",
            "DAG DB council decision scope does not match the subject",
            true,
        ),
        CouncilError::ApprovalDenied => dagdb_error_response(
            StatusCode::FORBIDDEN,
            "approval_denied",
            "DAG DB council decision was denied",
            true,
        ),
        CouncilError::CouncilEscalationRequired => dagdb_error_response(
            StatusCode::FORBIDDEN,
            "council_escalation_required",
            "DAG DB council decision requires escalation",
            true,
        ),
        CouncilError::ApprovalRequired => dagdb_error_response(
            StatusCode::FORBIDDEN,
            "approval_required",
            "DAG DB council approval is required",
            true,
        ),
    }
}

fn dagdb_error_response(
    status: StatusCode,
    error_code: &str,
    message: impl Into<String>,
    requires_council_review: bool,
) -> Response {
    (
        status,
        Json(DagDbErrorEnvelope {
            error_code: error_code.to_owned(),
            message: message.into(),
            receipt_hash: None,
            validation_report_id: None,
            requires_council_review,
            operational_event_type: operational_event_type_for_error_code(error_code)
                .map(ToOwned::to_owned),
        }),
    )
        .into_response()
}

fn operational_event_type_for_error_code(error_code: &str) -> Option<&'static str> {
    match error_code {
        "write_signature_required"
        | "default_route_approval_signature_required"
        | "default_route_approval_timestamp_required"
        | "context_packet_approval_signature_required"
        | "context_packet_approval_timestamp_required"
        | "lifecycle_signature_required"
        | "continuation_signature_required"
        | "lifecycle_approval_timestamp_required"
        | "continuation_approval_timestamp_required"
        | "provenance_denied" => Some("dagdb_signature_failure"),
        "tenant_scope_mismatch" => Some("dagdb_rls_tenant_violation"),
        "idempotency_key_conflict" => Some("dagdb_idempotency_conflict"),
        "approval_denied"
        | "authority_denied"
        | "consent_denied"
        | "default_route_approval_authority_required"
        | "context_packet_approval_authority_required"
        | "lifecycle_approval_authority_required"
        | "continuation_approval_authority_required" => Some("dagdb_approval_denied"),
        _ => None,
    }
}

#[cfg(feature = "production-db")]
fn receipt_event_type_for_error_code(error_code: &str) -> Option<ReceiptEventType> {
    match error_code {
        "write_signature_required"
        | "default_route_approval_signature_required"
        | "default_route_approval_timestamp_required"
        | "context_packet_approval_signature_required"
        | "context_packet_approval_timestamp_required"
        | "lifecycle_signature_required"
        | "continuation_signature_required"
        | "lifecycle_approval_timestamp_required"
        | "continuation_approval_timestamp_required"
        | "provenance_denied" => Some(ReceiptEventType::DagdbSignatureFailure),
        "tenant_scope_mismatch" => Some(ReceiptEventType::DagdbRlsTenantViolation),
        "idempotency_key_conflict" => Some(ReceiptEventType::DagdbIdempotencyConflict),
        "approval_denied"
        | "authority_denied"
        | "consent_denied"
        | "default_route_approval_authority_required"
        | "context_packet_approval_authority_required"
        | "lifecycle_approval_authority_required"
        | "continuation_approval_authority_required" => Some(ReceiptEventType::DagdbApprovalDenied),
        _ => None,
    }
}

// T1: the local-dev keypair loader (including the deterministic [0..31] seed
// fallback) is compiled ONLY in debug builds. A release binary has no path that
// can materialize a publicly-derivable signing key for the dev profile; the
// signing identity in release comes exclusively from a provisioned seed file or
// the canonical gatekeeper signer, which fail closed when absent.
#[cfg(debug_assertions)]
struct LocalDevKeypair {
    keypair: exo_core::crypto::KeyPair,
    source: &'static str,
}

#[cfg(debug_assertions)]
fn local_dev_key_seed_path() -> String {
    std::env::var("DAGDB_DEV_KEY_SEED").unwrap_or_else(|_| LOCAL_DEV_KEY_SEED_REL.to_owned())
}

#[cfg(debug_assertions)]
fn load_local_dev_keypair_from_seed_path(seed_path: &str) -> Result<LocalDevKeypair, String> {
    load_local_dev_keypair_from_seed_path_with_source(
        seed_path,
        LOCAL_DEV_KEY_SOURCE_EXPLICIT_SEED,
        local_dev_fallback_enabled(),
    )
}

#[cfg(debug_assertions)]
fn local_dev_fallback_enabled() -> bool {
    std::env::var(LOCAL_DEV_GATEKEEPER_ENV)
        .map(|value| value == "1")
        .unwrap_or(false)
}

#[cfg(debug_assertions)]
fn load_local_dev_keypair_from_seed_path_with_source(
    seed_path: &str,
    seed_source: &'static str,
    fallback_enabled: bool,
) -> Result<LocalDevKeypair, String> {
    use std::path::Path;

    use exo_core::crypto::KeyPair;

    let (seed_bytes, source) = match std::fs::read(Path::new(&seed_path)) {
        Ok(bytes) if bytes.len() >= 32 => {
            let mut seed = [0_u8; 32];
            seed.copy_from_slice(&bytes[..32]);
            (seed, seed_source)
        }
        Ok(_) => return Err(format!("dev key seed at {seed_path} is too short")),
        Err(error) => {
            if !fallback_enabled {
                return Err(format!(
                    "dev key seed unavailable at {seed_path}: {error}; set {LOCAL_DEV_GATEKEEPER_ENV}=1 to permit deterministic local-dev fallback"
                ));
            }
            (
                core::array::from_fn(|index| u8::try_from(index).unwrap_or(0)),
                LOCAL_DEV_KEY_SOURCE_DETERMINISTIC_FALLBACK,
            )
        }
    };
    let keypair = KeyPair::from_secret_bytes(seed_bytes).map_err(|error| error.to_string())?;
    Ok(LocalDevKeypair { keypair, source })
}

#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]

    use axum::{
        body::Body,
        extract::{Path, Query},
        http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    };
    use exo_api::dagdb::{
        CouncilDecisionStatus, DagDbCatalogLookupRequest, DagDbContextPacketRequest,
        DagDbCouncilDecisionRequest, DagDbErrorEnvelope, DagDbExportRequest, DagDbImportRequest,
        DagDbIntakeRequest, DagDbReceiptLookupRequest, DagDbRouteLookupRequest, DagDbRouteRequest,
        DagDbTrustCheckRequest, DagDbValidateRequest, DagDbWritebackRequest, DecisionSource,
        RiskClass, SubjectKind,
    };
    use exo_core::Hash256;
    use serde::{Serialize, Serializer, de::DeserializeOwned};
    use tower::ServiceExt;

    use super::*;

    fn dagdb_app() -> Router {
        dagdb_router::<()>()
    }

    #[test]
    fn dagdb_rest_prefix_is_pinned() {
        assert_eq!(DAGDB_REST_PREFIX, "/api/v1/dag-db");
    }

    #[test]
    fn quality_matrix_is_complete() {
        let matrix_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/dagdb/full-migration/quality-matrix.md");
        let matrix = std::fs::read_to_string(&matrix_path).unwrap_or_else(|error| {
            panic!(
                "quality matrix must exist at {}: {error}",
                matrix_path.display()
            )
        });
        let required_fields = [
            "red_command:",
            "red_failure:",
            "green_command:",
            "artifact:",
            "commit:",
        ];

        for index in 0..=19 {
            let id = format!("QM-{index:02}");
            let marker = format!("### {id}");
            let section_start = matrix
                .find(&marker)
                .unwrap_or_else(|| panic!("quality matrix missing section {id}"));
            let section_tail = &matrix[section_start..];
            let section_end = section_tail.find("\n### QM-").unwrap_or(section_tail.len());
            let section = &section_tail[..section_end];

            for field in required_fields {
                assert!(
                    section.contains(field),
                    "quality matrix section {id} missing {field}"
                );
            }
        }
    }

    fn repo_file(path: &str) -> String {
        let file_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        std::fs::read_to_string(&file_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", file_path.display()))
    }

    #[test]
    fn dagdb_full_migration_source_hygiene_guard() {
        let worker_package: serde_json::Value =
            serde_json::from_str(&repo_file("command-base/worker/package.json"))
                .expect("worker package.json parses");
        assert!(
            !worker_package
                .get("dependencies")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|deps| deps.contains_key("better-sqlite3")),
            "CommandBase worker must not depend on production better-sqlite3"
        );
        assert_eq!(
            worker_package
                .get("scripts")
                .and_then(|scripts| scripts.get("test"))
                .and_then(serde_json::Value::as_str),
            Some("node --test"),
            "CommandBase worker must expose a real source-hygiene test contract"
        );

        let worker_source = repo_file("command-base/worker/index.js");
        for forbidden in [
            "require('better-sqlite3')",
            "require(\"better-sqlite3\")",
            "new Database",
            "the_team.db",
            "DB_PATH",
        ] {
            assert!(
                !worker_source.contains(forbidden),
                "CommandBase worker production source must not contain {forbidden}"
            );
        }
        assert!(
            worker_source.contains("./worker-db"),
            "CommandBase worker entrypoint must route persistence through worker-db"
        );
        let worker_db_source = repo_file("command-base/worker/worker-db.js");
        assert!(
            worker_db_source.contains("../app/lib/commandbase-db-factory"),
            "CommandBase worker DB boundary must route production persistence through the DAG DB factory"
        );

        let app_package: serde_json::Value =
            serde_json::from_str(&repo_file("command-base/app/package.json"))
                .expect("CommandBase app package.json parses");
        assert!(
            !app_package
                .get("dependencies")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|deps| deps.contains_key("better-sqlite3")),
            "CommandBase app must not depend on production better-sqlite3"
        );

        let site_contact = repo_file("site/src/lib/contact-submissions.ts");
        for forbidden in [
            "CONTACT_DATABASE_URL",
            "site_contact_submissions",
            "site_contact_rate_limits",
            "from 'pg'",
            "from \"pg\"",
        ] {
            assert!(
                !site_contact.contains(forbidden),
                "site contact persistence must not contain legacy direct Postgres token {forbidden}"
            );
        }

        for service in [
            "audit-api",
            "consent-service",
            "crosschecked-api",
            "decision-forge",
            "gateway-api",
            "governance-engine",
            "identity-service",
            "livesafe-api",
            "provenance-writer",
            "vitallock-api",
        ] {
            let source = repo_file(&format!("demo/services/{service}/src/index.js"));
            assert!(
                !source.contains("new pg.Pool"),
                "demo service {service} must not open direct pg.Pool persistence"
            );
        }

        let web_guard = repo_file("web/src/lib/dagdbDurableState.test.ts");
        for family in [
            "council-tickets",
            "council-conversations",
            "feedback-issues",
            "layout-templates",
            "ape-onboarding",
        ] {
            assert!(
                web_guard.contains(family),
                "web durable-state source guard must cover {family}"
            );
        }
    }

    #[test]
    fn dagdb_full_migration_coverage_gate_contract() {
        for (package_path, expected) in [
            (
                "command-base/app/package.json",
                "--test-coverage-include=lib/commandbase-dagdb-adapter.js",
            ),
            (
                "command-base/worker/package.json",
                "--test-coverage-include=worker-db.js",
            ),
            (
                "web/package.json",
                "--coverage.include=src/lib/dagdbDurableState.ts",
            ),
            ("cybermedica/package.json", "--test-coverage-lines=90"),
        ] {
            let package: serde_json::Value =
                serde_json::from_str(&repo_file(package_path)).expect("package.json parses");
            let coverage = package
                .get("scripts")
                .and_then(|scripts| scripts.get("test:coverage"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("{package_path} missing test:coverage script"));
            assert!(
                coverage.contains(expected),
                "{package_path} test:coverage script must contain {expected}"
            );
        }

        let demo_package: serde_json::Value =
            serde_json::from_str(&repo_file("demo/package.json")).expect("demo package parses");
        let demo_coverage = demo_package["scripts"]["test:coverage:dagdb"]
            .as_str()
            .expect("demo DAG DB coverage script is a string");
        assert!(
            demo_coverage.contains("--coverage")
                && demo_coverage
                    .contains("--coverage.include=packages/shared/src/dagdb-adapter.js")
                && demo_coverage.contains("--coverage.thresholds.lines=90"),
            "demo DAG DB adapter coverage must enforce 90 percent focused adapter coverage"
        );

        let app_package: serde_json::Value =
            serde_json::from_str(&repo_file("command-base/app/package.json"))
                .expect("CommandBase app package parses");
        let app_coverage = app_package["scripts"]["test:coverage"]
            .as_str()
            .expect("CommandBase app coverage script is a string");
        assert!(
            app_coverage.contains("--test-coverage-lines=90")
                && app_coverage.contains("--test-coverage-include=lib/commandbase-db-factory.js"),
            "CommandBase app coverage must enforce 90 percent focused adapter/factory coverage"
        );

        let worker_package: serde_json::Value =
            serde_json::from_str(&repo_file("command-base/worker/package.json"))
                .expect("CommandBase worker package parses");
        let worker_coverage = worker_package["scripts"]["test:coverage"]
            .as_str()
            .expect("CommandBase worker coverage script is a string");
        assert!(
            worker_coverage.contains("--test-coverage-lines=90"),
            "CommandBase worker coverage must enforce 90 percent focused worker-db coverage"
        );

        let web_package: serde_json::Value =
            serde_json::from_str(&repo_file("web/package.json")).expect("web package parses");
        let web_coverage = web_package["scripts"]["test:coverage"]
            .as_str()
            .expect("web coverage script is a string");
        assert!(
            web_coverage.contains("--coverage.thresholds.lines=90"),
            "web durable-state coverage must enforce a 90 percent line threshold"
        );
    }

    #[test]
    fn dagdb_full_migration_live_proof_artifact_contract() {
        let proof = repo_file("docs/dagdb/full-migration/live-proof.md");
        for required in [
            "EXO_DAGDB_TEST_DATABASE_URL",
            "cargo test -p exochain-gateway --features production-db --test dagdb_route_integration_contract dagdb_routes_integration_contract",
            "cargo test -p exochain-gateway --features production-db --test dagdb_cross_tenant",
            "write/read/lookup",
            "tenant mismatch",
            "database_unavailable",
            "replay",
            "finality",
            "pg_ctl stop",
        ] {
            assert!(
                proof.contains(required),
                "QM-19 live proof artifact must record {required}"
            );
        }
    }

    #[test]
    fn dagdb_json_fixtures() {
        let fixtures = fixtures();
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
        assert_fixture::<DagDbErrorEnvelope>(&fixtures, "errors", "tenant_scope_mismatch");
    }

    #[tokio::test]
    async fn dagdb_router_mounts_full_rest_surface_fail_closed_without_db() {
        let fixtures = fixtures();
        let app = dagdb_app();

        assert_post_error(
            app.clone(),
            "/api/v1/dag-db/intake",
            "dagdb:intake",
            fixture::<DagDbIntakeRequest>(&fixtures, "requests", "intake"),
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
        assert_post_error(
            app.clone(),
            "/api/v1/dag-db/route",
            "dagdb:route",
            fixture::<DagDbRouteRequest>(&fixtures, "requests", "route"),
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
        assert_post_error(
            app.clone(),
            "/api/v1/dag-db/context-packet",
            "dagdb:context_packet",
            fixture::<DagDbContextPacketRequest>(&fixtures, "requests", "context_packet"),
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
        assert_post_error(
            app.clone(),
            "/api/v1/dag-db/validate",
            "dagdb:validate",
            fixture::<DagDbValidateRequest>(&fixtures, "requests", "validate"),
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
        // Writeback fails closed (503) with no production database pool,
        // identically to import/export — never a synthetic 201 scaffold receipt.
        assert_post_error(
            app.clone(),
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            fixture::<DagDbWritebackRequest>(&fixtures, "requests", "writeback"),
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
        assert_post_error(
            app.clone(),
            "/api/v1/dag-db/import",
            "dagdb:import",
            import_request(),
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
        assert_post_error(
            app.clone(),
            "/api/v1/dag-db/export",
            "dagdb:export",
            export_request(),
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
        assert_post_error(
            app.clone(),
            "/api/v1/dag-db/trust-check",
            "dagdb:trust_check",
            fixture::<DagDbTrustCheckRequest>(&fixtures, "requests", "trust_check"),
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
        assert_post_error(
            app.clone(),
            "/api/v1/dag-db/council/decision",
            "dagdb:council_decision",
            fixture::<DagDbCouncilDecisionRequest>(&fixtures, "requests", "council_decision"),
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;

        let receipt: DagDbReceiptLookupRequest = fixture(&fixtures, "requests", "receipt_lookup");
        assert_get_error(
            app.clone(),
            &format!(
                "/api/v1/dag-db/receipts/{}?tenant_id={}&namespace={}&include_body=true",
                receipt.receipt_hash, receipt.tenant_id, receipt.namespace
            ),
            "dagdb:receipt_lookup",
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
        let catalog: DagDbCatalogLookupRequest = fixture(&fixtures, "requests", "catalog_lookup");
        assert_get_error(
            app.clone(),
            &format!(
                "/api/v1/dag-db/catalog/{}?tenant_id={}&namespace={}&include_children=true&include_routes=true",
                catalog.catalog_id, catalog.tenant_id, catalog.namespace
            ),
            "dagdb:catalog_lookup",
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
        let route: DagDbRouteLookupRequest = fixture(&fixtures, "requests", "route_lookup");
        assert_get_error(
            app,
            &format!(
                "/api/v1/dag-db/routes/{}?tenant_id={}&namespace={}&include_memory_refs=true&include_validation=true",
                route.route_id, route.tenant_id, route.namespace
            ),
            "dagdb:route_lookup",
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
    }

    #[test]
    fn dagdb_full_rest_surface_has_governed_persistence_handlers() {
        let source = include_str!("dagdb.rs");
        for fragments in [
            &["persist_", "intake_response"][..],
            &["persist_", "validate_response"],
            &["persist_", "trust_check_response"],
            &["persist_", "council_decision_response"],
            &["load_", "receipt_lookup_response"],
            &["load_", "catalog_lookup_response"],
            &["load_", "route_lookup_response"],
            &["INSERT INTO ", "dagdb_memory_objects"],
            &["INSERT INTO ", "dagdb_validation_reports"],
            &["INSERT INTO ", "dagdb_inbound_agent_credentials"],
            &["INSERT INTO ", "dagdb_agent_safety_scores"],
            &["INSERT INTO ", "dagdb_council_decisions"],
            &["FROM ", "dagdb_receipts"],
            &["FROM ", "dagdb_catalog_entries"],
            &["FROM ", "dagdb_route_receipts"],
        ] {
            let needle = fragments.concat();
            assert!(
                source.contains(&needle),
                "DAG DB full REST surface missing governed persistence fragment {needle}"
            );
        }

        for fragments in [
            &["dagdb_", "authorized_response("][..],
            &["council_", "authorized_response("],
        ] {
            let removed_scaffold = fragments.concat();
            assert!(
                !source.contains(&removed_scaffold),
                "DAG DB full REST surface must not route through removed scaffold helper {removed_scaffold}"
            );
        }
    }

    #[test]
    fn dagdb_idempotency_replay_contract() {
        let source = include_str!("dagdb.rs");
        for (route_fragments, constant_fragments, function_fragments) in [
            (
                &["dagdb", ".", "intake"][..],
                &["INTAKE", "_ROUTE_IDEMPOTENCY_NAME"][..],
                &["persist", "_idempotent_", "intake", "_response"][..],
            ),
            (
                &["dagdb", ".", "validate"],
                &["VALIDATE", "_ROUTE_IDEMPOTENCY_NAME"],
                &["persist", "_idempotent_", "validate", "_response"],
            ),
            (
                &["dagdb", ".", "trust_check"],
                &["TRUST_CHECK", "_ROUTE_IDEMPOTENCY_NAME"],
                &["persist", "_idempotent_", "trust_check", "_response"],
            ),
            (
                &["dagdb", ".", "council_decision"],
                &["COUNCIL_DECISION", "_ROUTE_IDEMPOTENCY_NAME"],
                &["persist", "_idempotent_", "council_decision", "_response"],
            ),
        ] {
            let route_name = route_fragments.concat();
            let constant_name = constant_fragments.concat();
            let function_name = function_fragments.concat();
            let constant_marker = format!("const {constant_name}: &str = \"{route_name}\";");
            assert!(
                source.contains(&constant_marker),
                "{constant_name} must pin {route_name} as the replay route name"
            );
            let function_marker = ["async fn ", &function_name].concat();
            let start = source
                .find(&function_marker)
                .unwrap_or_else(|| panic!("{function_name} must wrap {route_name} writes"));
            let end = source[start..]
                .find("\n}\n\n#[cfg(feature = \"production-db\")]")
                .map(|offset| start + offset)
                .unwrap_or(source.len());
            let body = &source[start..end];
            for fragments in [
                &["reserve_gateway", "_idempotency_key"][..],
                &["store_gateway", "_idempotency_response"],
                &["idempotency_key"],
                &[&constant_name],
            ] {
                let needle = fragments.concat();
                assert!(
                    body.contains(&needle),
                    "{function_name} must use {needle} for stable replay/conflict semantics"
                );
            }
        }
    }

    #[tokio::test]
    async fn dagdb_router_rejects_metadata_failures_before_success_response() {
        let fixtures = fixtures();
        let app = dagdb_app();

        let intake = DagDbIntakeRequest {
            title_text: "fn raw_payload() {}".to_owned(),
            ..fixture(&fixtures, "requests", "intake")
        };
        let intake_response = app
            .clone()
            .oneshot(scoped_json_request(
                "POST",
                "/api/v1/dag-db/intake",
                "dagdb:intake",
                &intake,
            ))
            .await
            .expect("intake no-pool fail-closed response");
        assert_error_response(
            intake_response,
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;

        let import = DagDbImportRequest {
            import_report: json!({"raw_markdown": "forbidden"}),
            ..import_request()
        };
        assert_error_response(
            app.clone()
                .oneshot(scoped_json_request(
                    "POST",
                    "/api/v1/dag-db/import",
                    "dagdb:import",
                    &import,
                ))
                .await
                .expect("import adapter rejection"),
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
        )
        .await;

        let validate = DagDbValidateRequest {
            validation_notes_text: Some("fn raw_payload() {}".to_owned()),
            ..fixture(&fixtures, "requests", "validate")
        };
        let validate_response = app
            .clone()
            .oneshot(scoped_json_request(
                "POST",
                "/api/v1/dag-db/validate",
                "dagdb:validate",
                &validate,
            ))
            .await
            .expect("validate no-pool fail-closed response");
        assert_error_response(
            validate_response,
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;

        // Writeback now fails closed (503) on the no-pool path BEFORE building any
        // response, so raw-code summary metadata is no longer the first rejection
        // here — the fail-closed 503 is. Summary-metadata rejection on the real
        // persisted path (with a pool) is covered by `writeback_response_from_*`
        // tests. The knowledge-class metadata rejection (422) still precedes the
        // pool check; see `dagdb_writeback_route_rejects_unknown_knowledge_class`.
        let writeback = DagDbWritebackRequest {
            summary_text: Some("fn raw_payload() {}".to_owned()),
            ..fixture(&fixtures, "requests", "writeback")
        };
        assert_error_response(
            app.oneshot(scoped_json_request(
                "POST",
                "/api/v1/dag-db/writeback",
                "dagdb:writeback",
                &writeback,
            ))
            .await
            .expect("writeback no-pool fail-closed"),
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
    }

    #[tokio::test]
    async fn dagdb_export_route_rejects_malformed_included_memory_ids_before_scaffold() {
        let app = dagdb_app();
        let export = DagDbExportRequest {
            included_memory_ids: vec!["not-a-hash".to_owned()],
            ..export_request()
        };
        assert_error_response(
            app.oneshot(scoped_json_request(
                "POST",
                "/api/v1/dag-db/export",
                "dagdb:export",
                &export,
            ))
            .await
            .expect("malformed export memory id response"),
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
        )
        .await;
    }

    #[test]
    fn validate_writeback_knowledge_class_accepts_each_allowed_class_with_summary() {
        let fixtures = fixtures();
        for class in ["decision", "finding", "fix", "constraint", "handoff"] {
            let request = DagDbWritebackRequest {
                summary_text: Some(format!("content-bearing {class} summary")),
                knowledge_class: Some(class.to_owned()),
                ..fixture(&fixtures, "requests", "writeback")
            };
            assert!(
                validate_writeback_knowledge_class(&request).is_ok(),
                "class {class} with a summary must validate"
            );
        }
    }

    #[test]
    fn validate_writeback_knowledge_class_accepts_classless_writeback() {
        let fixtures = fixtures();
        let request = DagDbWritebackRequest {
            knowledge_class: None,
            ..fixture(&fixtures, "requests", "writeback")
        };
        assert!(validate_writeback_knowledge_class(&request).is_ok());
    }

    #[tokio::test]
    async fn dagdb_writeback_route_accepts_known_knowledge_class() {
        // A known knowledge class passes the pre-pool validation (no 422
        // class rejection) and then fails closed (503) on the no-pool path,
        // rather than being rejected as an invalid class. This distinguishes a
        // valid-class-but-no-pool writeback (503) from an invalid class (422).
        let fixtures = fixtures();
        let app = dagdb_app();
        let writeback = DagDbWritebackRequest {
            summary_text: Some("Implemented typed knowledge writebacks".to_owned()),
            knowledge_class: Some("finding".to_owned()),
            ..fixture(&fixtures, "requests", "writeback")
        };
        assert_post_error(
            app,
            "/api/v1/dag-db/writeback",
            "dagdb:writeback",
            writeback,
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;
    }

    #[tokio::test]
    async fn dagdb_writeback_route_rejects_unknown_knowledge_class() {
        let fixtures = fixtures();
        let app = dagdb_app();
        let writeback = DagDbWritebackRequest {
            summary_text: Some("Has a summary but an invalid class".to_owned()),
            knowledge_class: Some("rumor".to_owned()),
            ..fixture(&fixtures, "requests", "writeback")
        };
        assert_error_response(
            app.oneshot(scoped_json_request(
                "POST",
                "/api/v1/dag-db/writeback",
                "dagdb:writeback",
                &writeback,
            ))
            .await
            .expect("unknown knowledge class response"),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_knowledge_class",
        )
        .await;
    }

    #[tokio::test]
    async fn dagdb_writeback_route_rejects_knowledge_class_with_empty_summary() {
        let fixtures = fixtures();
        let app = dagdb_app();
        let writeback = DagDbWritebackRequest {
            summary_text: Some("   ".to_owned()),
            knowledge_class: Some("decision".to_owned()),
            ..fixture(&fixtures, "requests", "writeback")
        };
        assert_error_response(
            app.clone()
                .oneshot(scoped_json_request(
                    "POST",
                    "/api/v1/dag-db/writeback",
                    "dagdb:writeback",
                    &writeback,
                ))
                .await
                .expect("blank summary knowledge class response"),
            StatusCode::UNPROCESSABLE_ENTITY,
            "knowledge_class_requires_summary",
        )
        .await;

        let missing_summary = DagDbWritebackRequest {
            summary_text: None,
            knowledge_class: Some("decision".to_owned()),
            ..fixture(&fixtures, "requests", "writeback")
        };
        assert_error_response(
            app.oneshot(scoped_json_request(
                "POST",
                "/api/v1/dag-db/writeback",
                "dagdb:writeback",
                &missing_summary,
            ))
            .await
            .expect("missing summary knowledge class response"),
            StatusCode::UNPROCESSABLE_ENTITY,
            "knowledge_class_requires_summary",
        )
        .await;
    }

    #[tokio::test]
    async fn dagdb_import_export_json_rejections_use_sanitized_envelope() {
        let app = dagdb_app();
        let mut import = serde_json::to_value(import_request()).expect("import json");
        import
            .as_object_mut()
            .expect("import object")
            .insert("secret_api_key".to_owned(), json!("sk-prod-secret"));
        assert_sanitized_invalid_shape(
            app.clone()
                .oneshot(scoped_raw_json_request(
                    "POST",
                    "/api/v1/dag-db/import",
                    "dagdb:import",
                    import.to_string(),
                ))
                .await
                .expect("import unknown field response"),
            &["secret_api_key", "sk-prod-secret"],
        )
        .await;

        let mut export = serde_json::to_value(export_request()).expect("export json");
        export
            .as_object_mut()
            .expect("export object")
            .insert("secret_token".to_owned(), json!("bearer-secret-value"));
        assert_sanitized_invalid_shape(
            app.clone()
                .oneshot(scoped_raw_json_request(
                    "POST",
                    "/api/v1/dag-db/export",
                    "dagdb:export",
                    export.to_string(),
                ))
                .await
                .expect("export unknown field response"),
            &["secret_token", "bearer-secret-value"],
        )
        .await;

        assert_sanitized_invalid_shape(
            app.oneshot(scoped_raw_json_request(
                "POST",
                "/api/v1/dag-db/import",
                "dagdb:import",
                r#"{"tenant_id":"tenant-a","secret_api_key":"sk-prod-secret""#.to_owned(),
            ))
            .await
            .expect("import malformed json response"),
            &["secret_api_key", "sk-prod-secret"],
        )
        .await;
    }

    #[tokio::test]
    async fn dagdb_runtime_import_export_no_pool_503_error_shapes() {
        let ctx = DagDbRouteContext::from_pool(None);
        assert_error_response_shape(
            import_handler(&ctx, &authorized_headers("dagdb:import"), import_request()).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            "DAG DB import requires a configured production database",
            false,
        )
        .await;
        assert_error_response_shape(
            export_handler(&ctx, &authorized_headers("dagdb:export"), export_request()).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            "DAG DB export requires a configured production database",
            false,
        )
        .await;
    }

    /// P1: writeback fails closed (503, `database_unavailable`) with no
    /// production database pool — identical envelope shape to import/export,
    /// with no synthetic 201 scaffold and no fabricated receipt body.
    #[tokio::test]
    async fn dagdb_runtime_writeback_no_pool_fails_closed_503() {
        let fixtures = fixtures();
        let ctx = DagDbRouteContext::from_pool(None);
        let request: DagDbWritebackRequest = fixture(&fixtures, "requests", "writeback");
        assert_error_response_shape(
            writeback_handler(&ctx, &authorized_headers("dagdb:writeback"), request).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            "DAG DB writeback requires a configured production database",
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn dagdb_scaffold_routes_without_pool_fail_closed_when_authorized() {
        let fixtures = fixtures();
        let intake: DagDbIntakeRequest = fixture(&fixtures, "requests", "intake");
        assert_error_response_shape(
            handle_dagdb_intake(None, authorized_headers("dagdb:intake"), Json(intake)).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            "DAG DB intake requires a configured production database",
            false,
        )
        .await;

        let catalog: DagDbCatalogLookupRequest = fixture(&fixtures, "requests", "catalog_lookup");
        assert_error_response_shape(
            handle_dagdb_catalog_lookup(
                None,
                authorized_headers("dagdb:catalog_lookup"),
                Path(catalog.catalog_id.clone()),
                Query(lookup_query(&catalog.tenant_id, &catalog.namespace, &[])),
            )
            .await,
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            "DAG DB catalog_lookup requires a configured production database",
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn dagdb_handlers_cover_authorized_and_denied_branches_directly() {
        let fixtures = fixtures();
        let scaffold_post_status = StatusCode::SERVICE_UNAVAILABLE;
        let scaffold_get_status = StatusCode::SERVICE_UNAVAILABLE;
        let intake: DagDbIntakeRequest = fixture(&fixtures, "requests", "intake");
        assert_eq!(
            handle_dagdb_intake(
                None,
                authorized_headers("dagdb:intake"),
                Json(intake.clone())
            )
            .await
            .status(),
            scaffold_post_status
        );
        assert_eq!(
            handle_dagdb_intake(None, denied_headers("dagdb:intake"), Json(intake))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );

        let route: DagDbRouteRequest = fixture(&fixtures, "requests", "route");
        assert_eq!(
            handle_dagdb_route(None, authorized_headers("dagdb:route"), Json(route.clone()))
                .await
                .status(),
            scaffold_post_status
        );
        assert_eq!(
            handle_dagdb_route(None, denied_headers("dagdb:route"), Json(route))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );

        let packet: DagDbContextPacketRequest = fixture(&fixtures, "requests", "context_packet");
        assert_eq!(
            handle_dagdb_context_packet(
                None,
                authorized_headers("dagdb:context_packet"),
                Json(packet.clone()),
            )
            .await
            .status(),
            scaffold_post_status
        );
        assert_eq!(
            handle_dagdb_context_packet(
                None,
                denied_headers("dagdb:context_packet"),
                Json(packet),
            )
                .await
                .status(),
            StatusCode::FORBIDDEN
        );

        let validation: DagDbValidateRequest = fixture(&fixtures, "requests", "validate");
        assert_eq!(
            handle_dagdb_validate(
                None,
                authorized_headers("dagdb:validate"),
                Json(validation.clone())
            )
            .await
            .status(),
            scaffold_post_status
        );
        assert_eq!(
            handle_dagdb_validate(None, denied_headers("dagdb:validate"), Json(validation))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );

        let writeback: DagDbWritebackRequest = fixture(&fixtures, "requests", "writeback");
        // Authorized writeback fails closed (503) with no pool — the audit's
        // synthetic-201 scaffold is gone. Authority denial still precedes the
        // pool check, so the denied branch stays FORBIDDEN.
        assert_eq!(
            handle_dagdb_writeback(
                None,
                authorized_headers("dagdb:writeback"),
                Json(writeback.clone()),
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            handle_dagdb_writeback(None, denied_headers("dagdb:writeback"), Json(writeback),)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );

        let import = import_request();
        assert_eq!(
            handle_dagdb_import(
                None,
                authorized_headers("dagdb:import"),
                Ok(Json(import.clone())),
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            handle_dagdb_import(None, denied_headers("dagdb:import"), Ok(Json(import)))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );

        let export = export_request();
        assert_eq!(
            handle_dagdb_export(
                None,
                authorized_headers("dagdb:export"),
                Ok(Json(export.clone())),
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            handle_dagdb_export(None, denied_headers("dagdb:export"), Ok(Json(export)))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );

        let trust: DagDbTrustCheckRequest = fixture(&fixtures, "requests", "trust_check");
        assert_eq!(
            handle_dagdb_trust_check(
                None,
                authorized_headers("dagdb:trust_check"),
                Json(trust.clone())
            )
            .await
            .status(),
            scaffold_post_status
        );
        assert_eq!(
            handle_dagdb_trust_check(None, denied_headers("dagdb:trust_check"), Json(trust))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );

        let receipt: DagDbReceiptLookupRequest = fixture(&fixtures, "requests", "receipt_lookup");
        let receipt_query = lookup_query(
            &receipt.tenant_id,
            &receipt.namespace,
            &[("include_body", "true")],
        );
        assert_eq!(
            handle_dagdb_receipt_lookup(
                None,
                authorized_headers("dagdb:receipt_lookup"),
                Path(receipt.receipt_hash.clone()),
                Query(receipt_query)
            )
            .await
            .status(),
            scaffold_get_status
        );
        assert_eq!(
            handle_dagdb_receipt_lookup(
                None,
                denied_headers("dagdb:receipt_lookup"),
                Path(receipt.receipt_hash.clone()),
                Query(lookup_query(&receipt.tenant_id, &receipt.namespace, &[]))
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );

        let catalog: DagDbCatalogLookupRequest = fixture(&fixtures, "requests", "catalog_lookup");
        let catalog_query = lookup_query(
            &catalog.tenant_id,
            &catalog.namespace,
            &[("include_children", "true"), ("include_routes", "true")],
        );
        assert_eq!(
            handle_dagdb_catalog_lookup(
                None,
                authorized_headers("dagdb:catalog_lookup"),
                Path(catalog.catalog_id.clone()),
                Query(catalog_query)
            )
            .await
            .status(),
            scaffold_get_status
        );
        assert_eq!(
            handle_dagdb_catalog_lookup(
                None,
                denied_headers("dagdb:catalog_lookup"),
                Path(catalog.catalog_id.clone()),
                Query(lookup_query(&catalog.tenant_id, &catalog.namespace, &[]))
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );

        let route_lookup: DagDbRouteLookupRequest = fixture(&fixtures, "requests", "route_lookup");
        let route_query = lookup_query(
            &route_lookup.tenant_id,
            &route_lookup.namespace,
            &[
                ("include_memory_refs", "true"),
                ("include_validation", "true"),
            ],
        );
        assert_eq!(
            handle_dagdb_route_lookup(
                None,
                authorized_headers("dagdb:route_lookup"),
                Path(route_lookup.route_id.clone()),
                Query(route_query)
            )
            .await
            .status(),
            scaffold_get_status
        );
        assert_eq!(
            handle_dagdb_route_lookup(
                None,
                denied_headers("dagdb:route_lookup"),
                Path(route_lookup.route_id.clone()),
                Query(lookup_query(
                    &route_lookup.tenant_id,
                    &route_lookup.namespace,
                    &[]
                ))
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn dagdb_private_gateway_vectors_cover_fail_closed_branches() {
        let fixtures = fixtures();
        let route_vectors = [
            ("dagdb.intake", "dagdb:intake"),
            ("dagdb.route", "dagdb:route"),
            ("dagdb.context_packet", "dagdb:context_packet"),
            ("dagdb.validate", "dagdb:validate"),
            ("dagdb.writeback", "dagdb:writeback"),
            ("dagdb.import", "dagdb:import"),
            ("dagdb.export", "dagdb:export"),
            ("dagdb.trust_check", "dagdb:trust_check"),
        ];
        for (route_name, action) in route_vectors {
            assert!(route_name.starts_with("dagdb."));
            assert!(action.starts_with("dagdb:"));
        }
        let query = lookup_query(
            "tenant-a",
            "primary",
            &[("include_body", "true"), ("include_routes", "false")],
        );
        assert_eq!(required_query_text(&query, "tenant_id"), "tenant-a");
        assert_eq!(optional_query_bool(&query, "include_body"), Some(true));
        assert_eq!(optional_query_bool(&query, "include_routes"), Some(false));
        assert_eq!(optional_query_bool(&query, "missing"), None);

        let mut headers = HeaderMap::new();
        assert_eq!(
            verify_dagdb_authority(&headers, "tenant-a", "primary", "dagdb:intake")
                .expect("missing auth")
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            dagdb_authority_denial(&headers, "tenant-a", "primary", "dagdb:intake"),
            Some(DagDbAuthorityDenial {
                status: StatusCode::UNAUTHORIZED,
                error_code: "unauthenticated",
            })
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic test"),
        );
        assert_eq!(
            verify_dagdb_authority(&headers, "tenant-a", "primary", "dagdb:intake")
                .expect("basic auth")
                .status(),
            StatusCode::UNAUTHORIZED
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test"),
        );
        assert_eq!(
            verify_dagdb_authority(&headers, "tenant-a", "primary", "dagdb:intake")
                .expect("missing tenant")
                .status(),
            StatusCode::FORBIDDEN
        );
        headers.insert(TENANT_HEADER, HeaderValue::from_static("tenant-a"));
        assert_eq!(
            verify_dagdb_authority(&headers, "tenant-a", "primary", "dagdb:intake")
                .expect("missing namespace")
                .status(),
            StatusCode::FORBIDDEN
        );
        headers.insert(NAMESPACE_HEADER, HeaderValue::from_static("primary"));
        assert_eq!(
            verify_dagdb_authority(&headers, "tenant-a", "primary", "dagdb:intake")
                .expect("missing authority")
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            dagdb_authority_denial(&headers, "tenant-a", "primary", "dagdb:intake"),
            Some(DagDbAuthorityDenial {
                status: StatusCode::FORBIDDEN,
                error_code: "authority_denied",
            })
        );
        let mut namespace_mismatch = headers.clone();
        namespace_mismatch.insert(NAMESPACE_HEADER, HeaderValue::from_static("other"));
        assert_eq!(
            verify_dagdb_authority(&namespace_mismatch, "tenant-a", "primary", "dagdb:intake")
                .expect("namespace mismatch")
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            dagdb_authority_denial(&namespace_mismatch, "tenant-a", "primary", "dagdb:intake"),
            Some(DagDbAuthorityDenial {
                status: StatusCode::FORBIDDEN,
                error_code: "tenant_scope_mismatch",
            })
        );
        headers.insert(
            AUTHORITY_SCOPE_HEADER,
            HeaderValue::from_static("dagdb:other:tenant-a:primary dagdb:intake:tenant-a:primary"),
        );
        assert!(verify_dagdb_authority(&headers, "tenant-a", "primary", "dagdb:intake").is_none());
        log_dagdb_authority_denial(
            "dagdb.intake",
            &headers,
            "tenant-a",
            "primary",
            "dagdb:intake",
        );

        let intake: DagDbIntakeRequest = fixture(&fixtures, "requests", "intake");
        assert!(
            intake_response_from_request(
                DagDbIntakeRequest {
                    title_text: "fn raw_payload() {}".to_owned(),
                    ..intake.clone()
                },
                "dagdb.intake",
            )
            .is_err()
        );
        assert!(
            intake_response_from_request(
                DagDbIntakeRequest {
                    keyword_texts: Some(vec!["fn raw_payload() {}".to_owned()]),
                    ..intake
                },
                "dagdb.intake",
            )
            .is_err()
        );

        let mut route: DagDbRouteRequest = fixture(&fixtures, "requests", "route");
        route.requested_memory_ids = None;
        assert!(route_response_from_request(route, "dagdb.route").is_ok());

        let validate: DagDbValidateRequest = fixture(&fixtures, "requests", "validate");
        assert!(
            validate_response_from_request(
                DagDbValidateRequest {
                    validation_notes_text: None,
                    ..validate.clone()
                },
                "dagdb.validate",
            )
            .is_ok()
        );
        assert!(
            validate_response_from_request(
                DagDbValidateRequest {
                    validation_notes_text: Some("fn raw_payload() {}".to_owned()),
                    ..validate
                },
                "dagdb.validate",
            )
            .is_err()
        );

        let writeback: DagDbWritebackRequest = fixture(&fixtures, "requests", "writeback");
        assert!(
            writeback_response_from_request(
                DagDbWritebackRequest {
                    summary_text: None,
                    keyword_texts: None,
                    ..writeback.clone()
                },
                "dagdb.writeback",
            )
            .is_ok()
        );
        assert!(
            writeback_response_from_request(
                DagDbWritebackRequest {
                    keyword_texts: Some(vec!["fn raw_payload() {}".to_owned()]),
                    ..writeback
                },
                "dagdb.writeback",
            )
            .is_err()
        );

        let import = import_request();
        assert!(
            validated_import_report_json(&DagDbImportRequest {
                source_hash: "bad-hash".to_owned(),
                ..import
            })
            .is_err()
        );

        let export = export_request();
        assert!(
            export_scope_from_request(&DagDbExportRequest {
                requester_did: "agent-without-did-prefix".to_owned(),
                ..export
            })
            .is_err()
        );

        let receipt = DagDbReceiptLookupRequest {
            include_body: None,
            ..fixture(&fixtures, "requests", "receipt_lookup")
        };
        assert!(receipt_lookup_response(receipt).receipt_body.is_none());
        let catalog = DagDbCatalogLookupRequest {
            include_children: None,
            include_routes: None,
            ..fixture(&fixtures, "requests", "catalog_lookup")
        };
        let catalog_response = catalog_lookup_response(catalog);
        assert!(catalog_response.children.is_none());
        assert!(catalog_response.routes.is_none());
        let route_lookup = DagDbRouteLookupRequest {
            include_memory_refs: None,
            include_validation: None,
            ..fixture(&fixtures, "requests", "route_lookup")
        };
        assert!(route_lookup_response(route_lookup).memory_refs.is_none());

        let mut non_object = Value::Null;
        assert!(replace_metadata(&mut non_object, "raw", "safe", json!("value")).is_err());
        assert!(request_json(&FailingSerialize).is_err());
        assert!(request_hash("dagdb.test", "tenant-a", "primary", &FailingSerialize).is_err());
        assert!(hash_hex("dagdb.test", &FailingSerialize).is_err());
        assert!(sanitize_optional_metadata(MetadataField::Summary, None).is_ok());
    }

    #[test]
    fn dagdb_layered_runtime_gateway_context_packet_is_additive_and_fail_closed() {
        let fixtures = fixtures();
        let request: DagDbContextPacketRequest = fixture(&fixtures, "requests", "context_packet");

        let legacy = context_packet_response_from_request(request.clone(), "dagdb.context_packet")
            .expect("legacy context packet");
        assert!(legacy.layered_mode.is_none());
        assert!(legacy.selected_layers.is_none());
        assert!(legacy.selected_layer_edges.is_none());
        assert!(legacy.layer_budget_report.is_none());
        assert!(legacy.flat_fallback_used.is_none());
        assert!(legacy.layered_status.is_none());

        let auto = context_packet_response_from_request(
            DagDbContextPacketRequest {
                layered_mode: Some("auto".to_owned()),
                max_layer_depth: Some(4),
                require_layer_evidence: Some(false),
                ..request.clone()
            },
            "dagdb.context_packet",
        )
        .expect("auto layered context packet");
        assert_eq!(auto.layered_mode.as_deref(), Some("auto"));
        assert_eq!(
            auto.layered_status.as_deref(),
            Some("flat_fallback_no_layer_evidence")
        );
        assert_eq!(auto.flat_fallback_used, Some(true));
        assert_eq!(
            auto.layer_budget_report
                .as_ref()
                .expect("layer budget")
                .budget_status
                .as_str(),
            "flat_fallback_no_layer_evidence"
        );
        assert_eq!(auto.selected_layers.as_ref().expect("layers").len(), 0);

        assert!(
            context_packet_response_from_request(
                DagDbContextPacketRequest {
                    layered_mode: Some("required".to_owned()),
                    max_layer_depth: Some(4),
                    require_layer_evidence: Some(true),
                    ..request.clone()
                },
                "dagdb.context_packet",
            )
            .is_err(),
            "required layered context must reject scaffold packets with no layer evidence"
        );
        assert!(
            context_packet_response_from_request(
                DagDbContextPacketRequest {
                    layered_mode: Some("sometimes".to_owned()),
                    ..request.clone()
                },
                "dagdb.context_packet",
            )
            .is_err(),
            "unsupported layered_mode must fail closed"
        );
        assert!(
            context_packet_response_from_request(
                DagDbContextPacketRequest {
                    layered_mode: Some("auto".to_owned()),
                    max_layer_depth: Some(DAGDB_MAX_LAYER_DEPTH + 1),
                    ..request
                },
                "dagdb.context_packet",
            )
            .is_err(),
            "over-budget max_layer_depth must fail closed"
        );
    }

    #[test]
    fn dagdb_layered_runtime_gateway_writeback_records_target_layers() {
        let fixtures = fixtures();
        let request: DagDbWritebackRequest = fixture(&fixtures, "requests", "writeback");

        let legacy = writeback_response_from_request(request.clone(), "dagdb.writeback")
            .expect("legacy writeback");
        assert!(legacy.target_layer_path.is_none());
        assert!(legacy.target_layer_depth.is_none());
        assert!(legacy.target_layer_reason.is_none());
        assert!(legacy.created_child_layer_id.is_none());
        assert!(legacy.layered_writeback_status.is_none());

        let layered = writeback_response_from_request(
            DagDbWritebackRequest {
                layered_mode: Some("auto".to_owned()),
                target_layer_path: Some("root/codex/runtime".to_owned()),
                target_layer_depth: Some(2),
                target_layer_reason: Some("agent_runtime_layered_mode".to_owned()),
                ..request.clone()
            },
            "dagdb.writeback",
        )
        .expect("layered writeback");
        assert_eq!(
            layered.target_layer_path.as_deref(),
            Some("root/codex/runtime")
        );
        assert_eq!(layered.target_layer_depth, Some(2));
        assert_eq!(
            layered.target_layer_reason.as_deref(),
            Some("agent_runtime_layered_mode")
        );
        assert_eq!(
            layered.layered_writeback_status.as_deref(),
            Some("layer_target_recorded")
        );
        assert_eq!(
            layered
                .created_child_layer_id
                .as_ref()
                .expect("created child layer id")
                .len(),
            64
        );

        assert!(
            writeback_response_from_request(
                DagDbWritebackRequest {
                    layered_mode: Some("required".to_owned()),
                    ..request.clone()
                },
                "dagdb.writeback",
            )
            .is_err(),
            "required writeback must include an explicit target layer"
        );
        assert!(
            writeback_response_from_request(
                DagDbWritebackRequest {
                    layered_mode: Some("off".to_owned()),
                    target_layer_path: Some("root/codex/runtime".to_owned()),
                    target_layer_depth: Some(2),
                    target_layer_reason: Some("agent_runtime_layered_mode".to_owned()),
                    ..request.clone()
                },
                "dagdb.writeback",
            )
            .is_err(),
            "target layer fields must not be accepted when layered_mode is off"
        );
        assert!(
            writeback_response_from_request(
                DagDbWritebackRequest {
                    layered_mode: Some("auto".to_owned()),
                    target_layer_path: Some("/root/codex/runtime".to_owned()),
                    target_layer_depth: Some(2),
                    target_layer_reason: Some("agent_runtime_layered_mode".to_owned()),
                    ..request.clone()
                },
                "dagdb.writeback",
            )
            .is_err(),
            "absolute target layer paths must fail closed"
        );
        assert!(
            writeback_response_from_request(
                DagDbWritebackRequest {
                    layered_mode: Some("auto".to_owned()),
                    target_layer_path: Some("root/codex/runtime".to_owned()),
                    target_layer_depth: Some(1),
                    target_layer_reason: Some("agent_runtime_layered_mode".to_owned()),
                    ..request
                },
                "dagdb.writeback",
            )
            .is_err(),
            "target_layer_depth must match target_layer_path"
        );
    }

    #[cfg(feature = "production-db")]
    #[test]
    fn dagdb_writeback_signed_task_hash_binds_layer_target() {
        let fixtures = fixtures();
        let request: DagDbWritebackRequest = fixture(&fixtures, "requests", "writeback");
        let flat_without_metadata = DagDbWritebackRequest {
            summary_text: None,
            knowledge_class: None,
            layered_mode: None,
            target_layer_path: None,
            target_layer_depth: None,
            target_layer_reason: None,
            ..request.clone()
        };
        assert_eq!(
            writeback_signed_task_hash(&flat_without_metadata).expect("flat task hash"),
            flat_without_metadata.answer_hash,
            "flat writebacks without metadata or layered fields must keep signing the raw answer_hash"
        );

        let with_summary = DagDbWritebackRequest {
            summary_text: Some("Safe answer summary".to_owned()),
            ..flat_without_metadata.clone()
        };
        let summary_hash = writeback_signed_task_hash(&with_summary).expect("summary task hash");
        assert_ne!(
            summary_hash, with_summary.answer_hash,
            "metadata-bearing writebacks must not sign the raw answer_hash"
        );
        let mutated_summary = DagDbWritebackRequest {
            summary_text: Some("Mutated searchable summary".to_owned()),
            ..with_summary.clone()
        };
        assert_ne!(
            writeback_signed_task_hash(&mutated_summary).expect("mutated summary task hash"),
            summary_hash,
            "mutating summary_text must change the signed task hash"
        );

        let empty_summary = DagDbWritebackRequest {
            summary_text: Some(String::new()),
            ..flat_without_metadata.clone()
        };
        assert_ne!(
            writeback_signed_task_hash(&empty_summary).expect("empty summary task hash"),
            writeback_signed_task_hash(&flat_without_metadata).expect("absent summary task hash"),
            "absent and empty summary_text must bind to distinct task hashes"
        );

        let with_knowledge_class = DagDbWritebackRequest {
            summary_text: Some("Typed knowledge writeback summary".to_owned()),
            knowledge_class: Some("finding".to_owned()),
            ..flat_without_metadata.clone()
        };
        let knowledge_class_hash =
            writeback_signed_task_hash(&with_knowledge_class).expect("knowledge class task hash");
        let mutated_knowledge_class = DagDbWritebackRequest {
            knowledge_class: Some("decision".to_owned()),
            ..with_knowledge_class.clone()
        };
        assert_ne!(
            writeback_signed_task_hash(&mutated_knowledge_class)
                .expect("mutated knowledge class task hash"),
            knowledge_class_hash,
            "mutating knowledge_class must change the signed task hash"
        );

        let empty_knowledge_class = DagDbWritebackRequest {
            summary_text: Some("Typed knowledge writeback summary".to_owned()),
            knowledge_class: Some(String::new()),
            ..flat_without_metadata.clone()
        };
        let absent_knowledge_class = DagDbWritebackRequest {
            summary_text: Some("Typed knowledge writeback summary".to_owned()),
            knowledge_class: None,
            ..flat_without_metadata.clone()
        };
        assert_ne!(
            writeback_signed_task_hash(&empty_knowledge_class)
                .expect("empty knowledge class task hash"),
            writeback_signed_task_hash(&absent_knowledge_class)
                .expect("absent knowledge class task hash"),
            "absent and empty knowledge_class must bind to distinct task hashes"
        );

        let layered = DagDbWritebackRequest {
            layered_mode: Some("auto".to_owned()),
            target_layer_path: Some("root/codex/runtime".to_owned()),
            target_layer_depth: Some(2),
            target_layer_reason: Some("agent_runtime_layered_mode".to_owned()),
            ..flat_without_metadata.clone()
        };
        let layered_hash = writeback_signed_task_hash(&layered).expect("layered task hash");
        assert_ne!(
            layered_hash, layered.answer_hash,
            "layered writebacks must bind the layer target into the signed task hash"
        );
        assert_eq!(
            writeback_signed_task_hash(&layered).expect("layered task hash repeat"),
            layered_hash,
            "layer target binding must be deterministic"
        );

        let mutated_path = DagDbWritebackRequest {
            target_layer_path: Some("root/codex/exfiltration".to_owned()),
            ..layered.clone()
        };
        assert_ne!(
            writeback_signed_task_hash(&mutated_path).expect("mutated path task hash"),
            layered_hash,
            "mutating target_layer_path must change the signed task hash"
        );
        let mutated_depth = DagDbWritebackRequest {
            target_layer_depth: Some(3),
            ..layered.clone()
        };
        assert_ne!(
            writeback_signed_task_hash(&mutated_depth).expect("mutated depth task hash"),
            layered_hash,
            "mutating target_layer_depth must change the signed task hash"
        );
        let mutated_reason = DagDbWritebackRequest {
            target_layer_reason: Some("mutated_reason".to_owned()),
            ..layered.clone()
        };
        assert_ne!(
            writeback_signed_task_hash(&mutated_reason).expect("mutated reason task hash"),
            layered_hash,
            "mutating target_layer_reason must change the signed task hash"
        );
        let mutated_mode = DagDbWritebackRequest {
            layered_mode: Some("required".to_owned()),
            ..layered.clone()
        };
        assert_ne!(
            writeback_signed_task_hash(&mutated_mode).expect("mutated mode task hash"),
            layered_hash,
            "mutating layered_mode must change the signed task hash"
        );

        let mode_only = DagDbWritebackRequest {
            layered_mode: Some("auto".to_owned()),
            target_layer_path: None,
            target_layer_depth: None,
            target_layer_reason: None,
            ..flat_without_metadata.clone()
        };
        let mode_only_hash = writeback_signed_task_hash(&mode_only).expect("mode-only task hash");
        assert_ne!(
            mode_only_hash, flat_without_metadata.answer_hash,
            "adding layered_mode alone must change the signed task hash"
        );
        let empty_reason = DagDbWritebackRequest {
            layered_mode: Some("auto".to_owned()),
            target_layer_path: None,
            target_layer_depth: None,
            target_layer_reason: Some(String::new()),
            ..flat_without_metadata
        };
        assert_ne!(
            writeback_signed_task_hash(&empty_reason).expect("empty reason task hash"),
            mode_only_hash,
            "absent and empty layered fields must bind to distinct task hashes"
        );
    }

    #[tokio::test]
    async fn dagdb_layered_runtime_gateway_exposes_specific_error_codes() {
        let fixtures = fixtures();
        let app = dagdb_app();
        let request: DagDbContextPacketRequest = fixture(&fixtures, "requests", "context_packet");

        assert_error_response(
            app.clone()
                .oneshot(scoped_json_request(
                    "POST",
                    "/api/v1/dag-db/context-packet",
                    "dagdb:context_packet",
                    &DagDbContextPacketRequest {
                        layered_mode: Some("sometimes".to_owned()),
                        ..request.clone()
                    },
                ))
                .await
                .expect("invalid layered mode response"),
            StatusCode::BAD_REQUEST,
            "invalid_layered_mode",
        )
        .await;

        assert_error_response(
            app.oneshot(scoped_json_request(
                "POST",
                "/api/v1/dag-db/context-packet",
                "dagdb:context_packet",
                &DagDbContextPacketRequest {
                    layered_mode: Some("required".to_owned()),
                    require_layer_evidence: Some(true),
                    ..request
                },
            ))
            .await
            .expect("required layer evidence missing response"),
            StatusCode::BAD_REQUEST,
            "required_layer_evidence_missing",
        )
        .await;
    }

    #[test]
    fn runtime_request_basics_cover_success_empty_unsafe_and_did_branches() {
        assert!(
            validate_runtime_request_basics(
                "dagdb.import",
                "tenant-a",
                "primary",
                "idem-1",
                "dag_db-project_memory_v3",
                "did:exo:agent",
            )
            .is_ok()
        );

        let invalid_vectors = [
            (
                "",
                "primary",
                "idem-1",
                "dag_db-project_memory_v3",
                "did:exo:agent",
            ),
            (
                "tenant-a",
                " ",
                "idem-1",
                "dag_db-project_memory_v3",
                "did:exo:agent",
            ),
            (
                "tenant-a",
                "primary",
                "",
                "dag_db-project_memory_v3",
                "did:exo:agent",
            ),
            ("tenant-a", "primary", "idem-1", "", "did:exo:agent"),
            (
                "tenant-a",
                "primary",
                "idem-1",
                "dag_db-project_memory_v3",
                "",
            ),
            (
                "tenant-a",
                "primary",
                "idem-1",
                "dag_db-project_memory_v3",
                "agent-without-did",
            ),
            (
                "tenant-a",
                "primary",
                "fn raw_payload() {}",
                "dag_db-project_memory_v3",
                "did:exo:agent",
            ),
        ];
        for (tenant_id, namespace, idempotency_key, db_set_version, requester_did) in
            invalid_vectors
        {
            assert!(
                validate_runtime_request_basics(
                    "dagdb.import",
                    tenant_id,
                    namespace,
                    idempotency_key,
                    db_set_version,
                    requester_did,
                )
                .is_err(),
                "expected invalid basics for {tenant_id:?} {namespace:?} {idempotency_key:?} {db_set_version:?} {requester_did:?}"
            );
        }
    }

    // Debug-only: the deterministic local-dev fallback exists ONLY in debug
    // builds (T1). Under `cargo test --release` `debug_assertions` is off and
    // these symbols are compiled out, so the tests that exercise them are gated
    // to the same configuration. The release posture is proven separately by
    // `release_build_has_no_dev_gatekeeper_or_deterministic_seed` below.
    #[cfg(debug_assertions)]
    #[test]
    fn local_dev_gatekeeper_profile_requires_explicit_fallback_seed_gate() {
        let missing_seed = "__missing_dagdb_local_dev_seed__";
        assert!(
            load_local_dev_keypair_from_seed_path_with_source(
                missing_seed,
                LOCAL_DEV_KEY_SOURCE_EXPLICIT_SEED,
                false,
            )
            .is_err()
        );
        let fallback = load_local_dev_keypair_from_seed_path_with_source(
            missing_seed,
            LOCAL_DEV_KEY_SOURCE_EXPLICIT_SEED,
            true,
        )
        .expect("explicit local-dev fallback");
        assert_eq!(fallback.source, LOCAL_DEV_KEY_SOURCE_DETERMINISTIC_FALLBACK);
        DagDbRouteContext::from_pool(None).install_local_dev_gatekeeper_profile();
    }

    #[cfg(debug_assertions)]
    #[test]
    fn local_dev_keypair_reads_seed_file_and_rejects_short_seed() {
        let temp_dir =
            std::env::temp_dir().join(format!("dagdb-local-dev-seed-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).expect("create seed temp dir");
        let full_seed = temp_dir.join("full.seed");
        let short_seed = temp_dir.join("short.seed");
        std::fs::write(&full_seed, [7_u8; 32]).expect("write full seed");
        std::fs::write(&short_seed, [3_u8; 31]).expect("write short seed");

        let full_seed = full_seed.to_str().expect("utf8 seed path");
        let short_seed = short_seed.to_str().expect("utf8 short seed path");
        let loaded = load_local_dev_keypair_from_seed_path(full_seed).expect("full seed");
        assert_eq!(loaded.source, LOCAL_DEV_KEY_SOURCE_EXPLICIT_SEED);
        assert!(load_local_dev_keypair_from_seed_path(short_seed).is_err());
        DagDbRouteContext::from_pool(None)
            .install_local_dev_gatekeeper_profile_from_seed_path(short_seed);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn import_report_validation_accepts_scope_and_rejects_scope_drift() {
        let request = import_request();
        let report_json = validated_import_report_json(&request).expect("valid import report");
        let report_value: serde_json::Value =
            serde_json::from_str(&report_json).expect("report json");
        assert_eq!(report_value["tenant_id"], "tenant-a");
        assert_eq!(report_value["namespace"], "primary");

        let mut tenant_mismatch = import_request();
        tenant_mismatch.import_report["tenant_id"] = json!("tenant-b");
        assert!(validated_import_report_json(&tenant_mismatch).is_err());

        let mut namespace_mismatch = import_request();
        namespace_mismatch.import_report["namespace"] = json!("secondary");
        assert!(validated_import_report_json(&namespace_mismatch).is_err());

        let mut invalid_report = import_request();
        invalid_report.import_report["schema_version"] = json!("unknown_schema");
        assert!(validated_import_report_json(&invalid_report).is_err());

        // The report's declared actor must be the signature-verified
        // requester: receipts derive their actor from the report, so a
        // foreign actor here would attribute receipts to a principal that
        // never signed the request.
        let mut actor_mismatch = import_request();
        actor_mismatch.import_report["actor_did"] = json!("did:exo:rogue-actor");
        for intent in actor_mismatch.import_report["proposed_receipt_intents"]
            .as_array_mut()
            .into_iter()
            .flatten()
        {
            intent["actor_did"] = json!("did:exo:rogue-actor");
        }
        assert!(validated_import_report_json(&actor_mismatch).is_err());
    }

    #[test]
    fn export_scope_validation_copies_filters_and_rejects_defensive_branches() {
        let memory_id = Hash256::digest(b"memory-a").to_string();
        let request = DagDbExportRequest {
            included_memory_ids: vec![memory_id.clone()],
            included_graph_styles: vec!["semantic_catalog_graph".to_owned()],
            included_writeback_idempotency_keys: vec!["idem-writeback-1".to_owned()],
            include_preview_context: true,
            ..export_request()
        };
        let scope = export_scope_from_request(&request).expect("valid export scope");
        assert_eq!(scope.tenant_id, "tenant-a");
        assert_eq!(scope.namespace, "primary");
        assert_eq!(scope.included_memory_ids, vec![memory_id]);
        assert_eq!(
            scope.included_writeback_idempotency_keys,
            vec!["idem-writeback-1"]
        );
        assert!(scope.include_preview_context);

        assert!(
            export_scope_from_request(&DagDbExportRequest {
                included_graph_styles: vec!["style-a".to_owned(), "style-a".to_owned()],
                ..export_request()
            })
            .is_err()
        );
        assert!(
            export_scope_from_request(&DagDbExportRequest {
                source_commit_or_repo_ref: Some("".to_owned()),
                ..export_request()
            })
            .is_err()
        );
        assert!(
            export_scope_from_request(&DagDbExportRequest {
                source_commit_or_repo_ref: Some("fn raw_payload() {}".to_owned()),
                ..export_request()
            })
            .is_err()
        );
    }

    #[test]
    fn request_hash_uses_redacted_metadata_after_scope_verification() {
        let fixtures = fixtures();
        let request = DagDbIntakeRequest {
            title_text: "SSN 123-45-6789".to_owned(),
            ..fixture(&fixtures, "requests", "intake")
        };
        let raw_body = request_json(&request).expect("raw request json");
        let raw_hash = request_hash(
            "dagdb.intake",
            &request.tenant_id,
            &request.namespace,
            &raw_body,
        )
        .expect("raw request hash");

        let title = sanitize_metadata(MetadataField::Title, &request.title_text)
            .expect("SSN title is redacted");
        let summary = sanitize_metadata(MetadataField::Summary, &request.summary_text)
            .expect("summary is safe");
        let keywords =
            sanitize_keyword_texts(request.keyword_texts.as_deref()).expect("keywords are safe");
        let mut redacted_body = request_json(&request).expect("redacted body base");
        replace_metadata(
            &mut redacted_body,
            "title_text",
            "title",
            request_json(&title).expect("title json"),
        )
        .expect("replace title");
        replace_metadata(
            &mut redacted_body,
            "summary_text",
            "summary",
            request_json(&summary).expect("summary json"),
        )
        .expect("replace summary");
        replace_metadata(
            &mut redacted_body,
            "keyword_texts",
            "keywords",
            request_json(&keywords).expect("keywords json"),
        )
        .expect("replace keywords");
        let redacted_hash = request_hash(
            "dagdb.intake",
            &request.tenant_id,
            &request.namespace,
            &redacted_body,
        )
        .expect("redacted request hash");
        let encoded_redacted = serde_json::to_string(&redacted_body).expect("json string");

        assert_ne!(raw_hash, redacted_hash);
        assert!(!encoded_redacted.contains("123-45-6789"));
        assert!(encoded_redacted.contains("[REDACTED_SSN]"));
    }

    #[tokio::test]
    async fn dagdb_council_decision_route_is_mounted_and_fails_closed_without_live_persistence() {
        let app = dagdb_app();

        let unavailable = app
            .clone()
            .oneshot(council_request(
                "tenant-a",
                "primary",
                "dagdb:council_decision:tenant-a:primary",
            ))
            .await
            .expect("route response");
        assert_error_response(
            unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
        )
        .await;

        let mismatch = app
            .clone()
            .oneshot(council_request(
                "tenant-b",
                "primary",
                "dagdb:council_decision:tenant-b:primary",
            ))
            .await
            .expect("tenant mismatch response");
        assert_error_response(mismatch, StatusCode::FORBIDDEN, "tenant_scope_mismatch").await;

        let missing_scope = app
            .oneshot(council_request("tenant-a", "primary", "dagdb:other"))
            .await
            .expect("missing scope response");
        assert_error_response(
            missing_scope,
            StatusCode::FORBIDDEN,
            "council_authority_required",
        )
        .await;
    }

    #[test]
    fn council_authority_checks_fail_closed() {
        let request = council_decision_request();
        let mut headers = HeaderMap::new();
        assert_eq!(
            verify_council_authority(&headers, &request)
                .expect("missing auth")
                .status(),
            StatusCode::UNAUTHORIZED
        );

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic test"),
        );
        assert_eq!(
            verify_council_authority(&headers, &request)
                .expect("basic auth")
                .status(),
            StatusCode::UNAUTHORIZED
        );

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test"),
        );
        assert_eq!(
            verify_council_authority(&headers, &request)
                .expect("missing tenant")
                .status(),
            StatusCode::FORBIDDEN
        );
        headers.insert(TENANT_HEADER, HeaderValue::from_static("tenant-a"));
        assert_eq!(
            verify_council_authority(&headers, &request)
                .expect("missing namespace")
                .status(),
            StatusCode::FORBIDDEN
        );
        headers.insert(NAMESPACE_HEADER, HeaderValue::from_static("other"));
        assert_eq!(
            verify_council_authority(&headers, &request)
                .expect("namespace mismatch")
                .status(),
            StatusCode::FORBIDDEN
        );

        headers.insert(NAMESPACE_HEADER, HeaderValue::from_static("primary"));
        assert_eq!(
            verify_council_authority(&headers, &request)
                .expect("missing council authority")
                .status(),
            StatusCode::FORBIDDEN
        );

        headers.insert(
            AUTHORITY_SCOPE_HEADER,
            HeaderValue::from_static("other,dagdb:council_decision:tenant-a:primary"),
        );
        assert!(verify_council_authority(&headers, &request).is_none());
    }

    #[tokio::test]
    async fn council_error_responses_are_stable() {
        assert_error_response(
            council_error_response(
                exo_dag_db_domain::council::CouncilError::InvalidRequestShape("subject_id"),
            ),
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
        )
        .await;
        assert_error_response(
            council_error_response(exo_dag_db_domain::council::CouncilError::Hash(
                "cbor".to_owned(),
            )),
            StatusCode::BAD_REQUEST,
            "invalid_request_shape",
        )
        .await;
        let metadata_error = exo_dag_db_core::metadata::sanitize_runtime_metadata(
            exo_dag_db_core::metadata::MetadataField::CouncilNotes,
            "fn raw_payload() {}",
        )
        .expect_err("code excerpt rejected");
        assert_error_response(
            council_error_response(exo_dag_db_domain::council::CouncilError::Metadata(
                metadata_error,
            )),
            StatusCode::UNPROCESSABLE_ENTITY,
            "metadata_rejected",
        )
        .await;
        assert_error_response(
            council_error_response(exo_dag_db_domain::council::CouncilError::ApprovalScopeMismatch),
            StatusCode::CONFLICT,
            "approval_scope_mismatch",
        )
        .await;
        assert_error_response(
            council_error_response(exo_dag_db_domain::council::CouncilError::ApprovalDenied),
            StatusCode::FORBIDDEN,
            "approval_denied",
        )
        .await;
        assert_error_response(
            council_error_response(
                exo_dag_db_domain::council::CouncilError::CouncilEscalationRequired,
            ),
            StatusCode::FORBIDDEN,
            "council_escalation_required",
        )
        .await;
        assert_error_response(
            council_error_response(exo_dag_db_domain::council::CouncilError::ApprovalRequired),
            StatusCode::FORBIDDEN,
            "approval_required",
        )
        .await;
    }

    async fn assert_post_error<T>(
        app: Router,
        path: &str,
        action: &str,
        body: T,
        status: StatusCode,
        error_code: &str,
    ) where
        T: Serialize,
    {
        let response = app
            .oneshot(scoped_json_request("POST", path, action, &body))
            .await
            .expect("DAG DB POST route error response");
        assert_error_response(response, status, error_code).await;
    }

    async fn assert_get_error(
        app: Router,
        path: &str,
        action: &str,
        status: StatusCode,
        error_code: &str,
    ) {
        let response = app
            .oneshot(scoped_get_request(path, action))
            .await
            .expect("DAG DB GET route error response");
        assert_error_response(response, status, error_code).await;
    }

    fn scoped_json_request<T>(method: &str, uri: &str, action: &str, body: &T) -> Request<Body>
    where
        T: Serialize,
    {
        let body = serde_json::to_vec(body).expect("serialize DAG DB request");
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer test-token")
            .header(TENANT_HEADER, "tenant-a")
            .header(NAMESPACE_HEADER, "primary")
            .header(AUTHORITY_SCOPE_HEADER, format!("{action}:tenant-a:primary"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .expect("request")
    }

    fn scoped_raw_json_request(
        method: &str,
        uri: &str,
        action: &str,
        body: String,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer test-token")
            .header(TENANT_HEADER, "tenant-a")
            .header(NAMESPACE_HEADER, "primary")
            .header(AUTHORITY_SCOPE_HEADER, format!("{action}:tenant-a:primary"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .expect("request")
    }

    fn scoped_get_request(uri: &str, action: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer test-token")
            .header(TENANT_HEADER, "tenant-a")
            .header(NAMESPACE_HEADER, "primary")
            .header(AUTHORITY_SCOPE_HEADER, format!("{action}:tenant-a:primary"))
            .body(Body::empty())
            .expect("request")
    }

    fn authorized_headers(action: &str) -> HeaderMap {
        scoped_headers(action, "tenant-a")
    }

    fn denied_headers(action: &str) -> HeaderMap {
        scoped_headers(action, "tenant-b")
    }

    fn scoped_headers(action: &str, tenant: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test"),
        );
        headers.insert(
            TENANT_HEADER,
            HeaderValue::from_str(tenant).expect("valid tenant header"),
        );
        headers.insert(NAMESPACE_HEADER, HeaderValue::from_static("primary"));
        headers.insert(
            AUTHORITY_SCOPE_HEADER,
            HeaderValue::from_str(&format!("{action}:{tenant}:primary"))
                .expect("valid authority scope header"),
        );
        headers
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
            import_report: json!({
                "schema_version": exo_dag_db_exchange::kg_import::KG_IMPORT_DRY_RUN_REPORT_SCHEMA,
                "source_candidates_schema_version": exo_dag_db_exchange::kg_import::KG_IMPORT_CANDIDATES_SCHEMA,
                "graph_root": "KnowledgeGraphs/dag-db",
                "tenant_id": "tenant-a",
                "namespace": "primary",
                "actor_did": "did:exo:importer",
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
            included_memory_ids: Vec::new(),
            included_graph_styles: Vec::new(),
            included_writeback_idempotency_keys: Vec::new(),
            source_commit_or_repo_ref: Some("c706242d36f1c275e05d8a132778491da08f61c7".to_owned()),
            include_preview_context: false,
        }
    }

    fn lookup_query(tenant_id: &str, namespace: &str, extras: &[(&str, &str)]) -> QueryParams {
        let mut query = QueryParams::new();
        query.insert("tenant_id".to_owned(), tenant_id.to_owned());
        query.insert("namespace".to_owned(), namespace.to_owned());
        for (name, value) in extras {
            query.insert((*name).to_owned(), (*value).to_owned());
        }
        query
    }

    fn fixtures() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../exo-dag-db-api/fixtures/json/all_dto_fixtures.json"
        ))
        .expect("parse complete DAG DB fixture set")
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

    fn assert_fixture<T>(fixtures: &serde_json::Value, section: &str, name: &str)
    where
        T: DeserializeOwned + Serialize,
    {
        let parsed: T = fixture(fixtures, section, name);
        let serialized = serde_json::to_value(parsed)
            .unwrap_or_else(|err| panic!("serialize fixture {section}.{name}: {err}"));
        assert_eq!(
            serialized,
            fixtures
                .get(section)
                .and_then(|section| section.get(name))
                .unwrap_or_else(|| panic!("missing fixture {section}.{name}"))
                .clone(),
            "fixture {section}.{name} drifted"
        );
    }

    fn council_request(
        tenant_header: &str,
        namespace_header: &str,
        authority_scope: &str,
    ) -> Request<Body> {
        let body =
            serde_json::to_vec(&council_decision_request()).expect("serialize council request");

        Request::builder()
            .method("POST")
            .uri("/api/v1/dag-db/council/decision")
            .header(axum::http::header::AUTHORIZATION, "Bearer test-token")
            .header(TENANT_HEADER, tenant_header)
            .header(NAMESPACE_HEADER, namespace_header)
            .header(AUTHORITY_SCOPE_HEADER, authority_scope)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .expect("request")
    }

    fn council_decision_request() -> exo_api::dagdb::DagDbCouncilDecisionRequest {
        exo_api::dagdb::DagDbCouncilDecisionRequest {
            tenant_id: "tenant-a".to_owned(),
            namespace: "primary".to_owned(),
            idempotency_key: "idem-council-1".to_owned(),
            subject_kind: SubjectKind::Memory,
            subject_id: Hash256::from_bytes([0xf0; 32]).to_string(),
            requested_action: "memory:routable".to_owned(),
            approved_scope_hash: Hash256::from_bytes([0x12; 32]).to_string(),
            risk_class: RiskClass::R3,
            approver_did: "did:exo:council".to_owned(),
            decision_source: DecisionSource::Human,
            decision_status: CouncilDecisionStatus::Approved,
            reason_code: "operator_approved".to_owned(),
            created_at: "1000:0".to_owned(),
            expires_at: "2000:0".to_owned(),
            validation_report_id: None,
            route_id: None,
            context_packet_id: None,
            notes_text: Some("Safe approval notes".to_owned()),
        }
    }

    async fn json_body<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        serde_json::from_slice(&bytes).expect("json body")
    }

    async fn assert_error_response(
        response: axum::response::Response,
        expected_status: StatusCode,
        expected_code: &str,
    ) {
        assert_eq!(response.status(), expected_status);
        let envelope: exo_api::dagdb::DagDbErrorEnvelope = json_body(response).await;
        assert_eq!(envelope.error_code, expected_code);
    }

    fn fixed_approval_timestamp() -> &'static str {
        "2026-06-20T00:00:00Z"
    }

    async fn assert_sanitized_invalid_shape(
        response: axum::response::Response,
        forbidden_fragments: &[&str],
    ) {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        let envelope: exo_api::dagdb::DagDbErrorEnvelope =
            serde_json::from_str(&body).expect("DAG DB error envelope");
        assert_eq!(envelope.error_code, "invalid_request_shape");
        for fragment in forbidden_fragments {
            assert!(
                !body.contains(fragment),
                "sanitized envelope must not contain {fragment}"
            );
        }
    }

    async fn assert_error_response_shape(
        response: axum::response::Response,
        expected_status: StatusCode,
        expected_code: &str,
        expected_message: &str,
        expected_requires_council_review: bool,
    ) {
        assert_eq!(response.status(), expected_status);
        let envelope: exo_api::dagdb::DagDbErrorEnvelope = json_body(response).await;
        assert_eq!(envelope.error_code, expected_code);
        assert_eq!(envelope.message, expected_message);
        assert_eq!(
            envelope.requires_council_review,
            expected_requires_council_review
        );
    }

    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(serde::ser::Error::custom("intentional serialize failure"))
        }
    }

    #[cfg(feature = "production-db")]
    mod production_db_tests {
        use std::{collections::BTreeMap, sync::Arc, time::Duration};

        use axum::{
            Json,
            extract::Extension,
            http::{HeaderMap, HeaderValue, StatusCode, header},
        };
        use exo_api::dagdb::{DagDbContextPacketRequest, DagDbGraphContextSelectionStatus};
        use exo_core::crypto::KeyPair;
        use exo_dag_db_domain::scoring::DomainError;
        use exo_gatekeeper::{
            ConsentEngine, GatekeeperError, IdentityRegistry,
            dagdb_gate::{
                context_packet_record_payload_hash, continuation_record_payload_hash,
                default_route_payload_hash, lifecycle_action_payload_hash,
            },
            sign_write_payload,
            types::GovernedRoleName,
        };
        use sqlx::postgres::PgPoolOptions;

        use super::*;

        #[test]
        fn pre_auth_operational_audit_ignores_spoofed_scope_headers() {
            let mut headers = HeaderMap::new();
            headers.insert(
                TENANT_HEADER,
                HeaderValue::from_static("tenant-attacker-controlled"),
            );
            headers.insert(
                NAMESPACE_HEADER,
                HeaderValue::from_static("namespace-attacker-controlled"),
            );

            assert_eq!(
                mounted_audit_tenant_id(&headers, "tenant-request-body"),
                "tenant-request-body",
                "pre-auth audit receipts must stamp the parsed request tenant, not spoofable headers"
            );
            assert_eq!(
                mounted_audit_namespace(&headers, "namespace-request-body"),
                "namespace-request-body",
                "pre-auth audit receipts must stamp the parsed request namespace, not spoofable headers"
            );
        }

        #[tokio::test]
        async fn bind_requester_to_session_actor_rejects_self_asserted_requester() {
            // A session authenticated as one actor must not be able to drive an
            // import/export attributed to a different, self-asserted requester_did.
            let session_actor =
                DagDbSessionActor::Authenticated("did:exo:session-owner".to_owned());
            let denied = bind_requester_to_session_actor(
                &session_actor,
                "dagdb.import",
                "tenant-a",
                "did:exo:other-principal",
            )
            .expect_err("mismatched requester must be rejected");
            assert_error_response(*denied, StatusCode::FORBIDDEN, "requester_actor_mismatch").await;
        }

        #[test]
        fn bind_requester_to_session_actor_accepts_matching_requester() {
            let session_actor =
                DagDbSessionActor::Authenticated("did:exo:session-owner".to_owned());
            assert!(
                bind_requester_to_session_actor(
                    &session_actor,
                    "dagdb.import",
                    "tenant-a",
                    "did:exo:session-owner",
                )
                .is_ok(),
                "requester matching the session actor must be authorized"
            );
        }

        #[test]
        fn bind_requester_to_session_actor_no_pool_skips_actor_binding() {
            // Without a pool there is no persisted session identity to bind
            // against; route handlers still fail closed before claim success.
            assert!(
                bind_requester_to_session_actor(
                    &DagDbSessionActor::NoPool,
                    "dagdb.import",
                    "tenant-a",
                    "did:exo:anyone",
                )
                .is_ok(),
                "no-pool path must not block on requester binding"
            );
        }

        #[tokio::test]
        async fn install_gatekeeper_profile_wires_gatekeeper_service() {
            // An explicitly-installed profile short-circuits the DB resolver, so
            // an unreachable lazy pool is never queried.
            let ctx = DagDbRouteContext::from_pool(None);
            ctx.install_gatekeeper_profile(ConsentEngine::default(), IdentityRegistry::default());
            let pool = PgPoolOptions::new()
                .acquire_timeout(Duration::from_millis(50))
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            let _service = ctx
                .gatekeeper_service(&pool, "did:exo:agent", "tenant-a", "primary", &[])
                .await
                .expect("installed profile resolves without touching the DB");
        }

        #[tokio::test]
        async fn gatekeeper_service_resolver_unconfigured_fails_closed() {
            // No profile installed and an unreachable pool: the DB resolver must
            // fail closed with AuthorityResolverUnavailable, never an empty
            // registry. The resolver's first DB touch is the trusted-clock query.
            let ctx = DagDbRouteContext::from_pool(None);
            let pool = PgPoolOptions::new()
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            let result = ctx
                .gatekeeper_service(&pool, "did:exo:agent", "tenant-a", "primary", &[])
                .await;
            assert!(matches!(
                result,
                Err(GatekeeperError::AuthorityResolverUnavailable(_))
            ));
        }

        /// T1 release-posture regression. Compiles ONLY under `--release`
        /// (`debug_assertions` off) — exactly how CI runs the suite
        /// (`cargo test --workspace --release`). It proves the shipping binary
        /// has no fabricated dev authorization and no deterministic-key signing:
        ///
        /// * The dev gatekeeper profile installer is gated out: a release-config
        ///   build never installs the dev DID / dev consent. We assert no profile
        ///   is present after a bare `from_pool`, the only constructor available.
        /// * With no installed profile, the write gate authorizes solely via the
        ///   live DB resolver and fails closed with the typed
        ///   `AuthorityResolverUnavailable` against an unreachable pool — it never
        ///   falls back to a `[0..31]` deterministic key or an empty registry.
        ///
        /// The deterministic-seed loader and `install_local_dev_gatekeeper_*`
        /// are `#[cfg(debug_assertions)]` and do not exist in this configuration;
        /// the debug-only tests in the parent module exercise them.
        #[cfg(not(debug_assertions))]
        #[tokio::test]
        async fn release_build_has_no_dev_gatekeeper_or_deterministic_seed() {
            let ctx = DagDbRouteContext::from_pool(None);
            assert!(
                ctx.installed_gatekeeper_profile().is_none(),
                "release build must not install a fabricated dev gatekeeper profile"
            );
            let pool = PgPoolOptions::new()
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            let result = ctx
                .gatekeeper_service(&pool, "did:exo:agent", "tenant-a", "primary", &[])
                .await;
            assert!(
                matches!(
                    result,
                    Err(GatekeeperError::AuthorityResolverUnavailable(_))
                ),
                "release build must fail closed with a typed error, never a deterministic-key signer"
            );
        }

        fn unreachable_lazy_pool() -> sqlx::PgPool {
            PgPoolOptions::new()
                .acquire_timeout(Duration::from_millis(50))
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool")
        }

        #[test]
        fn dagdb_install_gatekeeper_profile_ignores_poisoned_lock() {
            let ctx = DagDbRouteContext::from_pool(None);
            let gatekeeper = ctx.gatekeeper.clone();
            let _ = std::thread::spawn(move || {
                let _guard = gatekeeper.write().expect("write lock");
                panic!("poison gatekeeper profile for coverage");
            })
            .join();

            ctx.install_gatekeeper_profile(ConsentEngine::default(), IdentityRegistry::default());
        }

        #[test]
        fn resolve_route_context_uses_extension_when_override_unset() {
            let ctx = Arc::new(DagDbRouteContext::from_pool(None));
            let resolved = resolve_route_context(Some(Extension(ctx.clone())));
            assert!(resolved.pool.is_none());
        }

        #[test]
        fn resolve_route_context_falls_back_to_empty_context() {
            let resolved = resolve_route_context(None);
            assert!(resolved.pool.is_none());
        }

        #[test]
        fn resolve_route_context_prefers_integration_override() {
            let ctx = Arc::new(DagDbRouteContext::from_pool(None));
            set_route_context_for_integration_tests(ctx);
            let resolved = resolve_route_context(Some(Extension(Arc::new(
                DagDbRouteContext::from_pool(None),
            ))));
            assert!(Arc::ptr_eq(
                &resolved,
                ROUTE_CONTEXT_OVERRIDE.get().expect("override")
            ));
        }

        #[tokio::test]
        async fn handle_dagdb_council_decision_no_pool_precedes_build_errors() {
            let mut request = council_decision_request();
            request.expires_at = "not-an-hlc".to_owned();
            let response = handle_dagdb_council_decision(
                None,
                authorized_headers("dagdb:council_decision"),
                Json(request),
            )
            .await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }

        #[tokio::test]
        async fn context_packet_handler_maps_database_failures_closed() {
            let pool = PgPoolOptions::new()
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            pool.close().await;
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let request = DagDbContextPacketRequest {
                tenant_id: "tenant-a".to_owned(),
                namespace: "primary".to_owned(),
                idempotency_key: "idem-packet-db-error".to_owned(),
                request_id: "request-db-error".to_owned(),
                route_id: Hash256::digest(b"route").to_string(),
                task_hash: Hash256::digest(b"task").to_string(),
                requesting_agent_did: "did:exo:agent".to_owned(),
                token_budget: 2048,
                force_revalidate: None,
                max_memory_refs: None,
                task: None,
                layered_mode: None,
                max_layer_depth: None,
                require_layer_evidence: None,
                drilldown_reserve_bp: None,
            };
            let response = context_packet_handler(&ctx, request).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }

        #[test]
        fn context_packet_response_from_persistent_marks_empty_and_database_modes() {
            let request = context_packet_request("packet-mode-request");

            let empty = persistent_context_packet(Vec::new());
            let empty_response =
                context_packet_response_from_persistent(&request, &empty).expect("empty packet");
            assert_eq!(
                empty_response.context_packet_mode.as_deref(),
                Some("empty_selection")
            );
            assert!(empty_response.selection_warning.is_some());

            let selected_ref = selected_context_ref();
            let selected_receipt_hash = Hash256::digest(b"selected memory receipt").to_string();
            let selected = persistent_context_packet_with_receipts(
                vec![selected_ref.clone()],
                BTreeMap::from([(
                    selected_ref.memory_id.clone(),
                    selected_receipt_hash.clone(),
                )]),
            );
            let selected_response = context_packet_response_from_persistent(&request, &selected)
                .expect("selected packet");
            assert_eq!(
                selected_response.context_packet_mode.as_deref(),
                Some("database")
            );
            assert_eq!(
                selected_response.validation_status,
                ValidationStatus::Passed
            );
            assert_eq!(selected_response.selection_warning, None);
            assert_eq!(selected_response.memory_refs.len(), 1);
            assert_eq!(
                selected_response.memory_refs[0].latest_receipt_hash,
                selected_receipt_hash
            );

            let missing_receipt = persistent_context_packet_with_receipts(
                vec![selected_context_ref()],
                BTreeMap::new(),
            );
            let missing_receipt_response =
                context_packet_response_from_persistent(&request, &missing_receipt)
                    .expect("missing receipt packet");
            assert_eq!(
                missing_receipt_response.validation_status,
                ValidationStatus::Failed
            );
            assert_eq!(
                missing_receipt_response.selection_warning.as_deref(),
                Some(
                    "selected memory reference receipt hash unavailable; validation failed closed"
                )
            );
            assert_eq!(missing_receipt_response.memory_refs.len(), 1);
            assert_eq!(
                missing_receipt_response.memory_refs[0].latest_receipt_hash,
                Hash256::ZERO.to_string()
            );

            let required_request = DagDbContextPacketRequest {
                layered_mode: Some("required".to_owned()),
                max_layer_depth: Some(3),
                require_layer_evidence: Some(true),
                ..request.clone()
            };
            assert!(
                context_packet_response_from_persistent(&required_request, &selected).is_err(),
                "flat persistent refs must not satisfy required layered evidence"
            );

            let auto_request = DagDbContextPacketRequest {
                layered_mode: Some("auto".to_owned()),
                max_layer_depth: Some(3),
                require_layer_evidence: Some(false),
                ..request
            };
            let auto_response = context_packet_response_from_persistent(&auto_request, &selected)
                .expect("auto packet");
            assert_eq!(
                auto_response.layered_status.as_deref(),
                Some("flat_fallback_no_layer_evidence")
            );
            assert_eq!(auto_response.flat_fallback_used, Some(true));
        }

        #[tokio::test]
        async fn writeback_handler_requires_write_signature_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_static("Bearer test"),
            );
            let request = fixture_writeback_request();
            let response = writeback_handler(&ctx, &headers, request).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn route_handler_requires_default_route_signature_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let fixtures = fixtures();
            let request: DagDbRouteRequest = fixture(&fixtures, "requests", "route");
            let response = route_handler(&ctx, &authorized_headers("dagdb:route"), request).await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "write_signature_required",
            )
            .await;
        }

        #[tokio::test]
        async fn route_handler_persists_default_route_or_fails_closed_at_db_layer() {
            let keypair = KeyPair::generate();
            let authority_keypair = KeyPair::generate();
            let authority_did = "did:exo:route-authority";
            let fixtures = fixtures();
            let request: DagDbRouteRequest = fixture(&fixtures, "requests", "route");
            let response =
                route_response_from_request(request.clone(), "dagdb.route").expect("route shape");
            let proposed = default_route_candidate_from_response(&request, &response)
                .expect("default route proposed record");
            let approval_payload_hash_hex = canonical_default_route_approval_payload_hash(
                &proposed,
                &request.requesting_agent_did,
                &request.idempotency_key,
                authority_did,
                DEFAULT_ROUTE_FINALITY_PURPOSE,
                fixed_approval_timestamp(),
            )
            .expect("default route approval payload hash");
            let approval_payload_hash: [u8; 32] = hex::decode(&approval_payload_hash_hex)
                .expect("approval hash hex")
                .try_into()
                .expect("approval hash bytes");
            let approval_signature = sign_write_payload(&authority_keypair, &approval_payload_hash)
                .expect("default route approval signature");
            let record = default_route_record_from_response(
                &request,
                &response,
                authority_did,
                &approval_signature,
                fixed_approval_timestamp(),
                &approval_payload_hash_hex,
            )
            .expect("default route record");
            let signature = sign_write_payload(
                &keypair,
                &default_route_payload_hash(&record).expect("default route payload hash"),
            )
            .expect("default route signature");
            let pool = PgPoolOptions::new()
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            ctx.install_gatekeeper_profile(
                consent_engine_for_agent(&request.tenant_id, &request.requesting_agent_did),
                identity_registry_for_agent(&request.requesting_agent_did, &keypair)
                    .with_public_key(authority_did, *authority_keypair.public_key().as_bytes())
                    .with_governed_role(authority_did, GovernedRoleName::Operator),
            );
            let mut headers = authorized_headers("dagdb:route");
            headers.insert(
                WRITE_SIGNATURE_HEADER,
                HeaderValue::from_str(&signature).expect("signature header"),
            );
            headers.insert(
                DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER,
                HeaderValue::from_str(&approval_signature).expect("approval signature header"),
            );
            headers.insert(
                DEFAULT_ROUTE_APPROVAL_DID_HEADER,
                HeaderValue::from_static(authority_did),
            );
            headers.insert(
                DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER,
                HeaderValue::from_static(fixed_approval_timestamp()),
            );
            let response = route_handler(&ctx, &headers, request).await;
            assert_error_response(
                response,
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
            )
            .await;
        }

        #[tokio::test]
        async fn route_handler_requires_external_default_route_approval_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let fixtures = fixtures();
            let request: DagDbRouteRequest = fixture(&fixtures, "requests", "route");
            let mut headers = authorized_headers("dagdb:route");
            headers.insert(
                WRITE_SIGNATURE_HEADER,
                HeaderValue::from_str(&"a".repeat(128)).expect("signature header"),
            );

            let response = route_handler(&ctx, &headers, request).await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "default_route_approval_signature_required",
            )
            .await;
        }

        #[tokio::test]
        async fn route_handler_requires_default_route_approval_timestamp_header() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let fixtures = fixtures();
            let request: DagDbRouteRequest = fixture(&fixtures, "requests", "route");
            let mut headers = authorized_headers("dagdb:route");
            headers.insert(
                WRITE_SIGNATURE_HEADER,
                HeaderValue::from_str(&"a".repeat(128)).expect("signature header"),
            );
            headers.insert(
                DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER,
                HeaderValue::from_str(&"b".repeat(128)).expect("approval signature header"),
            );
            headers.insert(
                DEFAULT_ROUTE_APPROVAL_DID_HEADER,
                HeaderValue::from_static("did:exo:route-authority"),
            );

            let response = route_handler(&ctx, &headers, request).await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "default_route_approval_timestamp_required",
            )
            .await;
        }

        #[tokio::test]
        async fn default_route_finality_rejects_approval_timestamp_mutation_before_persistence() {
            let keypair = KeyPair::generate();
            let authority_keypair = KeyPair::generate();
            let authority_did = "did:exo:route-authority";
            let fixtures = fixtures();
            let request: DagDbRouteRequest = fixture(&fixtures, "requests", "route");
            let response =
                route_response_from_request(request.clone(), "dagdb.route").expect("route shape");
            let proposed = default_route_candidate_from_response(&request, &response)
                .expect("default route proposed record");
            let signed_timestamp = fixed_approval_timestamp();
            let supplied_timestamp = "2026-06-20T00:05:00Z";
            let approval_payload_hash_hex = canonical_default_route_approval_payload_hash(
                &proposed,
                &request.requesting_agent_did,
                &request.idempotency_key,
                authority_did,
                DEFAULT_ROUTE_FINALITY_PURPOSE,
                signed_timestamp,
            )
            .expect("default route approval payload hash");
            let approval_payload_hash: [u8; 32] = hex::decode(&approval_payload_hash_hex)
                .expect("approval hash hex")
                .try_into()
                .expect("approval hash bytes");
            let approval_signature = sign_write_payload(&authority_keypair, &approval_payload_hash)
                .expect("default route approval signature");
            let record = default_route_record_from_response(
                &request,
                &response,
                authority_did,
                &approval_signature,
                signed_timestamp,
                &approval_payload_hash_hex,
            )
            .expect("default route record");
            let signature = sign_write_payload(
                &keypair,
                &default_route_payload_hash(&record).expect("default route payload hash"),
            )
            .expect("default route signature");
            let pool = PgPoolOptions::new()
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            ctx.install_gatekeeper_profile(
                consent_engine_for_agent(&request.tenant_id, &request.requesting_agent_did),
                identity_registry_for_agent(&request.requesting_agent_did, &keypair)
                    .with_public_key(authority_did, *authority_keypair.public_key().as_bytes())
                    .with_governed_role(authority_did, GovernedRoleName::Operator),
            );
            let mut headers = authorized_headers("dagdb:route");
            headers.insert(
                WRITE_SIGNATURE_HEADER,
                HeaderValue::from_str(&signature).expect("signature header"),
            );
            headers.insert(
                DEFAULT_ROUTE_APPROVAL_SIGNATURE_HEADER,
                HeaderValue::from_str(&approval_signature).expect("approval signature header"),
            );
            headers.insert(
                DEFAULT_ROUTE_APPROVAL_DID_HEADER,
                HeaderValue::from_static(authority_did),
            );
            headers.insert(
                DEFAULT_ROUTE_APPROVAL_TIMESTAMP_HEADER,
                HeaderValue::from_static(supplied_timestamp),
            );

            let response = route_handler(&ctx, &headers, request).await;
            assert_error_response(response, StatusCode::FORBIDDEN, "approval_denied").await;
        }

        #[tokio::test]
        async fn default_route_finality_rejects_forged_external_approval_before_persistence() {
            let keypair = KeyPair::generate();
            let authority_keypair = KeyPair::generate();
            let fixtures = fixtures();
            let request: DagDbRouteRequest = fixture(&fixtures, "requests", "route");
            let response =
                route_response_from_request(request.clone(), "dagdb.route").expect("route shape");
            let proposed = default_route_candidate_from_response(&request, &response)
                .expect("default route proposed record");
            let approval_payload_hash_hex = canonical_default_route_approval_payload_hash(
                &proposed,
                &request.requesting_agent_did,
                &request.idempotency_key,
                "did:exo:route-authority",
                DEFAULT_ROUTE_FINALITY_PURPOSE,
                fixed_approval_timestamp(),
            )
            .expect("default route approval payload hash");
            let approval_payload_hash: [u8; 32] = hex::decode(&approval_payload_hash_hex)
                .expect("approval hash hex")
                .try_into()
                .expect("approval hash bytes");
            let approval_signature = sign_write_payload(&authority_keypair, &approval_payload_hash)
                .expect("default route approval signature");
            let record = default_route_record_from_response(
                &request,
                &response,
                "did:exo:route-authority",
                &approval_signature,
                fixed_approval_timestamp(),
                &approval_payload_hash_hex,
            )
            .expect("default route record");
            let signature = sign_write_payload(
                &keypair,
                &default_route_payload_hash(&record).expect("default route payload hash"),
            )
            .expect("default route signature");
            let service = consented_service_for_agent_and_authority(
                &keypair,
                &authority_keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
                "did:exo:route-authority",
            );

            let error = gated_route_response(
                &service,
                &request,
                &signature,
                &"00".repeat(64),
                "did:exo:route-authority",
                fixed_approval_timestamp(),
            )
            .await
            .expect_err("forged default-route approval must fail before DB");

            assert_eq!(error.status(), StatusCode::FORBIDDEN);
            assert_eq!(error.error_code(), "approval_denied");
        }

        #[tokio::test]
        async fn default_route_finality_rejects_requester_self_approval_before_persistence() {
            let keypair = KeyPair::generate();
            let fixtures = fixtures();
            let request: DagDbRouteRequest = fixture(&fixtures, "requests", "route");
            let response =
                route_response_from_request(request.clone(), "dagdb.route").expect("route shape");
            let proposed = default_route_candidate_from_response(&request, &response)
                .expect("default route proposed record");
            let approval_payload_hash =
                default_route_payload_hash(&proposed).expect("default route approval payload hash");
            let approval_signature = sign_write_payload(&keypair, &approval_payload_hash)
                .expect("default route self-approval signature");
            let signature = sign_write_payload(&keypair, &approval_payload_hash)
                .expect("default route signature");
            let service = consented_service_for_agent(
                &keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
            );

            let error = gated_route_response(
                &service,
                &request,
                &signature,
                &approval_signature,
                &request.requesting_agent_did,
                fixed_approval_timestamp(),
            )
            .await
            .expect_err("requester self-approval must fail before DB");

            assert_eq!(error.status(), StatusCode::FORBIDDEN);
            assert_eq!(error.error_code(), "approval_denied");
        }

        #[tokio::test]
        async fn default_route_finality_rejects_registered_non_authority_before_persistence() {
            let keypair = KeyPair::generate();
            let registered_non_authority_keypair = KeyPair::generate();
            let registered_non_authority_did = "did:exo:registered-non-authority";
            let fixtures = fixtures();
            let request: DagDbRouteRequest = fixture(&fixtures, "requests", "route");
            let response =
                route_response_from_request(request.clone(), "dagdb.route").expect("route shape");
            let proposed = default_route_candidate_from_response(&request, &response)
                .expect("default route proposed record");
            let approval_payload_hash_hex = canonical_default_route_approval_payload_hash(
                &proposed,
                &request.requesting_agent_did,
                &request.idempotency_key,
                registered_non_authority_did,
                DEFAULT_ROUTE_FINALITY_PURPOSE,
                fixed_approval_timestamp(),
            )
            .expect("default route approval payload hash");
            let approval_payload_hash: [u8; 32] = hex::decode(&approval_payload_hash_hex)
                .expect("approval hash hex")
                .try_into()
                .expect("approval hash bytes");
            let approval_signature =
                sign_write_payload(&registered_non_authority_keypair, &approval_payload_hash)
                    .expect("registered non-authority approval signature");
            let record = default_route_record_from_response(
                &request,
                &response,
                registered_non_authority_did,
                &approval_signature,
                fixed_approval_timestamp(),
                &approval_payload_hash_hex,
            )
            .expect("default route record");
            let signature = sign_write_payload(
                &keypair,
                &default_route_payload_hash(&record).expect("default route payload hash"),
            )
            .expect("default route signature");
            let service = consented_service_for_agent_and_registered_did(
                &keypair,
                &registered_non_authority_keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
                registered_non_authority_did,
            );

            let error = gated_route_response(
                &service,
                &request,
                &signature,
                &approval_signature,
                registered_non_authority_did,
                fixed_approval_timestamp(),
            )
            .await
            .expect_err("registered non-authority approval must fail before DB persistence");

            assert_eq!(error.status(), StatusCode::FORBIDDEN);
            assert_eq!(error.error_code(), "approval_denied");
        }

        #[tokio::test]
        async fn context_packet_handler_requires_record_signature_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let response = gated_context_packet_handler(
                &ctx,
                &authorized_headers("dagdb:context_packet"),
                context_packet_request("missing-context-signature"),
            )
            .await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "write_signature_required",
            )
            .await;
        }

        #[tokio::test]
        async fn context_packet_handler_requires_external_approval_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let mut headers = authorized_headers("dagdb:context_packet");
            headers.insert(
                WRITE_SIGNATURE_HEADER,
                HeaderValue::from_str(&"a".repeat(128)).expect("signature header"),
            );
            let response = gated_context_packet_handler(
                &ctx,
                &headers,
                context_packet_request("missing-context-approval"),
            )
            .await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "context_packet_approval_signature_required",
            )
            .await;
        }

        #[tokio::test]
        async fn context_packet_handler_requires_external_approval_timestamp_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let mut headers = authorized_headers("dagdb:context_packet");
            headers.insert(
                WRITE_SIGNATURE_HEADER,
                HeaderValue::from_str(&"a".repeat(128)).expect("signature header"),
            );
            headers.insert(
                CONTEXT_PACKET_APPROVAL_SIGNATURE_HEADER,
                HeaderValue::from_str(&"b".repeat(128)).expect("approval signature header"),
            );
            headers.insert(
                CONTEXT_PACKET_APPROVAL_DID_HEADER,
                HeaderValue::from_static("did:exo:context-authority"),
            );
            let response = gated_context_packet_handler(
                &ctx,
                &headers,
                context_packet_request("missing-context-approval-timestamp"),
            )
            .await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "context_packet_approval_timestamp_required",
            )
            .await;
        }

        #[tokio::test]
        async fn gateway_context_packet_record_reaches_durable_persistence_layer() {
            let keypair = KeyPair::generate();
            let authority_keypair = KeyPair::generate();
            let authority_did = "did:exo:context-authority";
            let request = context_packet_request("context-d5-persist");
            let selected_ref = selected_context_ref();
            let persistent = persistent_context_packet(vec![selected_ref]);
            let response = context_packet_response_from_persistent(&request, &persistent)
                .expect("persistent context response");
            let proposed = context_packet_candidate_from_response(&request, &response)
                .expect("context packet proposed record");
            let approval_payload_hash_hex = canonical_context_packet_approval_payload_hash(
                &proposed,
                &request.requesting_agent_did,
                &proposed.idempotency_key,
                authority_did,
                CONTEXT_PACKET_FINALITY_PURPOSE,
                fixed_approval_timestamp(),
            )
            .expect("context approval hash");
            let approval_payload_hash: [u8; 32] = hex::decode(&approval_payload_hash_hex)
                .expect("approval hash hex")
                .try_into()
                .expect("approval hash bytes");
            let approval_signature = sign_write_payload(&authority_keypair, &approval_payload_hash)
                .expect("context approval signature");
            let record = context_packet_record_from_response(
                &request,
                &response,
                authority_did,
                &approval_signature,
                fixed_approval_timestamp(),
                &approval_payload_hash_hex,
            )
            .expect("context packet record");
            let signature = sign_write_payload(
                &keypair,
                &context_packet_record_payload_hash(&record).expect("context record payload hash"),
            )
            .expect("context packet signature");
            let service = consented_service_for_agent_and_authority(
                &keypair,
                &authority_keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
                authority_did,
            );
            assert!(
                validate_gateway_approval_payload(
                    &service,
                    &request.requesting_agent_did,
                    authority_did,
                    &approval_payload_hash,
                    &approval_signature,
                )
                .is_ok(),
                "context packet external approval should verify"
            );
            let invariant_context =
                service.dagdb_invariant_context(&request.tenant_id, &request.requesting_agent_did);
            let error = service
                .persist_context_packet_record(
                    &record,
                    &request.requesting_agent_did,
                    &signature,
                    invariant_context.as_ref(),
                )
                .await
                .expect_err("unreachable pool fails at context packet DB layer");
            let handler_error = DagDbHandlerError::from_gatekeeper(error);
            assert_eq!(handler_error.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(handler_error.error_code(), "database_unavailable");
        }

        #[tokio::test]
        async fn context_packet_finality_rejects_registered_non_authority_before_persistence() {
            let keypair = KeyPair::generate();
            let registered_non_authority_keypair = KeyPair::generate();
            let registered_non_authority_did = "did:exo:registered-context-non-authority";
            let request = context_packet_request("context-non-authority-finality");
            let selected_ref = selected_context_ref();
            let persistent = persistent_context_packet(vec![selected_ref]);
            let response = context_packet_response_from_persistent(&request, &persistent)
                .expect("persistent context response");
            let proposed = context_packet_candidate_from_response(&request, &response)
                .expect("context packet proposed record");
            let approval_payload_hash =
                context_packet_record_payload_hash(&proposed).expect("context approval hash");
            let approval_signature =
                sign_write_payload(&registered_non_authority_keypair, &approval_payload_hash)
                    .expect("registered non-authority context approval signature");
            let service = consented_service_for_agent_and_registered_did(
                &keypair,
                &registered_non_authority_keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
                registered_non_authority_did,
            );

            let error = validate_gateway_approval_payload(
                &service,
                &request.requesting_agent_did,
                registered_non_authority_did,
                &approval_payload_hash,
                &approval_signature,
            )
            .expect_err("registered non-authority context approval must fail before persistence");

            assert_eq!(error.status(), StatusCode::FORBIDDEN);
            assert_eq!(error.error_code(), "approval_denied");
        }

        #[tokio::test]
        async fn writeback_handler_requires_d5_lifecycle_signature_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let mut headers = authorized_headers("dagdb:writeback");
            headers.insert(WRITE_SIGNATURE_HEADER, HeaderValue::from_static("00"));
            let response = writeback_handler(&ctx, &headers, fixture_writeback_request()).await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "lifecycle_signature_required",
            )
            .await;
        }

        #[tokio::test]
        async fn writeback_handler_requires_d5_continuation_signature_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let mut headers = authorized_headers("dagdb:writeback");
            headers.insert(WRITE_SIGNATURE_HEADER, HeaderValue::from_static("00"));
            headers.insert(LIFECYCLE_SIGNATURE_HEADER, HeaderValue::from_static("00"));
            let response = writeback_handler(&ctx, &headers, fixture_writeback_request()).await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "continuation_signature_required",
            )
            .await;
        }

        #[tokio::test]
        async fn writeback_handler_requires_lifecycle_approval_timestamp_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let mut headers = authorized_headers("dagdb:writeback");
            headers.insert(WRITE_SIGNATURE_HEADER, HeaderValue::from_static("00"));
            headers.insert(LIFECYCLE_SIGNATURE_HEADER, HeaderValue::from_static("00"));
            headers.insert(
                CONTINUATION_SIGNATURE_HEADER,
                HeaderValue::from_static("00"),
            );
            headers.insert(
                LIFECYCLE_APPROVAL_DID_HEADER,
                HeaderValue::from_static("did:exo:finality-authority"),
            );
            headers.insert(
                CONTINUATION_APPROVAL_DID_HEADER,
                HeaderValue::from_static("did:exo:finality-authority"),
            );
            let response = writeback_handler(&ctx, &headers, fixture_writeback_request()).await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "lifecycle_approval_timestamp_required",
            )
            .await;
        }

        #[tokio::test]
        async fn writeback_handler_requires_continuation_approval_timestamp_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let mut headers = authorized_headers("dagdb:writeback");
            headers.insert(WRITE_SIGNATURE_HEADER, HeaderValue::from_static("00"));
            headers.insert(LIFECYCLE_SIGNATURE_HEADER, HeaderValue::from_static("00"));
            headers.insert(
                CONTINUATION_SIGNATURE_HEADER,
                HeaderValue::from_static("00"),
            );
            headers.insert(
                LIFECYCLE_APPROVAL_DID_HEADER,
                HeaderValue::from_static("did:exo:finality-authority"),
            );
            headers.insert(
                CONTINUATION_APPROVAL_DID_HEADER,
                HeaderValue::from_static("did:exo:finality-authority"),
            );
            headers.insert(
                LIFECYCLE_APPROVAL_TIMESTAMP_HEADER,
                HeaderValue::from_static("2026-06-20T00:00:00Z"),
            );
            let response = writeback_handler(&ctx, &headers, fixture_writeback_request()).await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "continuation_approval_timestamp_required",
            )
            .await;
        }

        #[tokio::test]
        async fn gateway_writeback_lifecycle_and_continuation_records_reach_db_layer() {
            let keypair = KeyPair::generate();
            let authority_keypair = KeyPair::generate();
            let request = fixture_writeback_request();
            let pool = PgPoolOptions::new()
                .acquire_timeout(Duration::from_millis(50))
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            let selection = fixture_writeback_selection_response(&request);
            let lifecycle_base =
                lifecycle_action_from_writeback(&request).expect("lifecycle action");
            let continuation_base =
                continuation_record_from_writeback(&request).expect("continuation record");
            assert_eq!(
                lifecycle_base.terminal_state,
                LifecycleTerminalState::OperatorDeferred
            );
            assert_eq!(
                lifecycle_base.production_lifecycle_approval,
                ProductionLifecycleApproval::OperatorDeferred
            );
            assert_eq!(
                continuation_base.production_lifecycle_approval,
                ProductionLifecycleApproval::OperatorDeferred
            );
            let (_, lifecycle_signature, continuation_signature) = writeback_preflight_signatures(
                &keypair,
                &authority_keypair,
                &selection,
                &lifecycle_base,
                &continuation_base,
                fixed_lifecycle_approval_timestamp(),
                fixed_continuation_approval_timestamp(),
            );

            let lifecycle = lifecycle_action_finalization_from_writeback(
                &request,
                lifecycle_base,
                &lifecycle_signature,
                "did:exo:finality-authority",
                fixed_lifecycle_approval_timestamp(),
            )
            .expect("lifecycle action");
            let accepted_lifecycle = lifecycle
                .base
                .approved_with_evidence(&lifecycle.approval)
                .expect("accepted lifecycle");
            assert_eq!(
                accepted_lifecycle.terminal_state,
                LifecycleTerminalState::Accepted
            );
            assert_eq!(
                accepted_lifecycle.production_lifecycle_approval,
                ProductionLifecycleApproval::Approved
            );
            let lifecycle_error =
                exo_dag_db_postgres::postgres::lifecycle_action::persist_approved_lifecycle_action(
                    &pool,
                    &lifecycle.base,
                    &lifecycle.approval,
                )
                .await
                .expect_err("unreachable pool fails at lifecycle DB layer");
            let lifecycle_handler_error =
                DagDbHandlerError::from_d5_postgres("lifecycle action", &lifecycle_error);
            assert_eq!(
                lifecycle_handler_error.status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(lifecycle_handler_error.error_code(), "database_unavailable");

            let continuation = continuation_record_finalization_from_writeback(
                &request,
                continuation_base,
                &continuation_signature,
                "did:exo:finality-authority",
                fixed_continuation_approval_timestamp(),
            )
            .expect("continuation record");
            let accepted_continuation = continuation
                .base
                .approved_with_evidence(&continuation.approval, 1)
                .expect("accepted continuation");
            assert_eq!(
                accepted_continuation.production_lifecycle_approval,
                ProductionLifecycleApproval::Approved
            );
            let continuation_error = exo_dag_db_postgres::postgres::continuation_persistence::persist_approved_continuation_record(
                    &pool,
                    &continuation.base,
                    &continuation.approval,
                    1,
                )
                .await
                .expect_err("unreachable pool fails at continuation DB layer");
            let continuation_handler_error =
                DagDbHandlerError::from_d5_postgres("continuation", &continuation_error);
            assert_eq!(
                continuation_handler_error.status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(
                continuation_handler_error.error_code(),
                "database_unavailable"
            );
        }

        #[tokio::test]
        async fn writeback_d5_preflight_rejects_bad_lifecycle_signature_before_persistence() {
            let keypair = KeyPair::generate();
            let authority_keypair = KeyPair::generate();
            let request = fixture_writeback_request();
            let service = consented_service_for_agent_and_authority(
                &keypair,
                &authority_keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
                "did:exo:finality-authority",
            );
            let selection = fixture_writeback_selection_response(&request);
            let lifecycle = lifecycle_action_from_writeback(&request).expect("lifecycle action");
            let continuation =
                continuation_record_from_writeback(&request).expect("continuation record");
            let (writeback_signature, _, continuation_signature) = writeback_preflight_signatures(
                &keypair,
                &authority_keypair,
                &selection,
                &lifecycle,
                &continuation,
                fixed_lifecycle_approval_timestamp(),
                fixed_continuation_approval_timestamp(),
            );

            let error = prevalidate_writeback_d5_gates(
                &service,
                &selection,
                &request.requesting_agent_did,
                &lifecycle,
                &continuation,
                &writeback_signature,
                &"00".repeat(64),
                &continuation_signature,
                "did:exo:finality-authority",
                "did:exo:finality-authority",
                fixed_lifecycle_approval_timestamp(),
                fixed_continuation_approval_timestamp(),
                None,
            )
            .expect_err("forged lifecycle signature must fail in preflight");

            assert_eq!(error.status(), StatusCode::FORBIDDEN);
            assert_eq!(error.error_code(), "approval_denied");
        }

        #[tokio::test]
        async fn writeback_d5_preflight_rejects_lifecycle_signature_not_bound_to_approval_timestamp()
         {
            let keypair = KeyPair::generate();
            let authority_keypair = KeyPair::generate();
            let request = fixture_writeback_request();
            let service = consented_service_for_agent_and_authority(
                &keypair,
                &authority_keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
                "did:exo:finality-authority",
            );
            let selection = fixture_writeback_selection_response(&request);
            let lifecycle = lifecycle_action_from_writeback(&request).expect("lifecycle action");
            let continuation =
                continuation_record_from_writeback(&request).expect("continuation record");
            let (writeback_signature, lifecycle_signature, continuation_signature) =
                writeback_base_record_signatures(
                    &keypair,
                    &authority_keypair,
                    &selection,
                    &lifecycle,
                    &continuation,
                );

            let error = prevalidate_writeback_d5_gates(
                &service,
                &selection,
                &request.requesting_agent_did,
                &lifecycle,
                &continuation,
                &writeback_signature,
                &lifecycle_signature,
                &continuation_signature,
                "did:exo:finality-authority",
                "did:exo:finality-authority",
                fixed_lifecycle_approval_timestamp(),
                fixed_continuation_approval_timestamp(),
                None,
            )
            .expect_err("lifecycle finality signature must bind approval timestamp");

            assert_eq!(error.status(), StatusCode::FORBIDDEN);
            assert_eq!(error.error_code(), "approval_denied");
        }

        #[tokio::test]
        async fn writeback_d5_preflight_rejects_lifecycle_signature_when_approval_timestamp_changes()
         {
            let keypair = KeyPair::generate();
            let authority_keypair = KeyPair::generate();
            let request = fixture_writeback_request();
            let service = consented_service_for_agent_and_authority(
                &keypair,
                &authority_keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
                "did:exo:finality-authority",
            );
            let selection = fixture_writeback_selection_response(&request);
            let lifecycle = lifecycle_action_from_writeback(&request).expect("lifecycle action");
            let continuation =
                continuation_record_from_writeback(&request).expect("continuation record");
            let (writeback_signature, lifecycle_signature, continuation_signature) =
                writeback_preflight_signatures(
                    &keypair,
                    &authority_keypair,
                    &selection,
                    &lifecycle,
                    &continuation,
                    fixed_lifecycle_approval_timestamp(),
                    fixed_continuation_approval_timestamp(),
                );

            let error = prevalidate_writeback_d5_gates(
                &service,
                &selection,
                &request.requesting_agent_did,
                &lifecycle,
                &continuation,
                &writeback_signature,
                &lifecycle_signature,
                &continuation_signature,
                "did:exo:finality-authority",
                "did:exo:finality-authority",
                "2026-06-20T00:05:00Z",
                fixed_continuation_approval_timestamp(),
                None,
            )
            .expect_err("lifecycle finality signature must bind exact approval timestamp");

            assert_eq!(error.status(), StatusCode::FORBIDDEN);
            assert_eq!(error.error_code(), "approval_denied");
        }

        #[tokio::test]
        async fn writeback_d5_preflight_rejects_bad_continuation_signature_before_persistence() {
            let keypair = KeyPair::generate();
            let authority_keypair = KeyPair::generate();
            let request = fixture_writeback_request();
            let service = consented_service_for_agent_and_authority(
                &keypair,
                &authority_keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
                "did:exo:finality-authority",
            );
            let selection = fixture_writeback_selection_response(&request);
            let lifecycle = lifecycle_action_from_writeback(&request).expect("lifecycle action");
            let continuation =
                continuation_record_from_writeback(&request).expect("continuation record");
            let (writeback_signature, lifecycle_signature, _) = writeback_preflight_signatures(
                &keypair,
                &authority_keypair,
                &selection,
                &lifecycle,
                &continuation,
                fixed_lifecycle_approval_timestamp(),
                fixed_continuation_approval_timestamp(),
            );

            let error = prevalidate_writeback_d5_gates(
                &service,
                &selection,
                &request.requesting_agent_did,
                &lifecycle,
                &continuation,
                &writeback_signature,
                &lifecycle_signature,
                &"00".repeat(64),
                "did:exo:finality-authority",
                "did:exo:finality-authority",
                fixed_lifecycle_approval_timestamp(),
                fixed_continuation_approval_timestamp(),
                None,
            )
            .expect_err("forged continuation signature must fail in preflight");

            assert_eq!(error.status(), StatusCode::FORBIDDEN);
            assert_eq!(error.error_code(), "approval_denied");
        }

        #[tokio::test]
        async fn writeback_d5_preflight_rejects_continuation_signature_not_bound_to_approval_timestamp()
         {
            let keypair = KeyPair::generate();
            let authority_keypair = KeyPair::generate();
            let request = fixture_writeback_request();
            let service = consented_service_for_agent_and_authority(
                &keypair,
                &authority_keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
                "did:exo:finality-authority",
            );
            let selection = fixture_writeback_selection_response(&request);
            let lifecycle = lifecycle_action_from_writeback(&request).expect("lifecycle action");
            let continuation =
                continuation_record_from_writeback(&request).expect("continuation record");
            let (writeback_signature, lifecycle_signature, continuation_signature) =
                writeback_base_record_signatures(
                    &keypair,
                    &authority_keypair,
                    &selection,
                    &lifecycle,
                    &continuation,
                );

            let error = prevalidate_writeback_d5_gates(
                &service,
                &selection,
                &request.requesting_agent_did,
                &lifecycle,
                &continuation,
                &writeback_signature,
                &lifecycle_signature,
                &continuation_signature,
                "did:exo:finality-authority",
                "did:exo:finality-authority",
                fixed_lifecycle_approval_timestamp(),
                fixed_continuation_approval_timestamp(),
                None,
            )
            .expect_err("continuation finality signature must bind approval timestamp");

            assert_eq!(error.status(), StatusCode::FORBIDDEN);
            assert_eq!(error.error_code(), "approval_denied");
        }

        #[tokio::test]
        async fn writeback_d5_preflight_rejects_continuation_signature_when_approval_timestamp_changes()
         {
            let keypair = KeyPair::generate();
            let authority_keypair = KeyPair::generate();
            let request = fixture_writeback_request();
            let service = consented_service_for_agent_and_authority(
                &keypair,
                &authority_keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
                "did:exo:finality-authority",
            );
            let selection = fixture_writeback_selection_response(&request);
            let lifecycle = lifecycle_action_from_writeback(&request).expect("lifecycle action");
            let continuation =
                continuation_record_from_writeback(&request).expect("continuation record");
            let (writeback_signature, lifecycle_signature, continuation_signature) =
                writeback_preflight_signatures(
                    &keypair,
                    &authority_keypair,
                    &selection,
                    &lifecycle,
                    &continuation,
                    fixed_lifecycle_approval_timestamp(),
                    fixed_continuation_approval_timestamp(),
                );

            let error = prevalidate_writeback_d5_gates(
                &service,
                &selection,
                &request.requesting_agent_did,
                &lifecycle,
                &continuation,
                &writeback_signature,
                &lifecycle_signature,
                &continuation_signature,
                "did:exo:finality-authority",
                "did:exo:finality-authority",
                fixed_lifecycle_approval_timestamp(),
                "2026-06-20T00:05:01Z",
                None,
            )
            .expect_err("continuation finality signature must bind exact approval timestamp");

            assert_eq!(error.status(), StatusCode::FORBIDDEN);
            assert_eq!(error.error_code(), "approval_denied");
        }

        #[tokio::test]
        async fn writeback_d5_preflight_rejects_requester_self_approval_before_persistence() {
            let keypair = KeyPair::generate();
            let request = fixture_writeback_request();
            let service = consented_service_for_agent(
                &keypair,
                &request.tenant_id,
                &request.requesting_agent_did,
            );
            let selection = fixture_writeback_selection_response(&request);
            let lifecycle = lifecycle_action_from_writeback(&request).expect("lifecycle action");
            let continuation =
                continuation_record_from_writeback(&request).expect("continuation record");
            let (writeback_signature, lifecycle_signature, continuation_signature) =
                writeback_preflight_signatures(
                    &keypair,
                    &keypair,
                    &selection,
                    &lifecycle,
                    &continuation,
                    fixed_lifecycle_approval_timestamp(),
                    fixed_continuation_approval_timestamp(),
                );

            let error = prevalidate_writeback_d5_gates(
                &service,
                &selection,
                &request.requesting_agent_did,
                &lifecycle,
                &continuation,
                &writeback_signature,
                &lifecycle_signature,
                &continuation_signature,
                &request.requesting_agent_did,
                &request.requesting_agent_did,
                fixed_lifecycle_approval_timestamp(),
                fixed_continuation_approval_timestamp(),
                None,
            )
            .expect_err("requester self-approval must fail in preflight");

            assert_eq!(error.status(), StatusCode::FORBIDDEN);
            assert_eq!(error.error_code(), "approval_denied");
        }

        #[tokio::test]
        async fn import_handler_requires_write_signature_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let response =
                import_handler(&ctx, &authorized_headers("dagdb:import"), import_request()).await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "write_signature_required",
            )
            .await;
        }

        #[tokio::test]
        async fn export_handler_requires_write_signature_when_pool_present() {
            let pool = unreachable_lazy_pool();
            let ctx = DagDbRouteContext::from_pool(Some(pool));
            let response =
                export_handler(&ctx, &authorized_headers("dagdb:export"), export_request()).await;
            assert_error_response(
                response,
                StatusCode::BAD_REQUEST,
                "write_signature_required",
            )
            .await;
        }

        #[test]
        fn import_adapter_failures_are_classified_without_collapsing_runtime_errors() {
            let validation = KgImportPersistenceError::Report(KgImportError::InvalidReport {
                reason: "bad shape".to_owned(),
            });
            assert_eq!(
                import_adapter_failure(&validation),
                AdapterFailure {
                    status: StatusCode::BAD_REQUEST,
                    error_code: "import_rejected",
                    class: "validation",
                    message: "DAG DB import request was rejected by the import adapter",
                }
            );

            let postgres = KgImportPersistenceError::Postgres {
                source: sqlx::Error::RowNotFound,
            };
            assert_eq!(
                import_adapter_failure(&postgres),
                AdapterFailure {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    error_code: "database_unavailable",
                    class: "postgres",
                    message: "DAG DB import adapter is temporarily unavailable",
                }
            );

            let conflict = KgImportPersistenceError::Conflict {
                reason: "existing row differs".to_owned(),
            };
            assert_eq!(import_adapter_failure(&conflict).class, "conflict");

            let unsupported = KgImportPersistenceError::UnsupportedSection {
                section: "raw_artifact".to_owned(),
            };
            assert_eq!(import_adapter_failure(&unsupported).class, "unsupported");
        }

        #[test]
        fn export_adapter_failures_are_classified_without_collapsing_runtime_errors() {
            let validation = KgExportError::ImportHash(KgImportError::InvalidHash {
                field: "memory_id".to_owned(),
            });
            assert_eq!(
                export_adapter_failure(&validation),
                AdapterFailure {
                    status: StatusCode::BAD_REQUEST,
                    error_code: "export_rejected",
                    class: "validation",
                    message: "DAG DB export request was rejected by the export adapter",
                }
            );

            let postgres = KgExportError::Postgres {
                source: Box::new(sqlx::Error::RowNotFound),
            };
            assert_eq!(
                export_adapter_failure(&postgres),
                AdapterFailure {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    error_code: "database_unavailable",
                    class: "postgres",
                    message: "DAG DB export adapter is temporarily unavailable",
                }
            );

            let conflict = KgExportError::Conflict {
                reason: "stored export differs".to_owned(),
            };
            assert_eq!(export_adapter_failure(&conflict).class, "conflict");

            let incompatible_cached = KgExportError::IncompatibleCachedResponse {
                route_name: "dagdb.kg_export.persisted.v1".to_owned(),
                reason: "cached schema_version mismatch".to_owned(),
            };
            assert_eq!(
                export_adapter_failure(&incompatible_cached),
                AdapterFailure {
                    status: StatusCode::CONFLICT,
                    error_code: "export_rejected",
                    class: "conflict",
                    message: "DAG DB export request conflicted with existing adapter state",
                }
            );

            let unsupported = KgExportError::UnsupportedPersistenceTarget {
                target: "raw_artifact".to_owned(),
            };
            assert_eq!(export_adapter_failure(&unsupported).class, "unsupported");
        }

        #[tokio::test]
        async fn adapter_error_responses_keep_validation_400_and_runtime_503() {
            assert_error_response(
                dagdb_import_adapter_error_response(
                    &import_request(),
                    &KgImportPersistenceError::Report(KgImportError::InvalidJson {
                        reason: "json".to_owned(),
                    }),
                ),
                StatusCode::BAD_REQUEST,
                "import_rejected",
            )
            .await;
            assert_error_response(
                dagdb_import_adapter_error_response(
                    &import_request(),
                    &KgImportPersistenceError::Postgres {
                        source: sqlx::Error::RowNotFound,
                    },
                ),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
            )
            .await;
            assert_error_response(
                dagdb_export_adapter_error_response(
                    &export_request(),
                    &KgExportError::InvalidScope {
                        reason: "scope".to_owned(),
                    },
                ),
                StatusCode::BAD_REQUEST,
                "export_rejected",
            )
            .await;
            assert_error_response(
                dagdb_export_adapter_error_response(
                    &export_request(),
                    &KgExportError::Postgres {
                        source: Box::new(sqlx::Error::RowNotFound),
                    },
                ),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
            )
            .await;
        }

        #[tokio::test]
        async fn dagdb_handler_error_mappings_cover_domain_gatekeeper_and_response_paths() {
            let scope_error = DagDbHandlerError::from_domain(DomainError::TenantScopeMismatch {
                expected_tenant_id: "tenant-a".to_owned(),
                expected_namespace: "primary".to_owned(),
                actual_tenant_id: "tenant-b".to_owned(),
                actual_namespace: "primary".to_owned(),
            });
            assert_eq!(scope_error.status(), StatusCode::FORBIDDEN);
            assert_eq!(scope_error.error_code(), "tenant_scope_mismatch");

            let metadata_error = exo_dag_db_core::metadata::sanitize_runtime_metadata(
                exo_dag_db_core::metadata::MetadataField::Summary,
                "fn raw_payload() {}",
            )
            .expect_err("metadata rejected");
            let metadata_error =
                DagDbHandlerError::from_domain(DomainError::Metadata(metadata_error));
            assert_eq!(metadata_error.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(metadata_error.error_code(), "metadata_rejected");

            let db_error = DagDbHandlerError::from_domain(DomainError::HashMaterial {
                reason: "postgres unavailable".to_owned(),
            });
            assert_eq!(db_error.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(db_error.error_code(), "database_unavailable");

            let validation_error = DagDbHandlerError::from_domain(DomainError::ValidationFailed);
            assert_eq!(validation_error.status(), StatusCode::BAD_REQUEST);
            assert_eq!(validation_error.error_code(), "invalid_request_shape");

            let consent_error = DagDbHandlerError::from_gatekeeper(
                GatekeeperError::InvariantViolation("ConsentRequired".to_owned()),
            );
            assert_eq!(consent_error.status(), StatusCode::FORBIDDEN);
            assert_eq!(consent_error.error_code(), "consent_denied");
            assert_eq!(consent_error.class(), "consent");

            let provenance_error = DagDbHandlerError::from_gatekeeper(
                GatekeeperError::InvariantViolation("ProvenanceVerifiable".to_owned()),
            );
            assert_eq!(provenance_error.status(), StatusCode::FORBIDDEN);
            assert_eq!(provenance_error.error_code(), "provenance_denied");
            assert_eq!(provenance_error.class(), "provenance");

            let gatekeeper_db_error =
                DagDbHandlerError::from_gatekeeper(GatekeeperError::InvariantViolation(
                    "dagdb write blocked: hash_material_failed: graph_context_selection_write_postgres: connection refused".to_owned(),
                ));
            assert_eq!(
                gatekeeper_db_error.status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(gatekeeper_db_error.error_code(), "database_unavailable");
            assert_eq!(gatekeeper_db_error.class(), "database");

            let denied_error = DagDbHandlerError::from_gatekeeper(
                GatekeeperError::InvariantViolation("writeback denied".to_owned()),
            );
            assert_eq!(denied_error.status(), StatusCode::FORBIDDEN);
            assert_eq!(denied_error.error_code(), "writeback_denied");
            assert_eq!(denied_error.class(), "invariant");

            let core_error =
                DagDbHandlerError::from_gatekeeper(GatekeeperError::Core("raw secret".to_owned()));
            assert_eq!(core_error.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(core_error.error_code(), "database_unavailable");
            assert_eq!(core_error.class(), "runtime");

            let tee_error =
                DagDbHandlerError::from_gatekeeper(GatekeeperError::TeeError("raw tee".to_owned()));
            assert_eq!(tee_error.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(tee_error.error_code(), "database_unavailable");
            assert_eq!(tee_error.class(), "runtime");
            assert_error_response_shape(
                tee_error.into_response(),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB database operation failed",
                false,
            )
            .await;

            let metadata_response = dagdb_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "metadata_rejected",
                "metadata rejected",
                true,
            );
            let response_error = DagDbHandlerError::from_response(metadata_response);
            assert_eq!(response_error.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(response_error.error_code(), "metadata_rejected");

            let shape_response = dagdb_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_shape",
                "invalid request",
                false,
            );
            let shape_error = DagDbHandlerError::from_response(shape_response);
            assert_eq!(shape_error.status(), StatusCode::BAD_REQUEST);
            assert_eq!(shape_error.error_code(), "invalid_request_shape");
        }

        #[tokio::test]
        async fn gatekeeper_responses_use_static_sanitized_messages() {
            let raw_did = "did:exo:raw-requester";
            let raw_reason = "raw actor text and database internals";
            let consent = DagDbHandlerError::from_gatekeeper(GatekeeperError::InvariantViolation(
                format!("ConsentRequired: tenant=tenant-a actor={raw_did} reason={raw_reason}"),
            ));
            assert_error_response_shape(
                consent.into_response(),
                StatusCode::FORBIDDEN,
                "consent_denied",
                "DAG DB writeback consent was denied",
                true,
            )
            .await;

            let provenance =
                DagDbHandlerError::from_gatekeeper(GatekeeperError::InvariantViolation(format!(
                    "ProvenanceVerifiable: tenant=tenant-a actor={raw_did} reason={raw_reason}"
                )));
            assert_error_response_shape(
                provenance.into_response(),
                StatusCode::FORBIDDEN,
                "provenance_denied",
                "DAG DB writeback provenance could not be verified",
                true,
            )
            .await;

            let denied = DagDbHandlerError::from_gatekeeper(GatekeeperError::CapabilityDenied(
                format!("actor={raw_did} reason={raw_reason}"),
            ));
            let response = denied.into_response();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body bytes");
            let body = String::from_utf8(bytes.to_vec()).expect("utf8 body");
            let envelope: exo_api::dagdb::DagDbErrorEnvelope =
                serde_json::from_str(&body).expect("DAG DB error envelope");
            assert_eq!(envelope.error_code, "writeback_denied");
            assert_eq!(envelope.message, "DAG DB writeback was denied");
            assert!(!body.contains(raw_did));
            assert!(!body.contains(raw_reason));
        }

        #[tokio::test]
        async fn gatekeeper_runtime_database_failures_map_to_503() {
            let raw_db_error = "password authentication failed for user did:exo:raw-db-user";
            let db_error = DagDbHandlerError::from_gatekeeper(GatekeeperError::InvariantViolation(
                format!(
                    "dagdb write blocked: hash_material_failed: graph_context_selection_write_postgres: {raw_db_error}"
                ),
            ));
            assert_error_response_shape(
                db_error.into_response(),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB database operation failed",
                false,
            )
            .await;

            let timeout = DagDbHandlerError::from_gatekeeper(GatekeeperError::Timeout(500));
            assert_error_response_shape(
                timeout.into_response(),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB database operation failed",
                false,
            )
            .await;
        }

        #[test]
        fn gatekeeper_database_failure_classifier_requires_dagdb_database_context() {
            assert!(is_gatekeeper_database_failure(
                "dagdb write blocked: hash_material_failed"
            ));
            assert!(is_gatekeeper_database_failure(
                "dagdb write blocked: graph_context_selection_write_postgres"
            ));
            assert!(!is_gatekeeper_database_failure("hash_material_failed"));
            assert!(!is_gatekeeper_database_failure(
                "dagdb write blocked: consent denied"
            ));
            // PRD-D5: the four lifecycle/persistence surfaces classify a backing
            // transaction outage as 503 via this marker, while a contract reject
            // (carrying the `metadata rejected` marker, mapped to 422 earlier in
            // GatekeeperFailure::from_error) is not a database failure here.
            assert!(is_gatekeeper_database_failure(
                "dagdb write blocked: surface_database_unavailable surface=lifecycle_action_postgres detail=prd17_lifecycle_postgres_failed"
            ));
            assert!(!is_gatekeeper_database_failure(
                "dagdb write blocked: metadata rejected surface=context_packet_record_postgres detail=context_packet_unsafe_replay: packet-d5-001"
            ));
        }

        #[test]
        fn runtime_import_export_request_hashes_are_deterministic_and_scope_sensitive() {
            let import = import_request();
            let import_hash =
                import_route_request_hash(&import).expect("first import request hash");
            assert_eq!(
                import_hash,
                import_route_request_hash(&import).expect("second import request hash")
            );
            let changed_import_hash = import_route_request_hash(&DagDbImportRequest {
                idempotency_key: "idem-import-2".to_owned(),
                ..import
            })
            .expect("changed import request hash");
            assert_ne!(import_hash, changed_import_hash);

            let export = export_request();
            let export_hash =
                export_route_request_hash(&export).expect("first export request hash");
            assert_eq!(
                export_hash,
                export_route_request_hash(&export).expect("second export request hash")
            );
            let changed_export_hash = export_route_request_hash(&DagDbExportRequest {
                include_preview_context: true,
                ..export
            })
            .expect("changed export request hash");
            assert_ne!(export_hash, changed_export_hash);
        }

        #[test]
        fn import_finality_payload_binds_import_report_body() {
            let import = import_request();
            let authorization_hash = Hash256::digest(b"import authorization payload");
            let finality_hash = import_finality_payload_hash(
                &import,
                authorization_hash,
                "did:exo:import-finality-authority",
                "2026-06-20T00:00:00Z",
            )
            .unwrap_or_else(|_| panic!("import finality hash"));

            let mut mutated = import;
            mutated.import_report["warnings"] = json!(["mutated-import-report-body"]);
            let mutated_hash = import_finality_payload_hash(
                &mutated,
                authorization_hash,
                "did:exo:import-finality-authority",
                "2026-06-20T00:00:00Z",
            )
            .unwrap_or_else(|_| panic!("mutated import finality hash"));

            assert_ne!(
                finality_hash, mutated_hash,
                "import finality signatures must bind the canonical import_report body, not only source_hash"
            );
        }

        #[test]
        fn idempotency_response_hash_uses_canonical_cbor_deterministically() {
            let left = json!({
                "route_name": "dagdb.import",
                "idempotency_status": RESERVED_IDEMPOTENCY_BODY_STATUS,
            });
            let mut right_fields = serde_json::Map::new();
            right_fields.insert(
                "idempotency_status".to_owned(),
                json!(RESERVED_IDEMPOTENCY_BODY_STATUS),
            );
            right_fields.insert("route_name".to_owned(), json!("dagdb.import"));
            let right = Value::Object(right_fields);

            let left_hash = gateway_idempotency_response_hash(
                &left,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                "reserve",
                "import",
                "tenant-a",
                "primary",
                "idem-response-1",
            )
            .expect("left response hash");
            let right_hash = gateway_idempotency_response_hash(
                &right,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                "reserve",
                "import",
                "tenant-a",
                "primary",
                "idem-response-1",
            )
            .expect("right response hash");
            assert_eq!(left_hash, right_hash);

            let changed = json!({
                "route_name": "dagdb.export",
                "idempotency_status": RESERVED_IDEMPOTENCY_BODY_STATUS,
            });
            let changed_hash = gateway_idempotency_response_hash(
                &changed,
                EXPORT_ROUTE_IDEMPOTENCY_NAME,
                "reserve",
                "export",
                "tenant-a",
                "primary",
                "idem-response-1",
            )
            .expect("changed response hash");
            assert_ne!(left_hash, changed_hash);
        }

        #[tokio::test]
        async fn idempotency_response_hash_encoding_failure_fails_closed() {
            let response = gateway_idempotency_response_hash(
                &FailingSerialize,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                "store",
                "import",
                "tenant-a",
                "primary",
                "idem-response-fail",
            )
            .expect_err("response hash encoding failure");
            assert_error_response_shape(
                *response,
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB import idempotency guard could not be checked",
                false,
            )
            .await;
        }

        #[test]
        fn production_response_hash_paths_do_not_hash_json_text() {
            let source = include_str!("dagdb.rs");
            let forbidden_patterns = [
                ["response_body", ".to_string()", ".as_bytes()"].concat(),
                ["Hash256::digest(", "response_body", ".to_string"].concat(),
            ];
            for forbidden in forbidden_patterns {
                assert!(
                    !source.contains(&forbidden),
                    "production response hash path must use canonical CBOR, found {forbidden}"
                );
            }
        }

        #[tokio::test]
        async fn idempotency_error_helpers_return_stable_envelopes() {
            assert_error_response_shape(
                *idempotency_conflict_response("import"),
                StatusCode::CONFLICT,
                "idempotency_key_conflict",
                "DAG DB import idempotency key was already used with a different request body",
                false,
            )
            .await;
            assert_error_response_shape(
                *idempotency_in_progress_response("export"),
                StatusCode::CONFLICT,
                "idempotency_key_in_progress",
                "DAG DB export idempotency key is currently being processed",
                false,
            )
            .await;
            assert_error_response_shape(
                *idempotency_unavailable_response("import"),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB import idempotency guard could not be checked",
                false,
            )
            .await;
        }

        #[tokio::test]
        async fn malformed_idempotency_row_hash_fails_closed() {
            let hash = Hash256::digest(b"row hash");
            assert_eq!(
                hash_from_idempotency_row(hash.as_bytes().to_vec(), "import")
                    .expect("valid row hash"),
                hash
            );
            let response =
                hash_from_idempotency_row(vec![0; 31], "export").expect_err("malformed row hash");
            assert_error_response_shape(
                *response,
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB export idempotency guard could not be checked",
                false,
            )
            .await;
        }

        #[tokio::test]
        async fn malformed_idempotency_row_status_fails_closed() {
            assert_eq!(
                status_from_idempotency_row(i32::from(StatusCode::OK.as_u16()), "import")
                    .expect("valid status"),
                StatusCode::OK
            );
            for status_code in [-1, 1000] {
                let response = status_from_idempotency_row(status_code, "export")
                    .expect_err("malformed row status");
                assert_error_response_shape(
                    *response,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "database_unavailable",
                    "DAG DB export idempotency guard could not be checked",
                    false,
                )
                .await;
            }
        }

        #[tokio::test]
        async fn cached_authorization_payload_hash_helpers_fail_closed_and_strip_private_field() {
            let payload_hash = Hash256::digest(b"cached authorization payload");
            let mut cached = json!({
                "ok": true,
                GATEWAY_AUTHORIZATION_PAYLOAD_HASH_FIELD: payload_hash.to_string(),
            });
            assert_eq!(
                gateway_authorization_payload_hash_from_cached_body(
                    IMPORT_ROUTE_IDEMPOTENCY_NAME,
                    "import",
                    "tenant-a",
                    "primary",
                    "idem-import-cache",
                    &mut cached,
                )
                .expect("cached authorization hash")
                .expect("hash is present"),
                payload_hash
            );
            assert_eq!(cached, json!({"ok": true}));

            let mut non_string = json!({
                GATEWAY_AUTHORIZATION_PAYLOAD_HASH_FIELD: true,
            });
            assert_error_response_shape(
                *gateway_authorization_payload_hash_from_cached_body(
                    IMPORT_ROUTE_IDEMPOTENCY_NAME,
                    "import",
                    "tenant-a",
                    "primary",
                    "idem-import-cache",
                    &mut non_string,
                )
                .expect_err("non-string cached authorization hash fails closed"),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB import idempotency guard could not be checked",
                false,
            )
            .await;

            let mut invalid_hex = json!({
                GATEWAY_AUTHORIZATION_PAYLOAD_HASH_FIELD: "not-hex",
            });
            assert_error_response_shape(
                *gateway_authorization_payload_hash_from_cached_body(
                    EXPORT_ROUTE_IDEMPOTENCY_NAME,
                    "export",
                    "tenant-a",
                    "primary",
                    "idem-export-cache",
                    &mut invalid_hex,
                )
                .expect_err("invalid cached authorization hash fails closed"),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB export idempotency guard could not be checked",
                false,
            )
            .await;

            let mut response_body = json!("not-an-object");
            assert_error_response_shape(
                *insert_gateway_authorization_payload_hash(
                    &mut response_body,
                    Some(payload_hash),
                    IMPORT_ROUTE_IDEMPOTENCY_NAME,
                    "import",
                    "tenant-a",
                    "primary",
                    "idem-import-cache",
                )
                .expect_err("non-object response body fails closed"),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB import idempotency guard could not be checked",
                false,
            )
            .await;
        }

        #[tokio::test]
        async fn import_export_authorization_deny_writeback_consent_and_signature() {
            let keypair = KeyPair::generate();
            let payload_hash = Hash256::digest(b"writeback-authorized import/export payload");
            let signature =
                sign_write_payload(&keypair, payload_hash.as_bytes()).expect("write signature");
            let pool = PgPoolOptions::new()
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            let service = DagDbGatekeeperService::new(
                pool.clone(),
                Arc::new(
                    ConsentEngine::default()
                        .with_bailment(
                            "tenant-a",
                            BailmentState::Active {
                                bailor: exo_core::Did::new("did:exo:bailor")
                                    .expect("valid bailor did"),
                                bailee: exo_core::Did::new("did:exo:importer")
                                    .expect("valid bailee did"),
                                scope: "dag-db:writeback".to_owned(),
                            },
                        )
                        .with_consent_record(DagDbConsentRecord {
                            tenant_id: "tenant-a".to_owned(),
                            agent_did: "did:exo:importer".to_owned(),
                            purpose: ConsentPurpose::Writeback,
                            active: true,
                        })
                        .with_consent_record(DagDbConsentRecord {
                            tenant_id: "tenant-a".to_owned(),
                            agent_did: "did:exo:exporter".to_owned(),
                            purpose: ConsentPurpose::Writeback,
                            active: true,
                        }),
                ),
                Arc::new(
                    IdentityRegistry::default()
                        .with_public_key("did:exo:importer", *keypair.public_key().as_bytes())
                        .with_public_key("did:exo:exporter", *keypair.public_key().as_bytes()),
                ),
            );

            let import_denied = gated_import_authorization(
                &service,
                &pool,
                &import_request(),
                &signature,
                false,
                Some(payload_hash),
            )
            .await
            .expect_err("writeback consent must not authorize import");
            assert_eq!(import_denied.status(), StatusCode::FORBIDDEN);
            assert_eq!(import_denied.error_code(), "consent_denied");

            let export_by_bailee = DagDbExportRequest {
                requester_did: "did:exo:importer".to_owned(),
                ..export_request()
            };
            let export_denied = gated_export_authorization(
                &service,
                &pool,
                &export_by_bailee,
                Hash256::digest(b"unread export hash"),
                &signature,
                false,
                Some(payload_hash),
            )
            .await
            .expect_err("writeback consent must not authorize export");
            assert_eq!(export_denied.status(), StatusCode::FORBIDDEN);
            assert_eq!(export_denied.error_code(), "consent_denied");

            let authorized_service = DagDbGatekeeperService::new(
                pool.clone(),
                Arc::new(
                    ConsentEngine::default()
                        .with_bailment(
                            "tenant-a",
                            BailmentState::Active {
                                bailor: exo_core::Did::new("did:exo:bailor")
                                    .expect("valid bailor did"),
                                bailee: exo_core::Did::new("did:exo:importer")
                                    .expect("valid bailee did"),
                                scope: "dag-db:writeback".to_owned(),
                            },
                        )
                        .with_consent_record(DagDbConsentRecord {
                            tenant_id: "tenant-a".to_owned(),
                            agent_did: "did:exo:importer".to_owned(),
                            purpose: ConsentPurpose::Import,
                            active: true,
                        })
                        .with_consent_record(DagDbConsentRecord {
                            tenant_id: "tenant-a".to_owned(),
                            agent_did: "did:exo:exporter".to_owned(),
                            purpose: ConsentPurpose::Export,
                            active: true,
                        }),
                ),
                Arc::new(
                    IdentityRegistry::default()
                        .with_public_key("did:exo:importer", *keypair.public_key().as_bytes())
                        .with_public_key("did:exo:exporter", *keypair.public_key().as_bytes()),
                ),
            );
            let import_authorized = gated_import_authorization(
                &authorized_service,
                &pool,
                &import_request(),
                &signature,
                false,
                Some(payload_hash),
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "distinct import consent authorizes import, got {}",
                    error.error_code()
                )
            });
            assert_eq!(import_authorized, payload_hash);

            let export_authorized = gated_export_authorization(
                &authorized_service,
                &pool,
                &export_request(),
                Hash256::digest(b"unread export hash"),
                &signature,
                false,
                Some(payload_hash),
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "distinct export consent authorizes export, got {}",
                    error.error_code()
                )
            });
            assert_eq!(export_authorized, payload_hash);
        }

        #[tokio::test]
        async fn import_export_authorization_deny_cross_purpose_consent_and_signature() {
            let keypair = KeyPair::generate();
            let payload_hash = Hash256::digest(b"cross-purpose import/export payload");
            let signature =
                sign_write_payload(&keypair, payload_hash.as_bytes()).expect("write signature");
            let pool = PgPoolOptions::new()
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            let service = DagDbGatekeeperService::new(
                pool.clone(),
                Arc::new(
                    ConsentEngine::default()
                        .with_bailment(
                            "tenant-a",
                            BailmentState::Active {
                                bailor: exo_core::Did::new("did:exo:bailor")
                                    .expect("valid bailor did"),
                                bailee: exo_core::Did::new("did:exo:importer")
                                    .expect("valid importer did"),
                                scope: "dag-db:writeback".to_owned(),
                            },
                        )
                        .with_consent_record(DagDbConsentRecord {
                            tenant_id: "tenant-a".to_owned(),
                            agent_did: "did:exo:importer".to_owned(),
                            purpose: ConsentPurpose::Import,
                            active: true,
                        })
                        .with_consent_record(DagDbConsentRecord {
                            tenant_id: "tenant-a".to_owned(),
                            agent_did: "did:exo:exporter".to_owned(),
                            purpose: ConsentPurpose::Export,
                            active: true,
                        }),
                ),
                Arc::new(
                    IdentityRegistry::default()
                        .with_public_key("did:exo:importer", *keypair.public_key().as_bytes())
                        .with_public_key("did:exo:exporter", *keypair.public_key().as_bytes()),
                ),
            );

            let export_with_import_consent = DagDbExportRequest {
                requester_did: "did:exo:importer".to_owned(),
                ..export_request()
            };
            let export_denied = gated_export_authorization(
                &service,
                &pool,
                &export_with_import_consent,
                Hash256::digest(b"unread export hash"),
                &signature,
                false,
                Some(payload_hash),
            )
            .await
            .expect_err("import consent must not authorize export");
            assert_eq!(export_denied.status(), StatusCode::FORBIDDEN);
            assert_eq!(export_denied.error_code(), "consent_denied");

            let import_with_export_consent = DagDbImportRequest {
                requester_did: "did:exo:exporter".to_owned(),
                ..import_request()
            };
            let import_denied = gated_import_authorization(
                &service,
                &pool,
                &import_with_export_consent,
                &signature,
                false,
                Some(payload_hash),
            )
            .await
            .expect_err("export consent must not authorize import");
            assert_eq!(import_denied.status(), StatusCode::FORBIDDEN);
            assert_eq!(import_denied.error_code(), "consent_denied");
        }

        #[test]
        fn dagdb_finality_requires_independent_authority() {
            let request = import_request();
            let payload_hash = Hash256::digest(b"import finality payload");
            let self_approval = import_finality_payload_hash(
                &request,
                payload_hash,
                &request.requester_did,
                "2026-06-23T00:00:00Z",
            )
            .expect_err("import self-finality must be denied");
            assert_eq!(self_approval.error_code(), "approval_denied");

            let export = export_request();
            let export_payload_hash = Hash256::digest(b"export finality payload");
            let export_self_approval = export_finality_payload_hash(
                &export,
                export_payload_hash,
                &export.requester_did,
                "2026-06-23T00:00:00Z",
            )
            .expect_err("export self-finality must be denied");
            assert_eq!(export_self_approval.error_code(), "approval_denied");

            let council = DagDbCouncilDecisionRequest {
                subject_id: "did:exo:council-self".to_owned(),
                approver_did: "did:exo:council-self".to_owned(),
                decision_status: CouncilDecisionStatus::Approved,
                ..council_decision_request()
            };
            let council_self_approval = validate_council_decision_finality(&council).expect_err(
                "approved council decision must require independent finality authority",
            );
            assert_eq!(council_self_approval.status(), StatusCode::FORBIDDEN);
            assert_eq!(council_self_approval.error_code(), "approval_denied");
        }

        #[test]
        fn runtime_import_response_counts_inserted_sections_and_non_claims() {
            let request = import_request();
            let response = import_response_from_summary(
                request,
                exo_dag_db_exchange::kg_import::KgImportPersistedSummary {
                    schema_version:
                        exo_dag_db_exchange::kg_import::KG_IMPORT_PERSISTED_SUMMARY_SCHEMA
                            .to_owned(),
                    tenant_id: "tenant-a".to_owned(),
                    namespace: "primary".to_owned(),
                    batch_id: "batch-a".to_owned(),
                    idempotency_key: "summary-idem-1".to_owned(),
                    replayed: false,
                    inserted_memory_count: 1,
                    inserted_catalog_count: 2,
                    inserted_graph_node_count: 3,
                    inserted_graph_edge_count: 4,
                    inserted_layer_count: 5,
                    inserted_layer_membership_count: 6,
                    inserted_layer_edge_count: 7,
                    inserted_validation_report_count: 8,
                    inserted_placement_decision_count: 9,
                    inserted_placement_trace_count: 10,
                    inserted_receipt_count: 11,
                    skipped_advisory_section_count: 12,
                },
                "persisted",
            )
            .expect("import response");

            assert_eq!(response.tenant_id, "tenant-a");
            assert_eq!(response.namespace, "primary");
            assert_eq!(response.import_status, "persisted");
            assert_eq!(
                response.import_receipt_id.as_deref(),
                Some("summary-idem-1")
            );
            // Sum of every inserted_* section count (1..=11); skipped advisory
            // sections are not imported records.
            assert_eq!(response.imported_record_count, 66);
            assert_eq!(response.non_claims, runtime_non_claims());
            assert!(response.operation_id.len() == 64);
        }

        #[test]
        fn runtime_export_response_counts_portable_sections_and_non_claims() {
            let request = export_request();
            let export = portable_export_with_counted_sections();
            let expected_export_id = export.export_id.clone();
            let expected_export_hash = export.hashes.whole_export_hash.clone();

            let response = export_response_from_portable(request, export).expect("export response");

            assert_eq!(response.tenant_id, "tenant-a");
            assert_eq!(response.namespace, "primary");
            assert_eq!(response.export_status, "built");
            assert_eq!(
                response.export_artifact_id.as_deref(),
                Some(expected_export_id.as_str())
            );
            assert_eq!(
                response.export_hash.as_deref(),
                Some(expected_export_hash.as_str())
            );
            assert_eq!(response.exported_record_count, 17);
            assert_eq!(response.non_claims, runtime_non_claims());
            assert!(response.operation_id.len() == 64);
        }

        #[test]
        fn runtime_adapter_failures_cover_runtime_classifier_branches() {
            let import_report_hash = KgImportPersistenceError::Report(KgImportError::Hash {
                reason: "hash failed".to_owned(),
            });
            assert_eq!(import_adapter_failure(&import_report_hash).class, "runtime");
            assert_eq!(
                import_adapter_failure(&KgImportPersistenceError::CountOutOfRange).class,
                "runtime"
            );

            let export_import_hash = KgExportError::ImportHash(KgImportError::Hash {
                reason: "hash failed".to_owned(),
            });
            assert_eq!(export_adapter_failure(&export_import_hash).class, "runtime");
            assert_eq!(
                export_adapter_failure(&KgExportError::CountOutOfRange).class,
                "runtime"
            );
        }

        #[tokio::test]
        async fn idempotency_db_error_and_short_circuit_paths_fail_closed() {
            let pool = PgPoolOptions::new()
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            pool.close().await;
            let request_hash = Hash256::digest(b"idempotency request");

            let reserve_error = match reserve_gateway_idempotency_key(
                &pool,
                "tenant-a",
                "primary",
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                "idem-import-1",
                request_hash,
                "did:exo:test-actor",
                "import",
            )
            .await
            {
                Ok(_) => panic!("closed pool reserve should fail"),
                Err(response) => response,
            };
            assert_error_response_shape(
                *reserve_error,
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB import idempotency guard could not be checked",
                false,
            )
            .await;

            let replay_error = match replay_gateway_idempotency_response(
                &pool,
                "tenant-a",
                "primary",
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                "idem-import-1",
                request_hash,
                "did:exo:test-actor",
                "import",
            )
            .await
            {
                Ok(_) => panic!("closed pool replay should fail"),
                Err(response) => response,
            };
            assert_error_response_shape(
                *replay_error,
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB import idempotency guard could not be checked",
                false,
            )
            .await;

            assert_error_response_shape(
                *store_gateway_idempotency_response(
                    &pool,
                    "tenant-a",
                    "primary",
                    EXPORT_ROUTE_IDEMPOTENCY_NAME,
                    "idem-export-1",
                    request_hash,
                    StatusCode::OK,
                    Err(export_idempotency_unavailable_response()),
                    None,
                    "export",
                )
                .await
                .expect_err("response body short-circuit"),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB export idempotency guard could not be checked",
                false,
            )
            .await;

            assert_error_response_shape(
                *store_gateway_idempotency_response(
                    &pool,
                    "tenant-a",
                    "primary",
                    EXPORT_ROUTE_IDEMPOTENCY_NAME,
                    "idem-export-1",
                    request_hash,
                    StatusCode::OK,
                    Ok(json!({"ok": true})),
                    None,
                    "export",
                )
                .await
                .expect_err("closed pool store should fail"),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB export idempotency guard could not be checked",
                false,
            )
            .await;

            assert!(
                delete_gateway_idempotency_reservation(
                    &pool,
                    "tenant-a",
                    "primary",
                    EXPORT_ROUTE_IDEMPOTENCY_NAME,
                    "idem-export-1",
                    request_hash,
                )
                .await
                .is_err()
            );

            let import_cleanup_error =
                cleanup_gateway_idempotency_reservation(&pool, &import_request(), request_hash)
                    .await
                    .expect_err("closed pool import cleanup should surface failure");
            assert_error_response_shape(
                *import_cleanup_error,
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB import idempotency guard could not be checked",
                false,
            )
            .await;

            let export_cleanup_error =
                cleanup_export_idempotency_reservation(&pool, &export_request(), request_hash)
                    .await
                    .expect_err("closed pool export cleanup should surface failure");
            assert_error_response_shape(
                *export_cleanup_error,
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB export idempotency guard could not be checked",
                false,
            )
            .await;
        }

        #[test]
        fn idempotency_cleanup_row_count_requires_exactly_one_removed() {
            assert!(!idempotency_reservation_cleanup_removed(0));
            assert!(idempotency_reservation_cleanup_removed(1));
            assert!(!idempotency_reservation_cleanup_removed(2));
        }

        #[tokio::test]
        #[allow(unexpected_cfgs)]
        async fn live_idempotency_replay_classifies_reserved_conflict_cached_and_bad_statuses() {
            #[cfg(coverage)]
            let pool = live_dagdb_pool().await.expect("live DAG DB pool");
            #[cfg(not(coverage))]
            let Some(pool) = live_dagdb_pool().await else {
                return;
            };
            let tenant_id = format!("tenant-coverage-{}", std::process::id());
            let namespace = "primary";
            delete_live_idempotency_rows(&pool, &tenant_id, namespace).await;

            let idempotency_key = "idem-live-classification";
            let request_hash = Hash256::digest(b"live idempotency request");
            let first = reserve_gateway_idempotency_key(
                &pool,
                &tenant_id,
                namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                idempotency_key,
                request_hash,
                "did:exo:test-actor",
                "import",
            )
            .await
            .expect("first reservation");
            assert!(matches!(first, GatewayIdempotencyDecision::Reserved));

            let in_progress = match reserve_gateway_idempotency_key(
                &pool,
                &tenant_id,
                namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                idempotency_key,
                request_hash,
                "did:exo:test-actor",
                "import",
            )
            .await
            {
                Ok(_) => panic!("reserved row should still be in progress"),
                Err(response) => response,
            };
            assert_error_response_shape(
                *in_progress,
                StatusCode::CONFLICT,
                "idempotency_key_in_progress",
                "DAG DB import idempotency key is currently being processed",
                false,
            )
            .await;

            let conflict = match reserve_gateway_idempotency_key(
                &pool,
                &tenant_id,
                namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                idempotency_key,
                Hash256::digest(b"different live idempotency request"),
                "did:exo:test-actor",
                "import",
            )
            .await
            {
                Ok(_) => panic!("different request hash should conflict"),
                Err(response) => response,
            };
            assert_error_response_shape(
                *conflict,
                StatusCode::CONFLICT,
                "idempotency_key_conflict",
                "DAG DB import idempotency key was already used with a different request body",
                false,
            )
            .await;

            store_gateway_idempotency_response(
                &pool,
                &tenant_id,
                namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                idempotency_key,
                request_hash,
                StatusCode::OK,
                Ok(json!({"ok": true})),
                None,
                "import",
            )
            .await
            .expect("store cached response");
            let replay = reserve_gateway_idempotency_key(
                &pool,
                &tenant_id,
                namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                idempotency_key,
                request_hash,
                "did:exo:test-actor",
                "import",
            )
            .await
            .expect("cached response replays");
            assert!(matches!(replay, GatewayIdempotencyDecision::Replayed(_)));
            assert_eq!(idempotency_ref(idempotency_key).len(), 64);

            let live_ctx = DagDbRouteContext::from_pool(Some(pool.clone()));
            let packet_response = context_packet_handler(
                &live_ctx,
                DagDbContextPacketRequest {
                    tenant_id: tenant_id.clone(),
                    namespace: namespace.to_owned(),
                    idempotency_key: "idem-live-context-packet".to_owned(),
                    ..context_packet_request("live-context-packet")
                },
            )
            .await;
            assert_eq!(packet_response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            let packet_error: DagDbErrorEnvelope = json_body(packet_response).await;
            assert_eq!(packet_error.error_code, "metadata_rejected");

            let export_denied_request = DagDbExportRequest {
                tenant_id: tenant_id.clone(),
                namespace: namespace.to_owned(),
                idempotency_key: "idem-live-export-gate-denied".to_owned(),
                ..export_request()
            };
            let export_denied_hash =
                export_route_request_hash(&export_denied_request).expect("export denied hash");
            let mut export_denied_headers = authorized_headers("dagdb:export");
            export_denied_headers.insert(
                WRITE_SIGNATURE_HEADER,
                HeaderValue::from_str(&"aa".repeat(64)).expect("signature header"),
            );
            let export_denied = export_handler(
                &live_ctx,
                &export_denied_headers,
                export_denied_request.clone(),
            )
            .await;
            assert_error_response(
                export_denied,
                StatusCode::BAD_REQUEST,
                "finality_approval_required",
            )
            .await;
            assert!(matches!(
                reserve_gateway_idempotency_key(
                    &pool,
                    &tenant_id,
                    namespace,
                    EXPORT_ROUTE_IDEMPOTENCY_NAME,
                    &export_denied_request.idempotency_key,
                    export_denied_hash,
                    "did:exo:test-actor",
                    "export",
                )
                .await
                .expect("export gate denial cleaned reservation"),
                GatewayIdempotencyDecision::Reserved
            ));
            cleanup_export_idempotency_reservation(
                &pool,
                &export_denied_request,
                export_denied_hash,
            )
            .await
            .expect("cleanup export denial proof reservation");

            let export_response = export_handler(
                &live_ctx,
                &authorized_headers("dagdb:export"),
                DagDbExportRequest {
                    tenant_id: tenant_id.clone(),
                    namespace: namespace.to_owned(),
                    idempotency_key: "idem-live-export-handler".to_owned(),
                    ..export_request()
                },
            )
            .await;
            assert_error_response(
                export_response,
                StatusCode::BAD_REQUEST,
                "write_signature_required",
            )
            .await;

            let cleanup_import_key = "idem-live-cleanup-import";
            let cleanup_import_hash = Hash256::digest(b"cleanup import reservation");
            assert!(matches!(
                reserve_gateway_idempotency_key(
                    &pool,
                    &tenant_id,
                    namespace,
                    IMPORT_ROUTE_IDEMPOTENCY_NAME,
                    cleanup_import_key,
                    cleanup_import_hash,
                    "did:exo:test-actor",
                    "import",
                )
                .await
                .expect("reserve import cleanup row"),
                GatewayIdempotencyDecision::Reserved
            ));
            cleanup_gateway_idempotency_reservation(
                &pool,
                &DagDbImportRequest {
                    idempotency_key: cleanup_import_key.to_owned(),
                    tenant_id: tenant_id.clone(),
                    namespace: namespace.to_owned(),
                    ..import_request()
                },
                cleanup_import_hash,
            )
            .await
            .expect("import cleanup removed reservation");
            assert!(matches!(
                reserve_gateway_idempotency_key(
                    &pool,
                    &tenant_id,
                    namespace,
                    IMPORT_ROUTE_IDEMPOTENCY_NAME,
                    cleanup_import_key,
                    cleanup_import_hash,
                    "did:exo:test-actor",
                    "import",
                )
                .await
                .expect("import cleanup removed reservation"),
                GatewayIdempotencyDecision::Reserved
            ));

            let cleanup_export_key = "idem-live-cleanup-export";
            let cleanup_export_hash = Hash256::digest(b"cleanup export reservation");
            assert!(matches!(
                reserve_gateway_idempotency_key(
                    &pool,
                    &tenant_id,
                    namespace,
                    EXPORT_ROUTE_IDEMPOTENCY_NAME,
                    cleanup_export_key,
                    cleanup_export_hash,
                    "did:exo:test-actor",
                    "export",
                )
                .await
                .expect("reserve export cleanup row"),
                GatewayIdempotencyDecision::Reserved
            ));
            cleanup_export_idempotency_reservation(
                &pool,
                &DagDbExportRequest {
                    idempotency_key: cleanup_export_key.to_owned(),
                    tenant_id: tenant_id.clone(),
                    namespace: namespace.to_owned(),
                    ..export_request()
                },
                cleanup_export_hash,
            )
            .await
            .expect("export cleanup removed reservation");
            assert!(matches!(
                reserve_gateway_idempotency_key(
                    &pool,
                    &tenant_id,
                    namespace,
                    EXPORT_ROUTE_IDEMPOTENCY_NAME,
                    cleanup_export_key,
                    cleanup_export_hash,
                    "did:exo:test-actor",
                    "export",
                )
                .await
                .expect("export cleanup removed reservation"),
                GatewayIdempotencyDecision::Reserved
            ));

            let stale_key = "idem-live-stale-store";
            let stale_hash = Hash256::digest(b"stale reservation");
            let stale = reserve_gateway_idempotency_key(
                &pool,
                &tenant_id,
                namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                stale_key,
                stale_hash,
                "did:exo:test-actor",
                "import",
            )
            .await
            .expect("stale reservation");
            assert!(matches!(stale, GatewayIdempotencyDecision::Reserved));
            let stale_store = store_gateway_idempotency_response(
                &pool,
                &tenant_id,
                namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                stale_key,
                Hash256::digest(b"wrong stale reservation"),
                StatusCode::OK,
                Ok(json!({"ok": true})),
                None,
                "import",
            )
            .await
            .expect_err("stale reservation hash fails closed");
            assert_error_response_shape(
                *stale_store,
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB import idempotency guard could not be checked",
                false,
            )
            .await;

            let missing_cleanup_hash = Hash256::digest(b"missing cleanup reservation");
            let missing_import_cleanup = cleanup_gateway_idempotency_reservation(
                &pool,
                &DagDbImportRequest {
                    idempotency_key: "idem-live-missing-import-cleanup".to_owned(),
                    tenant_id: tenant_id.clone(),
                    namespace: namespace.to_owned(),
                    ..import_request()
                },
                missing_cleanup_hash,
            )
            .await
            .expect_err("missing import cleanup should surface failure");
            assert_error_response_shape(
                *missing_import_cleanup,
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB import idempotency guard could not be checked",
                false,
            )
            .await;

            let missing_export_cleanup = cleanup_export_idempotency_reservation(
                &pool,
                &DagDbExportRequest {
                    idempotency_key: "idem-live-missing-export-cleanup".to_owned(),
                    tenant_id: tenant_id.clone(),
                    namespace: namespace.to_owned(),
                    ..export_request()
                },
                missing_cleanup_hash,
            )
            .await
            .expect_err("missing export cleanup should surface failure");
            assert_error_response_shape(
                *missing_export_cleanup,
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB export idempotency guard could not be checked",
                false,
            )
            .await;

            delete_live_idempotency_rows(&pool, &tenant_id, namespace).await;
        }

        #[tokio::test]
        #[allow(unexpected_cfgs)]
        async fn live_expired_reservation_is_reclaimed_on_retry() {
            use sqlx::Row as _;

            #[cfg(coverage)]
            let pool = live_dagdb_pool().await.expect("live DAG DB pool");
            #[cfg(not(coverage))]
            let Some(pool) = live_dagdb_pool().await else {
                return;
            };
            let tenant_id = format!("tenant-reclaim-{}", std::process::id());
            let namespace = "primary";
            delete_live_idempotency_rows(&pool, &tenant_id, namespace).await;

            // Simulate a crash between reserve and store: a reserved row whose
            // expiry is already in the past.
            let idempotency_key = "idem-live-expired-reclaim";
            let request_hash = Hash256::digest(b"expired reservation retry");
            insert_stale_live_reservation(
                &pool,
                &tenant_id,
                namespace,
                idempotency_key,
                request_hash,
            )
            .await;

            let retry = reserve_gateway_idempotency_key(
                &pool,
                &tenant_id,
                namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                idempotency_key,
                request_hash,
                "did:exo:test-actor",
                "import",
            )
            .await
            .expect("expired reservation must be reclaimable on retry");
            assert!(matches!(retry, GatewayIdempotencyDecision::Reserved));

            // The reclaimed reservation must carry real trusted-clock timestamps,
            // not the historical 1/86400001 placeholders.
            let mut tx = begin_tenant_transaction(&pool, &tenant_id)
                .await
                .expect("tenant-bound reclaimed reservation transaction");
            let row = sqlx::query(
                "SELECT created_at_physical_ms, expires_at_physical_ms FROM dagdb_idempotency_keys \
	         WHERE tenant_id = $1 AND namespace = $2 AND route_name = $3 AND idempotency_key = $4",
            )
            .bind(&tenant_id)
            .bind(namespace)
            .bind(IMPORT_ROUTE_IDEMPOTENCY_NAME)
            .bind(idempotency_key)
            .fetch_one(&mut *tx)
            .await
            .expect("fetch reclaimed reservation row");
            tx.commit()
                .await
                .expect("commit reclaimed reservation read");
            let created_at: i64 = row
                .try_get("created_at_physical_ms")
                .expect("created_at_physical_ms");
            let expires_at: i64 = row
                .try_get("expires_at_physical_ms")
                .expect("expires_at_physical_ms");
            assert!(
                created_at > 86_400_001,
                "reservation created_at must come from the trusted database clock, got {created_at}"
            );
            assert_eq!(
                expires_at,
                created_at + 86_400_000,
                "reservation expiry must be created_at plus the 24h TTL"
            );

            // A live (non-expired) reservation must still report in progress.
            let in_progress = match reserve_gateway_idempotency_key(
                &pool,
                &tenant_id,
                namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                idempotency_key,
                request_hash,
                "did:exo:test-actor",
                "import",
            )
            .await
            {
                Ok(_) => panic!("non-expired reservation must stay in progress"),
                Err(response) => response,
            };
            assert_error_response_shape(
                *in_progress,
                StatusCode::CONFLICT,
                "idempotency_key_in_progress",
                "DAG DB import idempotency key is currently being processed",
                false,
            )
            .await;

            // An expired reservation under a different request hash must still
            // fail closed as a conflict instead of being reclaimed.
            let conflict_key = "idem-live-expired-conflict";
            insert_stale_live_reservation(
                &pool,
                &tenant_id,
                namespace,
                conflict_key,
                Hash256::digest(b"original expired request"),
            )
            .await;
            let conflict = match reserve_gateway_idempotency_key(
                &pool,
                &tenant_id,
                namespace,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                conflict_key,
                Hash256::digest(b"different expired request"),
                "did:exo:test-actor",
                "import",
            )
            .await
            {
                Ok(_) => panic!("expired reservation with different request hash must conflict"),
                Err(response) => response,
            };
            assert_error_response_shape(
                *conflict,
                StatusCode::CONFLICT,
                "idempotency_key_conflict",
                "DAG DB import idempotency key was already used with a different request body",
                false,
            )
            .await;

            delete_live_idempotency_rows(&pool, &tenant_id, namespace).await;
        }

        async fn insert_stale_live_reservation(
            pool: &sqlx::PgPool,
            tenant_id: &str,
            namespace: &str,
            idempotency_key: &str,
            request_hash: Hash256,
        ) {
            let response_body = json!({
                "idempotency_status": RESERVED_IDEMPOTENCY_BODY_STATUS,
                "route_name": IMPORT_ROUTE_IDEMPOTENCY_NAME,
            });
            let response_hash = gateway_idempotency_response_hash(
                &response_body,
                IMPORT_ROUTE_IDEMPOTENCY_NAME,
                "reserve",
                "import",
                tenant_id,
                namespace,
                idempotency_key,
            )
            .expect("reserved response hash");
            let mut tx = begin_tenant_transaction(pool, tenant_id)
                .await
                .expect("tenant-bound stale reservation transaction");
            sqlx::query(
                "INSERT INTO dagdb_idempotency_keys \
	         (tenant_id, namespace, route_name, idempotency_key, request_hash, response_hash, \
	          response_body, status_code, cached_failure, created_at_physical_ms, \
                  created_at_logical, expires_at_physical_ms, expires_at_logical) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 202, false, 1, 0, 2, 0)",
            )
            .bind(tenant_id)
            .bind(namespace)
            .bind(IMPORT_ROUTE_IDEMPOTENCY_NAME)
            .bind(idempotency_key)
            .bind(request_hash.as_bytes().to_vec())
            .bind(response_hash.as_bytes().to_vec())
            .bind(response_body)
            .execute(&mut *tx)
            .await
            .expect("insert stale reserved row");
            tx.commit().await.expect("commit stale reserved row");
        }

        #[tokio::test]
        async fn idempotency_helper_wrappers_return_operation_specific_shapes() {
            assert_error_response_shape(
                *import_idempotency_unavailable_response(),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB import idempotency guard could not be checked",
                false,
            )
            .await;
            assert_error_response_shape(
                *export_idempotency_unavailable_response(),
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                "DAG DB export idempotency guard could not be checked",
                false,
            )
            .await;
        }

        async fn live_dagdb_pool() -> Option<sqlx::PgPool> {
            let database_url = std::env::var("EXO_DAGDB_TEST_DATABASE_URL").ok()?;
            exo_dag_db_postgres::postgres::init_pool(&database_url)
                .await
                .ok()
        }

        async fn delete_live_idempotency_rows(
            pool: &sqlx::PgPool,
            tenant_id: &str,
            namespace: &str,
        ) {
            let mut tx = begin_tenant_transaction(pool, tenant_id)
                .await
                .expect("tenant-bound idempotency cleanup transaction");
            sqlx::query(
                "DELETE FROM dagdb_idempotency_keys WHERE tenant_id = $1 AND namespace = $2",
            )
            .bind(tenant_id)
            .bind(namespace)
            .execute(&mut *tx)
            .await
            .expect("delete live idempotency rows");
            tx.commit().await.expect("commit live idempotency cleanup");
        }

        fn context_packet_request(request_id: &str) -> DagDbContextPacketRequest {
            DagDbContextPacketRequest {
                tenant_id: "tenant-a".to_owned(),
                namespace: "primary".to_owned(),
                idempotency_key: "idem-packet-mode".to_owned(),
                request_id: request_id.to_owned(),
                route_id: Hash256::digest(b"packet route").to_string(),
                task_hash: Hash256::digest(b"packet task").to_string(),
                requesting_agent_did: "did:exo:agent".to_owned(),
                token_budget: 512,
                force_revalidate: None,
                max_memory_refs: None,
                task: None,
                layered_mode: None,
                max_layer_depth: None,
                require_layer_evidence: None,
                drilldown_reserve_bp: None,
            }
        }

        fn selected_context_ref() -> exo_api::dagdb::DagDbSelectedContextRef {
            exo_api::dagdb::DagDbSelectedContextRef {
                memory_id: Hash256::digest(b"selected memory").to_string(),
                catalog_id: None,
                title: safe_gateway_metadata("Selected memory"),
                summary: safe_gateway_metadata("Selected summary"),
                catalog_path: Vec::new(),
                document_type: "note".to_owned(),
                selection_reason: "coverage fixture".to_owned(),
                token_estimate: 12,
                validation_status: ValidationStatus::Passed,
                citation_ref: "cite:selected".to_owned(),
                boundary_flags: Vec::new(),
            }
        }

        fn persistent_context_packet(
            selected_memory_refs: Vec<exo_api::dagdb::DagDbSelectedContextRef>,
        ) -> exo_dag_db_postgres::persistent_context::PersistentGraphContextPacket {
            let selected_memory_receipt_hashes = selected_memory_refs
                .iter()
                .map(|selected| {
                    (
                        selected.memory_id.clone(),
                        Hash256::digest(selected.memory_id.as_bytes()).to_string(),
                    )
                })
                .collect();
            persistent_context_packet_with_receipts(
                selected_memory_refs,
                selected_memory_receipt_hashes,
            )
        }

        fn persistent_context_packet_with_receipts(
            selected_memory_refs: Vec<exo_api::dagdb::DagDbSelectedContextRef>,
            selected_memory_receipt_hashes: BTreeMap<String, String>,
        ) -> exo_dag_db_postgres::persistent_context::PersistentGraphContextPacket {
            let selection_status = if selected_memory_refs.is_empty() {
                DagDbGraphContextSelectionStatus::Empty
            } else {
                DagDbGraphContextSelectionStatus::Selected
            };
            let selection = DagDbGraphContextSelectionResponse {
                tenant_id: "tenant-a".to_owned(),
                namespace: "primary".to_owned(),
                request_id: "packet-mode-request".to_owned(),
                task_hash: Hash256::digest(b"packet task").to_string(),
                selection_status,
                selected_memory_refs: selected_memory_refs.clone(),
                selected_graph_edges: Vec::new(),
                omitted_memory_refs: Vec::new(),
                selection_trace: Vec::new(),
                selected_token_estimate: 12,
                token_budget: 512,
                boundary_warnings: Vec::new(),
            };
            exo_dag_db_postgres::persistent_context::PersistentGraphContextPacket {
                tenant_id: "tenant-a".to_owned(),
                namespace: "primary".to_owned(),
                selection:
                    exo_dag_db_postgres::persistent_context::PersistentGraphContextSelection {
                        tenant_id: "tenant-a".to_owned(),
                        namespace: "primary".to_owned(),
                        memory_row_count: u32::try_from(selected_memory_refs.len())
                            .unwrap_or(u32::MAX),
                        catalog_row_count: 0,
                        graph_edge_row_count: 0,
                        validation_row_count: 0,
                        receipt_row_count: 0,
                        skipped_row_count: 0,
                        selection: selection.clone(),
                        selected_memory_receipt_hashes,
                        boundary_warnings: Vec::new(),
                    },
                packet: exo_api::dagdb::DagDbGraphContextPacket {
                    schema_version: "dagdb_graph_context_packet.v1".to_owned(),
                    tenant_id: "tenant-a".to_owned(),
                    namespace: "primary".to_owned(),
                    request_id: "packet-mode-request".to_owned(),
                    task: "packet mode coverage".to_owned(),
                    task_hash: Hash256::digest(b"packet task").to_string(),
                    packet_hash: Hash256::digest(b"packet hash").to_string(),
                    selected_memory_refs,
                    selected_graph_edges: Vec::new(),
                    citation_refs: Vec::new(),
                    packet_metrics: exo_api::dagdb::DagDbContextPacketMetrics {
                        token_budget: 512,
                        selected_token_estimate: 12,
                        selected_memory_ref_count: u32::try_from(
                            selection.selected_memory_refs.len(),
                        )
                        .unwrap_or(u32::MAX),
                        selected_graph_edge_count: 0,
                        citation_ref_count: 0,
                        end_to_end_savings_status: "not_claimed".to_owned(),
                        cost_savings_status: "not_claimed".to_owned(),
                    },
                    boundaries: exo_api::dagdb::DagDbContextPacketBoundaries {
                        repository_test_level_only: true,
                        production_runtime: "not_approved".to_owned(),
                        default_context_replacement: "not_claimed".to_owned(),
                        citation_locator_status: "fixture".to_owned(),
                        billing_savings: "not_claimed".to_owned(),
                    },
                    agent_usage_instructions: Vec::new(),
                    markdown: String::new(),
                },
                boundary_warnings: Vec::new(),
            }
        }

        fn portable_export_with_counted_sections()
        -> exo_dag_db_exchange::kg_export::KgPortableExport {
            let record = |key: &str, value: &str| {
                [(key.to_owned(), json!(value))]
                    .into_iter()
                    .collect::<exo_dag_db_exchange::kg_export::KgExportRecord>()
            };
            exo_dag_db_exchange::kg_export::build_portable_export(
                exo_dag_db_exchange::kg_export::KgExportBuildInput {
                    scope: KgExportScope {
                        tenant_id: "tenant-a".to_owned(),
                        namespace: "primary".to_owned(),
                        included_memory_ids: Vec::new(),
                        included_graph_styles: Vec::new(),
                        included_writeback_idempotency_keys: Vec::new(),
                        source_commit_or_repo_ref: Some(
                            "c706242d36f1c275e05d8a132778491da08f61c7".to_owned(),
                        ),
                        include_preview_context: true,
                    },
                    memory_records: vec![record("memory_id", "memory-a")],
                    catalog_entries: vec![record("catalog_id", "catalog-a")],
                    graph_nodes: vec![record("graph_node_id", "node-a")],
                    graph_edges: vec![record("graph_edge_id", "edge-a")],
                    similarity_results: vec![record("similarity_result_id", "similarity-a")],
                    canonicalization_decisions: vec![record("decision_id", "decision-a")],
                    placement_traces: vec![record("placement_trace_id", "trace-a")],
                    validation_reports: vec![record("validation_report_id", "validation-a")],
                    receipts: vec![record("receipt_hash", "receipt-a")],
                    subject_receipt_heads: vec![record("subject_id", "memory-a")],
                    context_packet_previews: vec![record("context_packet_id", "packet-preview-a")],
                    context_packet_records: vec![record("context_packet_id", "packet-a")],
                    route_receipts: vec![record("route_id", "route-a")],
                    writeback_summaries: vec![record("idempotency_key", "idem-writeback-a")],
                    idempotency_references: vec![record("idempotency_key", "idem-a")],
                    citation_index: vec![record("citation_handle", "cite-a")],
                    provenance_index: vec![record("subject_id", "memory-a")],
                },
            )
            .expect("portable export")
        }

        fn fixture_writeback_request() -> DagDbWritebackRequest {
            let fixtures = fixtures();
            fixture(&fixtures, "requests", "writeback")
        }

        fn fixed_lifecycle_approval_timestamp() -> &'static str {
            "2026-06-20T00:00:00Z"
        }

        fn fixed_continuation_approval_timestamp() -> &'static str {
            "2026-06-20T00:00:01Z"
        }

        fn fixture_writeback_selection_response(
            request: &DagDbWritebackRequest,
        ) -> DagDbGraphContextSelectionResponse {
            let selection_request =
                selection_request_from_writeback(request).expect("writeback selection request");
            DagDbGraphContextSelectionResponse {
                tenant_id: request.tenant_id.clone(),
                namespace: request.namespace.clone(),
                request_id: selection_request.request_id,
                task_hash: selection_request.task_hash,
                selection_status: DagDbGraphContextSelectionStatus::Empty,
                selected_memory_refs: Vec::new(),
                selected_graph_edges: Vec::new(),
                omitted_memory_refs: Vec::new(),
                selection_trace: Vec::new(),
                selected_token_estimate: 0,
                token_budget: selection_request.token_budget,
                boundary_warnings: Vec::new(),
            }
        }

        fn writeback_preflight_signatures(
            writer_keypair: &KeyPair,
            approval_keypair: &KeyPair,
            selection: &DagDbGraphContextSelectionResponse,
            lifecycle: &LifecycleAction,
            continuation: &ContinuationRecord,
            lifecycle_approval_timestamp: &str,
            continuation_approval_timestamp: &str,
        ) -> (String, String, String) {
            let writeback_signature = sign_write_payload(
                writer_keypair,
                &usage_event_payload_hash(selection).expect("writeback payload hash"),
            )
            .expect("writeback signature");
            let lifecycle_payload_hash_hex = canonical_lifecycle_approval_payload_hash(
                lifecycle,
                "did:exo:finality-authority",
                lifecycle.action_type.as_str(),
                lifecycle_approval_timestamp,
            )
            .expect("lifecycle approval payload hash");
            let lifecycle_payload_hash = hex::decode(lifecycle_payload_hash_hex)
                .expect("lifecycle approval hash hex")
                .try_into()
                .expect("lifecycle approval hash bytes");
            let lifecycle_signature = sign_write_payload(approval_keypair, &lifecycle_payload_hash)
                .expect("lifecycle signature");
            let continuation_payload_hash_hex = canonical_continuation_approval_payload_hash(
                continuation,
                "did:exo:finality-authority",
                CONTINUATION_FINALITY_PURPOSE,
                continuation_approval_timestamp,
            )
            .expect("continuation approval payload hash");
            let continuation_payload_hash = hex::decode(continuation_payload_hash_hex)
                .expect("continuation approval hash hex")
                .try_into()
                .expect("continuation approval hash bytes");
            let continuation_signature =
                sign_write_payload(approval_keypair, &continuation_payload_hash)
                    .expect("continuation signature");
            (
                writeback_signature,
                lifecycle_signature,
                continuation_signature,
            )
        }

        fn writeback_base_record_signatures(
            writer_keypair: &KeyPair,
            approval_keypair: &KeyPair,
            selection: &DagDbGraphContextSelectionResponse,
            lifecycle: &LifecycleAction,
            continuation: &ContinuationRecord,
        ) -> (String, String, String) {
            let writeback_signature = sign_write_payload(
                writer_keypair,
                &usage_event_payload_hash(selection).expect("writeback payload hash"),
            )
            .expect("writeback signature");
            let lifecycle_signature = sign_write_payload(
                approval_keypair,
                &lifecycle_action_payload_hash(lifecycle).expect("lifecycle payload hash"),
            )
            .expect("lifecycle signature");
            let continuation_signature = sign_write_payload(
                approval_keypair,
                &continuation_record_payload_hash(continuation).expect("continuation payload hash"),
            )
            .expect("continuation signature");
            (
                writeback_signature,
                lifecycle_signature,
                continuation_signature,
            )
        }

        fn consented_service_for_agent_and_authority(
            agent_keypair: &KeyPair,
            authority_keypair: &KeyPair,
            tenant_id: &str,
            agent_did: &str,
            authority_did: &str,
        ) -> DagDbGatekeeperService {
            let service = consented_service_for_agent_and_registered_did(
                agent_keypair,
                authority_keypair,
                tenant_id,
                agent_did,
                authority_did,
            );
            DagDbGatekeeperService::new(
                service.pool,
                service.consent_engine,
                Arc::new(
                    (*service.identity_registry)
                        .clone()
                        .with_governed_role(authority_did, GovernedRoleName::Operator),
                ),
            )
        }

        fn consented_service_for_agent_and_registered_did(
            agent_keypair: &KeyPair,
            registered_keypair: &KeyPair,
            tenant_id: &str,
            agent_did: &str,
            registered_did: &str,
        ) -> DagDbGatekeeperService {
            let pool = PgPoolOptions::new()
                .acquire_timeout(Duration::from_millis(50))
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            DagDbGatekeeperService::new(
                pool,
                Arc::new(consent_engine_for_agent(tenant_id, agent_did)),
                Arc::new(
                    identity_registry_for_agent(agent_did, agent_keypair).with_public_key(
                        registered_did,
                        *registered_keypair.public_key().as_bytes(),
                    ),
                ),
            )
        }

        fn consented_service_for_agent(
            keypair: &KeyPair,
            tenant_id: &str,
            agent_did: &str,
        ) -> DagDbGatekeeperService {
            let pool = PgPoolOptions::new()
                .acquire_timeout(Duration::from_millis(50))
                .connect_lazy("postgres://127.0.0.1:1/unreachable")
                .expect("lazy pool");
            DagDbGatekeeperService::new(
                pool,
                Arc::new(consent_engine_for_agent(tenant_id, agent_did)),
                Arc::new(identity_registry_for_agent(agent_did, keypair)),
            )
        }

        fn consent_engine_for_agent(tenant_id: &str, agent_did: &str) -> ConsentEngine {
            ConsentEngine::default()
                .with_bailment(
                    tenant_id,
                    BailmentState::Active {
                        bailor: exo_core::Did::new("did:exo:bailor").expect("valid bailor DID"),
                        bailee: exo_core::Did::new(agent_did).expect("valid agent DID"),
                        scope: DAGDB_WRITEBACK_SCOPE.to_owned(),
                    },
                )
                .with_consent_record(DagDbConsentRecord {
                    tenant_id: tenant_id.to_owned(),
                    agent_did: agent_did.to_owned(),
                    purpose: ConsentPurpose::Writeback,
                    active: true,
                })
        }

        fn identity_registry_for_agent(agent_did: &str, keypair: &KeyPair) -> IdentityRegistry {
            IdentityRegistry::default().with_public_key(agent_did, *keypair.public_key().as_bytes())
        }
    }
}
