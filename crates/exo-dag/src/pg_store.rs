//! PostgreSQL-backed `DagStore` implementation.
//!
//! Feature-gated behind `postgres`. Uses `sqlx` with `PgPool` for async
//! connection pooling.  Columnar storage (not CBOR) enables SQL-level queries.

use exo_core::types::{Did, Hash256, Signature, Timestamp};
use sqlx::PgPool;

use crate::{
    dag::DagNode,
    error::{DagError, Result},
    store::DagStore,
};

/// Map a sqlx error into `DagError::StoreError`.
fn store_err(e: impl std::fmt::Display) -> DagError {
    DagError::StoreError(e.to_string())
}

/// PostgreSQL-backed DAG store.
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Create a new `PostgresStore` wrapping the given connection pool.
    pub async fn new(pool: PgPool) -> Result<Self> {
        Ok(Self { pool })
    }

    /// Run schema migrations (idempotent — safe to call on every startup).
    pub async fn migrate(pool: &PgPool) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS dag_nodes (
                hash            BYTEA PRIMARY KEY,
                parents         BYTEA[] NOT NULL DEFAULT '{}',
                payload_hash    BYTEA NOT NULL,
                creator_did     TEXT NOT NULL,
                ts_physical_ms  BIGINT NOT NULL,
                ts_logical      BIGINT NOT NULL,
                signature       BYTEA NOT NULL,
                inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS dag_committed (
                hash   BYTEA PRIMARY KEY REFERENCES dag_nodes(hash),
                height BIGINT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_dag_nodes_creator ON dag_nodes(creator_did);
            CREATE INDEX IF NOT EXISTS idx_dag_committed_height ON dag_committed(height);
            "#,
        )
        .execute(pool)
        .await
        .map_err(store_err)?;

        Ok(())
    }

    /// Encode parents as `Vec<Vec<u8>>` for sqlx BYTEA[] binding.
    fn encode_parents(parents: &[Hash256]) -> Vec<Vec<u8>> {
        parents.iter().map(|h| h.as_bytes().to_vec()).collect()
    }

    /// Decode a fixed-width hash from raw bytes returned by Postgres.
    fn decode_hash256(bytes: &[u8], column: &str) -> Result<Hash256> {
        let arr = <[u8; 32]>::try_from(bytes).map_err(|_| {
            store_err(format!(
                "invalid dag_nodes.{column}: expected 32 bytes, got {}",
                bytes.len()
            ))
        })?;

        Ok(Hash256::from_bytes(arr))
    }

    /// Decode parents from raw byte arrays returned by Postgres.
    fn decode_parents(raw: &[Vec<u8>]) -> Result<Vec<Hash256>> {
        raw.iter()
            .enumerate()
            .map(|(idx, bytes)| Self::decode_hash256(bytes, &format!("parents[{idx}]")))
            .collect()
    }

    /// Encode a `Signature` to bytes for storage.
    /// Uses serde_json for full enum fidelity (Ed25519, PostQuantum, Hybrid, Empty).
    fn encode_signature(sig: &Signature) -> Result<Vec<u8>> {
        serde_json::to_vec(sig)
            .map_err(|e| store_err(format!("failed to serialize DAG node signature: {e}")))
    }

    /// Decode a `Signature` from stored bytes.
    fn decode_signature(bytes: &[u8]) -> Result<Signature> {
        serde_json::from_slice(bytes)
            .map_err(|e| store_err(format!("invalid DAG node signature encoding: {e}")))
    }

    /// Decode a timestamp from raw Postgres integer columns.
    fn decode_timestamp(physical_ms: i64, logical: i64) -> Result<Timestamp> {
        let physical_ms = u64::try_from(physical_ms).map_err(|_| {
            store_err(format!(
                "invalid dag_nodes.ts_physical_ms: expected non-negative value, got {physical_ms}"
            ))
        })?;
        let logical = u32::try_from(logical).map_err(|_| {
            store_err(format!(
                "invalid dag_nodes.ts_logical: expected u32-compatible value, got {logical}"
            ))
        })?;

        Ok(Timestamp::new(physical_ms, logical))
    }
}

#[async_trait::async_trait]
impl DagStore for PostgresStore {
    async fn get(&self, hash: &Hash256) -> Result<Option<DagNode>> {
        let row: Option<(
            Vec<u8>,      // hash
            Vec<Vec<u8>>, // parents
            Vec<u8>,      // payload_hash
            String,       // creator_did
            i64,          // ts_physical_ms
            i64,          // ts_logical
            Vec<u8>,      // signature
        )> = sqlx::query_as(
            "SELECT hash, parents, payload_hash, creator_did, ts_physical_ms, ts_logical, signature
             FROM dag_nodes WHERE hash = $1",
        )
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;

        match row {
            None => Ok(None),
            Some((hash_bytes, parents_raw, payload_bytes, did_str, phys, logical, sig_bytes)) => {
                let node = DagNode {
                    hash: Self::decode_hash256(&hash_bytes, "hash")?,
                    parents: Self::decode_parents(&parents_raw)?,
                    payload_hash: Self::decode_hash256(&payload_bytes, "payload_hash")?,
                    creator_did: Did::new(&did_str)
                        .map_err(|e| store_err(format!("invalid DID: {e}")))?,
                    timestamp: Self::decode_timestamp(phys, logical)?,
                    signature: Self::decode_signature(&sig_bytes)?,
                };
                Ok(Some(node))
            }
        }
    }

    async fn put(&mut self, node: DagNode) -> Result<()> {
        let parents = Self::encode_parents(&node.parents);
        let sig_bytes = Self::encode_signature(&node.signature)?;

        #[allow(clippy::as_conversions)]
        sqlx::query(
            "INSERT INTO dag_nodes (hash, parents, payload_hash, creator_did, ts_physical_ms, ts_logical, signature)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (hash) DO NOTHING",
        )
        .bind(node.hash.as_bytes().as_slice())
        .bind(&parents)
        .bind(node.payload_hash.as_bytes().as_slice())
        .bind(node.creator_did.as_str())
        .bind(node.timestamp.physical_ms as i64)
        .bind(node.timestamp.logical as i64)
        .bind(&sig_bytes)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;

        Ok(())
    }

    async fn contains(&self, hash: &Hash256) -> Result<bool> {
        let row: (bool,) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM dag_nodes WHERE hash = $1)")
            .bind(hash.as_bytes().as_slice())
            .fetch_one(&self.pool)
            .await
            .map_err(store_err)?;

        Ok(row.0)
    }

    async fn tips(&self) -> Result<Vec<Hash256>> {
        let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT hash FROM dag_nodes dn
             WHERE NOT EXISTS (
                 SELECT 1 FROM dag_nodes other
                 WHERE dn.hash = ANY(other.parents)
             )
             ORDER BY hash",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;

        let tips = rows
            .into_iter()
            .map(|(bytes,)| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Hash256::from_bytes(arr)
            })
            .collect();

        Ok(tips)
    }

    async fn committed_height(&self) -> Result<u64> {
        let row: (i64,) = sqlx::query_as("SELECT COALESCE(MAX(height), 0) FROM dag_committed")
            .fetch_one(&self.pool)
            .await
            .map_err(store_err)?;

        #[allow(clippy::as_conversions)]
        Ok(row.0 as u64)
    }

    async fn mark_committed(&mut self, hash: &Hash256, height: u64) -> Result<()> {
        if !self.contains(hash).await? {
            return Err(DagError::NodeNotFound(*hash));
        }

        #[allow(clippy::as_conversions)]
        sqlx::query(
            "INSERT INTO dag_committed (hash, height) VALUES ($1, $2)
             ON CONFLICT (hash) DO UPDATE SET height = EXCLUDED.height",
        )
        .bind(hash.as_bytes().as_slice())
        .bind(height as i64)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;

        Ok(())
    }
}

// ===========================================================================
// Tests — require DATABASE_URL to be set; skipped otherwise.
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        dag::{Dag, HybridClock, append},
        store::MemoryStore,
    };

    type SignFn = Box<dyn Fn(&[u8]) -> Signature>;

    fn make_sign_fn() -> SignFn {
        Box::new(|data: &[u8]| {
            let h = blake3::hash(data);
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(h.as_bytes());
            Signature::from_bytes(sig)
        })
    }

    fn make_test_node() -> DagNode {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = Did::new("did:exo:test").expect("valid");
        let sign_fn = make_sign_fn();
        append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap()
    }

    /// Try to connect to Postgres. Returns `None` (skipping) if DATABASE_URL is unset.
    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPool::connect(&url).await.ok()?;
        // Run migrations
        PostgresStore::migrate(&pool).await.ok()?;
        // Clean tables for test isolation
        sqlx::query("DELETE FROM dag_committed")
            .execute(&pool)
            .await
            .ok()?;
        sqlx::query("DELETE FROM dag_nodes")
            .execute(&pool)
            .await
            .ok()?;
        Some(pool)
    }

    macro_rules! pg_test {
        ($pool:ident) => {
            let Some($pool) = maybe_pool().await else {
                eprintln!("Skipping Postgres test: DATABASE_URL not set");
                return;
            };
        };
    }

    #[tokio::test]
    async fn test_pg_put_and_get() {
        pg_test!(pool);
        let mut store = PostgresStore::new(pool).await.unwrap();
        let node = make_test_node();

        store.put(node.clone()).await.unwrap();

        let retrieved = store.get(&node.hash).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.hash, node.hash);
        assert_eq!(retrieved.parents, node.parents);
        assert_eq!(retrieved.payload_hash, node.payload_hash);
        assert_eq!(retrieved.creator_did, node.creator_did);
        assert_eq!(retrieved.timestamp, node.timestamp);
    }

    #[test]
    fn decode_signature_rejects_invalid_stored_bytes() {
        let decoded = PostgresStore::decode_signature(b"not a serialized signature");

        assert!(
            decoded.is_err(),
            "corrupt signature storage must not decode as Signature::Empty"
        );
    }

    #[test]
    fn signature_encoding_roundtrips_without_fabrication() {
        let signature = Signature::from_bytes([7u8; 64]);

        let encoded = PostgresStore::encode_signature(&signature).unwrap();
        let decoded = PostgresStore::decode_signature(&encoded).unwrap();

        assert_eq!(decoded, signature);
    }

    #[test]
    fn decode_hash256_rejects_wrong_width_storage() {
        let err = PostgresStore::decode_hash256(&[1u8; 31], "hash").unwrap_err();
        let message = err.to_string();

        assert!(message.contains("dag_nodes.hash"));
        assert!(message.contains("expected 32 bytes, got 31"));
    }

    #[test]
    fn decode_timestamp_rejects_negative_storage_values() {
        let err = PostgresStore::decode_timestamp(-1, 0).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("ts_physical_ms"));
        assert!(message.contains("expected non-negative"));
    }

    #[tokio::test]
    async fn test_pg_contains() {
        pg_test!(pool);
        let mut store = PostgresStore::new(pool).await.unwrap();
        let node = make_test_node();

        assert!(!store.contains(&node.hash).await.unwrap());
        store.put(node.clone()).await.unwrap();
        assert!(store.contains(&node.hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_pg_tips_single() {
        pg_test!(pool);
        let mut store = PostgresStore::new(pool).await.unwrap();
        let node = make_test_node();
        store.put(node.clone()).await.unwrap();
        let t = store.tips().await.unwrap();
        assert_eq!(t, vec![node.hash]);
    }

    #[tokio::test]
    async fn test_pg_tips_with_children() {
        pg_test!(pool);
        let mut store = PostgresStore::new(pool).await.unwrap();

        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = Did::new("did:exo:test").expect("valid");
        let sign_fn = make_sign_fn();

        let genesis = append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        let child = append(
            &mut dag,
            &[genesis.hash],
            b"child",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        store.put(genesis).await.unwrap();
        store.put(child.clone()).await.unwrap();

        let t = store.tips().await.unwrap();
        assert_eq!(t, vec![child.hash]);
    }

    #[tokio::test]
    async fn test_pg_tips_multiple() {
        pg_test!(pool);
        let mut store = PostgresStore::new(pool).await.unwrap();

        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = Did::new("did:exo:test").expect("valid");
        let sign_fn = make_sign_fn();

        let genesis = append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        let c1 = append(
            &mut dag,
            &[genesis.hash],
            b"c1",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        let c2 = append(
            &mut dag,
            &[genesis.hash],
            b"c2",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        store.put(genesis).await.unwrap();
        store.put(c1.clone()).await.unwrap();
        store.put(c2.clone()).await.unwrap();

        let t = store.tips().await.unwrap();
        assert_eq!(t.len(), 2);
        assert!(t.contains(&c1.hash));
        assert!(t.contains(&c2.hash));
    }

    #[tokio::test]
    async fn test_pg_committed_height() {
        pg_test!(pool);
        let mut store = PostgresStore::new(pool).await.unwrap();
        let node = make_test_node();
        store.put(node.clone()).await.unwrap();

        assert_eq!(store.committed_height().await.unwrap(), 0);

        store.mark_committed(&node.hash, 1).await.unwrap();
        assert_eq!(store.committed_height().await.unwrap(), 1);

        store.mark_committed(&node.hash, 5).await.unwrap();
        assert_eq!(store.committed_height().await.unwrap(), 5);
    }

    #[tokio::test]
    async fn test_pg_committed_nonexistent_fails() {
        pg_test!(pool);
        let mut store = PostgresStore::new(pool).await.unwrap();
        let err = store.mark_committed(&Hash256::ZERO, 1).await.unwrap_err();
        assert!(matches!(err, DagError::NodeNotFound(_)));
    }

    #[tokio::test]
    async fn test_pg_roundtrip_deterministic() {
        pg_test!(pool);
        let mut store = PostgresStore::new(pool).await.unwrap();
        let node = make_test_node();

        store.put(node.clone()).await.unwrap();
        let retrieved = store.get(&node.hash).await.unwrap().unwrap();

        // Field-by-field comparison
        assert_eq!(retrieved.hash, node.hash);
        assert_eq!(retrieved.parents, node.parents);
        assert_eq!(retrieved.payload_hash, node.payload_hash);
        assert_eq!(retrieved.creator_did, node.creator_did);
        assert_eq!(retrieved.timestamp.physical_ms, node.timestamp.physical_ms);
        assert_eq!(retrieved.timestamp.logical, node.timestamp.logical);
    }

    #[tokio::test]
    async fn test_pg_parents_ordering() {
        pg_test!(pool);
        let mut store = PostgresStore::new(pool).await.unwrap();

        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = Did::new("did:exo:test").expect("valid");
        let sign_fn = make_sign_fn();

        let g = append(&mut dag, &[], b"g", &creator, &*sign_fn, &mut clock).unwrap();
        let a = append(&mut dag, &[g.hash], b"a", &creator, &*sign_fn, &mut clock).unwrap();
        let b = append(&mut dag, &[g.hash], b"b", &creator, &*sign_fn, &mut clock).unwrap();
        let merge = append(
            &mut dag,
            &[a.hash, b.hash],
            b"merge",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        store.put(g).await.unwrap();
        store.put(a.clone()).await.unwrap();
        store.put(b.clone()).await.unwrap();
        store.put(merge.clone()).await.unwrap();

        let retrieved = store.get(&merge.hash).await.unwrap().unwrap();
        // Parents should be in sorted order (as the DAG append guarantees)
        assert_eq!(retrieved.parents, merge.parents);
        let mut sorted = retrieved.parents.clone();
        sorted.sort();
        assert_eq!(retrieved.parents, sorted);
    }

    #[tokio::test]
    async fn test_pg_large_payload_hash() {
        pg_test!(pool);
        let mut store = PostgresStore::new(pool).await.unwrap();

        // Test with boundary values
        let creator = Did::new("did:exo:test").expect("valid");
        let sign_fn = make_sign_fn();

        // All-0xFF payload hash
        let payload_hash = Hash256::from_bytes([0xFF; 32]);
        let timestamp = Timestamp::new(1000, 1);
        let hash = crate::dag::compute_node_hash(&[], &payload_hash, &creator, &timestamp).unwrap();
        let signature = (*sign_fn)(hash.as_bytes());

        let node = DagNode {
            hash,
            parents: vec![],
            payload_hash,
            creator_did: creator.clone(),
            timestamp,
            signature,
        };

        store.put(node.clone()).await.unwrap();
        let retrieved = store.get(&hash).await.unwrap().unwrap();
        assert_eq!(retrieved.payload_hash, payload_hash);

        // All-zero hash lookup
        assert!(store.get(&Hash256::ZERO).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_memory_and_pg_parity() {
        pg_test!(pool);
        let mut pg_store = PostgresStore::new(pool).await.unwrap();
        let mut mem_store = MemoryStore::new();

        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = Did::new("did:exo:test").expect("valid");
        let sign_fn = make_sign_fn();

        // Build a small DAG: genesis → c1, genesis → c2
        let genesis = append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        let c1 = append(
            &mut dag,
            &[genesis.hash],
            b"c1",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        let c2 = append(
            &mut dag,
            &[genesis.hash],
            b"c2",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        // Apply same operations to both stores
        for node in [genesis.clone(), c1.clone(), c2.clone()] {
            pg_store.put(node.clone()).await.unwrap();
            mem_store.put(node).await.unwrap();
        }

        // Tips should match
        let pg_tips = pg_store.tips().await.unwrap();
        let mem_tips = mem_store.tips().await.unwrap();
        assert_eq!(pg_tips, mem_tips, "tips mismatch between PG and memory");

        // Committed height should match
        pg_store.mark_committed(&genesis.hash, 1).await.unwrap();
        mem_store.mark_committed(&genesis.hash, 1).await.unwrap();

        assert_eq!(
            pg_store.committed_height().await.unwrap(),
            mem_store.committed_height().await.unwrap(),
            "committed height mismatch"
        );

        // Contains should match
        for hash in [genesis.hash, c1.hash, c2.hash, Hash256::ZERO] {
            assert_eq!(
                pg_store.contains(&hash).await.unwrap(),
                mem_store.contains(&hash).await.unwrap(),
                "contains mismatch for {hash}"
            );
        }
    }
}
