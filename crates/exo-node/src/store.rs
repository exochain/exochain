//! SQLite-backed `DagStore` implementation.
//!
//! Each node persists the DAG and committed state in a local SQLite database.
//! This implementation mirrors `MemoryStore` from `exo-dag` but uses durable
//! storage so state survives restarts.

#![allow(clippy::as_conversions)]

use std::{collections::BTreeSet, path::Path};

use exo_core::types::{Did, Hash256};
use exo_dag::{
    consensus::{CommitCertificate, Vote},
    dag::DagNode,
    error::{DagError, Result as DagResult},
    store::DagStore,
};

/// Map a SQLite / CBOR error into `DagError::StoreError`.
fn store_err(e: impl std::fmt::Display) -> DagError {
    DagError::StoreError(e.to_string())
}
use rusqlite::{Connection, params};

/// SQLite-backed DAG store.
pub struct SqliteDagStore {
    conn: Connection,
}

impl SqliteDagStore {
    /// Open (or create) the SQLite database in the given data directory.
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        let db_path = data_dir.join("dag.db");
        let conn = Connection::open(&db_path)?;

        // WAL mode for concurrent reads.
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;")?;

        // Create tables if they don't exist.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS dag_nodes (
                hash         BLOB PRIMARY KEY NOT NULL,
                cbor_payload BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dag_parents (
                child_hash   BLOB NOT NULL,
                parent_hash  BLOB NOT NULL,
                PRIMARY KEY (child_hash, parent_hash)
            );

            CREATE TABLE IF NOT EXISTS committed (
                hash   BLOB PRIMARY KEY NOT NULL,
                height INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_parents_parent ON dag_parents(parent_hash);
            CREATE INDEX IF NOT EXISTS idx_committed_height ON committed(height);

            -- Persistent consensus state: survives restarts.
            CREATE TABLE IF NOT EXISTS consensus_meta (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS consensus_votes (
                round     INTEGER NOT NULL,
                node_hash BLOB    NOT NULL,
                voter_did TEXT    NOT NULL,
                signature BLOB   NOT NULL,
                PRIMARY KEY (round, node_hash, voter_did)
            );

            CREATE TABLE IF NOT EXISTS commit_certificates (
                node_hash BLOB PRIMARY KEY NOT NULL,
                round     INTEGER NOT NULL,
                cbor_data BLOB    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS validators (
                did TEXT PRIMARY KEY NOT NULL
            );

            CREATE TABLE IF NOT EXISTS trust_receipts (
                receipt_hash BLOB PRIMARY KEY NOT NULL,
                actor_did    TEXT    NOT NULL,
                action_type  TEXT    NOT NULL,
                outcome      TEXT    NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                cbor_data    BLOB    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_receipts_actor
                ON trust_receipts(actor_did);
            CREATE INDEX IF NOT EXISTS idx_receipts_ts
                ON trust_receipts(timestamp_ms);",
        )?;

        Ok(Self { conn })
    }

    /// Convenience accessor for the current committed height.
    #[must_use]
    pub fn committed_height_value(&self) -> u64 {
        self.committed_height().unwrap_or(0)
    }

    /// Serialize a `DagNode` to CBOR bytes.
    fn encode_node(node: &DagNode) -> DagResult<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(node, &mut buf)
            .map_err(|e| store_err(format!("CBOR encode: {e}")))?;
        Ok(buf)
    }

    /// Deserialize a `DagNode` from CBOR bytes.
    fn decode_node(bytes: &[u8]) -> DagResult<DagNode> {
        ciborium::from_reader(bytes).map_err(|e| store_err(format!("CBOR decode: {e}")))
    }

    /// Query committed nodes in a height range (inclusive), ordered by height.
    ///
    /// Returns `(hash, height)` pairs. Used by state sync to serve snapshot chunks.
    pub fn committed_nodes_in_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> DagResult<Vec<(Hash256, u64)>> {
        #[allow(clippy::as_conversions)]
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT hash, height FROM committed
                 WHERE height >= ?1 AND height <= ?2
                 ORDER BY height ASC",
            )
            .map_err(store_err)?;

        #[allow(clippy::as_conversions)]
        let rows = stmt
            .query_map(params![from_height as i64, to_height as i64], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                let height: i64 = row.get(1)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok((Hash256::from_bytes(arr), height as u64))
            })
            .map_err(store_err)?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(store_err)?);
        }
        Ok(result)
    }

    // -----------------------------------------------------------------
    // Consensus state persistence
    // -----------------------------------------------------------------

    /// Save the current consensus round number.
    pub fn save_consensus_round(&mut self, round: u64) -> DagResult<()> {
        #[allow(clippy::as_conversions)]
        self.conn
            .execute(
                "INSERT OR REPLACE INTO consensus_meta (key, value) VALUES ('round', ?1)",
                params![round.to_string()],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// Load the persisted consensus round number (0 if none).
    pub fn load_consensus_round(&self) -> DagResult<u64> {
        let result: Result<String, _> = self.conn.query_row(
            "SELECT value FROM consensus_meta WHERE key = 'round'",
            [],
            |row| row.get(0),
        );
        match result {
            Ok(s) => s.parse::<u64>().map_err(store_err),
            Err(_) => Ok(0),
        }
    }

    /// Persist a consensus vote.
    pub fn save_vote(&mut self, vote: &Vote) -> DagResult<()> {
        #[allow(clippy::as_conversions)]
        self.conn
            .execute(
                "INSERT OR IGNORE INTO consensus_votes (round, node_hash, voter_did, signature) VALUES (?1, ?2, ?3, ?4)",
                params![
                    vote.round as i64,
                    vote.node_hash.0.as_slice(),
                    vote.voter.to_string(),
                    vote.signature.as_bytes(),
                ],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// Load all votes for a given round.
    pub fn load_votes_for_round(&self, round: u64) -> DagResult<Vec<Vote>> {
        #[allow(clippy::as_conversions)]
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT node_hash, voter_did, signature FROM consensus_votes WHERE round = ?1",
            )
            .map_err(store_err)?;

        #[allow(clippy::as_conversions)]
        let rows = stmt
            .query_map(params![round as i64], |row| {
                let hash_bytes: Vec<u8> = row.get(0)?;
                let voter_str: String = row.get(1)?;
                let sig_bytes: Vec<u8> = row.get(2)?;

                let mut hash_arr = [0u8; 32];
                hash_arr.copy_from_slice(&hash_bytes);
                let mut sig_arr = [0u8; 64];
                if sig_bytes.len() == 64 {
                    sig_arr.copy_from_slice(&sig_bytes);
                }

                Ok(Vote {
                    #[allow(clippy::expect_used)] // Hardcoded constant — always valid.
                    voter: Did::new(&voter_str)
                        .unwrap_or_else(|_| Did::new("did:exo:unknown").expect("hardcoded DID")),
                    round,
                    node_hash: Hash256::from_bytes(hash_arr),
                    signature: exo_core::types::Signature::from_bytes(sig_arr),
                })
            })
            .map_err(store_err)?;

        let mut votes = Vec::new();
        for row in rows {
            votes.push(row.map_err(store_err)?);
        }
        Ok(votes)
    }

    /// Persist a commit certificate.
    pub fn save_certificate(&mut self, cert: &CommitCertificate) -> DagResult<()> {
        let mut cbor_buf = Vec::new();
        ciborium::into_writer(cert, &mut cbor_buf)
            .map_err(|e| store_err(format!("CBOR encode certificate: {e}")))?;

        #[allow(clippy::as_conversions)]
        self.conn
            .execute(
                "INSERT OR IGNORE INTO commit_certificates (node_hash, round, cbor_data) VALUES (?1, ?2, ?3)",
                params![
                    cert.node_hash.0.as_slice(),
                    cert.round as i64,
                    cbor_buf,
                ],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// Load all persisted commit certificates.
    pub fn load_certificates(&self) -> DagResult<Vec<CommitCertificate>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT cbor_data FROM commit_certificates ORDER BY round ASC")
            .map_err(store_err)?;

        let rows = stmt
            .query_map([], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(bytes)
            })
            .map_err(store_err)?;

        let mut certs = Vec::new();
        for row in rows {
            let bytes = row.map_err(store_err)?;
            let cert: CommitCertificate = ciborium::from_reader(bytes.as_slice())
                .map_err(|e| store_err(format!("CBOR decode certificate: {e}")))?;
            certs.push(cert);
        }
        Ok(certs)
    }

    // -----------------------------------------------------------------
    // Validator set persistence
    // -----------------------------------------------------------------

    /// Save the current validator set to the database.
    pub fn save_validator_set(&mut self, validators: &BTreeSet<Did>) -> DagResult<()> {
        self.conn
            .execute("DELETE FROM validators", [])
            .map_err(store_err)?;
        for did in validators {
            self.conn
                .execute(
                    "INSERT INTO validators (did) VALUES (?1)",
                    params![did.to_string()],
                )
                .map_err(store_err)?;
        }
        Ok(())
    }

    /// Load the persisted validator set (empty if none saved).
    pub fn load_validator_set(&self) -> DagResult<BTreeSet<Did>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT did FROM validators ORDER BY did ASC")
            .map_err(store_err)?;

        let rows = stmt
            .query_map([], |row| {
                let did_str: String = row.get(0)?;
                Ok(did_str)
            })
            .map_err(store_err)?;

        let mut set = BTreeSet::new();
        for row in rows {
            let did_str = row.map_err(store_err)?;
            if let Ok(did) = Did::new(&did_str) {
                set.insert(did);
            }
        }
        Ok(set)
    }

    /// Save a trust receipt to the database.
    pub fn save_receipt(&mut self, receipt: &exo_core::types::TrustReceipt) -> DagResult<()> {
        let mut buf = Vec::new();
        ciborium::into_writer(receipt, &mut buf)
            .map_err(|e| store_err(format!("CBOR encode receipt: {e}")))?;

        self.conn
            .execute(
                "INSERT OR IGNORE INTO trust_receipts (receipt_hash, actor_did, action_type, outcome, timestamp_ms, cbor_data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    receipt.receipt_hash.0.as_slice(),
                    receipt.actor_did.to_string(),
                    receipt.action_type,
                    receipt.outcome.to_string(),
                    receipt.timestamp.physical_ms as i64,
                    buf,
                ],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// Load a trust receipt by its hash.
    pub fn load_receipt(
        &self,
        receipt_hash: &Hash256,
    ) -> DagResult<Option<exo_core::types::TrustReceipt>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT cbor_data FROM trust_receipts WHERE receipt_hash = ?1")
            .map_err(store_err)?;

        let mut rows = stmt
            .query_map(params![receipt_hash.0.as_slice()], |row| {
                let data: Vec<u8> = row.get(0)?;
                Ok(data)
            })
            .map_err(store_err)?;

        match rows.next() {
            Some(row) => {
                let data = row.map_err(store_err)?;
                let receipt: exo_core::types::TrustReceipt = ciborium::from_reader(&data[..])
                    .map_err(|e| store_err(format!("CBOR decode receipt: {e}")))?;
                Ok(Some(receipt))
            }
            None => Ok(None),
        }
    }

    /// Load receipts by actor DID, ordered by timestamp descending.
    pub fn load_receipts_by_actor(
        &self,
        actor_did: &str,
        limit: u32,
    ) -> DagResult<Vec<exo_core::types::TrustReceipt>> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT cbor_data FROM trust_receipts WHERE actor_did = ?1 ORDER BY timestamp_ms DESC LIMIT ?2",
            )
            .map_err(store_err)?;

        let rows = stmt
            .query_map(params![actor_did, limit], |row| {
                let data: Vec<u8> = row.get(0)?;
                Ok(data)
            })
            .map_err(store_err)?;

        let mut receipts = Vec::new();
        for row in rows {
            let data = row.map_err(store_err)?;
            let receipt: exo_core::types::TrustReceipt = ciborium::from_reader(&data[..])
                .map_err(|e| store_err(format!("CBOR decode receipt: {e}")))?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    /// Find all child nodes of a given parent hash.
    pub fn children(&self, parent_hash: &Hash256) -> DagResult<Vec<Hash256>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT child_hash FROM dag_parents WHERE parent_hash = ?1")
            .map_err(store_err)?;

        let rows = stmt
            .query_map(params![parent_hash.0.as_slice()], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Hash256::from_bytes(arr))
            })
            .map_err(store_err)?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(store_err)?);
        }
        Ok(result)
    }

    /// Check whether a node hash is committed.
    #[allow(dead_code)]
    pub fn is_committed(&self, hash: &Hash256) -> DagResult<bool> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT 1 FROM committed WHERE hash = ?1")
            .map_err(store_err)?;
        Ok(stmt
            .query_row(params![hash.0.as_slice()], |_| Ok(()))
            .is_ok())
    }

    /// Get the committed height for a specific hash (if committed).
    pub fn committed_height_for(&self, hash: &Hash256) -> DagResult<Option<u64>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT height FROM committed WHERE hash = ?1")
            .map_err(store_err)?;

        match stmt.query_row(params![hash.0.as_slice()], |row| {
            let h: i64 = row.get(0)?;
            #[allow(clippy::as_conversions)]
            Ok(h as u64)
        }) {
            Ok(h) => Ok(Some(h)),
            Err(_) => Ok(None),
        }
    }

    /// Get all committed nodes with their full DagNode data, ordered by height.
    ///
    /// Used by state sync to serve snapshot chunks with actual node payloads.
    pub fn committed_dag_nodes_in_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> DagResult<Vec<DagNode>> {
        let committed = self.committed_nodes_in_range(from_height, to_height)?;
        let mut nodes = Vec::with_capacity(committed.len());
        for (hash, _height) in committed {
            if let Some(node) = self.get(&hash)? {
                nodes.push(node);
            }
        }
        Ok(nodes)
    }
}

impl DagStore for SqliteDagStore {
    fn get(&self, hash: &Hash256) -> DagResult<Option<DagNode>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT cbor_payload FROM dag_nodes WHERE hash = ?1")
            .map_err(store_err)?;

        let result: Option<Vec<u8>> = stmt
            .query_row(params![hash.0.as_slice()], |row| row.get(0))
            .ok();

        match result {
            Some(bytes) => Ok(Some(Self::decode_node(&bytes)?)),
            None => Ok(None),
        }
    }

    fn put(&mut self, node: DagNode) -> DagResult<()> {
        let cbor = Self::encode_node(&node)?;

        self.conn
            .execute(
                "INSERT OR IGNORE INTO dag_nodes (hash, cbor_payload) VALUES (?1, ?2)",
                params![node.hash.0.as_slice(), cbor],
            )
            .map_err(store_err)?;

        // Record parent relationships.
        for parent in &node.parents {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO dag_parents (child_hash, parent_hash) VALUES (?1, ?2)",
                    params![node.hash.0.as_slice(), parent.0.as_slice()],
                )
                .map_err(store_err)?;
        }

        Ok(())
    }

    fn contains(&self, hash: &Hash256) -> DagResult<bool> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT 1 FROM dag_nodes WHERE hash = ?1")
            .map_err(store_err)?;

        let exists = stmt
            .query_row(params![hash.0.as_slice()], |_| Ok(()))
            .is_ok();

        Ok(exists)
    }

    fn tips(&self) -> DagResult<Vec<Hash256>> {
        // Tips are nodes that are not parents of any other node.
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT hash FROM dag_nodes
                 WHERE hash NOT IN (SELECT parent_hash FROM dag_parents)
                 ORDER BY hash",
            )
            .map_err(store_err)?;

        let rows = stmt
            .query_map([], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Hash256::from_bytes(arr))
            })
            .map_err(store_err)?;

        let mut tips = Vec::new();
        for row in rows {
            tips.push(row.map_err(store_err)?);
        }
        Ok(tips)
    }

    fn committed_height(&self) -> DagResult<u64> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT COALESCE(MAX(height), 0) FROM committed")
            .map_err(store_err)?;

        let height: i64 = stmt.query_row([], |row| row.get(0)).map_err(store_err)?;

        #[allow(clippy::as_conversions)]
        Ok(height as u64)
    }

    fn mark_committed(&mut self, hash: &Hash256, height: u64) -> DagResult<()> {
        // Verify the node exists.
        if !self.contains(hash)? {
            return Err(DagError::NodeNotFound(*hash));
        }

        #[allow(clippy::as_conversions)]
        self.conn
            .execute(
                "INSERT OR REPLACE INTO committed (hash, height) VALUES (?1, ?2)",
                params![hash.0.as_slice(), height as i64],
            )
            .map_err(store_err)?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;

    use exo_core::types::{Did, Signature};
    use exo_dag::dag::{Dag, HybridClock, append};

    use super::*;

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

    fn temp_store() -> SqliteDagStore {
        let dir = tempfile::tempdir().unwrap();
        SqliteDagStore::open(dir.path()).unwrap()
    }

    #[test]
    fn new_store_is_empty() {
        let store = temp_store();
        assert_eq!(store.committed_height().unwrap(), 0);
        assert!(store.tips().unwrap().is_empty());
    }

    #[test]
    fn put_and_get() {
        let mut store = temp_store();
        let node = make_test_node();

        store.put(node.clone()).unwrap();
        let retrieved = store.get(&node.hash).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash, node.hash);
    }

    #[test]
    fn get_nonexistent() {
        let store = temp_store();
        let result = store.get(&Hash256::ZERO).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn contains() {
        let mut store = temp_store();
        let node = make_test_node();

        assert!(!store.contains(&node.hash).unwrap());
        store.put(node.clone()).unwrap();
        assert!(store.contains(&node.hash).unwrap());
    }

    #[test]
    fn tips_single_node() {
        let mut store = temp_store();
        let node = make_test_node();
        store.put(node.clone()).unwrap();
        let t = store.tips().unwrap();
        assert_eq!(t, vec![node.hash]);
    }

    #[test]
    fn tips_with_children() {
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

        let mut store = temp_store();
        store.put(genesis).unwrap();
        store.put(child.clone()).unwrap();

        let t = store.tips().unwrap();
        assert_eq!(t, vec![child.hash]);
    }

    #[test]
    fn committed_height_tracking() {
        let mut store = temp_store();
        let node = make_test_node();
        store.put(node.clone()).unwrap();

        assert_eq!(store.committed_height().unwrap(), 0);

        store.mark_committed(&node.hash, 1).unwrap();
        assert_eq!(store.committed_height().unwrap(), 1);
    }

    #[test]
    fn mark_committed_nonexistent_fails() {
        let mut store = temp_store();
        let err = store.mark_committed(&Hash256::ZERO, 1).unwrap_err();
        assert!(matches!(err, DagError::NodeNotFound(_)));
    }

    #[test]
    fn consensus_round_persistence() {
        let mut store = temp_store();
        assert_eq!(store.load_consensus_round().unwrap(), 0);
        store.save_consensus_round(42).unwrap();
        assert_eq!(store.load_consensus_round().unwrap(), 42);
        store.save_consensus_round(100).unwrap();
        assert_eq!(store.load_consensus_round().unwrap(), 100);
    }

    #[test]
    fn vote_persistence_roundtrip() {
        use exo_core::types::Signature;
        let mut store = temp_store();
        let did = Did::new("did:exo:voter1").unwrap();
        let mut hash = [0u8; 32];
        hash[0] = 0xAB;
        let vote = Vote {
            voter: did.clone(),
            round: 5,
            node_hash: Hash256::from_bytes(hash),
            signature: Signature::from_bytes([7u8; 64]),
        };
        store.save_vote(&vote).unwrap();

        let loaded = store.load_votes_for_round(5).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].voter, did);
        assert_eq!(loaded[0].round, 5);
        assert_eq!(loaded[0].node_hash, Hash256::from_bytes(hash));

        // Different round returns empty.
        let empty = store.load_votes_for_round(6).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn certificate_persistence_roundtrip() {
        use exo_core::types::Signature;
        let mut store = temp_store();
        let mut hash = [0u8; 32];
        hash[0] = 0xCD;
        let cert = CommitCertificate {
            node_hash: Hash256::from_bytes(hash),
            round: 3,
            votes: vec![Vote {
                voter: Did::new("did:exo:v0").unwrap(),
                round: 3,
                node_hash: Hash256::from_bytes(hash),
                signature: Signature::from_bytes([1u8; 64]),
            }],
        };
        store.save_certificate(&cert).unwrap();

        let loaded = store.load_certificates().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].round, 3);
        assert_eq!(loaded[0].node_hash, Hash256::from_bytes(hash));
        assert_eq!(loaded[0].votes.len(), 1);
    }

    #[test]
    fn validator_set_persistence() {
        let mut store = temp_store();
        let empty = store.load_validator_set().unwrap();
        assert!(empty.is_empty());

        let mut set = BTreeSet::new();
        set.insert(Did::new("did:exo:v0").unwrap());
        set.insert(Did::new("did:exo:v1").unwrap());
        set.insert(Did::new("did:exo:v2").unwrap());
        store.save_validator_set(&set).unwrap();

        let loaded = store.load_validator_set().unwrap();
        assert_eq!(loaded.len(), 3);
        assert!(loaded.contains(&Did::new("did:exo:v0").unwrap()));
        assert!(loaded.contains(&Did::new("did:exo:v2").unwrap()));

        // Overwrite with smaller set.
        let mut smaller = BTreeSet::new();
        smaller.insert(Did::new("did:exo:v0").unwrap());
        store.save_validator_set(&smaller).unwrap();
        let loaded2 = store.load_validator_set().unwrap();
        assert_eq!(loaded2.len(), 1);
    }

    #[test]
    fn receipt_save_and_load_by_hash() {
        use exo_core::types::{ReceiptOutcome, Timestamp, TrustReceipt};
        let mut store = temp_store();
        let sign_fn = make_sign_fn();

        let receipt = TrustReceipt::new(
            Did::new("did:exo:agent-a").unwrap(),
            Hash256::ZERO,
            None,
            "dag.commit".to_string(),
            Hash256::digest(b"action-payload"),
            ReceiptOutcome::Executed,
            Timestamp {
                physical_ms: 1_700_000_000_000,
                logical: 0,
            },
            &*sign_fn,
        );

        let hash = receipt.receipt_hash;
        store.save_receipt(&receipt).unwrap();

        let loaded = store.load_receipt(&hash).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.receipt_hash, hash);
        assert_eq!(loaded.actor_did.to_string(), "did:exo:agent-a");
        assert_eq!(loaded.action_type, "dag.commit");
        assert_eq!(loaded.outcome, ReceiptOutcome::Executed);
    }

    #[test]
    fn receipt_load_nonexistent() {
        let store = temp_store();
        let result = store.load_receipt(&Hash256::ZERO).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn receipt_load_by_actor_filters_and_limits() {
        use exo_core::types::{ReceiptOutcome, Timestamp, TrustReceipt};
        let mut store = temp_store();
        let sign_fn = make_sign_fn();

        // Save 3 receipts for actor-a at different timestamps.
        for i in 0u64..3 {
            let receipt = TrustReceipt::new(
                Did::new("did:exo:actor-a").unwrap(),
                Hash256::ZERO,
                None,
                format!("action.{i}"),
                Hash256::digest(format!("payload-{i}").as_bytes()),
                ReceiptOutcome::Executed,
                Timestamp {
                    physical_ms: 1_000_000 + i * 1000,
                    logical: 0,
                },
                &*sign_fn,
            );
            store.save_receipt(&receipt).unwrap();
        }

        // Save 1 receipt for actor-b.
        let other = TrustReceipt::new(
            Did::new("did:exo:actor-b").unwrap(),
            Hash256::ZERO,
            None,
            "other.action".to_string(),
            Hash256::digest(b"other"),
            ReceiptOutcome::Denied,
            Timestamp {
                physical_ms: 2_000_000,
                logical: 0,
            },
            &*sign_fn,
        );
        store.save_receipt(&other).unwrap();

        // Query actor-a — should get 3 receipts.
        let results = store.load_receipts_by_actor("did:exo:actor-a", 10).unwrap();
        assert_eq!(results.len(), 3);

        // Query with limit 2 — should get 2 (most recent first).
        let limited = store.load_receipts_by_actor("did:exo:actor-a", 2).unwrap();
        assert_eq!(limited.len(), 2);
        // Ordered by timestamp descending.
        assert!(limited[0].timestamp.physical_ms >= limited[1].timestamp.physical_ms);

        // Query actor-b — should get 1 receipt.
        let b_results = store.load_receipts_by_actor("did:exo:actor-b", 10).unwrap();
        assert_eq!(b_results.len(), 1);
        assert_eq!(b_results[0].outcome, ReceiptOutcome::Denied);

        // Query unknown actor — should get 0.
        let none = store.load_receipts_by_actor("did:exo:unknown", 10).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn multiple_tips() {
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

        let mut store = temp_store();
        store.put(genesis).unwrap();
        store.put(c1.clone()).unwrap();
        store.put(c2.clone()).unwrap();

        let t = store.tips().unwrap();
        assert_eq!(t.len(), 2);
        assert!(t.contains(&c1.hash));
        assert!(t.contains(&c2.hash));
    }
}
