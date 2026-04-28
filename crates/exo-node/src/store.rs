//! SQLite-backed `DagStore` implementation.
//!
//! Each node persists the DAG and committed state in a local SQLite database.
//! This implementation mirrors `MemoryStore` from `exo-dag` but uses durable
//! storage so state survives restarts.

#![allow(clippy::as_conversions)]

use std::{collections::BTreeSet, path::Path};

use exo_core::types::{Did, Hash256, Signature};
use exo_dag::{
    consensus::{CommitCertificate, Vote},
    dag::DagNode,
    error::{DagError, Result as DagResult},
};

/// Map a SQLite / CBOR error into `DagError::StoreError`.
fn store_err(e: impl std::fmt::Display) -> DagError {
    DagError::StoreError(e.to_string())
}
use rusqlite::{Connection, params};

fn sqlite_u64_to_i64(value: u64, field: &str) -> DagResult<i64> {
    i64::try_from(value)
        .map_err(|_| store_err(format!("{field} value {value} exceeds SQLite INTEGER max")))
}

#[allow(clippy::as_conversions)]
fn sqlite_i64_to_u64(value: i64, field: &str) -> DagResult<u64> {
    if value < 0 {
        return Err(store_err(format!("{field} value {value} is negative")));
    }
    Ok(value as u64)
}

fn decode_hash_bytes(bytes: &[u8], field: &str) -> DagResult<Hash256> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| store_err(format!("{field} must be 32 bytes, got {}", bytes.len())))?;
    Ok(Hash256::from_bytes(arr))
}

fn decode_signature_bytes(bytes: &[u8], field: &str) -> DagResult<Signature> {
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| store_err(format!("{field} must be 64 bytes, got {}", bytes.len())))?;
    let signature = Signature::from_bytes(arr);
    validate_signature(&signature, field)?;
    Ok(signature)
}

fn validate_signature(signature: &Signature, field: &str) -> DagResult<()> {
    if signature.is_empty() {
        return Err(store_err(format!("{field} must not be empty or all-zero")));
    }
    Ok(())
}

fn validate_ed25519_signature<'a>(
    signature: &'a Signature,
    field: &str,
) -> DagResult<&'a [u8; 64]> {
    let Signature::Ed25519(bytes) = signature else {
        return Err(store_err(format!(
            "{field} must be an Ed25519 signature for consensus persistence"
        )));
    };
    if bytes.iter().all(|b| *b == 0) {
        return Err(store_err(format!("{field} must not be empty or all-zero")));
    }
    Ok(bytes)
}

fn decode_did(value: &str, field: &str) -> DagResult<Did> {
    Did::new(value).map_err(|e| store_err(format!("{field} is invalid: {e}")))
}

fn validate_vote(vote: &Vote, context: &str) -> DagResult<()> {
    validate_ed25519_signature(&vote.signature, &format!("{context}.signature"))?;
    Ok(())
}

fn validate_commit_certificate(cert: &CommitCertificate) -> DagResult<()> {
    if cert.votes.is_empty() {
        return Err(store_err("commit_certificates.votes must not be empty"));
    }

    for (idx, vote) in cert.votes.iter().enumerate() {
        let context = format!("commit_certificates.votes[{idx}]");
        if vote.round != cert.round {
            return Err(store_err(format!(
                "{context}.round {} does not match certificate round {}",
                vote.round, cert.round
            )));
        }
        if vote.node_hash != cert.node_hash {
            return Err(store_err(format!(
                "{context}.node_hash does not match certificate node_hash"
            )));
        }
        validate_vote(vote, &context)?;
    }

    Ok(())
}

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
    pub fn committed_height_value(&self) -> DagResult<u64> {
        self.committed_height_sync()
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
        let from_height = sqlite_u64_to_i64(from_height, "committed.from_height")?;
        let to_height = sqlite_u64_to_i64(to_height, "committed.to_height")?;
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT hash, height FROM committed
                 WHERE height >= ?1 AND height <= ?2
                 ORDER BY height ASC",
            )
            .map_err(store_err)?;

        let rows = stmt
            .query_map(params![from_height, to_height], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                let height: i64 = row.get(1)?;
                Ok((bytes, height))
            })
            .map_err(store_err)?;

        let mut result = Vec::new();
        for row in rows {
            let (bytes, height) = row.map_err(store_err)?;
            result.push((
                decode_hash_bytes(&bytes, "committed.hash")?,
                sqlite_i64_to_u64(height, "committed.height")?,
            ));
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
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => Err(store_err(e)),
        }
    }

    /// Persist a consensus vote.
    pub fn save_vote(&mut self, vote: &Vote) -> DagResult<()> {
        let round = sqlite_u64_to_i64(vote.round, "consensus_votes.round")?;
        validate_vote(vote, "consensus_votes")?;
        let signature = validate_ed25519_signature(&vote.signature, "consensus_votes.signature")?;

        self.conn
            .execute(
                "INSERT OR IGNORE INTO consensus_votes (round, node_hash, voter_did, signature) VALUES (?1, ?2, ?3, ?4)",
                params![
                    round,
                    vote.node_hash.0.as_slice(),
                    vote.voter.to_string(),
                    signature,
                ],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// Load all votes for a given round.
    pub fn load_votes_for_round(&self, round: u64) -> DagResult<Vec<Vote>> {
        let round_i64 = sqlite_u64_to_i64(round, "consensus_votes.round")?;
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT node_hash, voter_did, signature FROM consensus_votes WHERE round = ?1",
            )
            .map_err(store_err)?;

        let rows = stmt
            .query_map(params![round_i64], |row| {
                let hash_bytes: Vec<u8> = row.get(0)?;
                let voter_str: String = row.get(1)?;
                let sig_bytes: Vec<u8> = row.get(2)?;
                Ok((hash_bytes, voter_str, sig_bytes))
            })
            .map_err(store_err)?;

        let mut votes = Vec::new();
        for row in rows {
            let (hash_bytes, voter_str, sig_bytes) = row.map_err(store_err)?;
            votes.push(Vote {
                voter: decode_did(&voter_str, "consensus_votes.voter_did")?,
                round,
                node_hash: decode_hash_bytes(&hash_bytes, "consensus_votes.node_hash")?,
                signature: decode_signature_bytes(&sig_bytes, "consensus_votes.signature")?,
            });
        }
        Ok(votes)
    }

    /// Persist a commit certificate.
    pub fn save_certificate(&mut self, cert: &CommitCertificate) -> DagResult<()> {
        let round = sqlite_u64_to_i64(cert.round, "commit_certificates.round")?;
        validate_commit_certificate(cert)?;

        let mut cbor_buf = Vec::new();
        ciborium::into_writer(cert, &mut cbor_buf)
            .map_err(|e| store_err(format!("CBOR encode certificate: {e}")))?;

        self.conn
            .execute(
                "INSERT OR IGNORE INTO commit_certificates (node_hash, round, cbor_data) VALUES (?1, ?2, ?3)",
                params![
                    cert.node_hash.0.as_slice(),
                    round,
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
            validate_commit_certificate(&cert)?;
            certs.push(cert);
        }
        Ok(certs)
    }

    // -----------------------------------------------------------------
    // Validator set persistence
    // -----------------------------------------------------------------

    /// Save the current validator set to the database.
    ///
    /// Only used today from inside the gated
    /// `#[cfg(feature = "unaudited-admin-governance-shortcut")]` path
    /// in `api.rs`. When RED #1 is reworked into real propose→commit
    /// via the reactor, this method will be invoked from that path
    /// instead and the `#[allow(dead_code)]` can come off.
    #[allow(dead_code)]
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
            let did = decode_did(&did_str, "validators.did")?;
            set.insert(did);
        }
        Ok(set)
    }

    /// Save a trust receipt to the database.
    pub fn save_receipt(&mut self, receipt: &exo_core::types::TrustReceipt) -> DagResult<()> {
        validate_signature(&receipt.signature, "trust_receipts.signature")?;
        let timestamp_ms =
            sqlite_u64_to_i64(receipt.timestamp.physical_ms, "trust_receipts.timestamp_ms")?;

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
                    timestamp_ms,
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
                Ok(bytes)
            })
            .map_err(store_err)?;

        let mut result = Vec::new();
        for row in rows {
            let bytes = row.map_err(store_err)?;
            result.push(decode_hash_bytes(&bytes, "dag_parents.child_hash")?);
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
            Ok(h)
        }) {
            Ok(h) => Ok(Some(sqlite_i64_to_u64(h, "committed.height")?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(store_err(e)),
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
            if let Some(node) = self.get_sync(&hash)? {
                nodes.push(node);
            }
        }
        Ok(nodes)
    }
}

// ---------------------------------------------------------------------------
// Sync helper methods — used by callers holding std::sync::Mutex locks.
// The async DagStore trait impl delegates to these.
// ---------------------------------------------------------------------------

impl SqliteDagStore {
    /// Sync version of `DagStore::get`.
    pub fn get_sync(&self, hash: &Hash256) -> DagResult<Option<DagNode>> {
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

    /// Sync version of `DagStore::put`.
    pub fn put_sync(&mut self, node: DagNode) -> DagResult<()> {
        let cbor = Self::encode_node(&node)?;

        self.conn
            .execute(
                "INSERT OR IGNORE INTO dag_nodes (hash, cbor_payload) VALUES (?1, ?2)",
                params![node.hash.0.as_slice(), cbor],
            )
            .map_err(store_err)?;

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

    /// Sync version of `DagStore::contains`.
    pub fn contains_sync(&self, hash: &Hash256) -> DagResult<bool> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT 1 FROM dag_nodes WHERE hash = ?1")
            .map_err(store_err)?;

        let exists = stmt
            .query_row(params![hash.0.as_slice()], |_| Ok(()))
            .is_ok();

        Ok(exists)
    }

    /// Sync version of `DagStore::tips`.
    pub fn tips_sync(&self) -> DagResult<Vec<Hash256>> {
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
                Ok(bytes)
            })
            .map_err(store_err)?;

        let mut tips = Vec::new();
        for row in rows {
            let bytes = row.map_err(store_err)?;
            tips.push(decode_hash_bytes(&bytes, "dag_nodes.hash")?);
        }
        Ok(tips)
    }

    /// Sync version of `DagStore::committed_height`.
    pub fn committed_height_sync(&self) -> DagResult<u64> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT COALESCE(MAX(height), 0) FROM committed")
            .map_err(store_err)?;

        let height: i64 = stmt.query_row([], |row| row.get(0)).map_err(store_err)?;

        sqlite_i64_to_u64(height, "committed.height")
    }

    /// Sync version of `DagStore::mark_committed`.
    pub fn mark_committed_sync(&mut self, hash: &Hash256, height: u64) -> DagResult<()> {
        if !self.contains_sync(hash)? {
            return Err(DagError::NodeNotFound(*hash));
        }

        let height = sqlite_u64_to_i64(height, "committed.height")?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO committed (hash, height) VALUES (?1, ?2)",
                params![hash.0.as_slice(), height],
            )
            .map_err(store_err)?;

        Ok(())
    }
}

// NOTE: SqliteDagStore does NOT implement the async DagStore trait because
// rusqlite::Connection is !Sync. Callers use the _sync methods directly
// (via Arc<Mutex<SqliteDagStore>>). The async DagStore trait is implemented
// by MemoryStore (exo-dag) and PostgresStore (exo-dag, postgres feature).

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;

    use exo_core::types::{Did, Signature};
    use exo_dag::dag::{Dag, DeterministicDagClock, append};

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
        let mut clock = DeterministicDagClock::new();
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
        assert_eq!(store.committed_height_sync().unwrap(), 0);
        assert!(store.tips_sync().unwrap().is_empty());
    }

    #[test]
    fn put_and_get() {
        let mut store = temp_store();
        let node = make_test_node();

        store.put_sync(node.clone()).unwrap();
        let retrieved = store.get_sync(&node.hash).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash, node.hash);
    }

    #[test]
    fn get_nonexistent() {
        let store = temp_store();
        let result = store.get_sync(&Hash256::ZERO).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn contains() {
        let mut store = temp_store();
        let node = make_test_node();

        assert!(!store.contains_sync(&node.hash).unwrap());
        store.put_sync(node.clone()).unwrap();
        assert!(store.contains_sync(&node.hash).unwrap());
    }

    #[test]
    fn tips_single_node() {
        let mut store = temp_store();
        let node = make_test_node();
        store.put_sync(node.clone()).unwrap();
        let t = store.tips_sync().unwrap();
        assert_eq!(t, vec![node.hash]);
    }

    #[test]
    fn tips_with_children() {
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
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
        store.put_sync(genesis).unwrap();
        store.put_sync(child.clone()).unwrap();

        let t = store.tips_sync().unwrap();
        assert_eq!(t, vec![child.hash]);
    }

    #[test]
    fn committed_height_tracking() {
        let mut store = temp_store();
        let node = make_test_node();
        store.put_sync(node.clone()).unwrap();

        assert_eq!(store.committed_height_sync().unwrap(), 0);

        store.mark_committed_sync(&node.hash, 1).unwrap();
        assert_eq!(store.committed_height_sync().unwrap(), 1);
    }

    #[test]
    fn mark_committed_nonexistent_fails() {
        let mut store = temp_store();
        let err = store.mark_committed_sync(&Hash256::ZERO, 1).unwrap_err();
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
    fn load_consensus_round_propagates_store_errors() {
        let store = temp_store();
        store.conn.execute("DROP TABLE consensus_meta", []).unwrap();

        let err = store.load_consensus_round().unwrap_err();

        assert!(err.to_string().contains("consensus_meta"));
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
    fn load_votes_for_round_rejects_short_hash() {
        let store = temp_store();
        store
            .conn
            .execute(
                "INSERT INTO consensus_votes (round, node_hash, voter_did, signature)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![7_i64, vec![0xABu8; 31], "did:exo:voter1", vec![7u8; 64]],
            )
            .unwrap();

        let err = store.load_votes_for_round(7).unwrap_err();

        assert!(err.to_string().contains("consensus_votes.node_hash"));
    }

    #[test]
    fn load_votes_for_round_rejects_short_signature() {
        let store = temp_store();
        let mut hash = [0u8; 32];
        hash[0] = 0xAB;
        store
            .conn
            .execute(
                "INSERT INTO consensus_votes (round, node_hash, voter_did, signature)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![7_i64, hash.as_slice(), "did:exo:voter1", vec![7u8; 63]],
            )
            .unwrap();

        let err = store.load_votes_for_round(7).unwrap_err();

        assert!(err.to_string().contains("consensus_votes.signature"));
    }

    #[test]
    fn load_votes_for_round_rejects_zero_signature() {
        let store = temp_store();
        let mut hash = [0u8; 32];
        hash[0] = 0xAB;
        store
            .conn
            .execute(
                "INSERT INTO consensus_votes (round, node_hash, voter_did, signature)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![7_i64, hash.as_slice(), "did:exo:voter1", vec![0u8; 64]],
            )
            .unwrap();

        let err = store.load_votes_for_round(7).unwrap_err();

        assert!(err.to_string().contains("consensus_votes.signature"));
    }

    #[test]
    fn load_votes_for_round_rejects_invalid_voter_did() {
        let store = temp_store();
        let mut hash = [0u8; 32];
        hash[0] = 0xAB;
        store
            .conn
            .execute(
                "INSERT INTO consensus_votes (round, node_hash, voter_did, signature)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![7_i64, hash.as_slice(), "not-a-did", vec![7u8; 64]],
            )
            .unwrap();

        let err = store.load_votes_for_round(7).unwrap_err();

        assert!(err.to_string().contains("consensus_votes.voter_did"));
    }

    #[test]
    fn save_vote_rejects_empty_signature() {
        let mut store = temp_store();
        let vote = Vote {
            voter: Did::new("did:exo:voter1").unwrap(),
            round: 5,
            node_hash: Hash256::digest(b"vote-target"),
            signature: Signature::from_bytes([0u8; 64]),
        };

        let err = store.save_vote(&vote).unwrap_err();

        assert!(err.to_string().contains("consensus_votes.signature"));
    }

    #[test]
    fn save_vote_rejects_signature_variants_that_cannot_roundtrip() {
        let mut store = temp_store();
        let vote = Vote {
            voter: Did::new("did:exo:voter1").unwrap(),
            round: 5,
            node_hash: Hash256::digest(b"vote-target"),
            signature: Signature::PostQuantum(vec![7u8; 64]),
        };

        let err = store.save_vote(&vote).unwrap_err();

        assert!(err.to_string().contains("consensus_votes.signature"));
    }

    #[test]
    fn save_vote_rejects_rounds_that_do_not_fit_sqlite_integer() {
        let mut store = temp_store();
        let vote = Vote {
            voter: Did::new("did:exo:voter1").unwrap(),
            round: u64::MAX,
            node_hash: Hash256::digest(b"vote-target"),
            signature: Signature::from_bytes([7u8; 64]),
        };

        let err = store.save_vote(&vote).unwrap_err();

        assert!(err.to_string().contains("consensus_votes.round"));
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
    fn save_certificate_rejects_empty_vote_signature() {
        let mut store = temp_store();
        let hash = Hash256::digest(b"cert-target");
        let cert = CommitCertificate {
            node_hash: hash,
            round: 3,
            votes: vec![Vote {
                voter: Did::new("did:exo:v0").unwrap(),
                round: 3,
                node_hash: hash,
                signature: Signature::Empty,
            }],
        };

        let err = store.save_certificate(&cert).unwrap_err();

        assert!(
            err.to_string()
                .contains("commit_certificates.votes[0].signature")
        );
    }

    #[test]
    fn save_certificate_rejects_signature_variants_that_cannot_verify() {
        let mut store = temp_store();
        let hash = Hash256::digest(b"cert-target");
        let cert = CommitCertificate {
            node_hash: hash,
            round: 3,
            votes: vec![Vote {
                voter: Did::new("did:exo:v0").unwrap(),
                round: 3,
                node_hash: hash,
                signature: Signature::PostQuantum(vec![7u8; 64]),
            }],
        };

        let err = store.save_certificate(&cert).unwrap_err();

        assert!(
            err.to_string()
                .contains("commit_certificates.votes[0].signature")
        );
    }

    #[test]
    fn load_certificates_rejects_empty_vote_signature() {
        let store = temp_store();
        let hash = Hash256::digest(b"cert-target");
        let cert = CommitCertificate {
            node_hash: hash,
            round: 3,
            votes: vec![Vote {
                voter: Did::new("did:exo:v0").unwrap(),
                round: 3,
                node_hash: hash,
                signature: Signature::Empty,
            }],
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&cert, &mut cbor).unwrap();
        store
            .conn
            .execute(
                "INSERT INTO commit_certificates (node_hash, round, cbor_data)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![hash.0.as_slice(), 3_i64, cbor],
            )
            .unwrap();

        let err = store.load_certificates().unwrap_err();

        assert!(
            err.to_string()
                .contains("commit_certificates.votes[0].signature")
        );
    }

    #[test]
    fn save_certificate_rejects_rounds_that_do_not_fit_sqlite_integer() {
        let mut store = temp_store();
        let hash = Hash256::digest(b"cert-target");
        let cert = CommitCertificate {
            node_hash: hash,
            round: u64::MAX,
            votes: vec![Vote {
                voter: Did::new("did:exo:v0").unwrap(),
                round: u64::MAX,
                node_hash: hash,
                signature: Signature::from_bytes([1u8; 64]),
            }],
        };

        let err = store.save_certificate(&cert).unwrap_err();

        assert!(err.to_string().contains("commit_certificates.round"));
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
    fn load_validator_set_rejects_invalid_did() {
        let store = temp_store();
        store
            .conn
            .execute("INSERT INTO validators (did) VALUES (?1)", ["not-a-did"])
            .unwrap();

        let err = store.load_validator_set().unwrap_err();

        assert!(err.to_string().contains("validators.did"));
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
        )
        .expect("test trust receipt should encode");

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
    fn save_receipt_rejects_empty_signature() {
        use exo_core::types::{ReceiptOutcome, Timestamp, TrustReceipt};
        let mut store = temp_store();

        let receipt = TrustReceipt::new(
            Did::new("did:exo:agent-a").unwrap(),
            Hash256::digest(b"authority"),
            None,
            "dag.commit".to_string(),
            Hash256::digest(b"action-payload"),
            ReceiptOutcome::Executed,
            Timestamp {
                physical_ms: 1_700_000_000_000,
                logical: 0,
            },
            &|_| Signature::Empty,
        )
        .expect("test trust receipt should encode");

        let err = store.save_receipt(&receipt).unwrap_err();

        assert!(err.to_string().contains("trust_receipts.signature"));
    }

    #[test]
    fn save_receipt_rejects_timestamps_that_do_not_fit_sqlite_integer() {
        use exo_core::types::{ReceiptOutcome, Timestamp, TrustReceipt};
        let mut store = temp_store();
        let sign_fn = make_sign_fn();

        let receipt = TrustReceipt::new(
            Did::new("did:exo:agent-a").unwrap(),
            Hash256::digest(b"authority"),
            None,
            "dag.commit".to_string(),
            Hash256::digest(b"action-payload"),
            ReceiptOutcome::Executed,
            Timestamp {
                physical_ms: u64::MAX,
                logical: 0,
            },
            &*sign_fn,
        )
        .expect("test trust receipt should encode");

        let err = store.save_receipt(&receipt).unwrap_err();

        assert!(err.to_string().contains("trust_receipts.timestamp_ms"));
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
            )
            .expect("test trust receipt should encode");
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
        )
        .expect("test trust receipt should encode");
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
        let mut clock = DeterministicDagClock::new();
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
        store.put_sync(genesis).unwrap();
        store.put_sync(c1.clone()).unwrap();
        store.put_sync(c2.clone()).unwrap();

        let t = store.tips_sync().unwrap();
        assert_eq!(t.len(), 2);
        assert!(t.contains(&c1.hash));
        assert!(t.contains(&c2.hash));
    }

    #[test]
    fn committed_nodes_in_range_rejects_short_hash() {
        let store = temp_store();
        store
            .conn
            .execute(
                "INSERT INTO committed (hash, height) VALUES (?1, ?2)",
                rusqlite::params![vec![0xCDu8; 31], 1_i64],
            )
            .unwrap();

        let err = store.committed_nodes_in_range(0, 10).unwrap_err();

        assert!(err.to_string().contains("committed.hash"));
    }

    #[test]
    fn committed_height_for_rejects_negative_height() {
        let store = temp_store();
        let hash = Hash256::digest(b"committed-node");
        store
            .conn
            .execute(
                "INSERT INTO committed (hash, height) VALUES (?1, ?2)",
                rusqlite::params![hash.0.as_slice(), -1_i64],
            )
            .unwrap();

        let err = store.committed_height_for(&hash).unwrap_err();

        assert!(err.to_string().contains("committed.height"));
    }

    #[test]
    fn committed_height_value_rejects_negative_height() {
        let store = temp_store();
        let hash = Hash256::digest(b"committed-node");
        store
            .conn
            .execute(
                "INSERT INTO committed (hash, height) VALUES (?1, ?2)",
                rusqlite::params![hash.0.as_slice(), -1_i64],
            )
            .unwrap();

        let err = store.committed_height_value().unwrap_err();

        assert!(err.to_string().contains("committed.height"));
    }

    #[test]
    fn committed_height_sync_rejects_negative_height() {
        let store = temp_store();
        let hash = Hash256::digest(b"committed-node");
        store
            .conn
            .execute(
                "INSERT INTO committed (hash, height) VALUES (?1, ?2)",
                rusqlite::params![hash.0.as_slice(), -1_i64],
            )
            .unwrap();

        let err = store.committed_height_sync().unwrap_err();

        assert!(err.to_string().contains("committed.height"));
    }

    #[test]
    fn mark_committed_rejects_heights_that_do_not_fit_sqlite_integer() {
        let mut store = temp_store();
        let node = make_test_node();
        store.put_sync(node.clone()).unwrap();

        let err = store.mark_committed_sync(&node.hash, u64::MAX).unwrap_err();

        assert!(err.to_string().contains("committed.height"));
    }

    #[test]
    fn children_rejects_short_child_hash() {
        let store = temp_store();
        let parent = Hash256::digest(b"parent");
        store
            .conn
            .execute(
                "INSERT INTO dag_parents (child_hash, parent_hash) VALUES (?1, ?2)",
                rusqlite::params![vec![0xABu8; 31], parent.0.as_slice()],
            )
            .unwrap();

        let err = store.children(&parent).unwrap_err();

        assert!(err.to_string().contains("dag_parents.child_hash"));
    }

    #[test]
    fn tips_rejects_short_hash() {
        let store = temp_store();
        store
            .conn
            .execute(
                "INSERT INTO dag_nodes (hash, cbor_payload) VALUES (?1, ?2)",
                rusqlite::params![vec![0xABu8; 31], vec![0x00u8]],
            )
            .unwrap();

        let err = store.tips_sync().unwrap_err();

        assert!(err.to_string().contains("dag_nodes.hash"));
    }
}
