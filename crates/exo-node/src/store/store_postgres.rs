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

//! `PostgresDagNodeStore` live-DB adapter methods.
//!
//! This module holds every `PostgresDagNodeStore` method that talks to a real
//! Postgres instance over `sqlx` transactions (DAG DB tenant-scoped tables).
//! It is structurally untestable by the default unit-test gate without
//! `DATABASE_URL`, applied SQLx migrations, and live database state, so it is
//! split out of `store.rs` and excluded from the tarpaulin scoped-coverage
//! gate (see `tarpaulin.toml`). The `PostgresDagNodeStore` struct definition,
//! its constructor (`DagDbNodeStore::open`), and the synchronous
//! `SqliteDagStore` facade that dispatches into these methods remain in
//! `store.rs` and stay in scope.

use std::collections::BTreeSet;

use exo_core::types::{Did, Hash256, Signature, Timestamp, TrustReceipt};
use exo_dag::{
    consensus::{CommitCertificate, Vote},
    dag::DagNode,
    error::{DagError, Result as DagResult},
};
use exo_economy::{EconomyObjectKind, EconomyRecordAnchor};
use serde::de::DeserializeOwned;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};

use super::{
    PostgresDagNodeStore, SqliteDagStore, decode_cbor, decode_did, decode_hash_bytes,
    decode_signature_bytes, encode_cbor, governance_payload_meta_key, sqlite_i64_to_u64,
    sqlite_u64_to_i64, store_err, validate_commit_certificate, validate_ed25519_signature,
    validate_signature, validate_vote,
};

fn row_type_decode_error(
    field: &'static str,
    expected_type: &'static str,
    error: sqlx::Error,
) -> DagError {
    store_err(format!(
        "{field} type decode failed (expected {expected_type}): {error}"
    ))
}

fn decode_committed_row(row: &PgRow) -> DagResult<(Hash256, u64)> {
    let hash: Vec<u8> = row
        .try_get("hash")
        .map_err(|error| row_type_decode_error("dagdb_node_committed.hash", "BYTEA", error))?;
    let height: i64 = row
        .try_get("height")
        .map_err(|error| row_type_decode_error("dagdb_node_committed.height", "BIGINT", error))?;
    Ok((
        decode_hash_bytes(&hash, "dagdb_node_committed.hash")?,
        sqlite_i64_to_u64(height, "dagdb_node_committed.height")?,
    ))
}

fn decode_vote_row(row: &PgRow) -> DagResult<(Hash256, Did, Signature)> {
    let hash_bytes: Vec<u8> = row.try_get("node_hash").map_err(|error| {
        row_type_decode_error("dagdb_node_consensus_votes.node_hash", "BYTEA", error)
    })?;
    let voter_str: String = row.try_get("voter_did").map_err(|error| {
        row_type_decode_error("dagdb_node_consensus_votes.voter_did", "TEXT", error)
    })?;
    let sig_bytes: Vec<u8> = row.try_get("signature").map_err(|error| {
        row_type_decode_error("dagdb_node_consensus_votes.signature", "BYTEA", error)
    })?;
    Ok((
        decode_hash_bytes(&hash_bytes, "dagdb_node_consensus_votes.node_hash")?,
        decode_did(&voter_str, "dagdb_node_consensus_votes.voter_did")?,
        decode_signature_bytes(&sig_bytes, "dagdb_node_consensus_votes.signature")?,
    ))
}

impl PostgresDagNodeStore {
    pub(super) async fn verify_schema(&self) -> anyhow::Result<()> {
        let mut tx =
            self.pool.begin().await.map_err(|error| {
                anyhow::anyhow!("DAG DB node store schema check failed: {error}")
            })?;
        self.bind_tenant(&mut tx)
            .await
            .map_err(|error| anyhow::anyhow!("DAG DB node store tenant binding failed: {error}"))?;
        let present: bool =
            sqlx::query_scalar("SELECT to_regclass('dagdb_node_dag_nodes') IS NOT NULL")
                .fetch_one(&mut *tx)
                .await
                .map_err(|error| {
                    anyhow::anyhow!("DAG DB node store schema lookup failed: {error}")
                })?;
        tx.commit().await.map_err(|error| {
            anyhow::anyhow!("DAG DB node store schema check commit failed: {error}")
        })?;
        if !present {
            anyhow::bail!("DAG DB node store schema is missing dagdb_node_dag_nodes");
        }
        Ok(())
    }

    async fn bind_tenant(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> std::result::Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('exo.tenant_id', $1, true)")
            .bind(&self.tenant_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    pub(super) async fn begin(&self) -> DagResult<Transaction<'_, Postgres>> {
        let mut tx = self.pool.begin().await.map_err(store_err)?;
        self.bind_tenant(&mut tx).await.map_err(store_err)?;
        Ok(tx)
    }

    async fn insert_node_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        node: &DagNode,
    ) -> DagResult<()> {
        let cbor = SqliteDagStore::encode_node(node)?;
        sqlx::query(
            "INSERT INTO dagdb_node_dag_nodes (tenant_id, namespace, hash, cbor_payload) \
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(node.hash.as_bytes().to_vec())
        .bind(cbor)
        .execute(&mut **tx)
        .await
        .map_err(store_err)?;

        for parent in &node.parents {
            sqlx::query(
                "INSERT INTO dagdb_node_dag_parents \
                 (tenant_id, namespace, child_hash, parent_hash) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            )
            .bind(&self.tenant_id)
            .bind(&self.namespace)
            .bind(node.hash.as_bytes().to_vec())
            .bind(parent.as_bytes().to_vec())
            .execute(&mut **tx)
            .await
            .map_err(store_err)?;
        }
        Ok(())
    }

    async fn ensure_node_exists_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        hash: &Hash256,
    ) -> DagResult<()> {
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM dagdb_node_dag_nodes
                 WHERE tenant_id = $1 AND namespace = $2 AND hash = $3
             )",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(hash.as_bytes().to_vec())
        .fetch_one(&mut **tx)
        .await
        .map_err(store_err)?;
        if present {
            Ok(())
        } else {
            Err(DagError::NodeNotFound(*hash))
        }
    }

    async fn insert_committed_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        hash: &Hash256,
        height: u64,
    ) -> DagResult<()> {
        let height = sqlite_u64_to_i64(height, "dagdb_node_committed.height")?;
        sqlx::query(
            "INSERT INTO dagdb_node_committed (tenant_id, namespace, hash, height) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, namespace, hash) DO UPDATE SET height = EXCLUDED.height",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(hash.as_bytes().to_vec())
        .bind(height)
        .execute(&mut **tx)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn insert_certificate_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        cert: &CommitCertificate,
    ) -> DagResult<()> {
        let round = sqlite_u64_to_i64(cert.round, "dagdb_node_commit_certificates.round")?;
        validate_commit_certificate(cert)?;
        let cbor_buf = encode_cbor(cert, "dagdb_node_commit_certificates.cbor_data")?;
        sqlx::query(
            "INSERT INTO dagdb_node_commit_certificates \
             (tenant_id, namespace, node_hash, round, cbor_data) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(cert.node_hash.as_bytes().to_vec())
        .bind(round)
        .bind(cbor_buf)
        .execute(&mut **tx)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn insert_receipt_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        receipt: &TrustReceipt,
    ) -> DagResult<()> {
        validate_signature(&receipt.signature, "dagdb_node_trust_receipts.signature")?;
        let timestamp_ms = sqlite_u64_to_i64(
            receipt.timestamp.physical_ms,
            "dagdb_node_trust_receipts.timestamp_ms",
        )?;
        let buf = encode_cbor(receipt, "dagdb_node_trust_receipts.cbor_data")?;
        sqlx::query(
            "INSERT INTO dagdb_node_trust_receipts \
             (tenant_id, namespace, receipt_hash, actor_did, action_type, outcome, timestamp_ms, cbor_data) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(receipt.receipt_hash.as_bytes().to_vec())
        .bind(receipt.actor_did.to_string())
        .bind(receipt.action_type.as_str())
        .bind(receipt.outcome.to_string())
        .bind(timestamp_ms)
        .bind(buf)
        .execute(&mut **tx)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn get_sync_async(&self, hash: &Hash256) -> DagResult<Option<DagNode>> {
        let mut tx = self.begin().await?;
        let result: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT cbor_payload FROM dagdb_node_dag_nodes \
             WHERE tenant_id = $1 AND namespace = $2 AND hash = $3",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(hash.as_bytes().to_vec())
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        result
            .map(|bytes| SqliteDagStore::decode_node(&bytes))
            .transpose()
    }

    pub(super) async fn put_many_sync_async(&self, nodes: Vec<DagNode>) -> DagResult<()> {
        let mut tx = self.begin().await?;
        for node in &nodes {
            self.insert_node_tx(&mut tx, node).await?;
        }
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn put_committed_node_with_receipt_sync_async(
        &self,
        node: DagNode,
        height: u64,
        receipt: TrustReceipt,
    ) -> DagResult<()> {
        if receipt.action_hash != node.hash {
            return Err(store_err(
                "dagdb_node_trust_receipts.action_hash must match committed node hash",
            ));
        }
        let mut tx = self.begin().await?;
        self.insert_node_tx(&mut tx, &node).await?;
        self.insert_committed_tx(&mut tx, &node.hash, height)
            .await?;
        self.insert_receipt_tx(&mut tx, &receipt).await?;
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn contains_sync_async(&self, hash: &Hash256) -> DagResult<bool> {
        let mut tx = self.begin().await?;
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM dagdb_node_dag_nodes
                 WHERE tenant_id = $1 AND namespace = $2 AND hash = $3
             )",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(hash.as_bytes().to_vec())
        .fetch_one(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        Ok(present)
    }

    pub(super) async fn tips_sync_async(&self) -> DagResult<Vec<Hash256>> {
        let mut tx = self.begin().await?;
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT node.hash FROM dagdb_node_dag_nodes node
             WHERE node.tenant_id = $1
               AND node.namespace = $2
               AND NOT EXISTS (
                   SELECT 1 FROM dagdb_node_dag_parents parent
                   WHERE parent.tenant_id = node.tenant_id
                     AND parent.namespace = node.namespace
                     AND parent.parent_hash = node.hash
               )
             ORDER BY node.hash ASC",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .fetch_all(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        rows.into_iter()
            .map(|bytes| decode_hash_bytes(&bytes, "dagdb_node_dag_nodes.hash"))
            .collect()
    }

    pub(super) async fn committed_height_sync_async(&self) -> DagResult<u64> {
        let mut tx = self.begin().await?;
        let height: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(height), 0) FROM dagdb_node_committed \
             WHERE tenant_id = $1 AND namespace = $2",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .fetch_one(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        sqlite_i64_to_u64(height, "dagdb_node_committed.height")
    }

    pub(super) async fn mark_committed_sync_async(
        &self,
        hash: Hash256,
        height: u64,
    ) -> DagResult<()> {
        let mut tx = self.begin().await?;
        self.ensure_node_exists_tx(&mut tx, &hash).await?;
        self.insert_committed_tx(&mut tx, &hash, height).await?;
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn committed_nodes_in_range_async(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> DagResult<Vec<(Hash256, u64)>> {
        let from_height = sqlite_u64_to_i64(from_height, "dagdb_node_committed.from_height")?;
        let to_height = sqlite_u64_to_i64(to_height, "dagdb_node_committed.to_height")?;
        let mut tx = self.begin().await?;
        let rows = sqlx::query(
            "SELECT hash, height FROM dagdb_node_committed
             WHERE tenant_id = $1 AND namespace = $2 AND height >= $3 AND height <= $4
             ORDER BY height ASC",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(from_height)
        .bind(to_height)
        .fetch_all(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        rows.iter().map(decode_committed_row).collect()
    }

    pub(super) async fn save_consensus_round_async(&self, round: u64) -> DagResult<()> {
        let mut tx = self.begin().await?;
        sqlx::query(
            "INSERT INTO dagdb_node_consensus_meta (tenant_id, namespace, key, value) \
             VALUES ($1, $2, 'round', $3) \
             ON CONFLICT (tenant_id, namespace, key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(round.to_string())
        .execute(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn load_consensus_round_async(&self) -> DagResult<u64> {
        let mut tx = self.begin().await?;
        let value: Option<String> = sqlx::query_scalar(
            "SELECT value FROM dagdb_node_consensus_meta \
             WHERE tenant_id = $1 AND namespace = $2 AND key = 'round'",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        value.map_or(Ok(0), |text| text.parse::<u64>().map_err(store_err))
    }

    pub(super) async fn save_vote_async(&self, vote: Vote) -> DagResult<()> {
        let round = sqlite_u64_to_i64(vote.round, "dagdb_node_consensus_votes.round")?;
        validate_vote(&vote, "dagdb_node_consensus_votes")?;
        let signature =
            validate_ed25519_signature(&vote.signature, "dagdb_node_consensus_votes.signature")?;
        let mut tx = self.begin().await?;
        sqlx::query(
            "INSERT INTO dagdb_node_consensus_votes \
             (tenant_id, namespace, round, node_hash, voter_did, signature) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(round)
        .bind(vote.node_hash.as_bytes().to_vec())
        .bind(vote.voter.to_string())
        .bind(signature.to_vec())
        .execute(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn load_votes_for_round_async(&self, round: u64) -> DagResult<Vec<Vote>> {
        let round_i64 = sqlite_u64_to_i64(round, "dagdb_node_consensus_votes.round")?;
        let mut tx = self.begin().await?;
        let rows = sqlx::query(
            "SELECT node_hash, voter_did, signature FROM dagdb_node_consensus_votes \
             WHERE tenant_id = $1 AND namespace = $2 AND round = $3 \
             ORDER BY node_hash ASC, voter_did ASC",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(round_i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        rows.into_iter()
            .map(|row| {
                let (node_hash, voter, signature) = decode_vote_row(&row)?;
                Ok(Vote {
                    voter,
                    round,
                    node_hash,
                    signature,
                })
            })
            .collect()
    }

    pub(super) async fn save_certificate_async(&self, cert: CommitCertificate) -> DagResult<()> {
        let mut tx = self.begin().await?;
        self.insert_certificate_tx(&mut tx, &cert).await?;
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn load_certificates_async(&self) -> DagResult<Vec<CommitCertificate>> {
        let mut tx = self.begin().await?;
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT cbor_data FROM dagdb_node_commit_certificates \
             WHERE tenant_id = $1 AND namespace = $2 ORDER BY round ASC, node_hash ASC",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .fetch_all(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        rows.into_iter()
            .map(|bytes| {
                let cert: CommitCertificate = ciborium::from_reader(bytes.as_slice())
                    .map_err(|e| store_err(format!("CBOR decode certificate: {e}")))?;
                validate_commit_certificate(&cert)?;
                Ok(cert)
            })
            .collect()
    }

    pub(super) async fn load_certificate_for_hash_async(
        &self,
        hash: Hash256,
    ) -> DagResult<Option<CommitCertificate>> {
        let mut tx = self.begin().await?;
        let result: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT cbor_data FROM dagdb_node_commit_certificates \
             WHERE tenant_id = $1 AND namespace = $2 AND node_hash = $3",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(hash.as_bytes().to_vec())
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        result
            .map(|bytes| {
                let certificate: CommitCertificate = ciborium::from_reader(bytes.as_slice())
                    .map_err(|e| store_err(format!("CBOR decode certificate: {e}")))?;
                if certificate.node_hash != hash {
                    return Err(store_err(
                        "dagdb_node_commit_certificates.node_hash does not match CBOR certificate node_hash",
                    ));
                }
                validate_commit_certificate(&certificate)?;
                Ok(certificate)
            })
            .transpose()
    }

    pub(super) async fn save_validator_set_async(
        &self,
        validators: BTreeSet<Did>,
    ) -> DagResult<()> {
        let mut tx = self.begin().await?;
        sqlx::query("DELETE FROM dagdb_node_validators WHERE tenant_id = $1 AND namespace = $2")
            .bind(&self.tenant_id)
            .bind(&self.namespace)
            .execute(&mut *tx)
            .await
            .map_err(store_err)?;
        for did in validators {
            sqlx::query(
                "INSERT INTO dagdb_node_validators (tenant_id, namespace, did) VALUES ($1, $2, $3)",
            )
            .bind(&self.tenant_id)
            .bind(&self.namespace)
            .bind(did.to_string())
            .execute(&mut *tx)
            .await
            .map_err(store_err)?;
        }
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn load_validator_set_async(&self) -> DagResult<BTreeSet<Did>> {
        let mut tx = self.begin().await?;
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT did FROM dagdb_node_validators \
             WHERE tenant_id = $1 AND namespace = $2 ORDER BY did ASC",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .fetch_all(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        rows.into_iter()
            .map(|did| decode_did(&did, "dagdb_node_validators.did"))
            .collect()
    }

    pub(super) async fn save_governance_payload_async(
        &self,
        node_hash: Hash256,
        payload: Vec<u8>,
    ) -> DagResult<()> {
        let key = governance_payload_meta_key(&node_hash);
        let mut tx = self.begin().await?;
        sqlx::query(
            "INSERT INTO dagdb_node_consensus_meta (tenant_id, namespace, key, value) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, namespace, key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(&key)
        .bind(hex::encode(&payload))
        .execute(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn load_governance_payload_async(
        &self,
        node_hash: Hash256,
    ) -> DagResult<Option<Vec<u8>>> {
        let key = governance_payload_meta_key(&node_hash);
        let mut tx = self.begin().await?;
        let value: Option<String> = sqlx::query_scalar(
            "SELECT value FROM dagdb_node_consensus_meta \
             WHERE tenant_id = $1 AND namespace = $2 AND key = $3",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(&key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        value
            .map(|text| hex::decode(&text).map_err(store_err))
            .transpose()
    }

    pub(super) async fn mark_committed_with_receipt_sync_async(
        &self,
        hash: Hash256,
        height: u64,
        receipt: TrustReceipt,
    ) -> DagResult<()> {
        if receipt.action_hash != hash {
            return Err(store_err(
                "dagdb_node_trust_receipts.action_hash must match committed node hash",
            ));
        }
        let mut tx = self.begin().await?;
        self.ensure_node_exists_tx(&mut tx, &hash).await?;
        self.insert_committed_tx(&mut tx, &hash, height).await?;
        self.insert_receipt_tx(&mut tx, &receipt).await?;
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn persist_commit_certificate_with_receipt_sync_async(
        &self,
        hash: Hash256,
        height: u64,
        cert: CommitCertificate,
        receipt: TrustReceipt,
    ) -> DagResult<()> {
        if cert.node_hash != hash {
            return Err(store_err(
                "dagdb_node_commit_certificates.node_hash must match committed node hash",
            ));
        }
        if receipt.action_hash != hash {
            return Err(store_err(
                "dagdb_node_trust_receipts.action_hash must match committed node hash",
            ));
        }
        let mut tx = self.begin().await?;
        self.ensure_node_exists_tx(&mut tx, &hash).await?;
        self.insert_committed_tx(&mut tx, &hash, height).await?;
        self.insert_certificate_tx(&mut tx, &cert).await?;
        self.insert_receipt_tx(&mut tx, &receipt).await?;
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn load_receipt_async(
        &self,
        receipt_hash: Hash256,
    ) -> DagResult<Option<TrustReceipt>> {
        let mut tx = self.begin().await?;
        let result: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT cbor_data FROM dagdb_node_trust_receipts \
             WHERE tenant_id = $1 AND namespace = $2 AND receipt_hash = $3",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(receipt_hash.as_bytes().to_vec())
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        result
            .map(|data| {
                ciborium::from_reader(&data[..])
                    .map_err(|e| store_err(format!("CBOR decode receipt: {e}")))
            })
            .transpose()
    }

    pub(super) async fn load_receipts_by_actor_async(
        &self,
        actor_did: String,
        limit: u32,
    ) -> DagResult<Vec<TrustReceipt>> {
        let mut tx = self.begin().await?;
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT cbor_data FROM dagdb_node_trust_receipts \
             WHERE tenant_id = $1 AND namespace = $2 AND actor_did = $3 \
             ORDER BY timestamp_ms DESC, receipt_hash ASC LIMIT $4",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(actor_did)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        rows.into_iter()
            .map(|data| {
                ciborium::from_reader(&data[..])
                    .map_err(|e| store_err(format!("CBOR decode receipt: {e}")))
            })
            .collect()
    }

    pub(super) async fn load_recent_receipts_async(
        &self,
        limit: u32,
    ) -> DagResult<Vec<TrustReceipt>> {
        let mut tx = self.begin().await?;
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT cbor_data FROM dagdb_node_trust_receipts \
             WHERE tenant_id = $1 AND namespace = $2 \
             ORDER BY timestamp_ms DESC, receipt_hash ASC LIMIT $3",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        rows.into_iter()
            .map(|data| {
                ciborium::from_reader(&data[..])
                    .map_err(|e| store_err(format!("CBOR decode receipt: {e}")))
            })
            .collect()
    }

    pub(super) async fn children_async(&self, parent_hash: Hash256) -> DagResult<Vec<Hash256>> {
        let mut tx = self.begin().await?;
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT child_hash FROM dagdb_node_dag_parents \
             WHERE tenant_id = $1 AND namespace = $2 AND parent_hash = $3 \
             ORDER BY child_hash ASC",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(parent_hash.as_bytes().to_vec())
        .fetch_all(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        rows.into_iter()
            .map(|bytes| decode_hash_bytes(&bytes, "dagdb_node_dag_parents.child_hash"))
            .collect()
    }

    pub(super) async fn committed_height_for_async(&self, hash: Hash256) -> DagResult<Option<u64>> {
        let mut tx = self.begin().await?;
        let height: Option<i64> = sqlx::query_scalar(
            "SELECT height FROM dagdb_node_committed \
             WHERE tenant_id = $1 AND namespace = $2 AND hash = $3",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(hash.as_bytes().to_vec())
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        height
            .map(|value| sqlite_i64_to_u64(value, "dagdb_node_committed.height"))
            .transpose()
    }

    pub(super) async fn put_committed_many_with_certificates_sync_async(
        &self,
        nodes: Vec<(DagNode, u64)>,
        certificates: Vec<CommitCertificate>,
    ) -> DagResult<()> {
        if nodes.len() != certificates.len() {
            return Err(store_err(format!(
                "committed batch must include one certificate per node: got {} certificates for {} nodes",
                certificates.len(),
                nodes.len()
            )));
        }
        let mut tx = self.begin().await?;
        for ((node, height), certificate) in nodes.iter().zip(certificates.iter()) {
            if certificate.node_hash != node.hash {
                return Err(store_err(format!(
                    "commit certificate node_hash {} does not match DAG node hash {}",
                    certificate.node_hash, node.hash
                )));
            }
            self.insert_node_tx(&mut tx, node).await?;
            self.insert_committed_tx(&mut tx, &node.hash, *height)
                .await?;
            self.insert_certificate_tx(&mut tx, certificate).await?;
        }
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    pub(super) async fn latest_economy_anchor_hash_sync_async(&self) -> DagResult<Hash256> {
        let mut tx = self.begin().await?;
        let value: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT value FROM dagdb_node_economy_meta \
             WHERE tenant_id = $1 AND namespace = $2 AND key = 'latest_anchor_hash'",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        match value {
            Some(bytes) => decode_hash_bytes(&bytes, "dagdb_node_economy_meta.latest_anchor_hash"),
            None => Ok(Hash256::ZERO),
        }
    }

    async fn latest_economy_anchor_hash_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> DagResult<Hash256> {
        let value: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT value FROM dagdb_node_economy_meta \
             WHERE tenant_id = $1 AND namespace = $2 AND key = 'latest_anchor_hash'",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .fetch_optional(&mut **tx)
        .await
        .map_err(store_err)?;
        match value {
            Some(bytes) => decode_hash_bytes(&bytes, "dagdb_node_economy_meta.latest_anchor_hash"),
            None => Ok(Hash256::ZERO),
        }
    }

    pub(super) async fn put_economy_object_sync_async(
        &self,
        object_kind: EconomyObjectKind,
        object_id: Hash256,
        content_hash: Hash256,
        created_at: Timestamp,
        object_cbor: Vec<u8>,
    ) -> DagResult<EconomyRecordAnchor> {
        if object_id == Hash256::ZERO {
            return Err(store_err("economy object_id must not be Hash256::ZERO"));
        }
        if content_hash == Hash256::ZERO {
            return Err(store_err("economy content_hash must not be Hash256::ZERO"));
        }
        if created_at == Timestamp::ZERO {
            return Err(store_err("economy created_at must not be Timestamp::ZERO"));
        }

        let mut tx = self.begin().await?;
        let previous_anchor_hash = self.latest_economy_anchor_hash_tx(&mut tx).await?;
        let anchor = EconomyRecordAnchor {
            anchor_hash: Hash256::ZERO,
            previous_anchor_hash,
            object_kind,
            object_id,
            object_hash: content_hash,
            created_at,
        }
        .anchor()
        .map_err(store_err)?;
        let anchor_cbor = encode_cbor(&anchor, "dagdb_node_economy_anchors.cbor_data")?;
        let created_physical_ms = sqlite_u64_to_i64(
            created_at.physical_ms,
            "dagdb_node_economy.created_physical_ms",
        )?;
        let created_logical = sqlite_u64_to_i64(
            u64::from(created_at.logical),
            "dagdb_node_economy.created_logical",
        )?;

        sqlx::query(
            "INSERT INTO dagdb_node_economy_objects (
                tenant_id, namespace, object_kind, object_id, content_hash,
                created_physical_ms, created_logical, cbor_data
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(object_kind.label())
        .bind(object_id.as_bytes().to_vec())
        .bind(content_hash.as_bytes().to_vec())
        .bind(created_physical_ms)
        .bind(created_logical)
        .bind(object_cbor)
        .execute(&mut *tx)
        .await
        .map_err(|e| store_err(format!("insert DAG DB economy object: {e}")))?;

        sqlx::query(
            "INSERT INTO dagdb_node_economy_anchors (
                tenant_id, namespace, anchor_hash, previous_anchor_hash, object_kind,
                object_id, object_hash, created_physical_ms, created_logical, cbor_data
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(anchor.anchor_hash.as_bytes().to_vec())
        .bind(anchor.previous_anchor_hash.as_bytes().to_vec())
        .bind(object_kind.label())
        .bind(object_id.as_bytes().to_vec())
        .bind(content_hash.as_bytes().to_vec())
        .bind(created_physical_ms)
        .bind(created_logical)
        .bind(anchor_cbor)
        .execute(&mut *tx)
        .await
        .map_err(|e| store_err(format!("insert DAG DB economy anchor: {e}")))?;

        sqlx::query(
            "INSERT INTO dagdb_node_economy_meta (tenant_id, namespace, key, value) \
             VALUES ($1, $2, 'latest_anchor_hash', $3) \
             ON CONFLICT (tenant_id, namespace, key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(anchor.anchor_hash.as_bytes().to_vec())
        .execute(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        Ok(anchor)
    }

    pub(super) async fn get_economy_object_sync_async<T>(
        &self,
        object_kind: EconomyObjectKind,
        object_id: Hash256,
    ) -> DagResult<Option<T>>
    where
        T: DeserializeOwned,
    {
        let mut tx = self.begin().await?;
        let result: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT cbor_data FROM dagdb_node_economy_objects \
             WHERE tenant_id = $1 AND namespace = $2 AND object_kind = $3 AND object_id = $4",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(object_kind.label())
        .bind(object_id.as_bytes().to_vec())
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        result
            .map(|bytes| decode_cbor(&bytes, "dagdb_node_economy_objects.cbor_data"))
            .transpose()
    }

    pub(super) async fn get_economy_anchor_sync_async(
        &self,
        anchor_hash: Hash256,
    ) -> DagResult<Option<EconomyRecordAnchor>> {
        let mut tx = self.begin().await?;
        let result: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT cbor_data FROM dagdb_node_economy_anchors \
             WHERE tenant_id = $1 AND namespace = $2 AND anchor_hash = $3",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(anchor_hash.as_bytes().to_vec())
        .fetch_optional(&mut *tx)
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        result
            .map(|bytes| decode_cbor(&bytes, "dagdb_node_economy_anchors.cbor_data"))
            .transpose()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use exo_dag::error::DagError;

    use super::*;

    fn assert_store_decode_error(error: DagError, column: &str) {
        match error {
            DagError::StoreError(message) => {
                assert!(message.contains(column), "error was {message}");
                assert!(message.contains("decode"), "error was {message}");
                assert!(message.contains("type"), "error was {message}");
            }
            other => panic!("expected StoreError for {column}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn postgres_malformed_rows_return_typed_errors() {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL is required for postgres_malformed_rows_return_typed_errors");
        let pool = exo_gateway::db::init_pool(&database_url)
            .await
            .expect("initialize canonical gateway and DAG DB migrations");

        let malformed_committed_hash =
            sqlx::query("SELECT 'not-bytea'::TEXT AS hash, 1::BIGINT AS height")
                .fetch_one(&pool)
                .await
                .expect("synthetic committed hash row");
        assert_store_decode_error(
            decode_committed_row(&malformed_committed_hash).unwrap_err(),
            "dagdb_node_committed.hash",
        );

        let malformed_committed_height = sqlx::query(
            "SELECT decode(repeat('11', 32), 'hex') AS hash, \
             'not-bigint'::TEXT AS height",
        )
        .fetch_one(&pool)
        .await
        .expect("synthetic committed height row");
        assert_store_decode_error(
            decode_committed_row(&malformed_committed_height).unwrap_err(),
            "dagdb_node_committed.height",
        );

        let malformed_vote_hash = sqlx::query(
            "SELECT 'not-bytea'::TEXT AS node_hash, \
             'did:exo:malformed-row'::TEXT AS voter_did, \
             decode(repeat('22', 64), 'hex') AS signature",
        )
        .fetch_one(&pool)
        .await
        .expect("synthetic vote hash row");
        assert_store_decode_error(
            decode_vote_row(&malformed_vote_hash).unwrap_err(),
            "dagdb_node_consensus_votes.node_hash",
        );

        let malformed_voter_did = sqlx::query(
            "SELECT decode(repeat('11', 32), 'hex') AS node_hash, \
             decode('22', 'hex') AS voter_did, \
             decode(repeat('33', 64), 'hex') AS signature",
        )
        .fetch_one(&pool)
        .await
        .expect("synthetic voter DID row");
        assert_store_decode_error(
            decode_vote_row(&malformed_voter_did).unwrap_err(),
            "dagdb_node_consensus_votes.voter_did",
        );

        let malformed_vote_signature = sqlx::query(
            "SELECT decode(repeat('11', 32), 'hex') AS node_hash, \
             'did:exo:malformed-row'::TEXT AS voter_did, \
             'not-bytea'::TEXT AS signature",
        )
        .fetch_one(&pool)
        .await
        .expect("synthetic vote signature row");
        assert_store_decode_error(
            decode_vote_row(&malformed_vote_signature).unwrap_err(),
            "dagdb_node_consensus_votes.signature",
        );

        pool.close().await;
    }
}
