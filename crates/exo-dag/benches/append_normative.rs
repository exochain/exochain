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

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! exo-dag benchmark suite.
//!
//! Covers the four operation families mandated by EXOCHAIN-REM-004:
//!   1. DAG append (sequential chain, diamond merge)
//!   2. DAG traversal (ancestors, tips)
//!   3. Checkpoint-equivalent store operations (MemoryStore put + mark_committed)
//!   4. BFT consensus rounds (propose → vote × n → check_commit → commit)

use std::collections::{BTreeMap, BTreeSet};

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use exo_core::{
    crypto::KeyPair,
    types::{Did, Hash256, PublicKey, Signature},
};
use exo_dag::{
    consensus::{
        ConsensusConfig, ConsensusState, Proposal, Vote, check_commit, commit_verified,
        propose_verified, vote_verified,
    },
    dag::{Dag, DeterministicDagClock, ancestors, append, tips},
    store::MemoryStore,
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn sign_fn(data: &[u8]) -> Signature {
    let h = blake3::hash(data);
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(h.as_bytes());
    Signature::from_bytes(buf)
}

fn creator() -> Did {
    Did::new("did:exo:bench").expect("valid DID")
}

/// Build a linear DAG of `depth` nodes (genesis + depth children).
/// Returns the dag and the hash of the final tip.
fn linear_dag(depth: usize) -> (Dag, Hash256) {
    let c = creator();
    let mut dag = Dag::new();
    let mut clock = DeterministicDagClock::new();
    let genesis = append(&mut dag, &[], b"genesis", &c, &sign_fn, &mut clock).expect("genesis");
    let mut tip = genesis.hash;
    for i in 0..depth {
        let payload = (u64::try_from(i).unwrap()).to_le_bytes();
        let node = append(&mut dag, &[tip], &payload, &c, &sign_fn, &mut clock).expect("append");
        tip = node.hash;
    }
    (dag, tip)
}

/// Build a set of `n` validators with DIDs `did:exo:v0` … `did:exo:v{n-1}`.
fn validators(n: usize) -> BTreeSet<Did> {
    (0..n)
        .map(|i| Did::new(&format!("did:exo:v{i}")).expect("valid"))
        .collect()
}

fn validator_keypair(index: usize) -> KeyPair {
    let seed = u8::try_from(index + 1).expect("validator index fits in deterministic seed");
    KeyPair::from_secret_bytes([seed; 32]).expect("valid deterministic validator keypair")
}

fn validator_public_keys(validators: &[Did]) -> BTreeMap<Did, PublicKey> {
    validators
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, did)| {
            let keypair = validator_keypair(index);
            (did, *keypair.public_key())
        })
        .collect()
}

fn signed_proposal_for(
    proposer: &Did,
    proposer_index: usize,
    round: u64,
    node_hash: Hash256,
) -> Signature {
    let proposal = Proposal {
        proposer: proposer.clone(),
        round,
        node_hash,
    };
    let payload = proposal.signing_payload().expect("proposal payload");
    validator_keypair(proposer_index).sign(&payload)
}

fn signed_vote_for(voter: &Did, voter_index: usize, round: u64, node_hash: Hash256) -> Vote {
    let mut vote = Vote {
        voter: voter.clone(),
        round,
        node_hash,
        signature: Signature::empty(),
    };
    let payload = vote.signing_payload().expect("vote payload");
    vote.signature = validator_keypair(voter_index).sign(&payload);
    vote
}

// ---------------------------------------------------------------------------
// 1. DAG append
// ---------------------------------------------------------------------------

fn bench_dag_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_append");
    let cr = creator();

    for depth in [10usize, 100, 1_000] {
        group.bench_with_input(
            BenchmarkId::new("sequential_chain", depth),
            &depth,
            |b, &n| {
                b.iter(|| {
                    let mut dag = Dag::new();
                    let mut clock = DeterministicDagClock::new();
                    let genesis = append(&mut dag, &[], b"genesis", &cr, &sign_fn, &mut clock)
                        .expect("genesis");
                    let mut tip = genesis.hash;
                    for i in 0..n {
                        let payload = (u64::try_from(i).unwrap()).to_le_bytes();
                        let node = append(&mut dag, &[tip], &payload, &cr, &sign_fn, &mut clock)
                            .expect("append");
                        tip = node.hash;
                    }
                    black_box(dag.len())
                });
            },
        );
    }

    // Diamond merge: genesis → (left ‖ right) → merge node.
    group.bench_function("diamond_merge", |b| {
        b.iter(|| {
            let mut dag = Dag::new();
            let mut clock = DeterministicDagClock::new();
            let g = append(&mut dag, &[], b"g", &cr, &sign_fn, &mut clock).expect("g");
            let left =
                append(&mut dag, &[g.hash], b"left", &cr, &sign_fn, &mut clock).expect("left");
            let right =
                append(&mut dag, &[g.hash], b"right", &cr, &sign_fn, &mut clock).expect("right");
            let merge = append(
                &mut dag,
                &[left.hash, right.hash],
                b"merge",
                &cr,
                &sign_fn,
                &mut clock,
            )
            .expect("merge");
            black_box(merge.hash)
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// 2. DAG traversal
// ---------------------------------------------------------------------------

fn bench_dag_traversal(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_traversal");

    for depth in [10usize, 100, 500] {
        let (dag, tip) = linear_dag(depth);

        group.bench_with_input(
            BenchmarkId::new("ancestors", depth),
            &(dag.clone(), tip),
            |b, (d, h)| {
                b.iter(|| {
                    let ancs = ancestors(d, h);
                    black_box(ancs.len())
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("tips", depth), &dag, |b, d| {
            b.iter(|| {
                let t = tips(d);
                black_box(t.len())
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 3. Store checkpoint operations (MemoryStore put + mark_committed)
// ---------------------------------------------------------------------------

fn bench_store_checkpoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_checkpoint");
    let cr = creator();

    for batch in [10usize, 100, 1_000] {
        // Pre-build nodes outside the timed section.
        let nodes: Vec<_> = {
            let mut dag = Dag::new();
            let mut clock = DeterministicDagClock::new();
            let genesis =
                append(&mut dag, &[], b"genesis", &cr, &sign_fn, &mut clock).expect("genesis");
            let mut tip = genesis.hash;
            let mut out = vec![genesis];
            for i in 0..batch {
                let payload = (u64::try_from(i).unwrap()).to_le_bytes();
                let node =
                    append(&mut dag, &[tip], &payload, &cr, &sign_fn, &mut clock).expect("node");
                tip = node.hash;
                out.push(node);
            }
            out
        };

        group.bench_with_input(
            BenchmarkId::new("put_and_mark_committed", batch),
            &nodes,
            |b, ns| {
                b.iter(|| {
                    let mut store = MemoryStore::new();
                    for (height, node) in ns.iter().enumerate() {
                        store.put_sync(node.clone()).expect("put");
                        store
                            .mark_committed_sync(&node.hash, u64::try_from(height).unwrap())
                            .expect("mark_committed");
                    }
                    black_box(store.committed_height_sync().expect("height"))
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("store_get", batch), &nodes, |b, ns| {
            // Pre-populated store — only measure read throughput.
            let mut store = MemoryStore::new();
            for node in ns {
                store.put_sync(node.clone()).expect("put");
            }
            let hashes: Vec<Hash256> = ns.iter().map(|n| n.hash).collect();
            b.iter(|| {
                let mut found = 0usize;
                for h in &hashes {
                    if store.get_sync(h).expect("get").is_some() {
                        found += 1;
                    }
                }
                black_box(found)
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 4. BFT consensus rounds
// ---------------------------------------------------------------------------

fn bench_consensus_rounds(c: &mut Criterion) {
    let mut group = c.benchmark_group("consensus_rounds");

    for n_validators in [4usize, 7, 13] {
        let vs: Vec<Did> = validators(n_validators).into_iter().collect();
        let public_keys = validator_public_keys(&vs);
        let config = ConsensusConfig::new(vs.iter().cloned().collect(), 1_000);

        // Build a genesis DAG node to propose.
        let cr = creator();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(&mut dag, &[], b"genesis", &cr, &sign_fn, &mut clock).expect("genesis");

        group.bench_with_input(
            BenchmarkId::new("propose_vote_commit", n_validators),
            &(
                config.clone(),
                node.clone(),
                vs.clone(),
                public_keys.clone(),
            ),
            |b, (cfg, n, v, keys)| {
                b.iter(|| {
                    let mut state = ConsensusState::new(cfg.clone());
                    let resolver = |did: &Did| keys.get(did).copied();
                    let proposal_sig = signed_proposal_for(&v[0], 0, 0, n.hash);
                    propose_verified(&mut state, n, &v[0], &proposal_sig, &resolver)
                        .expect("propose");
                    let quorum = cfg.quorum_size();
                    for (index, voter) in v.iter().enumerate().take(quorum) {
                        let vt = signed_vote_for(voter, index, 0, n.hash);
                        vote_verified(&mut state, vt, &resolver).expect("vote");
                    }
                    let cert = check_commit(&state, &n.hash).expect("cert");
                    commit_verified(&mut state, cert, &resolver).expect("commit");
                    black_box(state.committed.len())
                });
            },
        );

        // Multi-round: advance through 10 rounds, each with a fresh proposal.
        let nodes: Vec<_> = {
            let mut d = Dag::new();
            let mut clk = DeterministicDagClock::new();
            let g = append(&mut d, &[], b"r0", &cr, &sign_fn, &mut clk).expect("g");
            let mut tip = g.hash;
            let mut out = vec![g];
            for i in 1..10usize {
                let payload = (u64::try_from(i).unwrap()).to_le_bytes();
                let nd = append(&mut d, &[tip], &payload, &cr, &sign_fn, &mut clk).expect("nd");
                tip = nd.hash;
                out.push(nd);
            }
            out
        };

        group.bench_with_input(
            BenchmarkId::new("multi_round_10", n_validators),
            &(
                config.clone(),
                nodes.clone(),
                vs.clone(),
                public_keys.clone(),
            ),
            |b, (cfg, ns, v, keys)| {
                let quorum = cfg.quorum_size();
                b.iter(|| {
                    let mut state = ConsensusState::new(cfg.clone());
                    for node in ns {
                        let resolver = |did: &Did| keys.get(did).copied();
                        let proposal_sig =
                            signed_proposal_for(&v[0], 0, state.current_round, node.hash);
                        propose_verified(&mut state, node, &v[0], &proposal_sig, &resolver)
                            .expect("propose");
                        for (index, voter) in v.iter().enumerate().take(quorum) {
                            let vt = signed_vote_for(voter, index, state.current_round, node.hash);
                            vote_verified(&mut state, vt, &resolver).expect("vote");
                        }
                        if let Some(cert) = check_commit(&state, &node.hash) {
                            commit_verified(&mut state, cert, &resolver).expect("commit");
                        }
                        state.advance_round().expect("round advances");
                    }
                    black_box(state.committed.len())
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion entry point
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_dag_append,
    bench_dag_traversal,
    bench_store_checkpoint,
    bench_consensus_rounds,
);
criterion_main!(benches);
