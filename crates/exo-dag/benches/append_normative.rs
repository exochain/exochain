#![allow(clippy::unwrap_used, clippy::expect_used)]
// Bench suite exists to measure baseline perf of the legacy
// consensus API (propose/vote/commit). The GAP-014 fix added
// _verified counterparts and marked the legacy path deprecated —
// benching the legacy path is still valuable for perf regression
// tracking and defense-in-depth testing.
#![allow(deprecated)]
//! exo-dag benchmark suite.
//!
//! Covers the four operation families mandated by EXOCHAIN-REM-004:
//!   1. DAG append (sequential chain, diamond merge)
//!   2. DAG traversal (ancestors, tips)
//!   3. Checkpoint-equivalent store operations (MemoryStore put + mark_committed)
//!   4. BFT consensus rounds (propose → vote × n → check_commit → commit)

use std::collections::BTreeSet;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use exo_core::types::{Did, Hash256, Signature};
use exo_dag::{
    consensus::{ConsensusConfig, ConsensusState, Vote, check_commit, commit, propose, vote},
    dag::{Dag, HybridClock, ancestors, append, tips},
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
    let mut clock = HybridClock::new();
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
                    let mut clock = HybridClock::new();
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
            let mut clock = HybridClock::new();
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
            let mut clock = HybridClock::new();
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
        let config = ConsensusConfig::new(vs.iter().cloned().collect(), 1_000);

        // Build a genesis DAG node to propose.
        let cr = creator();
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let node = append(&mut dag, &[], b"genesis", &cr, &sign_fn, &mut clock).expect("genesis");

        group.bench_with_input(
            BenchmarkId::new("propose_vote_commit", n_validators),
            &(config.clone(), node.clone(), vs.clone()),
            |b, (cfg, n, v)| {
                b.iter(|| {
                    let mut state = ConsensusState::new(cfg.clone());
                    propose(&mut state, n, &v[0]).expect("propose");
                    let quorum = cfg.quorum_size();
                    for voter in v.iter().take(quorum) {
                        let vt = Vote {
                            voter: voter.clone(),
                            round: 0,
                            node_hash: n.hash,
                            signature: Signature::from_bytes([1u8; 64]),
                        };
                        vote(&mut state, vt).expect("vote");
                    }
                    let cert = check_commit(&state, &n.hash).expect("cert");
                    commit(&mut state, cert);
                    black_box(state.committed.len())
                });
            },
        );

        // Multi-round: advance through 10 rounds, each with a fresh proposal.
        let nodes: Vec<_> = {
            let mut d = Dag::new();
            let mut clk = HybridClock::new();
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
            &(config.clone(), nodes.clone(), vs.clone()),
            |b, (cfg, ns, v)| {
                let quorum = cfg.quorum_size();
                b.iter(|| {
                    let mut state = ConsensusState::new(cfg.clone());
                    for node in ns {
                        propose(&mut state, node, &v[0]).expect("propose");
                        for voter in v.iter().take(quorum) {
                            let vt = Vote {
                                voter: voter.clone(),
                                round: state.current_round,
                                node_hash: node.hash,
                                signature: Signature::from_bytes([1u8; 64]),
                            };
                            vote(&mut state, vt).expect("vote");
                        }
                        if let Some(cert) = check_commit(&state, &node.hash) {
                            commit(&mut state, cert);
                        }
                        state.advance_round();
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
