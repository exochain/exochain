# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# EXOCHAIN Node image — headless constitutional governance node.
#
# This image builds ONLY the Rust node binary. The decision-forum web UI
# is a separate concern and ships as its own service under its own domain
# (recommended: forum.exochain.io via a separate Railway service).
#
# Build locally:  docker build -t exochain/node .
# Run locally:    docker run -p 4001:4001 -p 8080:8080 -v exochain:/data exochain/node

# Stage 1: Build Rust binaries
# Use 1.90 — workspace rust-version is 1.85, but the 0.2.4 CGR / RISC Zero
# graph pulls ruint 1.20 (rustc 1.90) and enum-ordinalize 4.4.1 (rustc 1.89).
# Railway's previous 1.88 builder failed closed on that graph.
FROM rust:1.90-slim-bookworm AS rust-builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev clang && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# Build the distributed node binary and standalone gateway with DB-backed
# adjudication enabled for production container deployments.
# EXTRA_CARGO_FEATURES is empty by default (image unchanged). Private-network
# deployments may pass e.g. ",exochain-gateway/unaudited-gateway-graphql-api"
# to compile the GraphQL surface into an instance that is never publicly
# exposed. The public build must keep this empty until VCG-003/Spline R1 land.
ARG EXTRA_CARGO_FEATURES=""
RUN cargo build --release --bin exochain --bin exo-gateway --features "exochain-gateway/production-db${EXTRA_CARGO_FEATURES}"

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 curl gosu && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --create-home --shell /usr/sbin/nologin exochain && \
    mkdir -p /data && chown exochain:exochain /data && chmod 755 /data
WORKDIR /app

# Copy both binaries — `exochain` is the primary entrypoint;
# `exo-gateway` is the standalone gateway for environments that prefer it.
COPY --from=rust-builder /app/target/release/exochain /app/
COPY --from=rust-builder /app/target/release/exo-gateway /app/
COPY crates/exo-gateway/migrations /app/migrations
COPY artifacts/trust/avc-exo-ceremony-2026 /app/artifacts/trust/avc-exo-ceremony-2026
# Bundle the entrypoint script so env-var driven configuration works
# regardless of which start-command override is in effect.
COPY deploy/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh && ln -s /app/exochain /usr/local/bin/exochain

# Default data directory inside the container.
ENV EXOCHAIN_DATA_DIR=/data
ENV EXO_AVC_ROOT_TRUST_BUNDLE=/app/artifacts/trust/avc-exo-ceremony-2026/root-trust-bundle.canonical.json
ENV RUST_LOG=info

# P2P (TCP + QUIC) and HTTP API.
EXPOSE 4001 4002 8080

# Persistent state (identity key + DAG) lives at /data.
# On Railway, /data is mounted via a Railway volume — do NOT use the
# Dockerfile VOLUME keyword (Railway bans it).
# For plain Docker: `docker run -v exochain-data:/data exochain/node`.
# Keep the container entrypoint as root so mounted volumes can have ownership
# repaired at startup; deploy/entrypoint.sh drops to the exochain user before
# launching the node process.

# Probe the dependency-validating readiness endpoint on the effective API port
# (Railway sets $PORT; otherwise $API_PORT or 8080).
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf "http://localhost:${PORT:-${API_PORT:-8080}}/ready" || exit 1

# ENTRYPOINT (exec form) ensures the script is always invoked and signals
# reach the child binary via entrypoint.sh's `exec exochain ...`.
ENTRYPOINT ["/app/entrypoint.sh"]
