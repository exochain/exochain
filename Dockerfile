# EXOCHAIN Node image — headless constitutional governance node.
#
# This image builds ONLY the Rust node binary. The decision-forum web UI
# is a separate concern and ships as its own service under its own domain
# (recommended: forum.exochain.io via a separate Railway service).
#
# Build locally:  docker build -t exochain/node .
# Run locally:    docker run -p 4001:4001 -p 8080:8080 -v exochain:/data exochain/node

# Stage 1: Build Rust binaries
# Use 1.88 — workspace minimum is 1.85, but some transitive deps
# (time 0.3.47, async-graphql 7.0.17) require newer rustc. 1.88 is
# the lowest version that satisfies the current full dep graph.
FROM rust:1.88-slim-bookworm AS rust-builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev clang && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# Build the distributed node binary and the legacy HTTP gateway.
RUN cargo build --release --bin exochain --bin exo-gateway

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
# Bundle the entrypoint script so env-var driven configuration works
# regardless of which start-command override is in effect.
COPY deploy/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh && ln -s /app/exochain /usr/local/bin/exochain

# Default data directory inside the container.
ENV EXOCHAIN_DATA_DIR=/data
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

# Probe the effective API port (Railway sets $PORT; otherwise $API_PORT or 8080).
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf "http://localhost:${PORT:-${API_PORT:-8080}}/health" || exit 1

# ENTRYPOINT (exec form) ensures the script is always invoked and signals
# reach the child binary via entrypoint.sh's `exec exochain ...`.
ENTRYPOINT ["/app/entrypoint.sh"]
