# Multi-stage Kernel log-api — build context = packed monorepo root
# (scripts/pack-railway-context.sh).

FROM rust:1.88-bookworm AS rust-builder
WORKDIR /app
RUN apt-get update \
  && apt-get install -y --no-install-recommends pkg-config libssl-dev clang \
  && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build -p intelwar-core --release \
  --bin intelwar-log-append \
  --bin intelwar-crosscheck-verify \
  --bin intelwar-crosscheck-sign

FROM node:20-bookworm-slim
WORKDIR /app
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY intelwar/services/log-api/package.json intelwar/services/log-api/package-lock.json ./
RUN npm ci --omit=dev
COPY intelwar/services/log-api/server.js \
     intelwar/services/log-api/crosscheck-verify.js \
     intelwar/services/log-api/dagdb-persist.js \
     intelwar/services/log-api/adversarial.js \
     intelwar/services/log-api/campaign-zero.js ./
RUN mkdir -p /app/native
COPY --from=rust-builder /app/target/release/intelwar-log-append /app/native/
COPY --from=rust-builder /app/target/release/intelwar-crosscheck-verify /app/native/
COPY --from=rust-builder /app/target/release/intelwar-crosscheck-sign /app/native/
RUN chmod +x /app/native/* && mkdir -p /data/intelwar-bridge-state

ENV INTELWAR_CORE_BIN=/app/native/intelwar-log-append
ENV INTELWAR_CROSSCHECK_BIN=/app/native/intelwar-crosscheck-verify
ENV INTELWAR_CROSSCHECK_SIGN_BIN=/app/native/intelwar-crosscheck-sign
ENV INTELWAR_CORE_STATE_DIR=/data/intelwar-bridge-state
ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080
CMD ["npm", "start"]
