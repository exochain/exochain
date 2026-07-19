#!/usr/bin/env bash
# Build linux amd64 intelwar-core bins into services/log-api/native for Railway.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
OUT="$(cd "$(dirname "$0")/.." && pwd)/native"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker required to produce linux bins on this host" >&2
  exit 1
fi

docker run --rm \
  --platform linux/amd64 \
  -v "$ROOT:/app" \
  -w /app \
  rust:1.88-bookworm \
  bash -lc '
    set -euo pipefail
    apt-get update
    apt-get install -y --no-install-recommends pkg-config libssl-dev clang
    cargo build -p intelwar-core --release \
      --bin intelwar-log-append \
      --bin intelwar-crosscheck-verify \
      --bin intelwar-crosscheck-sign
  '

mkdir -p "$OUT"
cp -f target/release/intelwar-log-append "$OUT/"
cp -f target/release/intelwar-crosscheck-verify "$OUT/"
cp -f target/release/intelwar-crosscheck-sign "$OUT/"
chmod +x "$OUT"/*
file "$OUT"/* || true
echo "Prepared linux native bins in $OUT"
ls -la "$OUT"
