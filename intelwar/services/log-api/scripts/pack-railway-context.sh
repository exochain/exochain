#!/usr/bin/env bash
# Pack slim monorepo context for Railway multi-stage Docker build.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
STAGE="${INTELWAR_RAILWAY_STAGE:-/tmp/intelwar-log-api-railway-ctx}"
rm -rf "$STAGE"
mkdir -p "$STAGE"

rsync -a "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" "$STAGE/"
rsync -a --exclude target "$ROOT/crates/" "$STAGE/crates/"
mkdir -p "$STAGE/intelwar"
rsync -a --exclude target "$ROOT/intelwar/crates/" "$STAGE/intelwar/crates/"
rsync -a \
  --exclude node_modules \
  --exclude native \
  --exclude .intelwar-bridge-state \
  "$ROOT/intelwar/services/log-api/" "$STAGE/intelwar/services/log-api/"

# Stub non-essential workspace members so Cargo.toml members resolve.
python3 - <<'PY' "$ROOT" "$STAGE"
import pathlib, re, shutil, sys
root, stage = map(pathlib.Path, sys.argv[1:])
toml = (root / "Cargo.toml").read_text()
paths = re.findall(r'^\s*"([^"]+)"\s*,?\s*$', toml, flags=re.M)
# Also catch members without trailing comma patterns inside members = [ ... ]
block = re.search(r"members\s*=\s*\[(.*?)\]", toml, flags=re.S)
if block:
    paths = re.findall(r'"([^"]+)"', block.group(1))
for rel in paths:
    src = root / rel
    dst = stage / rel
    if dst.exists():
        continue
    if not src.exists():
        continue
    # Skip huge adjacent trees — stub them
    if any(p in rel for p in ("livesafe", "command-base", "demo/", "site", "packages/")):
        dst.mkdir(parents=True, exist_ok=True)
        (dst / "Cargo.toml").write_text(
            '[package]\nname = "iw_stub"\nversion = "0.0.0"\nedition = "2024"\n[lib]\npath = "src/lib.rs"\n'
        )
        (dst / "src").mkdir(exist_ok=True)
        (dst / "src" / "lib.rs").write_text("//! stub workspace member\n")
        continue
    if src.is_dir():
        shutil.copytree(
            src,
            dst,
            ignore=shutil.ignore_patterns("target", "node_modules", "dist", ".git"),
        )
# Root railway config for this upload
shutil.copy(stage / "intelwar/services/log-api/Dockerfile", stage / "Dockerfile")
shutil.copy(stage / "intelwar/services/log-api/railway.json", stage / "railway.json")
print(stage)
PY

echo "Packed: $STAGE ($(du -sh "$STAGE" | awk '{print $1}'))"
