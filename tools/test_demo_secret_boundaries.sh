#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

demo_file_list="$(mktemp)"
trap 'rm -f "$demo_file_list"' EXIT

git -C "$ROOT" ls-files demo \
  | grep -Ev '^(demo/coverage/|demo/node_modules/)' \
  | sed "s#^#$ROOT/#" > "$demo_file_list"

if [ ! -s "$demo_file_list" ]; then
  echo "no tracked demo files found" >&2
  exit 1
fi

if xargs grep -En \
  'exochain_dev|postgres://exochain:exochain|DATABASE_URL:-postgres://|POSTGRES_PASSWORD:[[:space:]]*exochain_dev' \
  < "$demo_file_list"; then
  echo "demo secret boundary failed: hardcoded database credentials or DATABASE_URL fallbacks remain" >&2
  exit 1
fi

compose="$ROOT/demo/infra/docker-compose.yml"
if ! grep -Fq 'POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?' "$compose"; then
  echo "demo secret boundary failed: docker compose must require POSTGRES_PASSWORD from the environment" >&2
  exit 1
fi

if grep -Eq 'DATABASE_URL:[[:space:]]+postgres://[^$]' "$compose"; then
  echo "demo secret boundary failed: docker compose DATABASE_URL must interpolate environment secrets" >&2
  exit 1
fi

shared="$ROOT/demo/packages/shared/src/index.js"
if ! grep -Fq 'DATABASE_URL is required' "$shared"; then
  echo "demo secret boundary failed: shared pool helper must fail closed when DATABASE_URL is missing" >&2
  exit 1
fi

dev_script="$ROOT/demo/scripts/dev.sh"
if ! grep -Fq '${DATABASE_URL:?set DATABASE_URL' "$dev_script"; then
  echo "demo secret boundary failed: local dev script must require DATABASE_URL explicitly" >&2
  exit 1
fi

echo "demo secret boundary test passed"
