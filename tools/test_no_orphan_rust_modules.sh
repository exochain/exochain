#!/usr/bin/env bash
# Guard against top-level Rust files under crates/*/src that are not declared
# by the crate root. Undeclared files do not compile, do not run tests, and can
# carry stale APIs that mislead readers.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "orphan Rust module test failed: $*" >&2
  exit 1
}

orphans=()

for src_dir in crates/*/src; do
  [ -d "$src_dir" ] || continue

  declarations=$(mktemp)
  trap 'rm -f "$declarations"' EXIT

  for root in "$src_dir/lib.rs" "$src_dir/main.rs"; do
    [ -f "$root" ] || continue
    sed -nE \
      's/^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*;.*/\2/p' \
      "$root" >>"$declarations"
  done

  sort -u -o "$declarations" "$declarations"

  for file in "$src_dir"/*.rs; do
    [ -e "$file" ] || continue
    module=$(basename "$file" .rs)
    case "$module" in
      lib | main)
        continue
        ;;
    esac

    if ! grep -qx "$module" "$declarations"; then
      orphans+=("$file")
    fi
  done

  rm -f "$declarations"
  trap - EXIT
done

if [ "${#orphans[@]}" -ne 0 ]; then
  printf '%s\n' "${orphans[@]}" >&2
  fail "top-level Rust files must be declared in lib.rs/main.rs or removed"
fi

removed_orphans=(
  "crates/exo-core/src/event.rs"
  "crates/exo-dag/src/proof.rs"
  "crates/exo-gatekeeper/src/proof.rs"
  "crates/exo-governance/src/anchor.rs"
  "crates/exo-governance/src/decision.rs"
  "crates/exo-governance/src/emergency.rs"
  "crates/exo-identity/src/key.rs"
)

stale_refs=()
for path in "${removed_orphans[@]}"; do
  for ref in "$path" "${path#crates/}"; do
    while IFS= read -r hit; do
      stale_refs+=("$hit")
    done < <(grep -RInF -- "$ref" README.md docs governance gap 2>/dev/null || true)
  done
done

if [ "${#stale_refs[@]}" -ne 0 ]; then
  printf '%s\n' "${stale_refs[@]}" >&2
  fail "docs must not point at removed orphan modules"
fi

echo "orphan Rust module test passed"
