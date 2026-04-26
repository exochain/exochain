#!/usr/bin/env bash
# Guard the container entrypoint contract Railway depends on: the HTTP API
# must bind to all container interfaces while still allowing explicit override.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "railway entrypoint argument test failed: $*" >&2
  exit 1
}

assert_arg_pair() {
  local file="$1"
  local flag="$2"
  local expected="$3"
  local previous=""

  while IFS= read -r arg; do
    if [ "$previous" = "$flag" ]; then
      [ "$arg" = "$expected" ] || fail "$flag expected '$expected', got '$arg'"
      return 0
    fi
    previous="$arg"
  done <"$file"

  fail "$flag was not passed to exochain"
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

fake_bin="$tmp_dir/exochain"
cat >"$fake_bin" <<'FAKE'
#!/usr/bin/env sh
if [ -z "${ENTRYPOINT_ARGS_FILE:-}" ]; then
  echo "ENTRYPOINT_ARGS_FILE is required" >&2
  exit 2
fi
printf '%s\n' "$@" >"$ENTRYPOINT_ARGS_FILE"
FAKE
chmod +x "$fake_bin"

args_file="$tmp_dir/default.args"
env -i \
  PATH="$tmp_dir:/usr/bin:/bin" \
  ENTRYPOINT_ARGS_FILE="$args_file" \
  EXOCHAIN_DATA_DIR="/data" \
  PORT="9999" \
  P2P_PORT="4001" \
  IS_VALIDATOR="true" \
  ./deploy/entrypoint.sh >/dev/null

first_arg="$(sed -n '1p' "$args_file")"
[ "$first_arg" = "start" ] || fail "expected start command, got '$first_arg'"
assert_arg_pair "$args_file" "--api-port" "9999"
assert_arg_pair "$args_file" "--api-host" "0.0.0.0"
assert_arg_pair "$args_file" "--p2p-port" "4001"

args_file="$tmp_dir/override.args"
env -i \
  PATH="$tmp_dir:/usr/bin:/bin" \
  ENTRYPOINT_ARGS_FILE="$args_file" \
  EXOCHAIN_DATA_DIR="/data" \
  PORT="9999" \
  API_HOST="127.0.0.1" \
  SEED_ADDR="seed.example.com:4001" \
  ./deploy/entrypoint.sh >/dev/null

first_arg="$(sed -n '1p' "$args_file")"
[ "$first_arg" = "join" ] || fail "expected join command, got '$first_arg'"
assert_arg_pair "$args_file" "--seed" "seed.example.com:4001"
assert_arg_pair "$args_file" "--api-host" "127.0.0.1"

echo "railway entrypoint argument test passed"
