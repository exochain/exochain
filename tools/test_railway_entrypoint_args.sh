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

cat >"$tmp_dir/id" <<'FAKE'
#!/usr/bin/env sh
if [ "${1:-}" = "-u" ]; then
  echo 0
else
  /usr/bin/id "$@"
fi
FAKE
chmod +x "$tmp_dir/id"

cat >"$tmp_dir/mkdir" <<'FAKE'
#!/usr/bin/env sh
printf '%s\n' "$@" >"${ENTRYPOINT_MKDIR_ARGS_FILE:?}"
FAKE
chmod +x "$tmp_dir/mkdir"

cat >"$tmp_dir/chown" <<'FAKE'
#!/usr/bin/env sh
printf '%s\n' "$@" >"${ENTRYPOINT_CHOWN_ARGS_FILE:?}"
FAKE
chmod +x "$tmp_dir/chown"

cat >"$tmp_dir/chmod" <<'FAKE'
#!/usr/bin/env sh
printf '%s\n' "$@" >"${ENTRYPOINT_CHMOD_ARGS_FILE:?}"
FAKE
chmod +x "$tmp_dir/chmod"

cat >"$tmp_dir/gosu" <<'FAKE'
#!/usr/bin/env sh
user="$1"
shift
printf '%s\n' "$user" >"${ENTRYPOINT_GOSU_USER_FILE:?}"
exec "$@"
FAKE
chmod +x "$tmp_dir/gosu"

args_file="$tmp_dir/root.args"
env -i \
  PATH="$tmp_dir:/usr/bin:/bin" \
  ENTRYPOINT_ARGS_FILE="$args_file" \
  ENTRYPOINT_MKDIR_ARGS_FILE="$tmp_dir/mkdir.args" \
  ENTRYPOINT_CHOWN_ARGS_FILE="$tmp_dir/chown.args" \
  ENTRYPOINT_CHMOD_ARGS_FILE="$tmp_dir/chmod.args" \
  ENTRYPOINT_GOSU_USER_FILE="$tmp_dir/gosu.user" \
  EXOCHAIN_DATA_DIR="/data" \
  PORT="9999" \
  P2P_PORT="4001" \
  ./deploy/entrypoint.sh >/dev/null

first_arg="$(sed -n '1p' "$args_file")"
[ "$first_arg" = "start" ] || fail "expected root path to start node, got '$first_arg'"
assert_arg_pair "$args_file" "--data-dir" "/data"
assert_arg_pair "$args_file" "--api-host" "0.0.0.0"
grep -qx -- "-p" "$tmp_dir/mkdir.args" || fail "root path must ensure data dir exists"
grep -qx -- "/data" "$tmp_dir/mkdir.args" || fail "root path mkdir must target /data"
grep -qx -- "exochain:exochain" "$tmp_dir/chown.args" || fail "root path must chown /data to exochain"
grep -qx -- "/data" "$tmp_dir/chown.args" || fail "root path chown must target /data"
grep -qx -- "755" "$tmp_dir/chmod.args" || fail "root path must chmod /data to 755"
grep -qx -- "/data" "$tmp_dir/chmod.args" || fail "root path chmod must target /data"
grep -qx -- "exochain" "$tmp_dir/gosu.user" || fail "root path must drop to exochain user"

echo "railway entrypoint argument test passed"
