#!/bin/sh
# Exochain node entrypoint — joins an existing network if SEED_ADDR is set,
# otherwise bootstraps as a standalone seed node.
#
# Runs initially as root (when launched that way by Docker/Railway) just long
# enough to chown the data volume, then steps down to the unprivileged
# `exochain` user via gosu. On subsequent invocations (re-exec with correct
# ownership) the chown/re-exec block is skipped. (A-040)
set -eu

DATA_DIR="${EXOCHAIN_DATA_DIR:-/data}"
P2P_PORT="${P2P_PORT:-4001}"
# Honor Railway/Heroku-style $PORT first, then $API_PORT, then default 8080.
API_PORT="${PORT:-${API_PORT:-8080}}"

# Privilege drop: Railway mounts the persistent volume as root on first
# boot. Chown /data then re-exec ourselves as `exochain`.
if [ "$(id -u)" = "0" ]; then
    mkdir -p "${DATA_DIR}"
    chown -R exochain:exochain "${DATA_DIR}"
    exec gosu exochain "$0" "$@"
fi

# Build base arguments.
ARGS="--data-dir ${DATA_DIR} --p2p-port ${P2P_PORT} --api-port ${API_PORT}"

if [ -n "${VALIDATORS:-}" ]; then
    ARGS="${ARGS} --validator --validators ${VALIDATORS}"
elif [ "${IS_VALIDATOR:-}" = "true" ]; then
    ARGS="${ARGS} --validator"
fi

if [ -n "${SEED_ADDR:-}" ]; then
    echo "Joining network via seed: ${SEED_ADDR}"
    # shellcheck disable=SC2086
    exec exochain join --seed "${SEED_ADDR}" ${ARGS}
else
    echo "Starting as seed node"
    # shellcheck disable=SC2086
    exec exochain start ${ARGS}
fi
