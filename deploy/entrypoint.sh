#!/bin/sh
# Exochain node entrypoint — joins an existing network if SEED_ADDR is set,
# otherwise bootstraps as a standalone seed node.
set -e

DATA_DIR="${EXOCHAIN_DATA_DIR:-/data}"
P2P_PORT="${P2P_PORT:-4001}"
# Honor Railway/Heroku-style $PORT first, then $API_PORT, then default 8080.
API_PORT="${PORT:-${API_PORT:-8080}}"
# Containers must bind HTTP to all interfaces for Railway/public ingress.
# Direct CLI execution keeps the binary's safer 127.0.0.1 default unless this
# deployment entrypoint is used.
API_HOST="${API_HOST:-0.0.0.0}"

# Build base arguments.
ARGS="--data-dir ${DATA_DIR} --p2p-port ${P2P_PORT} --api-port ${API_PORT} --api-host ${API_HOST}"

if [ -n "${VALIDATORS}" ]; then
    ARGS="${ARGS} --validator --validators ${VALIDATORS}"
elif [ "${IS_VALIDATOR}" = "true" ]; then
    ARGS="${ARGS} --validator"
fi

if [ -n "${SEED_ADDR}" ]; then
    echo "Joining network via seed: ${SEED_ADDR}"
    # shellcheck disable=SC2086
    exec exochain join --seed "${SEED_ADDR}" ${ARGS}
else
    echo "Starting as seed node"
    # shellcheck disable=SC2086
    exec exochain start ${ARGS}
fi
