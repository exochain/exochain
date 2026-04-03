#!/bin/sh
# Exochain node entrypoint — joins an existing network if SEED_ADDR is set,
# otherwise bootstraps as a standalone seed node.
set -e

DATA_DIR="${EXOCHAIN_DATA_DIR:-/data}"
P2P_PORT="${P2P_PORT:-4001}"
API_PORT="${API_PORT:-8080}"

# Build base arguments.
ARGS="--data-dir ${DATA_DIR} --p2p-port ${P2P_PORT} --api-port ${API_PORT}"

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
