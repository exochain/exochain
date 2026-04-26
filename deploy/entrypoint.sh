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
RUN_AS_USER="${EXOCHAIN_RUN_AS:-exochain}"

# Build base arguments.
set -- --data-dir "${DATA_DIR}" --p2p-port "${P2P_PORT}" --api-port "${API_PORT}" --api-host "${API_HOST}"

if [ -n "${VALIDATORS:-}" ]; then
    set -- "$@" --validator --validators "${VALIDATORS}"
elif [ "${IS_VALIDATOR:-}" = "true" ]; then
    set -- "$@" --validator
fi

if [ -n "${SEED_ADDR:-}" ]; then
    echo "Joining network via seed: ${SEED_ADDR}"
    set -- join --seed "${SEED_ADDR}" "$@"
else
    echo "Starting as seed node"
    set -- start "$@"
fi

if [ "$(id -u)" = "0" ]; then
    mkdir -p "${DATA_DIR}"
    # Railway mounts volumes after pre-deploy commands run; repair the live
    # mounted tree before dropping privileges so existing root-owned state
    # remains readable and writable by the node process.
    chown -R "${RUN_AS_USER}:${RUN_AS_USER}" "${DATA_DIR}"
    chmod 755 "${DATA_DIR}"

    if command -v gosu >/dev/null 2>&1; then
        exec gosu "${RUN_AS_USER}" exochain "$@"
    fi

    if command -v runuser >/dev/null 2>&1; then
        exec runuser -u "${RUN_AS_USER}" -- exochain "$@"
    fi

    echo "Cannot drop privileges: neither gosu nor runuser is available" >&2
    exit 127
fi

exec exochain "$@"
