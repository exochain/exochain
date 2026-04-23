#!/bin/sh
# exoguard entrypoint. Connects the facade + MCP surfaces against a pre-existing
# exochain n0 DAG; refuses to start if the DAG's McpAuditLog chain is corrupt.
set -e

DATA_DIR="${EXOGUARD_DATA_DIR:-/data}"
LISTEN_ADDR="${EXOGUARD_LISTEN_ADDR:-0.0.0.0:8443}"
FACADES="${EXOGUARD_FACADE:-openai,anthropic,gemini}"
UPSTREAM="${EXOGUARD_UPSTREAM:-openrouter}"
SCANNER_BACKEND="${EXOGUARD_SCANNER_BACKEND:-hybrid}"

if [ -z "${EXOGUARD_IDENTITY_REF}" ]; then
    echo "EXOGUARD_IDENTITY_REF is required (e.g. did:exo:service/exoguard-pilot)" >&2
    exit 1
fi
if [ -z "${EXOGUARD_N0_DAG_URL}" ]; then
    echo "EXOGUARD_N0_DAG_URL is required (Railway managed Postgres URL for n0 DAG)" >&2
    exit 1
fi

ARGS="--data-dir ${DATA_DIR} \
      --listen ${LISTEN_ADDR} \
      --facades ${FACADES} \
      --upstream ${UPSTREAM} \
      --scanner-backend ${SCANNER_BACKEND} \
      --identity-ref ${EXOGUARD_IDENTITY_REF} \
      --n0-dag-url ${EXOGUARD_N0_DAG_URL}"

echo "Starting exoguard facade on ${LISTEN_ADDR} against n0=${EXOGUARD_IDENTITY_REF}"
# shellcheck disable=SC2086
exec /app/exo-gateway ${ARGS}
