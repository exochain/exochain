#!/usr/bin/env bash
set -euo pipefail

export EXO_AVC_RFC3161_LIVE_PREFLIGHT="${EXO_AVC_RFC3161_LIVE_PREFLIGHT:-1}"

cargo test -p exo-node live_microsoft_rfc3161_preflight -- --ignored --nocapture
