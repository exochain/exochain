#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "public route verifier portability test failed: $*" >&2
  exit 1
}

if grep -F '"${CURL_DNS_ARGS[@]}"' tools/verify_public_exochain_route.sh >/dev/null; then
  fail "verify_public_exochain_route.sh must not expand an empty array under set -u"
fi

fake_bin_dir="$(mktemp -d)"
trap 'rm -rf "${fake_bin_dir}"' EXIT

cat >"${fake_bin_dir}/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail

headers=""
body=""
method="GET"
url=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --doh-url)
      echo "unexpected DoH argument in default verifier path" >&2
      exit 2
      ;;
    --max-time|-w|-D|-o|-X)
      case "$1" in
        -D) headers="$2" ;;
        -o) body="$2" ;;
        -X) method="$2" ;;
      esac
      shift 2
      ;;
    -sS)
      shift
      ;;
    -*)
      echo "unexpected curl argument: $1" >&2
      exit 2
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done

[ -n "${headers}" ] || { echo "missing -D header destination" >&2; exit 2; }
[ -n "${body}" ] || { echo "missing -o body destination" >&2; exit 2; }
[ -n "${url}" ] || { echo "missing URL" >&2; exit 2; }

path="${url#https://exochain.test}"
case "${method} ${path}" in
  "GET /health")
    code="200"
    payload='{"status":"ok","version":"0.2.1-beta"}'
    ;;
  "GET /ready")
    code="200"
    payload='{"status":"ok","dagdb_runtime_status":"dagdb_active"}'
    ;;
  "GET /.well-known/exochain.json")
    code="200"
    payload='{"base_url":"https://exochain.io","routes":{"health":"/health","ready":"/ready","avc":{"receipts_emit":"/api/v1/avc/receipts/emit"}},"mcp":{"public_transport":false,"capabilities":["tools","resources","prompts"]}}'
    ;;
  "POST /api/v1/avc/issue")
    code="401"
    payload=''
    ;;
  *)
    echo "unexpected verifier request: ${method} ${path}" >&2
    exit 2
    ;;
esac

printf 'HTTP/2 %s\r\nserver: railway-hikari\r\n\r\n' "${code}" >"${headers}"
printf '%s' "${payload}" >"${body}"
printf '%s' "${code}"
FAKE_CURL

chmod +x "${fake_bin_dir}/curl"

unset EXOCHAIN_PUBLIC_ROUTE_DOH_URL
PATH="${fake_bin_dir}:/usr/bin:/bin" \
  EXOCHAIN_PUBLIC_ROUTE_BASE_URL="https://exochain.test" \
  bash tools/verify_public_exochain_route.sh >/tmp/public-route-verifier-portability.out

grep -F "public route verification passed for https://exochain.test" \
  /tmp/public-route-verifier-portability.out >/dev/null \
  || fail "verifier did not complete with the expected success message"

echo "public route verifier portability test passed"
