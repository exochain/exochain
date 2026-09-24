#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
# No upload operation lives here. release.yml owns the protected PyPI action.
set -euo pipefail

fail() { printf 'Python 0.2.7 recovery failed: %s\n' "$1" >&2; exit 1; }

public_command() {
  /usr/bin/env -i PATH=/usr/bin:/bin HOME="$tool_home" TMPDIR="$tool_home" \
    PIP_CONFIG_FILE=/dev/null "$@"
}

python_verify() { public_command "$tool_python" -I -B "$verifier" "$@"; }

file_digest() {
  public_command "$tool_python" -I -B -c '
import hashlib,os,stat,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,"rb") as stream:
    before=os.fstat(stream.fileno())
    assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
    assert 0<=before.st_size<=128*1024*1024
    digest=hashlib.file_digest(stream,"sha256").hexdigest()
    after=os.fstat(stream.fileno())
    assert (before.st_dev,before.st_ino,before.st_mode,before.st_nlink,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_mode,after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    print(digest)
' "$1"
}

fetch_public() {
  local url="$1" response="$2" limit="$3" status
  # No redirects, proxy configuration, curlrc, credentials, or retry flags.
  status="$(public_command /usr/bin/curl -q --silent --show-error --output "$response" \
    --write-out '%{http_code}' --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 60 --max-filesize "$limit" \
    --header 'Accept: application/vnd.pypi.integrity.v1+json, application/json' "$url")" || return 1
  printf '%s\n' "$status" > "$response.http-status"
  printf '%s' "$status"
}

visibility_sleep() { /bin/sleep 15; }

verify_sigstore() {
  public_command "$attestation_cli" verify pypi \
    --repository https://github.com/exochain/exochain \
    --provenance-file "$1" "$2"
}

publication_identity() {
  local filename="$1" profile record
  case "$filename" in
    exochain-0.2.7-py3-none-any.whl) profile=python-wheel ;;
    exochain-0.2.7.tar.gz) profile=python-sdist ;;
    *) fail 'unexpected mapped Python filename' ;;
  esac
  record="$(public_command "$tool_python" -I -B "$publication_verifier" publication \
    --manifest "$publication_manifest" --identities "$publication_identities" --publication "$profile")" \
    || fail 'publication identity is not the exact reviewed record'
  public_command "$tool_python" -I -B -c '
import json,sys
r=json.loads(sys.argv[1]); assert r["file"]["path"] == "dist/"+sys.argv[2]
print(r["source"]["commit"], r["source"]["ref"], sep=chr(9))
' "$record" "$filename"
}

verify_existing() {
  local list="$1" attempt="$2" retry_404="$3" filename provenance status before artifact_before list_before identity publication_commit publication_ref
  list_before="$(file_digest "$list")" || fail 'invalid existing inventory file'
  while IFS= read -r filename; do
    [[ "$filename" = exochain-0.2.7-py3-none-any.whl || "$filename" = exochain-0.2.7.tar.gz ]] \
      || fail 'unexpected Python filename'
    provenance="$receipts/$attempt-$filename.provenance.json"
    status="$(fetch_public "https://pypi.org/integrity/exochain/0.2.7/$filename/provenance" "$provenance" 8388608)" \
      || fail 'provenance transport failed'
    case "$status" in
      200) ;;
      404) [[ "$retry_404" = true ]] && return 4; fail 'existing file provenance is absent' ;;
      *) fail "unexpected provenance HTTP status $status" ;;
    esac
    before="$(file_digest "$provenance")" || fail 'invalid provenance file'
    artifact_before="$(file_digest "$dist_dir/$filename")" || fail 'invalid artifact file'
    identity="$(publication_identity "$filename")" || fail 'cannot select exact publication identity'
    IFS=$'\t' read -r publication_commit publication_ref <<< "$identity"
    [[ "$publication_commit" =~ ^[0-9a-f]{40}$ && "$publication_ref" = refs/tags/* ]] \
      || fail 'invalid selected publication identity'
    verify_sigstore "$provenance" "$dist_dir/$filename" || fail 'Sigstore verification failed'
    python_verify provenance "$provenance" "$dist_dir/$filename" \
      exochain/exochain release.yml release "$publication_ref" "$publication_commit" \
      || fail 'provenance controller identity failed'
    [[ "$(file_digest "$provenance")" = "$before" \
      && "$(file_digest "$dist_dir/$filename")" = "$artifact_before" ]] \
      || fail 'provenance or artifact changed during verification'
  done < "$list"
  [[ "$(file_digest "$list")" = "$list_before" ]] || fail 'existing inventory changed'
}

inventory_lists() {
  python_verify recovery-preflight "$1" exochain 0.2.7 "$manifest" > "$receipts/inventory.json"
  # This is canonical-validator output, never raw provider text or shell code.
  public_command "$tool_python" -I -B -c '
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); inventory=json.loads((root/"inventory.json").read_text())
for field in ("existing","missing"):
    (root/(field+".txt")).write_text("".join(name+"\n" for name in inventory[field]))
' "$receipts"
}

prepare_publication() {
  [[ ! -e "$stage" && ! -L "$stage" ]] || fail 'staging directory already exists'
  [[ ! -e "$stage_state" && ! -L "$stage_state" ]] || fail 'staging state already exists'
  local response="$receipts/preflight.json" status manifest_before missing_before
  manifest_before="$(file_digest "$manifest")"
  status="$(fetch_public https://pypi.org/pypi/exochain/0.2.7/json "$response" 1048576)" \
    || fail 'registry transport failed'
  case "$status" in
    200) ;;
    404)
      # An explicit absent version is represented as the canonical empty inventory.
      printf '%s\n' '{"info":{"name":"exochain","version":"0.2.7"},"urls":[]}' \
        > "$receipts/absent-inventory.json"
      response="$receipts/absent-inventory.json" ;;
    *) fail "unexpected registry HTTP status $status" ;;
  esac
  inventory_lists "$response"
  [[ ! -s "$receipts/missing.txt" ]] || fail 'mapped Python publications must already exist; uploads forbidden'
  # Bind the missing list across untrusted external verification processes.
  missing_before="$(file_digest "$receipts/missing.txt")"
  verify_existing "$receipts/existing.txt" preflight false
  [[ "$(file_digest "$manifest")" = "$manifest_before" ]] || fail 'manifest changed'
  [[ "$(file_digest "$receipts/missing.txt")" = "$missing_before" ]] \
    || fail 'missing inventory changed'
  # O_EXCL/O_NOFOLLOW and a newly-created private directory forbid overwrites.
  public_command "$tool_python" -I -B - "$dist_dir" "$manifest" "$receipts/missing.txt" "$stage" <<'PY'
import hashlib,os,pathlib,stat,sys
dist,manifest,missing,stage=map(pathlib.Path,sys.argv[1:])
records={row.split("\t")[0]:row.split("\t")[1:] for row in manifest.read_text().splitlines()}
names=missing.read_text().splitlines()
assert len(names)==len(set(names)) and all(name in records for name in names)
stage.mkdir(mode=0o700)
for name in names:
    digest,size=records[name]
    fd=os.open(dist/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as source:
        before=os.fstat(source.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==int(size)
        contents=source.read(int(size)+1)
        after=os.fstat(source.fileno())
        assert (before.st_dev,before.st_ino,before.st_mode,before.st_nlink,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_mode,after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
        assert len(contents)==int(size)
        assert hashlib.sha256(contents).hexdigest()==digest
    fd=os.open(stage/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,"wb") as target: target.write(contents)
PY
  public_command "$tool_python" -I -B - "$receipts/missing.txt" "$stage_state" "$GITHUB_SHA" "$GITHUB_REF" <<'PY'
import json,os,pathlib,sys
missing,state,sha,ref=sys.argv[1:]
value={'schema':'exochain-python-recovery-stage/v1','controller_sha':sha,'controller_ref':ref,'staged':pathlib.Path(missing).read_text().splitlines()}
fd=os.open(state,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
with os.fdopen(fd,'w') as output: json.dump(value,output,sort_keys=True)
PY
}

accept_readback() {
  local attempt response status result
  for ((attempt=1; attempt<=25; attempt++)); do
    response="$receipts/readback-$attempt.json"
    status="$(fetch_public https://pypi.org/pypi/exochain/0.2.7/json "$response" 1048576)" \
      || fail 'registry transport failed'
    case "$status" in
      200)
        python_verify registry-response "$response" exochain 0.2.7 "$manifest" \
          || fail 'final registry inventory is incomplete or conflicting'
        inventory_lists "$response"
        result=0
        verify_existing "$receipts/existing.txt" "$attempt" true || result=$?
        [[ "$result" = 0 ]] && return
        [[ "$result" = 4 ]] || fail 'final provenance verification failed' ;;
      404) ;;
      *) fail "unexpected registry HTTP status $status" ;;
    esac
    [[ "$attempt" = 25 ]] || visibility_sleep
  done
  fail 'bounded PyPI visibility budget exhausted'
}

trusted_git() {
  /usr/bin/env -i PATH=/usr/bin:/bin GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 /usr/bin/git --no-replace-objects \
    -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false \
    -C "$workspace" "$@"
}

assert_inputs() {
  local path
  for path in "${captured_paths[@]}"; do
    trusted_git show "$GITHUB_SHA:$path" | /usr/bin/cmp - "$capture/${path##*/}" \
      || fail 'captured controller input changed'
  done
  /usr/bin/env -i "${identity_env[@]}" "RELEASE_RECOVERY_PYTHON_PHASE=$python_phase" \
    /bin/bash --noprofile --norc -p \
    "$capture/verify_release_recovery_027.sh" > "$receipts/identity-$identity_count.json"
  identity_count=$((identity_count+1))
  public_command "$tool_python" -I -B "$capture/verify_release_recovery_027.py" files \
    --manifest "$capture/RECOVERY-MANIFEST.json" --directory "$recovery_dir" --lane python
  python_verify artifacts "$dist_dir" exochain 0.2.7 --expect-manifest "$manifest"
}

install_verification_tools() {
  public_command "$python_path" -I -B -m venv "$capture/verification-tools"
  tool_python="$capture/verification-tools/bin/python"
  public_command "$tool_python" -I -B -m pip --isolated install --disable-pip-version-check \
    --no-compile --require-hashes --only-binary=:all: --index-url=https://pypi.org/simple \
    -r "$capture/python-release-requirements.lock"
  public_command "$tool_python" -I -B -c '
import importlib.metadata,pathlib,re,sys
for name,version in re.findall(r"^([A-Za-z0-9_.-]+)==([^ \\\n]+)",pathlib.Path(sys.argv[1]).read_text(),re.M):
    assert importlib.metadata.version(name)==version, name
' "$capture/python-release-requirements.lock"
  attestation_cli="$capture/verification-tools/bin/pypi-attestations"
  [[ -f "$attestation_cli" && -x "$attestation_cli" && ! -L "$attestation_cli" ]] \
    || fail 'attestation executable is not a regular installed file'
  [[ "$(public_command "$attestation_cli" --version)" = 'pypi-attestations 0.0.30' ]] \
    || fail 'attestation tool version differs'
}

write_outputs() {
  public_command "$tool_python" -I -B - "${GITHUB_OUTPUT:?}" "$stage_state" "$scratch" <<'PY'
import json,os,pathlib,stat,sys
output,state,scratch=map(pathlib.Path,sys.argv[1:])
assert output.is_absolute() and output.parent.resolve().is_relative_to(scratch)
fd=os.open(output,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,"w") as stream:
    info=os.fstat(stream.fileno()); assert stat.S_ISREG(info.st_mode) and info.st_nlink==1
    needed='true' if json.loads(state.read_text())['staged'] else 'false'
    stream.write(f'publish_needed={needed}\npackages_dir=.release-recovery-python-stage/\n')
PY
}

main() {
  [[ "$#" = 1 && ( "$1" = preflight || "$1" = readback ) ]] || fail 'expected preflight or readback'
  local mode="$1" credential path
  umask 077
  if /usr/bin/env | /usr/bin/grep -Eq '^BASH_FUNC_.*%%='; then
    fail 'inherited shell functions are forbidden'
  fi
  for credential in CARGO_REGISTRY_TOKEN NPM_TOKEN NODE_AUTH_TOKEN TWINE_PASSWORD PYPI_TOKEN \
      ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL; do
    [[ -z "${!credential:-}" ]] || fail 'publication credentials must be absent'
  done
  [[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ && "${RELEASE_TAG:-}" =~ ^v0\.2\.7-recover\.[1-9][0-9]*$ ]] \
    || fail 'invalid controller commit or maintenance tag'
  [[ "${RELEASE_VERSION:-0.2.7}" = 0.2.7 ]] || fail 'only fixed product 0.2.7 is supported'
  [[ "${GITHUB_REF:-}" = "refs/tags/$RELEASE_TAG" && "${EXPECTED_COMMIT_SHA:-}" = "$GITHUB_SHA" \
    && "${TRUSTED_RELEASE_REF:-}" = "$GITHUB_SHA" && "${EXPECTED_TAG_COMMIT_SHA:-}" = "$GITHUB_SHA" ]] \
    || fail 'controller identity mismatch'
  [[ "${RELEASE_TRUSTED_PYTHON_VERSION:-}" = 3.13.7 ]] || fail 'pinned Python version required'
  workspace="${GITHUB_WORKSPACE:?}"; scratch="${RUNNER_TEMP:?}"
  recovery_dir="${RELEASE_RECOVERY_DIRECTORY:?}"
  for path in "$workspace" "$scratch" "$recovery_dir" "${RELEASE_TRUSTED_PYTHON_ROOT:?}"; do
    [[ "$path" = /* && -d "$path" && ! -L "$path" && "$(cd "$path" && pwd -P)" = "$path" ]] \
      || fail 'paths must be absolute canonical real directories'
  done
  case "$scratch/" in "$workspace/"*) fail 'scratch directory is inside checkout' ;; esac
  case "$recovery_dir/" in "$scratch/"*) ;; *) fail 'recovery artifacts are outside RUNNER_TEMP' ;; esac
  stage="$workspace/.release-recovery-python-stage"
  stage_state="$scratch/exochain-recovery-python-state.json"
  [[ "$mode" != preflight || ( ! -e "$stage" && ! -L "$stage" ) ]] || fail 'staging directory already exists'
  [[ "$mode" != preflight || ( ! -e "$stage_state" && ! -L "$stage_state" ) ]] || fail 'staging state already exists'
  python_path="$(/usr/bin/realpath "${RELEASE_PYTHON:?}")"
  case "$python_path" in "$RELEASE_TRUSTED_PYTHON_ROOT"/*) ;; *) fail 'Python is outside trusted root' ;; esac
  [[ -f "$python_path" && -x "$python_path" && ! -L "$python_path" ]] || fail 'invalid Python executable'
  [[ "$(/usr/bin/env -i "$python_path" -I -B -c 'import sys; print(".".join(map(str,sys.version_info[:3])))')" = 3.13.7 ]] \
    || fail 'Python version differs'
  trusted_git fsck --strict --no-reflogs --no-progress --no-dangling "$GITHUB_SHA" >/dev/null
  [[ "$(trusted_git rev-parse --verify 'HEAD^{commit}')" = "$GITHUB_SHA" ]] || fail 'HEAD differs from dispatch'
  capture="$(/usr/bin/mktemp -d "$scratch/exochain-python-recovery.XXXXXX")"
  receipts="$capture/receipts"; tool_home="$capture/home"
  /bin/mkdir -m 700 "$receipts" "$tool_home"
  captured_paths=(tools/verify_release_recovery_027.sh tools/verify_release_recovery_027.py \
    tools/verify_release_recovery_python_stage.py \
    tools/verify_python_release_package.py tools/python-release-requirements.lock \
    tools/recover_release_python_027.sh governance/releases/v0.2.7/RECOVERY-MANIFEST.json \
    governance/releases/v0.2.7/PUBLICATION-IDENTITIES.json)
  for path in "${captured_paths[@]}"; do
    trusted_git show "$GITHUB_SHA:$path" > "$capture/${path##*/}"
    /bin/chmod 400 "$capture/${path##*/}"
  done
  /usr/bin/cmp "${BASH_SOURCE[0]}" "$capture/recover_release_python_027.sh" \
    || fail 'running orchestration differs from controller source'
  identity_env=("PATH=/usr/bin:/bin" "GITHUB_WORKSPACE=$workspace" "RUNNER_TEMP=$scratch"
    "GITHUB_SHA=$GITHUB_SHA" "GITHUB_REF=$GITHUB_REF" "EXPECTED_COMMIT_SHA=$GITHUB_SHA"
    "TRUSTED_RELEASE_REF=$GITHUB_SHA" "EXPECTED_TAG_COMMIT_SHA=$GITHUB_SHA"
    "EXPECTED_TAG_OBJECT_SHA=${EXPECTED_TAG_OBJECT_SHA:?}" "RELEASE_TAG=$RELEASE_TAG"
    "GITHUB_ACTIONS=${GITHUB_ACTIONS:-}" "GITHUB_SERVER_URL=${GITHUB_SERVER_URL:-}"
    "GITHUB_REPOSITORY=${GITHUB_REPOSITORY:-}" "RELEASE_GITHUB_TOKEN=${RELEASE_GITHUB_TOKEN:-}"
    "RELEASE_PYTHON=$python_path" "RELEASE_TRUSTED_PYTHON_ROOT=$RELEASE_TRUSTED_PYTHON_ROOT"
    "RELEASE_TRUSTED_PYTHON_VERSION=3.13.7" "GNUPGHOME=${GNUPGHOME:-}"
    "EXOCHAIN_RELEASE_SIGNING_FINGERPRINT=${EXOCHAIN_RELEASE_SIGNING_FINGERPRINT:-}")
  verifier="$capture/verify_python_release_package.py"; tool_python="$python_path"
  publication_verifier="$capture/verify_release_recovery_027.py"
  publication_manifest="$capture/RECOVERY-MANIFEST.json"
  publication_identities="$capture/PUBLICATION-IDENTITIES.json"
  dist_dir="$recovery_dir/python/dist"; manifest="$recovery_dir/python/artifact-manifest.tsv"
  identity_count=0
  python_phase=""
  if [[ "$mode" = readback ]]; then
    python_phase=readback
  fi
  assert_inputs
  install_verification_tools
  assert_inputs
  if [[ "$mode" = preflight ]]; then
    prepare_publication
    python_phase=staged
  else
    accept_readback
  fi
  assert_inputs
  if [[ "$mode" = preflight ]]; then
    write_outputs
  fi
  printf 'Python recovery %s validated; receipts: %s\n' "$mode" "$receipts"
}

main "$@"
