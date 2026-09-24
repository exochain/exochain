#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
helper="$repo/tools/recover_release_python_027.sh"
[[ -f "$helper" ]] || { echo 'missing Python recovery orchestration' >&2; exit 1; }
test_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-python-recovery-test.XXXXXX")"
test_root="$(cd "$test_root" && pwd -P)"
trap '/bin/rm -rf -- "$test_root"' EXIT
# Load function definitions, not the production bootstrap. No production bypass
# switch exists. These are orchestration tests, not signed-origin acceptance.
sed '/^main "\$@"$/,$d' "$helper" > "$test_root/functions.sh"
source "$test_root/functions.sh"
# Local macOS cryptography may be user-site-only, excluded by production -I.
# Test-only venv exposes the already-installed dependency explicitly; no pip,
# network, global installation, or claim about hosted runtime isolation.
python3 - "$test_root" <<'PY'
import cryptography,pathlib,sys,venv
root=pathlib.Path(sys.argv[1])/'test-python'
# Keep managed CPython's executable-relative shared library reachable on macOS.
venv.EnvBuilder(with_pip=False, symlinks=True).create(root)
site=root/'lib'/f'python{sys.version_info.major}.{sys.version_info.minor}'/'site-packages'
(site/'fixture-dependencies.pth').write_text(str(pathlib.Path(cryptography.__file__).parent.parent)+'\n')
PY
tool_python="$test_root/test-python/bin/python"
verifier="$repo/tools/verify_python_release_package.py"
publication_verifier="$repo/tools/verify_release_recovery_027.py"
publication_manifest="$repo/governance/releases/v0.2.7/RECOVERY-MANIFEST.json"
publication_identities="$repo/governance/releases/v0.2.7/PUBLICATION-IDENTITIES.json"
tool_home="$test_root/home"
mkdir "$tool_home"
GITHUB_SHA=1111111111111111111111111111111111111111
GITHUB_REF=refs/tags/v0.2.7-recover.1
export GITHUB_TOKEN=sentinel-github ACTIONS_ID_TOKEN_REQUEST_TOKEN=sentinel-oidc
export PYTHONPATH=sentinel-python CURL_HOME=sentinel-curl
python3 - "$test_root" <<'PY'
import base64,datetime,hashlib,json,pathlib,sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ObjectIdentifier
root=pathlib.Path(sys.argv[1]); dist=root/'dist'; dist.mkdir()
names=['exochain-0.2.7-py3-none-any.whl','exochain-0.2.7.tar.gz']
records=[]; rows=[]
for name in names:
    data=('fixture bytes '+name).encode(); (dist/name).write_bytes(data)
    digest=hashlib.sha256(data).hexdigest()
    rows.append(f'{name}\t{digest}\t{len(data)}\n')
    records.append({'filename':name,'size':len(data),'digests':{'sha256':digest},'yanked':False,
                    'url':'https://files.pythonhosted.org/packages/aa/bb/'+'c'*60+'/'+name})
    key=ec.generate_private_key(ec.SECP256R1()); now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'fixture')]))
      .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'fixture')])).public_key(key.public_key())
      .serial_number(1).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(minutes=1))
      .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier('https://github.com/exochain/exochain/.github/workflows/release.yml@refs/tags/v0.2.7-recover.2')]),True))
    for suffix,value in {'1':'https://token.actions.githubusercontent.com','2':'workflow_dispatch','3':'2198e4ef610e9ef6d04adf726f7f4b3e156a3bc1','5':'exochain/exochain','6':'refs/tags/v0.2.7-recover.2','11':'github-hosted'}.items():
        cert=cert.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.3.6.1.4.1.57264.1.'+suffix),value.encode()),False)
    statement={'_type':'https://in-toto.io/Statement/v1','subject':[{'name':name,'digest':{'sha256':digest}}],'predicateType':'https://docs.pypi.org/attestations/publish/v1','predicate':None}
    provenance={'version':1,'attestation_bundles':[{'publisher':{'kind':'GitHub','repository':'exochain/exochain','workflow':'release.yml','environment':'release','claims':None},'attestations':[{'version':1,'envelope':{'statement':base64.b64encode(json.dumps(statement).encode()).decode(),'signature':base64.b64encode(b'not a real signature').decode()},'verification_material':{'certificate':base64.b64encode(cert.sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.DER)).decode(),'transparency_entries':[{'logIndex':'1'}]}}]}]}
    (root/(name+'.json')).write_text(json.dumps(provenance))
(root/'manifest.tsv').write_text(''.join(rows))
for label,indexes in [('none',[]),('wheel',[0]),('sdist',[1]),('both',[0,1])]:
    (root/(label+'.json')).write_text(json.dumps({'info':{'name':'exochain','version':'0.2.7'},'urls':[records[i] for i in indexes]}))
records[0]['size']+=1
(root/'conflict.json').write_text(json.dumps({'info':{'name':'exochain','version':'0.2.7'},'urls':records}))
(root/'malformed.json').write_text('{')
PY
dist_dir="$test_root/dist"
manifest="$test_root/manifest.tsv"
# Only external HTTP, Sigstore crypto, and waiting are replaced. The strict
# provenance identity parser, metadata validator, hashing and copies are real.
fetch_public() {
  printf '%s\n' "$1" >> "$calls"
  case "$1" in
    */json)
      if [[ "$scenario" = transport ]]; then return 1; fi
      if [[ "$scenario" = delayed ]]; then
        [[ "$(grep -c '/json' "$calls")" -gt 1 ]] || { printf 404; return; }
        cp "$test_root/both.json" "$2"; printf 200; return
      fi
      if [[ "$scenario" = 404* ]]; then printf 404; return; fi
      if [[ "$scenario" = 401 || "$scenario" = 500 ]]; then printf '%s' "$scenario"; return; fi
      if [[ "$scenario" = provenance404 || "$scenario" = provenance500 ]]; then
        cp "$test_root/both.json" "$2"; printf 200; return
      fi
      cp "$test_root/$scenario.json" "$2"; printf 200 ;;
    */provenance)
      if [[ "$scenario" = provenance404 ]]; then printf 404; return; fi
      if [[ "$scenario" = provenance500 ]]; then printf 500; return; fi
      cp "$test_root/$(basename "$(dirname "$1")").json" "$2"; printf 200 ;;
    https://files.pythonhosted.org/packages/*)
      cp "$dist_dir/$(basename "$1")" "$2"
      if [[ "${substitute_bytes:-false}" = true ]]; then printf wrong >> "$2"; fi
      printf 200 ;;
    *) return 1 ;;
  esac
}
verify_sigstore() {
  printf 'crypto\n' >> "$calls"
  if [[ "${mutate_provenance:-false}" = true ]]; then printf ' ' >> "$1"; fi
  if [[ "${mutate_inventory:-false}" = true ]]; then printf '\n' >> "$receipts/existing.txt"; fi
  [[ "${bad_crypto:-false}" = false ]]
}
visibility_sleep() { printf 'sleep\n' >> "$calls"; }
reset_case() {
  local name="$1"
  receipts="$test_root/$name"; mkdir "$receipts"
  stage="$receipts/.release-recovery-python-stage"; calls="$receipts/calls"; : > "$calls"
  stage_state="$receipts/state.json"
  bad_crypto=false
  mutate_provenance=false; mutate_inventory=false
}
expect_failure() {
  local result=0
  ( "$@" ) > "$receipts/stdout" 2> "$receipts/stderr" || result=$?
  [[ "$result" != 0 ]] || { echo "unexpected success: $*" >&2; exit 1; }
}
# Successor acceptance requires both mapped publications; no new upload stage.
for scenario in both; do
  reset_case "preflight-$scenario"
  prepare_publication
  # Exercise the real shared stage validator with this fixture inventory;
  # the production CLI additionally requires its immutable reviewed manifest.
  public_command "$tool_python" -I -B - "$repo/tools/verify_release_recovery_python_stage.py" "$receipts" "$stage_state" "$manifest" "$GITHUB_SHA" "$GITHUB_REF" <<'PY'
import importlib.util,pathlib,sys
helper,workspace,state,manifest,sha,ref=sys.argv[1:]
spec=importlib.util.spec_from_file_location('stage_fixture',helper)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
inventory={}
for row in pathlib.Path(manifest).read_text().splitlines():
    name,digest,size=row.split('\t'); inventory[name]={'sha256':digest,'size':int(size)}
module.validate_stage(pathlib.Path(workspace),pathlib.Path(state),'staged',sha,ref,inventory)
PY
  case "$scenario" in
    none|404) expected=2 ;;
    wheel|sdist) expected=1 ;;
    both) expected=0 ;;
  esac
  [[ "$(find "$stage" -type f | wc -l | tr -d ' ')" = "$expected" ]]
  [[ "$scenario" != wheel || -f "$stage/exochain-0.2.7.tar.gz" ]]
  [[ "$scenario" != sdist || -f "$stage/exochain-0.2.7-py3-none-any.whl" ]]
  scratch="$receipts"; GITHUB_OUTPUT="$receipts/github-output"; : > "$GITHUB_OUTPUT"
  write_outputs
  expected_needed=true; [[ "$expected" != 0 ]] || expected_needed=false
  [[ "$(sed -n '1p' "$GITHUB_OUTPUT")" = "publish_needed=$expected_needed" ]]
  [[ "$(sed -n '2p' "$GITHUB_OUTPUT")" = 'packages_dir=.release-recovery-python-stage/' ]]
done
for scenario in none wheel sdist 404 conflict malformed transport 401 500 provenance404 provenance500; do
  reset_case "reject-$scenario"; expect_failure prepare_publication; [[ ! -e "$stage" ]]
done
scenario=both; reset_case invalid-crypto; bad_crypto=true
expect_failure prepare_publication; [[ ! -e "$stage" ]]
scenario=both; reset_case wrong-publication-map
publication_identities="$test_root/malformed.json"
expect_failure prepare_publication; [[ ! -e "$stage" ]]
publication_identities="$repo/governance/releases/v0.2.7/PUBLICATION-IDENTITIES.json"
scenario=both; reset_case changed-provenance; mutate_provenance=true
expect_failure prepare_publication; [[ ! -e "$stage" ]]
scenario=both; reset_case changed-inventory; mutate_inventory=true
expect_failure prepare_publication; [[ ! -e "$stage" ]]
scenario=both; reset_case existing-stage; mkdir "$stage"; expect_failure prepare_publication
scenario=both; reset_case existing-state; printf existing > "$stage_state"; expect_failure prepare_publication
scenario=both; reset_case stage-symlink; ln -s "$dist_dir" "$stage"; expect_failure prepare_publication
scenario=both; reset_case readback-complete; accept_readback
for scenario in none wheel sdist conflict malformed transport 401 500; do
  reset_case "readback-$scenario"; expect_failure accept_readback
  [[ "$(wc -l < "$calls" | tr -d ' ')" = 1 ]]
done
scenario=delayed; reset_case readback-delayed; accept_readback
[[ "$(grep -c sleep "$calls")" = 1 ]]
scenario=provenance500; reset_case readback-provenance-terminal; expect_failure accept_readback
[[ "$(grep -c '/json' "$calls")" = 1 && "$(grep -c '/provenance' "$calls")" = 1 ]]
scenario=both; reset_case readback-invalid-crypto; bad_crypto=true; expect_failure accept_readback
[[ "$(grep -c '/json' "$calls")" = 1 ]]
scenario=provenance404; reset_case provenance-exhausted; expect_failure accept_readback
[[ "$(grep -c sleep "$calls")" = 24 && "$(grep -c '/provenance' "$calls")" = 25 ]]
scenario=404; reset_case exhausted; expect_failure accept_readback
[[ "$(grep -c sleep "$calls")" = 24 ]]
[[ "$(grep -c '/json' "$calls")" = 25 ]]
reset_case isolation
public_command "$tool_python" -I -B -c 'import os; assert not any(k in os.environ for k in ("GITHUB_TOKEN","ACTIONS_ID_TOKEN_REQUEST_TOKEN","PYTHONPATH","CURL_HOME"))'
scenario=both; reset_case retained-readback-no-receipts
mode=retained-readback
declare -F readback_without_stage >/dev/null || { echo 'readback-only API absent' >&2; exit 1; }
readback_without_stage
[[ ! -e "$stage" && ! -e "$receipts/exochain-0.2.7-py3-none-any.whl.result.json" ]]
[[ "$(grep -c '^crypto$' "$calls")" = 2 ]]
mode=accept
for dry in true false; do
  RELEASE_WORKFLOW_DRY_RUN="$dry"
  scenario=both; reset_case "retained-$dry"; accept_without_stage
  [[ ! -e "$stage" && ! -e "$stage_state" ]]
  [[ "$(grep -c files.pythonhosted.org "$calls")" = 2 && "$(grep -c crypto "$calls")" = 2 ]]
  [[ -f "$receipts/exochain-0.2.7-py3-none-any.whl.result.json" && -f "$receipts/exochain-0.2.7.tar.gz.result.json" ]]
done
scenario=both; reset_case retained-wrong-public-bytes; substitute_bytes=true
expect_failure accept_without_stage
[[ ! -e "$stage" && ! -e "$stage_state" && ! -e "$receipts/exochain-0.2.7-py3-none-any.whl.result.json" ]]
substitute_bytes=false
for scenario in wheel sdist none conflict provenance500; do
  reset_case "retained-reject-$scenario"; expect_failure accept_without_stage
  [[ ! -e "$stage" && ! -e "$stage_state" ]]
done
scenario=both; reset_case retained-bad-crypto; bad_crypto=true; expect_failure accept_without_stage
[[ ! -e "$receipts/exochain-0.2.7-py3-none-any.whl.result.json" && ! -e "$stage" ]]
unset mode
reset_case bootstrap-rejects-oidc
expect_failure /bin/bash "$helper" preflight
grep -q 'publication credentials must be absent' "$receipts/stderr"
reset_case bootstrap-rejects-ref
expect_failure /usr/bin/env ACTIONS_ID_TOKEN_REQUEST_TOKEN= RELEASE_TAG=v0.2.7 /bin/bash "$helper" preflight
grep -q 'invalid controller commit or maintenance tag' "$receipts/stderr"
echo 'Python recovery orchestration tests passed (fixture crypto seam; no live publication proof).'
