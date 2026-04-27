#!/usr/bin/env bash
# Guard the authoritative CR-001 status across public and governance docs.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "CR-001 status test failed: $*" >&2
  exit 1
}

assert_contains() {
  local file=$1
  local pattern=$2
  if ! grep -Eq "$pattern" "$file"; then
    fail "$file missing required pattern: $pattern"
  fi
}

assert_lacks() {
  local file=$1
  local pattern=$2
  if grep -nE "$pattern" "$file"; then
    fail "$file contains forbidden pattern: $pattern"
  fi
}

resolution=governance/resolutions/CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY.md
index=governance/resolutions/INDEX.md
refactor=governance/EXOCHAIN-REFACTOR-PLAN.md
quality=governance/quality_gates.md
adr=docs/adr/ADR-001-authority-of-text.md
onboarding=docs/guides/developer-onboarding.md

assert_contains "$resolution" '^status: draft$'
assert_contains "$resolution" '^\*\*Status:\*\* DRAFT .+ Pending Council Ratification$'
assert_contains "$resolution" '^- \[ \] Quality gates pass without exception$'

assert_contains "$index" 'CR-001.*\| DRAFT \| 2026-03-18 \| - \|'

assert_contains README.md 'CR-001 \(AEGIS/SYBIL/Authentic Plurality\) is \*\*DRAFT .+ pending council ratification\*\*'
assert_contains README.md 'Council Resolutions.*CR-001 DRAFT'
assert_lacks README.md 'CR-001[^[:cntrl:]]*ratified|ratified resolutions \(CR-001|CR-001[^[:cntrl:]]*fully implemented'

assert_contains "$refactor" 'CR-001 remains DRAFT'
assert_contains "$refactor" 'Section 9 acceptance criteria remain open'
assert_lacks "$refactor" '\[x\] Ratify CR-001|CR-001 ratified|CR-001[^[:cntrl:]]*RATIFIED|CR-001[^[:cntrl:]]*fully implemented'

assert_contains "$quality" 'draft CR-001 release-blocking criteria'
assert_lacks "$quality" 'ratified CR-001 resolution'

assert_contains "$adr" 'CR-001 draft hierarchy'
assert_lacks "$adr" 'ratification of CR-001|After CR-001 it is incorrect|Mandated by \[CR-001\]'

assert_contains "$onboarding" 'resolution \(draft, pending ratification\)'

echo "CR-001 status test passed"
