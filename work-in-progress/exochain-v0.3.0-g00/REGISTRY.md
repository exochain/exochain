# Artifact registry

Snapshot date: `2026-08-25`

Preservation branch: `agent/exochain-paid-work-registry`

G00 preservation reference base: `98bd90ee2081ab28f506236cfb009d726118c494`

Publication branch base: `origin/main` at
`8020ceab355eefa7f5185d9cdd0436da7af46efb`

## Governing records

| File | Status | SHA-256 | Bytes |
| --- | --- | --- | ---: |
| `governing/EXOCHAIN_v0-3-0_G00_Evidence-Recovery_Principal-Directive_DRAFT.md` | `ISSUED; HISTORICAL G00 AUTHORITY` | `c3239796eb258bd9ff430b675f2844d25824d1fe617e274517c97b2d22a0f494` | 27189 |
| `governing/EXOCHAIN_v0-3-0_G00_Post-Exposure_Continuation_Principal-Directive_DRAFT.md` | `ISSUED; PARTIALLY SUPERSEDED` | `edc4663630cff8366aa3b82a3d77b990d40f65578e7a2e3cd563a4cd7251aece` | 15736 |
| `governing/EXOCHAIN_v0-3-0_G00_Controller-Credential-Exposure_Incident_2026-08-09.md` | `SANITIZED HISTORICAL INCIDENT` | `4d291a0dedad83d563dbf2500c0e2af54ce53998beaf9d362150cf8af6c3173b` | 4626 |
| `governing/EXOCHAIN_v0-3-0_Open-Issue_Integrity-Intake_2026-08-09.md` | `NON-OPERATIVE SUCCESSOR INTAKE` | `42a90e13eeb97184fcf3ca935fe170b13ea08cbd6e6be0becad7dbffc14db25c` | 8827 |
| `governing/EXOCHAIN_v0-3-0_EXO-DAG-DB_Inclusion-Assessment_2026-08-09.md` | `NON-OPERATIVE SUCCESSOR INTAKE` | `40874c0253093fa5160b39ff93ee9f10170a6e03cc303c067f38d3d51b1cab4f` | 10729 |
| `governing/EXOCHAIN_Cursor-Independence_and_G00_Unblocking_Principal-Directive_DRAFT.md` | `ISSUED; CURSOR EXCLUDED FROM EXOCHAIN` | `93aea4948394cba35a6a234c35702ce4db38143e4946374285e3db4bd7fb2929` | 11611 |

The Cursor-independence directive supersedes only the Cursor-dependent G00
gates described in its exact bytes. It does not approve source changes or make
the preserved candidate release-ready.

## Current worktree snapshots

| Set | Classification | Source branch and HEAD | Preserved material |
| --- | --- | --- | --- |
| `current-worktrees/main-uncommitted/` | `ADJACENT_SURFACE_UNCOMMITTED_SNAPSHOT` | `bob-stewart/EXOCHAINv0.3.0Evidence-GradeTrustRelease` at `c5f1b17571e25e2fec2c71f384467748da00af74` | 25 tracked modifications in `tracked.patch`; 16 untracked files under `untracked/` |
| `current-worktrees/pr-817-deletions/` | `CONTAMINATED_DELETION_STATE` | `bob-stewart/pr-817-fix` at `49ea877005db731f0e2844ad481b436a0a975da8` | 140 tracked deletions; do not apply without owner review |
| `current-worktrees/release-integration-deletions/` | `CONTAMINATED_DELETION_STATE` | `bob-stewart/v0.3.0-release-integration` at `92c0d931b55e38067a3f99e46b4f3e1b29a25cd1` | 140 tracked deletions; byte-identical patch to the PR-817 deletion snapshot |

Patch bindings:

- Main tracked patch: `49e5364e6b269a731c717b92ff61e58d68b5535c9e0d3abc03955e2f2e11ded4`, `68420` bytes.
- Main untracked path inventory: `4c1a700f6ccd98c60d1a24b2cfcfdfe902f06cf99f866d14ba0399a84acba79d`, `756` bytes.
- Each 140-deletion patch: `7831a9661fa48105c294d929899cffaad7009e09be4774890250588c98211956`, `1268381` bytes.
- Each deletion name-status inventory: `db0da7e2c73e32deab02de77bbe2896c51a2212eff007cad1172a530adfa4fcd`, `6656` bytes.

## Clean local workstreams observed

These worktrees had no local changes at the snapshot. Their committed work is
referenced rather than duplicated:

- `codex/pr828-repo-truth-fix` at `798e0c3600ccb309b6344a95367c63859c8256d2`
- `codex/privacy-remediation-exochain-integration-20260824` at `6578f758fd62df78ce1e47f70074e7c3c14c2bee`

## Base commits preserved on `origin`

- `bob-stewart/EXOCHAINv0.3.0Evidence-GradeTrustRelease` at
  `c5f1b17571e25e2fec2c71f384467748da00af74`
- `bob-stewart/pr-817-fix` at
  `49ea877005db731f0e2844ad481b436a0a975da8`
- `bob-stewart/v0.3.0-release-integration` at
  `92c0d931b55e38067a3f99e46b4f3e1b29a25cd1`
- `codex/pr828-repo-truth-fix` at
  `798e0c3600ccb309b6344a95367c63859c8256d2`
- `codex/privacy-remediation-exochain-integration-20260824` at
  `6578f758fd62df78ce1e47f70074e7c3c14c2bee`

The first two branches were created on the remote during this preservation
operation because their exact local commits were previously absent there.

## Missing sources

The earlier recharter and G00-recovery worktree directories were absent on
2026-08-25. Their last authenticated tuples are retained in
`missing-sources/KNOWN_BINDINGS.md`. They are not silently replaced or
synthesized.
