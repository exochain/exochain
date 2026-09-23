# DRAFT — EXOCHAIN v0.3.0 G00 evidence-recovery principal directive

This text is a proposal for Bob Stewart's review. It is not operative unless
Bob Stewart explicitly approves and issues it as EXOCHAIN principal and Chair.

I, Bob Stewart, acting as EXOCHAIN principal and Chair, authorize one narrowly
bounded G00 evidence-recovery and frozen-candidate promotion lane from the
unchanged commit:

`98bd90ee2081ab28f506236cfb009d726118c494`

This directive supplies new authority only for:

`PRIOR_MUTATION_CONTROLS_PARENT_MANIFEST_REFERENCES_DELETED_DISPOSABLE_INPUTS`

and for isolating, without modifying, the subsequently observed contaminated
working-tree state that prevents guard-only verification in the prior
worktree.

It does not reopen guard implementation, approve the preserved candidate,
cure the prior terminal ruling, alter the unchanged v0.3.0 release objective,
or authorize any other finding or operation.

The unchanged release objective remains bound to predecessor plan SHA-256
`86bf931624aa99a7440fadb39e0ef4964d8d5b4e141a8e6d2f4be9a2996752f6`,
final-exhaustion ruling SHA-256
`517d67e51b3d899be1a435435983b88556898612ee74c093a368f9d6eb05fff6`,
final manifest SHA-256
`83178dba46f4b3d9af3cf4336d4337adc6397d31606eea30ab9a3d0623d60ad8`,
terminated predecessor lease SHA-256
`98b0ffc2cb24a1d33d939cee5746830dda67e42888bf80bb9840db87e96d7e32`,
and predecessor commit
`8eb75e58ef9d33288873e4c5b18bc78b7c281014`. None is amended, resumed,
adopted as completion evidence, or made operative by this directive.

## Bound base and preserved candidate

The immutable base is:

- Commit: `98bd90ee2081ab28f506236cfb009d726118c494`
- Parent: `72c5e35777df412a27a3f8b1ccc9f1b8653ed576`
- Tree: `68961840c71da6032548b3b3d2c4517136e805a8`
- Guard path: `tools/release/test_v030_recharter_authority.sh`
- Base guard SHA-256:
  `9121c2c343be9d2677b5dcba47cd376b50b6bb5d5a5ab392737a3af3e8ea57ec`
- Base guard byte length: `137335`
- Base guard mode: `100755`
- Base guard blob: `c7f93ebffbbd69708556bbadf104ee953eb144de`

The preserved, uncommitted candidate is frozen as:

- Guard SHA-256:
  `99e55df63bb228d74da3a9a91bdd8ca85849b92e105080811b383d17b8b275ab`
- Guard byte length: `209646`
- Guard mode: `100755`
- Guard blob: `eb798e28fd3f233cf81f3c1a14413e6d5de70369`
- Guard-only diff SHA-256:
  `a736a0fe2fca952ca1e230d5746a1cee53286a81ab980f9760cd4f2637c64a39`
- Guard-only diff byte length: `118385`
- Guard-only diff insertions: `2928`
- Guard-only diff deletions: `529`

The candidate bytes are independently present at both:

1. `/Users/bobstewart/.codex/worktrees/exochain-v0.3.0-recharter-001/tools/release/test_v030_recharter_authority.sh`
2. `/Users/bobstewart/.codex/worktrees/exochain-v0.3.0-recharter-001/.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001/evidence/G00/canonical-fixture-git-boundary-repair/esm-route-tests-only-red/tests-only-red.sh`

Both sources must be byte-identical and match the complete preserved-candidate
tuple immediately before any authorized transfer. Any mismatch immediately
stops G00.

No guard byte, mode, behavior, test identity, diagnostic, or implementation
may be changed by this directive. If the preserved guard fails any required
replay, G00 stops; repair of the guard requires separate new authority.

## Bound terminal records

The prior stopped state remains binding through these sealed records:

- Chair directive SHA-256:
  `76c477dbfe6f49f75376b0fc2a19a873a9a68fb407cd997c65640ad79d276c42`
- Closed writer lease SHA-256:
  `1222fb1af55073c5f6913e51767704d77f9a32843769ed1b830e0180d90ef053`
- Writer report SHA-256:
  `c3f2ab7cb5432514858240f5823f4e3b21fedfc7d3a6cf0be061a4c99fb0605e`
- Terminal-decision JSON SHA-256:
  `28fb269de82ca8341a4442761b79652787e54ca132d8ba3085b8f2ff6b5c6db2`
- Terminal-decision Markdown SHA-256:
  `25d7e9056e2b0cc418c8d7fedf8fc7f10725e03c0720ffda764cb4f938330aaa`
- Terminal closure-audit SHA-256:
  `a5209727537d0525137057ca3033d9fc2aca0c5a9efc438a9085411742f92500`

The prior authorization terminated with zero successor commits. Its unused
commit allowance is not inherited.

## Bound evidence-integrity RED

The failing manifest is:

`.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001/evidence/G00/canonical-fixture-git-boundary-repair/verification-precommit-final-v3/prior-mutation-controls/artifacts.sha256`

Its frozen failure tuple is:

- Manifest SHA-256:
  `d7d0cda53c1e4cd50fa665601045786192d7c86cd7a8ab8dfd658548597ee833`
- Byte length: `12696`
- Line count: `113`
- Present verified entries: `95`
- Missing entries: `18`
- Verification exit code: `1`
- Stdout byte length: `5996`
- Stdout SHA-256:
  `b9f94396384ad89ae07cad4deee7d41a04d487f78d05836f5b0b83fb7565f0e8`
- Stderr byte length: `1434`
- Stderr SHA-256:
  `48f106d06c5b12e9a2615312df44ac4e25203380c57d0bb595c400e31ab5b6e6`
- Complete-output SHA-256:
  `dd334c9697a95ec3a8b9e24767ee784c7b3f010f2cb6abbd24c1efc10d317ac0`
- Stable diagnostic:
  `shasum: WARNING: 18 listed files could not be read`

The frozen ignored producer
`run-prior-mutation-controls.sh`, SHA-256
`336cee8f1b9d45878e247d97a3d7ec3fd3ee33601582597d905a02b7ababfaf4`,
`16811` bytes, mode `0644`, created a `disposable.XXXXXX` directory inside
the evidence package, included its 18 scripts in the parent manifest, printed
success, and then deleted those scripts through its exit trap. The parent
manifest was never reverified after cleanup.

The frozen ignored full-precommit producer
`run-full-precommit-verification.sh`, SHA-256
`baffdcb25742e202f44a69b03fcab5f6a9c6f7c6073b194d25ad0e7e12c8575a`,
`17970` bytes, mode `0644`, also generated its root snapshot before the prior
mutation controls existed. The failed parent excluded the child manifest files
themselves. The recovery must close both lifecycle gaps.

The historical v3 package is immutable failed evidence. It may not be edited,
regenerated in place, deleted, renamed to imply success, or treated as GREEN.

## Mandatory quarantine of the prior worktree

The prior worktree is:

`/Users/bobstewart/.codex/worktrees/exochain-v0.3.0-recharter-001`

It remains at the bound base with no staged delta relative to
`98bd90ee2081ab28f506236cfb009d726118c494`; `git diff --cached --exit-code
98bd90ee2081ab28f506236cfb009d726118c494 --` exits `0`. It now contains
`141` unstaged tracked changes:

- the one preserved guard modification;
- `32` deletions below `demo/coverage/`;
- `32` deletions below `packages/exochain-llm-proxy/dist/`; and
- `76` deletions below `packages/exochain-sdk/dist/`.

The complete name-status inventory is `141` lines and `6705` bytes with
SHA-256
`65737dadab753894390d1b7d58d45db0e6c4984831c40766402968689ca0a32d`.
The deletion-only inventory is `140` lines and `6656` bytes with SHA-256
`db0da7e2c73e32deab02de77bbe2896c51a2212eff007cad1172a530adfa4fcd`.
The complete tracked patch is `1385892` bytes with SHA-256
`8ac873573e1ebe7e9398ea229dc3d4687cc5c9db8ce524d13e692a8442320055`.

Those three digests are serialized only by these canonical commands with
`LC_ALL=C` and `src` bound to the exact quarantined worktree:

```bash
git -C "$src" diff --name-status | shasum -a 256
git -C "$src" diff --name-status | awk '$1 == "D"' | shasum -a 256
git -C "$src" diff --no-ext-diff --no-textconv | shasum -a 256
```

Those 140 deletions are observed, unattributed, outside G00 authority, and not
accepted as release work. This directive does not authorize restoring,
cleaning, resetting, checking out, stashing, staging, committing, deleting,
rebuilding, or otherwise normalizing them.

The prior worktree is read-only quarantine. It may be read only to rehash and
copy the exact bound candidate and historical ignored evidence. No test,
verification producer, package manager, build, mutation runner, or cleanup may
execute there.

## Authorized isolated recovery worktree

This directive authorizes creation of exactly one new local linked worktree:

- Path:
  `/Users/bobstewart/.codex/worktrees/exochain-v0.3.0-recharter-001-g00-recovery`
- Branch:
  `bob-stewart/release-v0.3.0-recharter-001-g00-recovery`
- Starting commit:
  `98bd90ee2081ab28f506236cfb009d726118c494`

The path and branch must be absent before creation. The new worktree must be
pristine at the exact starting commit, with no staged delta relative to that
commit and no untracked or ignored recovery material before transfer. `git diff
--cached --exit-code 98bd90ee2081ab28f506236cfb009d726118c494 --` must exit
`0`. It must contain the committed versions of all 140 paths missing from the
quarantined worktree.

Before candidate transfer, independently freeze the source and destination
commit, tree, status, index, complete tracked-path inventory, Git configuration
relevant to diff generation, and tool identities. Any mismatch stops G00.

Only these transfers are authorized:

1. copy the exact preserved candidate bytes to
   `tools/release/test_v030_recharter_authority.sh`, preserving mode `100755`;
2. copy `.superpowers/sdd/.gitignore`, which is exactly `2` bytes with
   SHA-256
   `cdbcae15105d6b781e620813c79c7e868740d4e9cc53ce6f5fcbbc12387adf4b`;
3. copy the prior ignored plan workspace from exactly
   `/Users/bobstewart/.codex/worktrees/exochain-v0.3.0-recharter-001/.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001/`
   into exactly
   `/Users/bobstewart/.codex/worktrees/exochain-v0.3.0-recharter-001-g00-recovery/.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/historical/EXOCHAIN_v0-3-0_RECHARTER_001/`
   as immutable historical context.

The prior ignored plan workspace was observed before this directive proposal
with `1079` regular files, `47` directories, `11458386` total regular-file
bytes, zero symlinks, and relative-path/content-manifest SHA-256
`dea29b9fcdcd1cb3e948aab6509e0f53c22f1d7da334d6b4b9280167883de4ba`.
That digest is serialized only by:

```bash
(
  cd "$src/.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001"
  find . -type f -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 shasum -a 256 \
    | shasum -a 256
)
```

It must match that tuple at transfer time or G00 stops. The historical snapshot
must produce the same relative-path/content manifest from its exact destination
root after transfer. It is context and adverse history only. No output or
result file from it may be used as a fresh recovery result. No other path from
the source worktree may be transferred. In particular, no path in the bound
140-path deletion inventory, no working-tree metadata, and no deletion state
may be copied or reconstructed from the quarantined worktree.

After candidate transfer, the new tracked state must be exactly one unstaged
modification at the guard path, with no staged delta relative to the bound base.
The guard and diff must match the complete preserved-candidate tuple, and all
140 unrelated paths must remain present and unmodified.

No stash, broad copy, `git add -A`, restore, clean, reset, checkout of working
files, or transfer of deletion state is authorized.

## New recovery evidence workspace

Except for the exact authorized two-byte transfer of
`.superpowers/sdd/.gitignore`, all new ignored writes are limited to:

`.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/`

Historical snapshot material must be clearly separated from the fresh recovery
package. Fresh outputs must be generated from scratch. Executable recovery
driver creation or modification is limited to these exact paths:

```text
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/reproduce-frozen-false-pass.sh
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/capture-tests-only-red.sh
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/run-full-precommit-verification.sh
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/run-prior-mutation-controls.sh
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/test-manifest-lifecycle.sh
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/verify-evidence-package.sh
```

Generated durable baseline and mutant execution inputs may exist only below the
closed `inputs/` directory of each authorized fresh package and are evidence
inputs, not additional recovery drivers. Evidence output directories may be
populated only by the whitelisted drivers. No other executable driver, helper,
callback, or producer may be created or modified.

Copied driver logic may change only to:

- bind the new worktree and recovery evidence paths;
- implement the tests-first evidence-manifest lifecycle correction;
- persist every exact executed input;
- order cleanup, producer exit, manifest generation, fresh-process
  verification, and sealing correctly; and
- enforce closed deterministic inventories and the checks in this directive.

No source-controlled harness, guard byte, mutation operator, expected result,
test identity, or diagnostic may change.

## Strict tests-first evidence recovery

Before changing any copied recovery driver, a distinct `EVID-ORACLE-G00`
identity must reproduce the bound v3 parent-manifest failure from the immutable
historical snapshot in the new worktree. The exact command, exit code, 95
verified entries, 18 missing entries, diagnostics, stdout, stderr, complete
output, byte lengths, and hashes must be preserved under the new recovery
evidence root.

A tests-only manifest-lifecycle regression must then fail for the intended
post-cleanup referential-integrity reason before implementation begins. It must
exercise the producer-exit and fresh-verifier boundary. A source-text assertion,
mocked `shasum`, in-process verification before cleanup, or inference from
child-manifest success is insufficient.

Before any harness implementation change, freeze and manifest the lifecycle
regression source, producer and verifier bytes, initial input inventory, exact
commands, exits, stdout, stderr, diagnostic, hashes, and evidence-oracle
attestation. The same frozen regression, without modification, must pass after
the minimal ignored-harness correction.

`EVID-ORACLE-G00` alone may author the tests-only lifecycle regression and its
fresh-process verifier at the two exact whitelisted paths. It must close its
tests-only lease after freezing RED and before the recovery writer modifies any
copied producer, begins implementation, or runs GREEN verification. The writer
may create the isolated worktree and perform only the exact immutable transfers
authorized above before the oracle RED lease begins; no copied producer may be
modified or executed in that interval. `EVID-ORACLE-G00` may not be the recovery
writer, controller, Council advisor, `EVID-VER-G00`, SPEC-G00, QUAL-G00,
ADV-G00, or VER-G00. The recovery writer may not modify the frozen regression
or verifier bytes.

The minimal ignored-harness implementation must:

1. create every relocated baseline and every mutant execution input in a
   durable `inputs/` directory inside the unsealed evidence package;
2. include the exact executed input bytes, mutation diffs, commands,
   environment and tool tuples, raw outputs, exits, diagnostics, result rows,
   and inventories in the manifest hierarchy;
3. use temporary runtime repositories only outside the evidence root and never
   record an ephemeral `disposable.*`, `/tmp`, absolute, or escaping path in a
   manifest or command contract;
4. complete and verify runtime cleanup before manifest generation;
5. exit the producer process before any acceptance verification;
6. generate each child manifest from a fresh verifier process, excluding only
   that child manifest itself;
7. generate the final root manifest last, excluding only itself and explicitly
   including every child manifest;
8. accept only sorted, unique, safe-relative, in-root, regular, non-symlink
   files, with no missing, extra, duplicate, self-referential, malformed,
   truncated, absolute, or path-escaping entry;
9. require the root-manifest entry count to equal the complete post-cleanup
   durable-file inventory;
10. replay every child and root manifest twice from fresh verifier processes;
11. atomically seal or rename the package only after all replay checks pass;
    and
12. record the final root-manifest hash, byte length, line count, package
    inventory, guard tuple, producer identity, and verifier identity in a
    detached terminal record.

Independent negative tests must prove rejection of at least:

- one missing manifested execution input;
- one missing child manifest;
- one unmanifested extra file;
- a duplicate entry;
- an unsorted entry set;
- self-inclusion;
- an absolute path;
- a parent-path escape;
- a symlink target;
- a malformed or truncated digest row; and
- any `disposable.*` or temporary-runtime path.

The two freshly generated complete recovery packages must come from two
separate producer executions into two separate initially empty roots. The
second execution may not copy, hard-link, reuse, or derive any output, result,
manifest, or seal from the first package. The completed packages must be
byte-identical, including durable inputs, raw results, inventories, child
manifests, and final root manifests. Nondeterministic paths, timestamps, random
identifiers, locale, ambient Git object format, or tool-default selection are
prohibited.

Historical scripts remain byte-exact immutable reference inputs. A freshly
executed relocated input may differ from its historical reference only by the
deterministic replacement of the quarantined absolute `ROOT` with the exact new
recovery-worktree root. Each relocation must be mechanically derived, diffed,
hashed, persisted, and independently proven to leave the mutation operator,
self-test identities, expected case count, and diagnostics unchanged. Any other
byte difference stops G00.

The immutable historical base false-pass mutant is SHA-256
`7fa8bb10b6652d8280c4fe7f35133ac6ec84f23b6aaf06ac8cc9e738b5523066`,
`138808` bytes. The immutable historical successor mutant is SHA-256
`0de7700c4040d03e754d101c623e53a587661d4bf26fc999b98d7431f770056a`,
`211059` bytes. Neither historical file may execute because both bind the
quarantined absolute worktree. Only their frozen, mechanically relocated
derivatives may execute in the recovery worktree.

## Complete guard replay

Historical provisional results are requirements and adverse history only. The
new recovery package must freshly execute and bind all of the following before
any staging:

1. The deterministically relocated exact frozen base false-pass mutant under external
   `GIT_DEFAULT_HASH` unset, `sha1`, and `sha256`; each must exit `0`, execute
   `197` cases, perform `13` unreceipted real SHA-1 fixture initializations,
   and produce complete-output SHA-256
   `33cc2b279c3482c35b74d5a59d37bf8589446dcac6e512ab802fa9335bb1f554`.
2. The exact tests-only RED against the frozen base; it must exit `1` after
   all `197` identities with diagnostic
   `canonical fixture Git boundary accepted alternate realpath bypass: exit=0 cases=197 unreceipted_inits=13`
   and complete-output SHA-256
   `fa64e47921c0cea0844d8dbd235af22895c8ba5f3754ad624c74439fe3961374`.
3. Two unset, two external-SHA-1, and two external-SHA-256 candidate runs; all
   six must exit `0`, execute `250` self-test identities and `13` embedded route
   mutations, emit `18037` stdout bytes and zero stderr bytes, and be
   byte-identical at complete-output SHA-256
   `5d92344fe40d2b4935e0e5f85b15f3d8249c670a9d49f855b8e6b5df16f75984`.
4. The deterministically relocated derivative of the exact successor frozen
   mutant under unset, SHA-1, and SHA-256; all three must exit `1` after `188`
   cases with empty bypass logs, the intended boundary diagnostic, and
   complete-output SHA-256
   `679d6ffe328e5f8797fdda4ce48e672a0b05edc6c7831899b3ffd385d478dc65`.
5. All 13 real-behavior route mutations in every canonical run: frozen
   pre-init realpath, cached executable, absolute realpath, direct
   `execFileSync`, direct `spawnSync`, shell or `execSync`, fresh PATH lookup,
   alias or helper, injected callback, extra pre-init, extra post-init,
   executable-identity replacement, and ESM named export.
6. Byte-identical historical prefixes at `176`, `181`, `189`, and `197`.
7. All `17` continuing mutation executions and all six cached/pre-resolved
   explicit-control executions, with semantic row-for-row equality to the
   frozen v3 results. Equality requires the same mutation operator, external
   environment, exit, case count, diagnostic, stdout and stderr hashes,
   complete-output hash, and identity coverage. Historical absolute command
   paths and historical mutant-input hashes are reference fields: each lawful
   relocation must instead bind its new input hash, length, and relocation diff.
8. All 52 required continuing identities exactly once in each of the six
   canonical outputs, producing exactly `312` bound identity rows.
9. Bash syntax; preload, bootstrap, and embedded Node syntax; `git diff
   --check`; two byte-identical ordinary-RED executions; exact guard tuple and
   guard-only scope; no staged delta relative to the bound base; formal-DRAFT
   absence; Round-6 absence; secret scan; and zero temporary-resource leaks for
   every established prefix.

Any missing identity, output difference, mutation survivor, ambient default,
nonzero canonical run, unexpected zero mutant run, evidence leak, or mismatch
immediately stops G00. No guard repair is authorized.

## Separation of powers and pre-commit acceptance

One new sole writer lease may be opened in the recovery worktree. Its holder
may create the worktree, transfer the exact candidate and historical context,
author only the ignored recovery harness and evidence, execute the authorized
matrix, and conditionally create the one local guard-only commit.

The writer may not act as controller, Council, `EVID-ORACLE-G00`, evidence
verifier, SPEC-G00, QUAL-G00, ADV-G00, or VER-G00. The controller may
coordinate, independently rehash, and freeze state but may not edit the
candidate, author the evidence harness, approve the evidence, or act as a final
reviewer. Council input is advisory only.

Before staging, a fresh, distinct, read-only `EVID-VER-G00` identity must issue
`PRECOMMIT_EVIDENCE_ACCEPTED` against both byte-identical recovery packages and
the exact candidate tuple. That decision must independently confirm:

- clean isolated recovery base and the complete preserved candidate tuple;
- exactly one unstaged tracked guard path and no staged delta relative to the
  bound base;
- all 140 unrelated paths present and unchanged;
- complete RED, canonical, mutation, prefix, identity, syntax, ordinary-RED,
  scope, absence, secret, and leak matrices;
- producer exit and cleanup before verification;
- two fresh-process replays of every child and final root manifest;
- closed manifest inventories with no ephemeral or external reference;
- byte identity between the two complete recovery packages; and
- absence of formal DRAFT inputs, Round 6, external-state access, secret
  access, and every prohibited operation.

Any rejection or inability to prove a requirement stops G00 before staging.

## Conditional one-commit authority

This directive authorizes at most one new local commit. It may be created only
after `PRECOMMIT_EVIDENCE_ACCEPTED` exists and verifies.

Immediately before staging, the writer must re-prove:

- parent `98bd90ee2081ab28f506236cfb009d726118c494`;
- one changed source-controlled path, exactly
  `tools/release/test_v030_recharter_authority.sh`;
- no staged delta relative to the bound base;
- exactly one unstaged tracked path, the guard;
- working-tree guard SHA-256
  `99e55df63bb228d74da3a9a91bdd8ca85849b92e105080811b383d17b8b275ab`;
- working-tree guard byte length `209646`;
- working-tree mode `100755`;
- working-tree blob `eb798e28fd3f233cf81f3c1a14413e6d5de70369`;
- working-tree guard-only diff SHA-256
  `a736a0fe2fca952ca1e230d5746a1cee53286a81ab980f9760cd4f2637c64a39`;
- no modification to any of the 140 quarantined deletion paths.

The writer may then stage exactly the guard path. After staging and before
commit, a separate cached-state gate must prove:

- `git diff --cached --name-status
  98bd90ee2081ab28f506236cfb009d726118c494 --` is exactly one line:
  `M<TAB>tools/release/test_v030_recharter_authority.sh`;
- the cached mode is `100755` and cached blob is
  `eb798e28fd3f233cf81f3c1a14413e6d5de70369`;
- the cached guard-only diff SHA-256 is
  `a736a0fe2fca952ca1e230d5746a1cee53286a81ab980f9760cd4f2637c64a39`;
- the cached numstat is exactly `2928` insertions and `529` deletions at the
  guard path;
- there is no unstaged tracked delta; and
- no other staged, unstaged, deleted, untracked source, or mode change exists.

Any cached-state mismatch stops before commit. Only after that independent
post-stage gate passes may the writer create exactly one local guard-only
commit whose parent is the bound base. `git add -A`, a broad pathspec, an
evidence commit, a cleanup commit, an amendment, a follow-up commit, a merge,
or a second repair commit is prohibited.

After commit, the writer lease must close and freeze the exact successor
commit, parent, tree, guard SHA-256, byte length, mode, blob, changed-path
inventory, commit count, complete evidence-root manifest, and final status.

If any pre-commit gate fails, no commit may be created. If a commit is created,
the one-commit authority is consumed. This directive authorizes no amendment or
repair after either outcome.

## Fresh post-commit review

All prior approvals, rejections, provisional passes, and verification decisions
expire for the successor commit.

Fresh, distinct, read-only SPEC-G00, QUAL-G00, ADV-G00, and VER-G00 identities,
none of whom is the writer, controller, Council advisor, or EVID-VER-G00, must
unanimously approve the same frozen successor commit, guard SHA-256, and final
evidence-root manifest.

Review must independently cover the preserved guard requirements, complete
mutation matrix, manifest lifecycle and negative tests, source scope, role
separation, terminal records, formal-DRAFT and Round-6 absence, secrets,
temporary resources, and clean recovery-worktree state.

Any rejection, authority false-pass, surviving mutation, recurrence of any
earlier defect, evidence-integrity failure, non-guard tracked change,
nondeterminism, reviewer conflict, or lack of unanimity immediately stops G00.
No further repair is authorized by this directive.

GREEN and formal DRAFT authoring remain prohibited throughout this recovery
lane. Unanimous approval may establish only
`G00_GUARD_AND_EVIDENCE_RECOVERY_VERIFIED`; any authority to begin formal DRAFT
authoring must be separately confirmed by the principal.

## Continuing prohibitions

This directive does not authorize:

- editing or normalizing the quarantined worktree;
- changing any preserved guard byte or behavior;
- any source-controlled path other than the exact guard path;
- formal DRAFT inputs or GREEN;
- predecessor modification;
- source development;
- external-state or secret access;
- GitHub operations or push;
- publication;
- signing or a signing ceremony;
- ratification or activation;
- deployment;
- public claims;
- release operations; or
- Round 6.

This directive authorizes no further recovery, amendment, or repair.
