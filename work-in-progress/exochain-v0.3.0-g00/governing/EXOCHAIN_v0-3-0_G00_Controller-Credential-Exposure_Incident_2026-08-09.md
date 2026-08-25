# EXOCHAIN v0.3.0 G00 controller credential-exposure incident

Status: **SANITIZED TERMINAL INCIDENT RECORD**

This record contains no credential value, token fragment, private key, secret,
or replacement credential. It records only the security-relevant event and
the fail-closed consequence.

## Bound context

- Issued recovery directive SHA-256:
  `c3239796eb258bd9ff430b675f2844d25824d1fe617e274517c97b2d22a0f494`
- Recovery base commit:
  `98bd90ee2081ab28f506236cfb009d726118c494`
- Recovery worktree:
  `/Users/bobstewart/.codex/worktrees/exochain-v0.3.0-recharter-001-g00-recovery`
- Recovery branch:
  `bob-stewart/release-v0.3.0-recharter-001-g00-recovery`
- Incident date: `2026-08-09`
- Incident time: approximately `07:06` America/New_York
- Incident identity: original G00 controller
- Affected credential class: unrelated Cursor agent-worker API credential

## Event

After the writer stopped on a suspected ignored-file scope mismatch, the
controller ran a broad read-only operating-system process listing while trying
to attribute the file's creation. The process-list output included an
unrelated process command line containing a credential value.

The controller did not intentionally request the credential, use it, repeat it
to the user, copy it into a file, write it into the recovery worktree, include
it in an evidence package, or use it to access any provider. Nevertheless, the
credential appeared in tool output visible to the controller and the task
transcript. Under the issued directive's prohibition on secret access, this is
a terminal G00 stop.

## Scope correction for the triggering file

The distinct read-only contamination audit established that
`.superpowers/sdd/progress.md` was not an unauthorized ignored write:

- it is tracked in the bound base at mode `100644`;
- Git blob: `9e36691f4291dc03a0359734eb5c6bea49ba4efb`;
- SHA-256:
  `ad83f6885c6a9aa591e44ebc66109923487c1ab7391da7f499e470c5029fb3e7`;
- byte length: `3340`;
- worktree and index bytes equal the bound base;
- Git does not classify the tracked file as ignored; and
- its creation time matches normal linked-worktree checkout.

The writer's initial stop was appropriately fail-closed, but the file itself
does not constitute a transfer or source-scope violation. This correction does
not cure the separate credential-exposure stop.

## State at stop

No guard, test, historical producer, mutation runner, package manager, build,
cleanup, staging, commit, GitHub operation, publication, deployment, or release
operation executed in the recovery worktree.

The authorized worktree creation and three immutable transfers completed. The
preserved current state is:

- HEAD:
  `98bd90ee2081ab28f506236cfb009d726118c494`;
- tree: `68961840c71da6032548b3b3d2c4517136e805a8`;
- no staged delta relative to the base;
- exactly one unstaged tracked modification:
  `tools/release/test_v030_recharter_authority.sh`;
- candidate guard SHA-256:
  `99e55df63bb228d74da3a9a91bdd8ca85849b92e105080811b383d17b8b275ab`;
- candidate guard byte length: `209646`;
- candidate guard mode: `100755`;
- candidate guard blob: `eb798e28fd3f233cf81f3c1a14413e6d5de70369`;
- guard-only diff SHA-256:
  `a736a0fe2fca952ca1e230d5746a1cee53286a81ab980f9760cd4f2637c64a39`;
- historical snapshot: `1079` files, `47` directories, `11458386` bytes,
  zero symlinks, manifest SHA-256
  `dea29b9fcdcd1cb3e948aab6509e0f53c22f1d7da334d6b4b9280167883de4ba`;
- tracked path inventory: `2865` paths, SHA-256
  `a72fcda7018a6857a11c425fedba559dd345b072286f915a5c525d815838861c`;
- no tracked deletion, no untracked nonignored path, and no commit created.

The prior quarantined worktree remains unchanged at its 141-path tracked delta
inventory.

## Required security response

Before any G00 continuation:

1. the exposed Cursor credential must be revoked or rotated by an authorized
   security operator outside the original controller identity;
2. no credential value or fragment may be placed in evidence;
3. a sanitized attestation must bind the operator identity, credential class,
   provider, revocation or rotation result, and completion time;
4. the original controller must be excluded from the continued controller,
   writer, evidence-oracle, verifier, Council, and final-review roles; and
5. process listings, environment dumps, shell tracing, and any command capable
   of returning unrelated process arguments or secret values must be prohibited
   from the continued G00 command set.

Rotation is an external secret operation and requires new explicit principal
authority. This incident record does not authorize it or any G00 continuation.

