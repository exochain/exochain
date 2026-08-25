# DRAFT — EXOCHAIN v0.3.0 G00 post-exposure continuation directive

This text is a proposal for Bob Stewart's review. It is not operative unless
Bob Stewart explicitly approves and issues it as EXOCHAIN principal and Chair.

I, Bob Stewart, acting as EXOCHAIN principal and Chair, acknowledge the
fail-closed stop under the issued G00 evidence-recovery directive SHA-256
`c3239796eb258bd9ff430b675f2844d25824d1fe617e274517c97b2d22a0f494`,
byte length `27189`, and authorize one narrowly bounded security response and
G00 continuation from the exact preserved recovery state below.

This directive binds the sanitized terminal incident record:

- Path:
  `/Users/bobstewart/Downloads/EXOCHAIN_v0-3-0_G00_Controller-Credential-Exposure_Incident_2026-08-09.md`
- SHA-256:
  `4d291a0dedad83d563dbf2500c0e2af54ce53998beaf9d362150cf8af6c3173b`
- Byte length: `4626`

It supplies new authority only because an unrelated Cursor agent-worker API
credential appeared in the original controller's read-only process-list tool
output. No credential value is ratified, reproduced, incorporated, or made
evidence by this directive.

## Correction of the suspected transfer finding

The file
`.superpowers/sdd/progress.md` is not an unauthorized ignored transfer. It is
tracked in the bound base and frozen as:

- mode: `100644`;
- Git blob: `9e36691f4291dc03a0359734eb5c6bea49ba4efb`;
- SHA-256:
  `ad83f6885c6a9aa591e44ebc66109923487c1ab7391da7f499e470c5029fb3e7`;
- byte length: `3340`; and
- worktree/index equality to
  `98bd90ee2081ab28f506236cfb009d726118c494`.

It must remain untouched. This correction closes only the suspected
ignored-transfer finding. It does not cure or minimize the credential exposure.

## Frozen continuation state

The sole canonical G00 recovery worktree is:

- Path:
  `/Users/bobstewart/.codex/worktrees/exochain-v0.3.0-recharter-001-g00-recovery`
- Branch:
  `bob-stewart/release-v0.3.0-recharter-001-g00-recovery`
- HEAD:
  `98bd90ee2081ab28f506236cfb009d726118c494`
- Parent:
  `72c5e35777df412a27a3f8b1ccc9f1b8653ed576`
- Tree: `68961840c71da6032548b3b3d2c4517136e805a8`
- Tracked path count: `2865`
- Tracked path-inventory SHA-256:
  `a72fcda7018a6857a11c425fedba559dd345b072286f915a5c525d815838861c`

Its tracked state must remain exactly one unstaged modification at:

`tools/release/test_v030_recharter_authority.sh`

with no staged delta, no tracked deletion, no other tracked modification, and
no untracked nonignored path.

The candidate remains bound as:

- SHA-256:
  `99e55df63bb228d74da3a9a91bdd8ca85849b92e105080811b383d17b8b275ab`
- Byte length: `209646`
- Mode: `100755`
- Blob: `eb798e28fd3f233cf81f3c1a14413e6d5de70369`
- Guard-only diff SHA-256:
  `a736a0fe2fca952ca1e230d5746a1cee53286a81ab980f9760cd4f2637c64a39`
- Guard-only diff byte length: `118385`
- Insertions/deletions: `2928` / `529`

The transferred historical snapshot remains bound as:

- destination:
  `.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/historical/EXOCHAIN_v0-3-0_RECHARTER_001/`;
- `1079` regular files;
- `47` directories;
- `11458386` regular-file bytes;
- zero symlinks; and
- relative-path/content manifest SHA-256:
  `dea29b9fcdcd1cb3e948aab6509e0f53c22f1d7da334d6b4b9280167883de4ba`.

The exact two-byte `.superpowers/sdd/.gitignore` remains SHA-256
`cdbcae15105d6b781e620813c79c7e868740d4e9cc53ce6f5fcbbc12387adf4b`.

The earlier three immutable transfers are complete and may not be repeated,
repaired, normalized, deleted, or replaced. No second recovery worktree or
branch is authorized.

## Mandatory credential containment before G00 continuation

This directive authorizes exactly one bounded external containment sequence:

1. one `SECURITY-OP-G00` containment transaction against the affected Cursor
   agent-worker API credential: inspect only its secret-safe provider status;
   if already expired, perform zero state-changing actions; otherwise perform
   at most one state-changing revocation or rotation action; and
2. one subsequent read-only `SECURITY-VER-G00` sanitized provider-status
   readback against the same provider credential record.

`SECURITY-OP-G00` must prefer revocation or confirmed expiry. Rotation is
permitted only when revocation or expiry cannot contain the credential and the
provider keeps the replacement provider-managed without returning it.

`SECURITY-OP-G00` must not be the original controller, replacement controller,
writer, `EVID-ORACLE-G00`, `EVID-VER-G00`, Council advisor, SPEC-G00,
QUAL-G00, ADV-G00, or VER-G00. It may access only the minimum Cursor credential
control required to revoke or rotate the affected credential. It may not access
GitHub, repository secrets, source code, release credentials, deployment
providers, signing material, or any unrelated secret.

The security operation must produce a sanitized attestation at:

`.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/security/cursor-credential-rotation-attestation.json`

The attestation must satisfy an exact closed JSON Schema with every field
required, `additionalProperties: false`, and only these fields and constraints:

| field | JSON type and constraint |
| --- | --- |
| `schema_version` | string constant `g00-cursor-credential-rotation-attestation-v1` |
| `operator_identity` | string, 1–128 ASCII characters, pattern `^[A-Za-z0-9._:-]+$` |
| `provider` | string constant `Cursor` |
| `credential_class` | string constant `agent-worker-api-credential` |
| `credential_record_reference_sha256` | string, exactly 64 lowercase hexadecimal characters |
| `old_credential_status` | string enum `revoked`, `expired` |
| `replacement_created` | boolean |
| `completed_at_utc` | string, exact UTC RFC 3339 seconds format `YYYY-MM-DDTHH:MM:SSZ` |
| `evidence_reference` | string, 1–128 ASCII characters, pattern `^[A-Za-z0-9._:-]+$` |
| `attestation_sha256` | string, exactly 64 lowercase hexadecimal characters |

`credential_record_reference_sha256` must be the SHA-256 of a non-secret,
provider-assigned credential-record reference. The raw reference may be used
only inside the preauthenticated provider control plane and may not be emitted
to the task transcript or evidence. Both security roles must bind the same
reference digest.

`attestation_sha256` is SHA-256 over deterministic canonical CBOR encoding of
the nine required fields other than `attestation_sha256`. The CBOR must be a
definite-length map; text keys must be ordered by their UTF-8 byte sequences;
strings must be definite-length UTF-8 text; the boolean must use its canonical
single-byte encoding; tags, floats, indefinite lengths, duplicate keys, and a
trailing newline or any other trailing byte are prohibited. The digest is
encoded as 64 lowercase hexadecimal characters. `SECURITY-VER-G00` must run an
independent secret-free known-answer canonicalization fixture and bind its
input bytes, canonical-CBOR bytes, expected digest, actual digest, and pass/fail
result without placing any provider data in the fixture.

No credential value, prefix, suffix, fragment, command line, environment value,
private URL, account token, or replacement secret may appear in the
attestation, task transcript, command output, filename, evidence package, or
review record. If the provider cannot establish revocation or expiry without
revealing secret material, G00 remains stopped.

The containment actions must use a preauthenticated, secret-safe control-plane
interface whose bounded request and response schemas cannot return credential
values. No credential may be supplied through tool inputs, command arguments,
environment variables, standard input, URLs, captured UI, logs, or output. If
rotation is unavoidable, the replacement may not be retrieved, displayed,
exported, installed, copied, or used under this directive. If the interface
would display or return a replacement, the operator must not invoke it and G00
remains stopped pending separate authority.

A distinct read-only `SECURITY-VER-G00` identity must verify the attestation,
confirm the old credential is revoked or expired through the one authorized
sanitized provider-status readback, confirm that no secret material was
emitted, and write exactly:

`.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/security/cursor-credential-containment-verification.json`

The verification artifact must satisfy an exact closed JSON Schema with every
field required, `additionalProperties: false`, and only:

| field | JSON type and constraint |
| --- | --- |
| `schema_version` | string constant `g00-cursor-credential-containment-verification-v1` |
| `verifier_identity` | string, 1–128 ASCII characters, pattern `^[A-Za-z0-9._:-]+$` |
| `provider` | string constant `Cursor` |
| `credential_class` | string constant `agent-worker-api-credential` |
| `credential_record_reference_sha256` | string, exactly 64 lowercase hexadecimal characters and equal to the attestation field |
| `attestation_sha256` | string, exactly 64 lowercase hexadecimal characters and equal to the verified attestation digest |
| `observed_old_credential_status` | string enum `revoked`, `expired` |
| `no_secret_material_observed` | boolean constant `true` |
| `canonicalization_kat_passed` | boolean constant `true` |
| `completed_at_utc` | string, exact UTC RFC 3339 seconds format `YYYY-MM-DDTHH:MM:SSZ` |
| `decision` | string constant `CREDENTIAL_CONTAINMENT_VERIFIED` |
| `verification_sha256` | string, exactly 64 lowercase hexadecimal characters |

`verification_sha256` is computed by the identical deterministic canonical-CBOR
and lowercase-hex rules over the eleven required fields other than
`verification_sha256`. `SECURITY-VER-G00` may not be any other named role.

No repository, recovery, guard, historical, harness, test, mutation, build,
staging, commit, or evidence-package command may execute until both sanitized
security artifacts are frozen and valid. The sole exceptions before that gate
are the one authorized `SECURITY-OP-G00` containment transaction with zero or
at most one state-changing action, the one authorized `SECURITY-VER-G00`
read-only status action, their secret-free known-answer computation, and
writing and hashing only the two exact sanitized security artifact paths.

## Replacement controller and command-output boundary

The original controller is permanently excluded from every continued G00 role,
including replacement controller, writer, evidence oracle, evidence verifier,
Council advisor, security operator, security verifier, SPEC-G00, QUAL-G00,
ADV-G00, and VER-G00. It may relay the Chair's directive and receive only
sanitized terminal decisions; it may not execute, inspect, or review continued
G00 commands or filesystem state.

Every continued role, including `SECURITY-OP-G00`, `SECURITY-VER-G00`,
`CONTROLLER-2-G00`, `EVID-ORACLE-G00`, the fresh writer, Council advisors,
`EVID-VER-G00`, SPEC-G00, QUAL-G00, ADV-G00, and VER-G00, must begin in a clean
room with no inherited conversation turns, tool outputs, summaries, process
list, or context from the contaminated task. They may receive only the exact
byte-bound sanitized incident record, the exact byte-bound issued and
continuation directives, these two preserved intake records:

- `/Users/bobstewart/Downloads/EXOCHAIN_v0-3-0_Open-Issue_Integrity-Intake_2026-08-09.md`,
  SHA-256
  `42a90e13eeb97184fcf3ca935fe170b13ea08cbd6e6be0becad7dbffc14db25c`,
  byte length `8827`; and
- `/Users/bobstewart/Downloads/EXOCHAIN_v0-3-0_EXO-DAG-DB_Inclusion-Assessment_2026-08-09.md`,
  SHA-256
  `40874c0253093fa5160b39ff93ee9f10170a6e03cc303c067f38d3d51b1cab4f`,
  byte length `10729`;

and only the non-secret frozen-state tuples literally enumerated in this
directive. No additional state tuple, summary, command output, path inventory,
or contextual interpretation may be added to the clean-room handoff. Any
access to the contaminated transcript or its tool output immediately stops
G00.

A fresh `CONTROLLER-2-G00` identity must coordinate the continuation. It may
not be any other named role and may not edit the guard, harness, evidence,
attestations, or review decisions.

The continued command set must prohibit:

- process listings or process-argument inspection;
- environment dumps or shell tracing;
- keychain, credential-store, browser-storage, or secret-manager reads except
  the narrowly authorized Cursor rotation/status operation by the two security
  roles;
- commands that print configuration values rather than names and sanitized
  presence/status;
- recursive inspection outside the exact recovery worktree and sealed
  Downloads artifacts; and
- any output containing a secret-like value.

If any credential, token, private key, secret, sensitive URL, or unrelated
process argument appears, all output handling stops and G00 terminates.

## Continued G00 authority

After `CREDENTIAL_CONTAINMENT_VERIFIED`, this directive reauthorizes exactly
the unfinished actions in the issued directive SHA-256
`c3239796eb258bd9ff430b675f2844d25824d1fe617e274517c97b2d22a0f494`.
Every unchanged requirement, role separation, strict tests-first gate,
manifest-lifecycle rule, mutation matrix, precommit acceptance condition,
one-commit constraint, post-commit review requirement, immediate-stop clause,
and prohibition in that directive remains binding.

The completed writer transfer lease is closed. The next lawful G00 action is a
fresh `EVID-ORACLE-G00` lease. It must reproduce the historical manifest
failure and freeze the same tests-only lifecycle RED before any copied producer
is modified, any implementation begins, or any GREEN verification runs.

Only after the oracle closes RED may a fresh writer lease modify these four
copied producer paths:

```text
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/reproduce-frozen-false-pass.sh
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/capture-tests-only-red.sh
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/run-full-precommit-verification.sh
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/run-prior-mutation-controls.sh
```

The oracle-authored tests-only lifecycle regression and fresh-process verifier
at these two paths remain immutable after RED is frozen, though they may be
executed as authorized:

```text
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/test-manifest-lifecycle.sh
.superpowers/sdd/EXOCHAIN_v0-3-0_RECHARTER_001_RECOVERY_001/drivers/verify-evidence-package.sh
```

The preserved guard bytes may not change.

Exactly one local guard-only commit remains conditionally authorized. No commit
has yet been created. The commit may be created only after all original
evidence, precommit, staging, and cached-state gates pass. No additional,
replacement, cleanup, evidence, incident, or security commit is authorized.

## Continuing release-objective and intake boundary

The unchanged v0.3.0 objective and preserved successor-planning intake records
remain as directed by the principal. They are not activated by this directive.
Formal successor-plan authoring remains prohibited until
`G00_GUARD_AND_EVIDENCE_RECOVERY_VERIFIED` is lawfully established and the
principal separately authorizes formal authoring.

This directive does not authorize any guard repair, source development,
formal-DRAFT input, predecessor change, GitHub operation, push, publication,
signing, ratification, activation, deployment, public claim, release operation,
or Round 6.

Any failed credential containment, secret recurrence, state mismatch,
authority false-pass, evidence-integrity failure, surviving mutation,
non-guard tracked change, reviewer conflict, or lack of unanimity immediately
stops G00. This directive authorizes no further repair or continuation.
