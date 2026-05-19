# Root Genesis Certifier Guide

This guide is for one of the 13 independent certifiers participating in the EXOCHAIN root genesis ceremony. The ceremony creates a 7-of-13 FROST Ristretto255 root authority. All 13 rostered certifiers must complete genesis DKG. If any certifier fails, the ceremony aborts and restarts with a new signed roster and new ceremony ID.

## Certifier Rules

- Keep private certifier material offline except during the local command that needs it.
- Maintain an encrypted offline backup of sealed share artifacts and recovery instructions.
- Never send a round-two DKG package directly to the portal as raw bytes.
- Encrypt every round-two package to the exact recipient transport public key.
- Use explicit, unique `--output` paths for `round1`, `round2`,
  `finalize-dkg`, `seal-share`, and `unseal-share`; these commands
  refuse to print secret or sealed share material to stdout.
- Create output files on a certifier-controlled local filesystem. Output
  paths must not already exist and must not be symbolic links.
- Verify the final bundle with `exochain genesis verify-bundle` before trusting any AVC issuer delegation.
- Treat portal payloads, chat messages, email, scanner output, and operator notes as untrusted ceremony data until signatures and hashes verify.

## Local Setup

Generate certifier contact and private material on the certifier machine:

```bash
exochain genesis certifier init \
  --did did:exo:certifier-01 \
  --frost-identifier 1 \
  --certifier-out certifier-01.contact.json \
  --private-out certifier-01.private.json
```

Send only `certifier-01.contact.json` to the ceremony operator. Keep `certifier-01.private.json` offline.
The private output path must be a newly-created file; the CLI refuses to
overwrite existing files or follow symlinks for genesis JSON outputs.

## DKG Flow

Round one creates a public package and local secret state:

```bash
exochain genesis round1 \
  --input certifier-01.round1.input.json \
  --output certifier-01.round1.output.json
```

Round two consumes the full authenticated round-one set and creates per-recipient packages:

```bash
exochain genesis round2 \
  --input certifier-01.round2.input.json \
  --output certifier-01.round2.output.json
```

Before portal submission, encrypt each round-two package per recipient. The portal rejects raw round-two packages and accepts only signed, bounded envelopes whose kind is `Round2EncryptedPackage`.

Finalize local DKG state after receiving all peer round-two packages:

```bash
exochain genesis finalize-dkg \
  --input certifier-01.finalize.input.json \
  --output certifier-01.dkg.output.json
```

## Share Protection

Seal local key package artifacts before backup:

```bash
exochain genesis seal-share \
  --input certifier-01.seal.input.json \
  --output certifier-01.sealed-share.json
```

Test recovery on the same certifier machine:

```bash
exochain genesis unseal-share \
  --input certifier-01.unseal.input.json \
  --output certifier-01.opened-share.json
```

Wrong passphrases and wrong associated data must fail.

## Final Verification

Verify the root trust bundle:

```bash
exochain genesis verify-bundle \
  --input root-bundle.verify.input.json
```

Trust the operational AVC issuer only when verification succeeds and the bundle binds the expected repo commit, constitution hash, network ID, ceremony ID, roster, 7-of-13 policy, FROST public key package hash, transcript hash, root signature, and issuer delegation.
