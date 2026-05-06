# SYBIL Codex + decision.forum

This MVP turns **decision advantage** into code.

It gives you a *gravity well* in the form of a first‑class artifact:

- **DecisionRecord** (ADR-inspired): `context -> decision -> consequences`
- **CrosscheckReport**: plural intelligence (crosschecked.ai-ready)
- **CustodyEvents**: attestations + optional signatures
- **Clearance rules**: quorum + (optional) signature verification
- **Anchoring interface**: pluggable providers (simulated by default)

Everything is **file-backed** (Git-friendly) so decisions are diffable, reviewable, and portable.

---

## Install

```bash
pip install -r requirements.txt
```

## Neo4j configuration

`graph_schema.py` fails closed unless Neo4j connection settings are supplied
explicitly:

```bash
export NEO4J_URI="<neo4j-bolt-uri>"
export NEO4J_USERNAME="<neo4j-username>"
export NEO4J_PASSWORD="<secret-from-your-password-manager>"
```

---

## Initialize store

```bash
python sybil-cli.py forum init
```

Creates:

```
.decision_forum/
  records/
  keys.json
  anchors.log
  certificates/
```

---

## Create a decision record

```bash
python sybil-cli.py forum new \
  --title "Adopt DecisionRecord + forum clearance" \
  --context "We need a canonical decision artifact that can be cleared + anchored" \
  --decision "Adopt DecisionRecord v0.2 with Crosscheck + Custody + Clearance + Anchors" \
  --consequences "Decisions become legible, versionable, and globally referencable"
```

List + show:

```bash
python sybil-cli.py forum list
python sybil-cli.py forum show DR-2026-02-08-xxxxxx
python sybil-cli.py forum hash DR-2026-02-08-xxxxxx
```

---

## Crosscheck (plural intelligence)

Generate a JSON template:

```bash
python sybil-cli.py forum crosscheck template > crosscheck.json
```

Fill `crosscheck.json` using **crosschecked.ai** (or any multi-agent process), then attach:

```bash
python sybil-cli.py forum crosscheck add DR-... --file crosscheck.json
```

> Note: Adding crosschecks changes the canonical record hash (by design).

---

## Custody keys (optional)

Generate an Ed25519 keypair:

```bash
python sybil-cli.py forum keys gen
```

Register your public key so the forum can verify signatures:

```bash
python sybil-cli.py forum keys register --actor did:example:bob --public-key-b64 <BASE64>
```

---

## Attest (approve / reject)

Record an attestation:

```bash
python sybil-cli.py forum attest DR-... --actor did:example:reviewer1 --attestation approve
python sybil-cli.py forum attest DR-... --actor did:example:reviewer2 --attestation approve
```

If you want cryptographic custody:

```bash
python sybil-cli.py forum attest DR-... \
  --actor did:example:reviewer1 \
  --attestation approve \
  --secret-key-b64 <BASE64_SECRET_KEY>
```

---

## Clearance (gravity)

Evaluate clearance:

```bash
python sybil-cli.py forum clearance DR-...
```

Clear + accept (issues a certificate):

```bash
python sybil-cli.py forum clear DR-... --actor did:example:steward
```

Clearance policy lives in `upk.yaml`:

```yaml
governance:
  decision_forum:
    clearance:
      mode: quorum
      quorum: 2
      allowed_roles: [reviewer, steward]
      require_valid_signatures: false
      reject_veto: true
```

---

## Anchor (EXOCHAIN-ready interface)

Anchor the record hash (simulated providers for MVP):

```bash
python sybil-cli.py forum anchor DR-... --provider exochain_sim
```

This writes a receipt to:
- `.decision_forum/anchors.log`
- and appends the receipt into the record.

---

## Hash semantics

The canonical hash **excludes**:
- timestamps (`created_at`, `updated_at`)
- lifecycle status (`status`)
- custody + anchors (because those reference the hash)

So approvals remain valid when a record is accepted/anchored.

---

## Why this matters

You are not building “AI governance.”

You are building a system where:
- plural intelligence can speak (crosschecks),
- identity can attest (custody),
- legitimacy can be conferred (clearance),
- and decisions can be globally referenced (anchors).

That’s gravity.
