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

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import typer

from router import route_to_model
from utils import load_upk

from codex.anchors import get_provider
from codex.clearance import ClearanceMode, ClearancePolicy, evaluate_clearance, issue_certificate
from codex.identity import generate_keypair, sign_detached
from codex.key_registry import KeyRegistry
from codex.schemas import (
    CrosscheckOpinion,
    CrosscheckReport,
    CustodyEvent,
    DecisionStatus,
    EvidenceItem,
)
from codex.store import CodexStore, compute_record_hash


cli = typer.Typer(help="SYBIL CLI (Mosaic Mind) + decision.forum codex")

forum = typer.Typer(help="Decision.forum commands")
cli.add_typer(forum, name="forum")

keys = typer.Typer(help="Public key registry (for custody verification)")
forum.add_typer(keys, name="keys")

crosscheck = typer.Typer(help="Crosscheck reports (plural intelligence)")
forum.add_typer(crosscheck, name="crosscheck")


# ---------------------------
# SYBIL
# ---------------------------

@cli.command()
def ask(prompt: str, archetype: str = "Visionary Strategist"):
    """Ask SYBIL a question with selected archetype."""
    answer = route_to_model(prompt, archetype)
    print("\n🧠 SYBIL says:\n")
    print(answer)


# ---------------------------
# Forum: init + CRUD
# ---------------------------

@forum.command("init")
def forum_init(path: str = ".decision_forum"):
    """Initialize the local decision.forum store."""
    store = CodexStore(root=Path(path))
    store.init()
    typer.echo(f"✅ Initialized decision.forum store at: {store.root.resolve()}")


@forum.command("new")
def forum_new(
    title: str = typer.Option(..., help="Short title for the decision"),
    context: str = typer.Option(..., help="Why we need this decision"),
    decision: str = typer.Option(..., help="What we are deciding"),
    consequences: str = typer.Option(..., help="Consequences / tradeoffs"),
    tags: Optional[str] = typer.Option(None, help="Comma-separated tags"),
    actor: str = typer.Option("local", help="Actor id / DID / key fingerprint"),
    path: str = typer.Option(".decision_forum", help="Store path"),
):
    """Create a new Decision Record."""
    store = CodexStore(root=Path(path))
    rec = store.create(
        title=title,
        context=context,
        decision=decision,
        consequences=consequences,
        tags=[t.strip() for t in (tags or "").split(",") if t.strip()],
        actor_id=actor,
    )
    typer.echo(f"🧲 Created {rec.id} ({rec.status})")
    typer.echo(f"hash: {rec.record_hash}")


@forum.command("list")
def forum_list(
    status: Optional[DecisionStatus] = typer.Option(None, help="Filter by status"),
    path: str = typer.Option(".decision_forum", help="Store path"),
):
    """List decision records."""
    store = CodexStore(root=Path(path))
    rows = store.list(status=status)
    if not rows:
        typer.echo("(no decision records yet)")
        raise typer.Exit(code=0)
    for r in rows:
        typer.echo(f"{r.id}  [{r.status}]  {r.title}")


@forum.command("show")
def forum_show(record_id: str, path: str = ".decision_forum"):
    """Show a decision record as JSON."""
    store = CodexStore(root=Path(path))
    rec = store.load(record_id)
    typer.echo(json.dumps(rec.model_dump(), indent=2, ensure_ascii=False, default=str))


@forum.command("hash")
def forum_hash(record_id: str, path: str = ".decision_forum"):
    """Print the current canonical hash for a record."""
    store = CodexStore(root=Path(path))
    rec = store.load(record_id)
    typer.echo(compute_record_hash(rec))


@forum.command("evidence")
def forum_add_evidence(
    record_id: str,
    kind: str = typer.Option("link", help="Type of evidence"),
    description: str = typer.Option(..., help="What this evidence supports"),
    uri: Optional[str] = typer.Option(None, help="URI/link"),
    content_hash: Optional[str] = typer.Option(None, help="sha256 of the artifact"),
    actor: str = typer.Option("local", help="Actor id"),
    path: str = typer.Option(".decision_forum", help="Store path"),
):
    """Attach evidence to a decision record."""
    store = CodexStore(root=Path(path))
    store.add_evidence(
        record_id,
        EvidenceItem(kind=kind, description=description, uri=uri, content_hash=content_hash),
        actor_id=actor,
    )
    typer.echo("✅ Evidence added")


@forum.command("status")
def forum_set_status(
    record_id: str,
    status: DecisionStatus = typer.Option(..., help="New status"),
    actor: str = typer.Option("local", help="Actor id"),
    path: str = typer.Option(".decision_forum", help="Store path"),
):
    """Update status (e.g., draft -> rfc -> accepted)."""
    store = CodexStore(root=Path(path))
    store.set_status(record_id, status=status, actor_id=actor)
    typer.echo(f"✅ Status updated: {record_id} -> {status}")


# ---------------------------
# Crosscheck (plural intelligence)
# ---------------------------

@crosscheck.command("template")
def crosscheck_template(
    question: str = typer.Option("What should we decide, and why?", help="Crosscheck question"),
    path: str = typer.Option(".decision_forum", help="Store path (unused; for symmetry)"),
):
    """Print a CrosscheckReport JSON template.

    This is meant to be filled by crosschecked.ai (or any plural reasoning pipeline)
    and then attached to a DecisionRecord via `forum crosscheck add`.
    """
    template = {
        "schema_version": "0.2",
        "id": "CR-<auto>",
        "created_at": "<auto>",
        "created_by": "did:example:crosschecked-ai",
        "question": question,
        "method": "mosaic",
        "prompt": "Paste the prompt / context used for this crosscheck run",
        "inputs": ["evidence://...", "doc://...", "dataset://..."],
        "opinions": [
            {
                "agent_id": "did:example:agent-redteam",
                "agent_kind": "ai",
                "agent_label": "Red Team",
                "model": "gpt-4o",
                "policy_id": "redteam_v1",
                "stance": "oppose",
                "summary": "High-level position in 3-6 sentences",
                "rationale": "Optional deeper reasoning",
                "confidence": 0.62,
                "risks": ["risk 1", "risk 2"],
                "suggested_edits": "Optional patch / diff / recommended changes",
                "evidence_refs": ["https://...", "sha256:..."],
            }
        ],
        "synthesis": "Reconciled synthesis across voices",
        "dissent": "Minority view that should be preserved",
        "dissenters": ["did:example:agent-redteam"],
        "metadata": {"run_id": "optional"},
    }
    typer.echo(json.dumps(template, indent=2, ensure_ascii=False))


@crosscheck.command("add")
def crosscheck_add(
    record_id: str = typer.Argument(..., help="DecisionRecord id"),
    file: str = typer.Option(..., "--file", "-f", help="Path to CrosscheckReport JSON file"),
    actor: str = typer.Option("local", help="Actor id attaching the report"),
    path: str = typer.Option(".decision_forum", help="Store path"),
):
    """Attach a CrosscheckReport (JSON) to a DecisionRecord."""
    store = CodexStore(root=Path(path))
    payload = json.loads(Path(file).read_text(encoding="utf-8"))
    # Allow templates to omit id/created_at and still validate by filling defaults.
    if payload.get("id") in (None, "", "CR-<auto>"):
        payload.pop("id", None)
    payload.pop("created_at", None)  # allow auto
    report = CrosscheckReport.model_validate(payload)
    store.add_crosscheck(record_id, report, actor_id=actor)
    typer.echo("✅ Crosscheck report attached")


# ---------------------------
# Keys (custody)
# ---------------------------

@keys.command("gen")
def keys_gen():
    """Generate a new Ed25519 keypair (prints JSON)."""
    kp = generate_keypair()
    typer.echo(json.dumps(asdict(kp), indent=2, ensure_ascii=False))


@keys.command("register")
def keys_register(
    actor: str = typer.Option(..., help="Actor id / DID / key fingerprint"),
    public_key_b64: str = typer.Option(..., help="Base64 public key"),
    path: str = typer.Option(".decision_forum", help="Store path"),
):
    """Register a public key for an actor (for signature verification)."""
    reg = KeyRegistry(root=Path(path))
    reg.register(actor, public_key_b64)
    typer.echo(f"✅ Registered public key for: {actor}")


@keys.command("get")
def keys_get(
    actor: str = typer.Option(..., help="Actor id"),
    path: str = typer.Option(".decision_forum", help="Store path"),
):
    """Fetch a registered public key for an actor."""
    reg = KeyRegistry(root=Path(path))
    pk = reg.get(actor)
    if not pk:
        typer.echo("(not found)")
        raise typer.Exit(code=1)
    typer.echo(pk)


# ---------------------------
# Attestations + clearance
# ---------------------------

@forum.command("attest")
def forum_attest(
    record_id: str,
    attestation: str = typer.Option("approve", help="approve | reject | abstain | amend"),
    role: str = typer.Option("reviewer", help="reviewer | steward | participant"),
    notes: Optional[str] = typer.Option(None, help="Optional notes"),
    actor: str = typer.Option("local", help="Actor id"),
    secret_key_b64: Optional[str] = typer.Option(
        None, help="If provided, signs the record_hash (Ed25519 base64 secret key)"
    ),
    public_key_b64: Optional[str] = typer.Option(
        None, help="Optional public key (base64) to store with the attestation"
    ),
    path: str = typer.Option(".decision_forum", help="Store path"),
):
    """Add an attestation custody event for the current record hash."""
    store = CodexStore(root=Path(path))
    rec = store.load(record_id)
    current_hash = compute_record_hash(rec)

    sig = None
    if secret_key_b64:
        sig = sign_detached(current_hash, secret_key_b64=secret_key_b64)

    ev = CustodyEvent(
        actor_id=actor,
        role=role,
        action=f"attest:{attestation.strip().lower()}",
        attestation=attestation.strip().lower(),
        notes=notes,
        record_hash=current_hash,
        signature=sig,
        public_key_b64=public_key_b64,
    )
    store.add_custody_event(record_id, ev)
    typer.echo("✅ Attestation recorded")


def _load_clearance_policy_from_upk() -> ClearancePolicy:
    upk = load_upk()
    dforum = ((upk.get("governance") or {}).get("decision_forum") or {})
    policy_dict = dforum.get("clearance") or {}
    if not policy_dict:
        return ClearancePolicy()
    try:
        return ClearancePolicy.model_validate(policy_dict)
    except Exception:
        return ClearancePolicy()


@forum.command("clearance")
def forum_clearance(
    record_id: str,
    mode: Optional[ClearanceMode] = typer.Option(None, help="Override mode: single|quorum"),
    quorum: Optional[int] = typer.Option(None, help="Override quorum size"),
    require_signatures: Optional[bool] = typer.Option(
        None, help="Override signature requirement (true/false)"
    ),
    reject_veto: Optional[bool] = typer.Option(None, help="Override reject veto (true/false)"),
    path: str = typer.Option(".decision_forum", help="Store path"),
):
    """Evaluate whether a record is cleared under the forum policy."""
    store = CodexStore(root=Path(path))
    rec = store.load(record_id)

    policy = _load_clearance_policy_from_upk()
    if mode is not None:
        policy.mode = mode
    if quorum is not None:
        policy.quorum = quorum
    if require_signatures is not None:
        policy.require_valid_signatures = require_signatures
    if reject_veto is not None:
        policy.reject_veto = reject_veto

    reg = KeyRegistry(root=Path(path))
    result = evaluate_clearance(rec, policy=policy, key_registry=reg)

    typer.echo(f"🧾 Clearance: {record_id}")
    typer.echo(f"hash: {result.record_hash}")
    typer.echo(f"cleared: {result.cleared} ({result.reason})")
    typer.echo(f"required_quorum: {result.required_quorum}")
    typer.echo(f"approvals: {len({a.actor_id for a in result.approvals})}  rejects: {len({r.actor_id for r in result.rejects})}  abstains: {len({a.actor_id for a in result.abstains})}")

    if result.approvals:
        typer.echo("Approvers:")
        for a in sorted(result.approvals, key=lambda x: x.at):
            typer.echo(f"  - {a.actor_id} ({a.role}) at {a.at} sig_ok={a.signature_valid}")
    if result.rejects:
        typer.echo("Rejectors:")
        for r in sorted(result.rejects, key=lambda x: x.at):
            typer.echo(f"  - {r.actor_id} ({r.role}) at {r.at} sig_ok={r.signature_valid}")


@forum.command("clear")
def forum_clear(
    record_id: str,
    actor: str = typer.Option("local", help="Actor id performing clearance"),
    role: str = typer.Option("steward", help="Role of clearing actor"),
    secret_key_b64: Optional[str] = typer.Option(None, help="Optional signing key (base64)"),
    public_key_b64: Optional[str] = typer.Option(None, help="Optional public key (base64)"),
    path: str = typer.Option(".decision_forum", help="Store path"),
):
    """Clear a record (if it meets policy), issue a certificate, and set status=accepted."""
    store = CodexStore(root=Path(path))
    rec = store.load(record_id)

    policy = _load_clearance_policy_from_upk()
    reg = KeyRegistry(root=Path(path))
    result = evaluate_clearance(rec, policy=policy, key_registry=reg)
    if not result.cleared:
        typer.echo(f"❌ Not cleared: {result.reason}")
        raise typer.Exit(code=2)

    cert = issue_certificate(result, policy=policy)

    # Persist certificate (portable proof).
    cert_dir = Path(path) / "certificates"
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / f"{cert.id}.json"
    cert_path.write_text(json.dumps(cert.model_dump(), indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")

    current_hash = result.record_hash
    sig = sign_detached(current_hash, secret_key_b64=secret_key_b64) if secret_key_b64 else None

    store.add_custody_event(
        record_id,
        CustodyEvent(
            actor_id=actor,
            role=role,
            action="clear",
            record_hash=current_hash,
            signature=sig,
            public_key_b64=public_key_b64,
            metadata={"certificate_id": cert.id, "certificate_path": str(cert_path)},
        ),
    )
    store.set_status(record_id, DecisionStatus.accepted, actor_id=actor)

    typer.echo("✅ Cleared + accepted")
    typer.echo(f"certificate: {cert_path}")


# ---------------------------
# Anchoring (EXOCHAIN / providers)
# ---------------------------

@forum.command("anchor")
def forum_anchor(
    record_id: str,
    provider: str = typer.Option("exochain_sim", help="local_sim | exochain_sim"),
    actor: str = typer.Option("local", help="Actor id"),
    path: str = typer.Option(".decision_forum", help="Store path"),
):
    """Anchor a record hash using an anchor provider (MVP uses simulated providers)."""
    store = CodexStore(root=Path(path))
    rec = store.load(record_id)
    record_hash = compute_record_hash(rec)

    prov = get_provider(provider, root=Path(path))
    receipt = prov.anchor(record_hash, metadata={"record_id": record_id})
    store.add_anchor(record_id, receipt, actor_id=actor)

    typer.echo("✅ Anchored")
    typer.echo(f"chain: {receipt.chain}")
    typer.echo(f"txid: {receipt.txid}")
    typer.echo(f"hash: {receipt.record_hash}")


# ---------------------------
# Misc (placeholders)
# ---------------------------

@cli.command()
def memory():
    """Show current stored memories (placeholder)."""
    print("🧬 Memory feature coming soon.")


@cli.command()
def upk():
    """Open UPK YAML for editing."""
    import os
    os.system("nano upk.yaml")


if __name__ == "__main__":
    cli()
