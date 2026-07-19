import { useEffect, useState } from "react";
import {
  draftCrossCheck,
  signDemoCrossCheck,
  verifyCrossCheck,
} from "../ai/crosscheck.js";

export default function CrossCheckPanel({ apiBase, entries }) {
  const first = Array.isArray(entries) ? entries[0] : null;
  const [authorDid, setAuthorDid] = useState(
    () => first?.author_did || "did:exo:intelwar-actor",
  );
  const [subjectHex, setSubjectHex] = useState(
    () => String(first?.content_hash || "") || "",
  );
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!first) return;
    setAuthorDid(first.author_did || "did:exo:intelwar-actor");
    setSubjectHex(String(first.content_hash || ""));
  }, [first]);

  async function onVerify() {
    setBusy(true);
    setResult(null);
    try {
      if (!/^[0-9a-fA-F]{64}$/.test(subjectHex)) {
        setResult({
          ok: false,
          error: "invalid_subject",
          message: "subject must be 64 hex chars (Kernel content_hash)",
        });
        return;
      }
      const signed = await signDemoCrossCheck(apiBase, {
        subject_entry_hash_hex: subjectHex,
        verdict: "abstain",
        evidence_hash_hex: subjectHex,
        voice_kind: "synthetic",
      });
      if (!signed.ok || signed.http_status >= 400) {
        setResult(signed);
        return;
      }
      if (signed.signature_hex === "ab".repeat(64)) {
        setResult({
          ok: false,
          error: "fake_signature_rejected",
          message: "Refusing placeholder signature",
        });
        return;
      }
      const draft = draftCrossCheck({
        checker_did: signed.checker_did,
        subject_entry_hash_hex: subjectHex,
        verdict: "abstain",
        evidence_hash_hex: subjectHex,
        voice_kind: "synthetic",
        signature_hex: signed.signature_hex,
      });
      if (!draft.ok) {
        setResult(draft);
        return;
      }
      const verified = await verifyCrossCheck(apiBase, {
        author_did: authorDid,
        subject_entry_hash_hex: subjectHex,
        crosschecks: [draft.result],
        trusted_checker_keys_hex: {
          [signed.checker_did]: [signed.public_key_hex],
        },
      });
      setResult(verified);
    } catch (err) {
      setResult({
        ok: false,
        error: "client_error",
        message: err instanceof Error ? err.message : "failed",
      });
    } finally {
      setBusy(false);
    }
  }

  const coreVerified = result?.ok === true && result?.simulated !== true;

  return (
    <div className="crosscheck-panel">
      <p className="support">
        Signs via <code>/api/crosscheck/sign-demo</code> (server demo key), then
        verifies with <code>INTELWAR_CROSSCHECK_BIN</code>. Fake signatures are
        refused.
      </p>
      <div className="form-grid">
        <label className="span-2">
          Author DID
          <input value={authorDid} onChange={(e) => setAuthorDid(e.target.value)} />
        </label>
        <label className="span-2">
          Subject content hash (hex)
          <input value={subjectHex} onChange={(e) => setSubjectHex(e.target.value)} />
        </label>
      </div>
      <div className="actions">
        <button type="button" className="primary" disabled={busy} onClick={onVerify}>
          {busy ? "Signing + verifying…" : "Sign & verify crosscheck"}
        </button>
      </div>
      {result ? (
        <div className={`verify-card ${coreVerified ? "ok" : "fail"}`}>
          <p className="verify-label">
            {coreVerified ? "Core verified" : "Verification failed / refused"}
          </p>
          <pre className="result-block">{JSON.stringify(result, null, 2)}</pre>
        </div>
      ) : null}
    </div>
  );
}
