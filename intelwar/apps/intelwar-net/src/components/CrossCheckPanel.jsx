import { useEffect, useState } from "react";
import { draftCrossCheck, verifyCrossCheck } from "../ai/crosscheck.js";

export default function CrossCheckPanel({ apiBase, entries }) {
  const first = Array.isArray(entries) ? entries[0] : null;
  const [authorDid, setAuthorDid] = useState(
    () => first?.author_did || "did:exo:intelwar-human-1",
  );
  const [subjectHex, setSubjectHex] = useState(
    () => String(first?.content_hash || "").replace(/^sim-/, "") || "00".repeat(32),
  );
  const [checkerDid, setCheckerDid] = useState("did:exo:crosscheck-peer");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!first) return;
    setAuthorDid(first.author_did || "did:exo:intelwar-human-1");
    setSubjectHex(
      String(first.content_hash || "").replace(/^sim-/, "") || "00".repeat(32),
    );
  }, [first]);

  async function onVerify() {
    setBusy(true);
    setResult(null);
    try {
      const draft = draftCrossCheck({
        checker_did: checkerDid,
        subject_entry_hash_hex: subjectHex,
        verdict: "abstain",
        evidence_hash_hex: subjectHex,
        voice_kind: "synthetic",
        signature_hex: "ab".repeat(64),
      });
      if (!draft.ok) {
        setResult(draft);
        return;
      }
      const verified = await verifyCrossCheck(apiBase, {
        author_did: authorDid,
        subject_entry_hash_hex: subjectHex,
        crosschecks: [draft.result],
        trusted_checker_keys_hex: {},
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

  const coreVerified = result?.core_verified === true;
  const structural = result && result.ok && !coreVerified;

  return (
    <div className="crosscheck-panel">
      <p className="support">
        Posts to <code>/api/crosscheck/verify</code>. Without{" "}
        <code>INTELWAR_CROSSCHECK_BIN</code> the API returns structural-only
        results (<code>core_verified: false</code>) — never a forged Permitted.
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
        <label className="span-2">
          Checker DID
          <input value={checkerDid} onChange={(e) => setCheckerDid(e.target.value)} />
        </label>
      </div>
      <div className="actions">
        <button type="button" className="primary" disabled={busy} onClick={onVerify}>
          {busy ? "Verifying…" : "Verify crosscheck"}
        </button>
      </div>
      {result ? (
        <div className={`verify-card ${coreVerified ? "ok" : structural ? "structural" : "fail"}`}>
          <p className="verify-label">
            {coreVerified
              ? "Core verified"
              : structural
                ? "Structural only — core path not configured"
                : "Verification failed / refused"}
          </p>
          <pre className="result-block">{JSON.stringify(result, null, 2)}</pre>
        </div>
      ) : null}
    </div>
  );
}
