import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  adversarialSessionId,
  consumeAdversarialHandoff,
  formatMicroUsd,
  localStructureDryRun,
  normalizeStressSections,
  stageAdversarialHandoff,
} from "./adversarial.js";

describe("adversarial dry-run", () => {
  it("labels structure demo and denies Log eligibility", () => {
    const r = localStructureDryRun({
      mode: "stress_test",
      claim: "Provenance is decisive terrain when generation is cheap.",
      steelman_first: true,
      focus: ["evidence"],
    });
    assert.equal(r.ok, true);
    assert.equal(r.dry_run, true);
    assert.equal(r.final_authority, false);
    assert.equal(r.provider, "local-structure-demo");
    assert.equal(r.artifact_draft.provenance.eligible_for_log, false);
    assert.match(r.runs[0].content.notes, /STRUCTURE DEMO/);
  });

  it("normalizeStressSections extracts lists", () => {
    const r = localStructureDryRun({
      mode: "stress_test",
      claim: "A short claim for normalization testing here.",
    });
    const s = normalizeStressSections(r.runs[0]);
    assert.ok(s.key_vulnerabilities.length >= 1);
    assert.ok(s.fortifications.length >= 1);
    assert.equal(s.voice_kind, "synthetic");
  });

  it("formatMicroUsd uses integer math", () => {
    assert.equal(formatMicroUsd(150_000), "$0.15");
    assert.equal(formatMicroUsd(1_000_000), "$1.00");
    assert.equal(formatMicroUsd(29_500), "$0.0295");
    assert.equal(formatMicroUsd(0), "$0.00");
  });

  it("session id is stable per process", () => {
    assert.equal(adversarialSessionId(), adversarialSessionId());
  });

  it("stages and consumes .tv handoff once", () => {
    assert.equal(
      stageAdversarialHandoff({
        claim: "Scene claim for adversarial pressure.",
        source: "tv",
        sceneId: "scene-1",
        mode: "cross",
      }),
      true,
    );
    const once = consumeAdversarialHandoff();
    assert.equal(once?.claim, "Scene claim for adversarial pressure.");
    assert.equal(once?.mode, "cross");
    assert.equal(consumeAdversarialHandoff(), null);
  });
});
