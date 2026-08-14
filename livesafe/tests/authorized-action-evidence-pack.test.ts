import { presentAuthorizedActionEvidencePack } from "../src/authorized-action-evidence-pack.js";

const PACK_HASH = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ACTION_HASH = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

describe("Authorized Action Evidence Pack presentation", () => {
  it("presents hash commitments when the verified adapter permits", () => {
    const view = presentAuthorizedActionEvidencePack({
      packHash: PACK_HASH,
      actionCommitmentHash: ACTION_HASH,
      classification: "adjacent-surface",
      adapterState: "verified",
      exochainResponse: "permit",
      claimsInsuranceUnderwritable: false,
      storesRawPhi: false,
    });

    expect(view).toEqual({
      presented: true,
      recordType: "hashes",
      insuranceUnderwritable: false,
      exochainProtected: true,
      reasons: [],
    });
  });

  it("does not claim EXOCHAIN protection when the adapter is unverified", () => {
    const view = presentAuthorizedActionEvidencePack({
      packHash: PACK_HASH,
      actionCommitmentHash: ACTION_HASH,
      classification: "adjacent-surface",
      adapterState: "unverified",
      exochainResponse: "not-called",
      claimsInsuranceUnderwritable: false,
      storesRawPhi: false,
    });

    expect(view.presented).toBe(false);
    expect(view.exochainProtected).toBe(false);
    expect(view.insuranceUnderwritable).toBe(false);
    expect(view.reasons).toContain("EXOCHAIN trust claims require a verified runtime adapter.");
  });

  it("fails closed when EXOCHAIN does not permit", () => {
    const view = presentAuthorizedActionEvidencePack({
      packHash: PACK_HASH,
      actionCommitmentHash: ACTION_HASH,
      classification: "adjacent-surface",
      adapterState: "verified",
      exochainResponse: "deny",
      claimsInsuranceUnderwritable: false,
      storesRawPhi: false,
    });

    expect(view.presented).toBe(false);
    expect(view.exochainProtected).toBe(false);
    expect(view.reasons).toContain(
      "Verified adapters must fail closed unless EXOCHAIN permits.",
    );
  });

  it("never treats the pack as insurance-underwritable", () => {
    const view = presentAuthorizedActionEvidencePack({
      packHash: PACK_HASH,
      actionCommitmentHash: ACTION_HASH,
      classification: "adjacent-surface",
      adapterState: "verified",
      exochainResponse: "permit",
      claimsInsuranceUnderwritable: true,
      storesRawPhi: false,
    });

    expect(view.presented).toBe(false);
    expect(view.insuranceUnderwritable).toBe(false);
    expect(view.reasons).toContain(
      "LiveSafe cannot claim an insurance-underwritable event.",
    );
  });

  it("refuses raw PHI even with a verified permit", () => {
    const view = presentAuthorizedActionEvidencePack({
      packHash: PACK_HASH,
      actionCommitmentHash: ACTION_HASH,
      classification: "adjacent-surface",
      adapterState: "verified",
      exochainResponse: "permit",
      claimsInsuranceUnderwritable: false,
      storesRawPhi: true,
    });

    expect(view.presented).toBe(false);
    expect(view.reasons).toContain(
      "Raw PHI must remain off-chain; only hashes and commitments are presentable.",
    );
    expect(view.reasons).toContain("Raw sensitive data must remain off-chain.");
  });
});
