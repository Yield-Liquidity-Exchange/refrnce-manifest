// Program dictionary and registry version. The dictionary decides whether a program is "known",
// which decides unknown_program versus unknown_variant for every instruction, so a wrong or truncated ID
// would silently relabel evidence. Each ID was checked against official sources by hand (see programs.ts).
// Pure: no network.
import { describe, expect, it } from "vitest";
import { decodeBase58 } from "../base58.js";
import {
  BRIDGE_PROGRAM_ID,
  PROGRAM_IDS,
  PROGRAM_LABELS,
  REGISTRY_VERSION,
  programLabel,
} from "../programs.js";

describe("program dictionary", () => {
  it("holds exactly the seven required programs while the bridge is undecided", () => {
    expect(BRIDGE_PROGRAM_ID).toBeUndefined();
    expect([...PROGRAM_LABELS.entries()]).toEqual([
      ["11111111111111111111111111111111", "System"],
      ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "SPL Token"],
      ["TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "Token-2022"],
      ["ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "Associated Token"],
      ["ComputeBudget111111111111111111111111111111", "Compute Budget"],
      ["MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "Memo"],
      ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "Jupiter v6"],
    ]);
  });

  it("every dictionary ID base58-decodes to exactly 32 bytes, so a typo or truncation is caught", () => {
    for (const id of PROGRAM_LABELS.keys()) {
      expect(decodeBase58(id).length, id).toBe(32);
    }
  });

  it("the named constants and the dictionary agree", () => {
    for (const id of Object.values(PROGRAM_IDS)) expect(PROGRAM_LABELS.has(id)).toBe(true);
    expect(PROGRAM_LABELS.size).toBe(Object.values(PROGRAM_IDS).length);
  });

  it("programLabel returns the label for a known ID and undefined for anything else", () => {
    expect(programLabel(PROGRAM_IDS.jupiterV6)).toBe("Jupiter v6");
    expect(programLabel("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc")).toBeUndefined();
    // Untrusted program IDs must never hit inherited object properties.
    expect(programLabel("constructor")).toBeUndefined();
    expect(programLabel("__proto__")).toBeUndefined();
  });
});

describe("REGISTRY_VERSION", () => {
  it("is a name@semver string the manifest tooling block can carry", () => {
    expect(REGISTRY_VERSION).toMatch(/^[a-z][a-z0-9-]*@\d+\.\d+\.\d+$/);
  });
});
