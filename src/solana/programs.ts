// Program dictionary for the Solana decoders: program ID to label, plus the registry version the
// manifest tooling block carries. The dictionary decides whether a program is "known" (unknown_variant when
// no decoder understands the bytes) or not (unknown_program), so a wrong ID would silently relabel evidence.
// Each ID below was checked against the official source named beside it (verified 2026-10-07):
//   System            anza-xyz/solana-sdk  system-interface/src/lib.rs:34 and sdk-ids/src/lib.rs:68
//   SPL Token         solana-program/token  interface/src/lib.rs:17
//   Token-2022        solana-program/token-2022  interface/src/lib.rs:29
//   Associated Token  solana-program/associated-token-account  interface/src/lib.rs:11
//   Compute Budget    anza-xyz/solana-sdk  sdk-ids/src/lib.rs:21 (re-exported by compute-budget-interface)
//   Memo (v3)         solana-program/memo  interface/src/lib.rs:16 (v1 and v4 have other IDs, not listed here)
//   Jupiter v6        jup-ag/jupiter-cpi  src/lib.rs:3
// Pure and isomorphic: no network, no Node-only imports. Lookups use a Map so an untrusted program ID such
// as "__proto__" or "constructor" can never reach an inherited property.

import { readOnlyMap } from "./readonly-map.js";

export const PROGRAM_IDS = Object.freeze({
  system: "11111111111111111111111111111111",
  splToken: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  token2022: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
  associatedToken: "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
  computeBudget: "ComputeBudget111111111111111111111111111111",
  memo: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
  jupiterV6: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
} as const);

/**
 * Bridge program, label only. Not decided yet.
 * TODO: set this to the chosen bridge program ID, verified against the bridge's official docs, and
 * set BRIDGE_PROGRAM_LABEL to the bridge's name. Until then it is undefined and the dictionary omits it.
 */
export const BRIDGE_PROGRAM_ID: string | undefined = undefined;
const BRIDGE_PROGRAM_LABEL = "Bridge";

const entries: [string, string][] = [
  [PROGRAM_IDS.system, "System"],
  [PROGRAM_IDS.splToken, "SPL Token"],
  [PROGRAM_IDS.token2022, "Token-2022"],
  [PROGRAM_IDS.associatedToken, "Associated Token"],
  [PROGRAM_IDS.computeBudget, "Compute Budget"],
  [PROGRAM_IDS.memo, "Memo"],
  [PROGRAM_IDS.jupiterV6, "Jupiter v6"],
];
if (BRIDGE_PROGRAM_ID !== undefined) entries.push([BRIDGE_PROGRAM_ID, BRIDGE_PROGRAM_LABEL]);

/**
 * Program ID to human label. A program in this map is "known" even if no decoder understands it yet.
 * Read-only: callers cannot add or remove entries.
 */
export const PROGRAM_LABELS: ReadonlyMap<string, string> = readOnlyMap(entries);

/** The label for a known program ID, or undefined when the program is outside the dictionary. */
export function programLabel(programId: string): string | undefined {
  return PROGRAM_LABELS.get(programId);
}

/**
 * Version of the decoder set as a whole, in name@version form, carried in the manifest's tooling block.
 * Bump it whenever a decoder is added, removed or changes what it outputs, so an old manifest can be
 * re-read with the decoders that produced it.
 */
export const REGISTRY_VERSION = "solana-decoders@0.4.0";
