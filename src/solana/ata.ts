// Associated token address derivation. The associated token account of (owner, mint) under a
// token program is the program derived address of the seeds [owner, token program, mint] under the
// Associated Token Account program (solana-program/associated-token-account, interface get_associated_
// token_address_and_bump_seed_internal). A program derived address is the first SHA-256 hash, trying bump
// seeds 255 down to 0, that is NOT a point on the ed25519 curve:
//   hash = SHA-256(seed_1 || ... || seed_n || [bump] || program_id || "ProgramDerivedAddress")
// The curve test uses @noble/ed25519 point decompression with ZIP215 rules, which accepts exactly the
// encodings curve25519-dalek's decompress accepts (the test Solana's runtime applies). Pure and isomorphic:
// no network, no @solana/web3.js, no bs58, no Node-only imports.
import { Point } from "@noble/ed25519";
import { decodeBase58 } from "./base58.js";
import { encodeBase58 } from "./base58-encode.js";
import { PROGRAM_IDS } from "./programs.js";
import { sha256 } from "./sha256.js";

const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");

function address32(text: string, what: string): Uint8Array {
  const bytes = decodeBase58(text);
  if (bytes.length !== 32) throw new Error(`${what} is not a 32-byte address`);
  return bytes;
}

/** True when the 32 bytes decode to a point on the ed25519 curve (so they cannot be a program derived address). */
function isOnCurve(bytes: Uint8Array): boolean {
  try {
    Point.fromBytes(bytes, true);
    return true;
  } catch {
    return false;
  }
}

/**
 * The associated token address of (owner, mint) under the given token program (SPL Token or Token-2022),
 * as base58 text. Throws if an input is not a 32-byte address. The mint and owner are not looked up: this is
 * arithmetic only, and says nothing about whether the account exists.
 */
export function deriveAssociatedTokenAddress(
  owner: string,
  mint: string,
  tokenProgramId: string,
): string {
  const seeds = [
    address32(owner, "owner"),
    address32(tokenProgramId, "token program"),
    address32(mint, "mint"),
  ];
  const programId = address32(PROGRAM_IDS.associatedToken, "associated token program");
  const buffer = new Uint8Array(32 * 3 + 1 + 32 + PDA_MARKER.length);
  seeds.forEach((seed, i) => buffer.set(seed, i * 32));
  buffer.set(programId, 97);
  buffer.set(PDA_MARKER, 129);
  for (let bump = 255; bump >= 0; bump--) {
    buffer[96] = bump;
    const candidate = sha256(buffer);
    if (!isOnCurve(candidate)) return encodeBase58(candidate);
  }
  // Probability about 2^-255 per owner and mint: reported rather than answered with a wrong address.
  throw new Error("no valid bump seed found");
}
