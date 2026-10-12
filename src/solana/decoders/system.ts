// System program decoder: CreateAccount, Transfer and TransferWithSeed, the instructions that
// move or fund native SOL. System instruction data is the bincode encoding of the SystemInstruction enum: a
// u32 little-endian variant index, then the fields in order (u64 little-endian numbers, 32-byte addresses,
// and a String as a u64 length followed by its bytes). Variant indexes and account orders were checked
// against the official source (anza-xyz/solana-sdk, system-interface/src/instruction.rs, 2026-10-07):
//   0 CreateAccount     { lamports, space, owner }                accounts [from, to]
//   2 Transfer          { lamports }                              accounts [from, to]
//   11 TransferWithSeed { lamports, from_seed, from_owner }       accounts [from, base, to]
// Every other index returns null, and so does anything whose data length, seed or account count does not
// match exactly: the registry then keeps the raw bytes as unknown_variant, so nothing is half-decoded.
// Amounts are decimal strings of lamports. Pure and isomorphic.
import { PROGRAM_IDS } from "../programs.js";
import { readAddress, readU32, readU64, readU64String } from "./bytes.js";
import type { DecodedFields, Decoder } from "./index.js";

// Strict: invalid UTF-8 is rejected instead of replaced with U+FFFD, and a leading U+FEFF is kept so the
// decoded text always re-encodes to the original bytes.
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const CREATE_ACCOUNT = 0;
const TRANSFER = 2;
const TRANSFER_WITH_SEED = 11;

function decodeSystem(data: Uint8Array, accounts: readonly string[]): DecodedFields | null {
  const index = readU32(data, 0);
  if (index === undefined) return null;

  if (index === CREATE_ACCOUNT) {
    // u32 index + u64 lamports + u64 space + 32-byte owner
    if (data.length !== 52 || accounts.length !== 2) return null;
    const lamports = readU64String(data, 4);
    const space = readU64String(data, 12);
    const owner = readAddress(data, 20);
    if (lamports === undefined || space === undefined || owner === undefined) return null;
    return {
      kind: "system_create_account",
      fields: { from: accounts[0], to: accounts[1], lamports, space, owner },
    };
  }

  if (index === TRANSFER) {
    // u32 index + u64 lamports
    if (data.length !== 12 || accounts.length !== 2) return null;
    const lamports = readU64String(data, 4);
    if (lamports === undefined) return null;
    return { kind: "system_transfer", fields: { from: accounts[0], to: accounts[1], lamports } };
  }

  if (index === TRANSFER_WITH_SEED) {
    // u32 index + u64 lamports + u64 seed length + seed bytes + 32-byte owner
    if (accounts.length !== 3) return null;
    const lamports = readU64String(data, 4);
    const seedLength = readU64(data, 12);
    if (lamports === undefined || seedLength === undefined) return null;
    // Compared as bigints: a declared length above 2^32 must not wrap into a small number.
    if (BigInt(data.length) !== 4n + 8n + 8n + seedLength + 32n) return null;
    const seedEnd = 20 + Number(seedLength);
    const owner = readAddress(data, seedEnd);
    if (owner === undefined) return null;
    let seed: string;
    try {
      seed = strictUtf8.decode(data.subarray(20, seedEnd));
    } catch {
      return null;
    }
    return {
      kind: "system_transfer_with_seed",
      fields: { from: accounts[0], base: accounts[1], to: accounts[2], lamports, seed, owner },
    };
  }

  return null;
}

// Frozen: the decoder is shared by every caller, so none may reassign its version or decode.
export const systemDecoder: Decoder = Object.freeze<Decoder>({
  programId: PROGRAM_IDS.system,
  name: "system",
  version: "1.0.0",
  decode(node) {
    return decodeSystem(node.data, node.accounts);
  },
});
