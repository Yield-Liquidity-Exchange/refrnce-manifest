// Byte readers shared by the System and SPL Token decoders. Everything is little-endian, as the
// Solana runtime packs it. Amounts are read with BigInt and printed as decimal strings: a u64 above 2^53
// does not survive a JavaScript number, and the manifest holds only integers and strings. Each reader is
// handed a position and returns undefined when the bytes do not reach, so a decoder never reads past the
// end and never guesses. Pure and isomorphic.
import { encodeBase58 } from "../base58-encode.js";

export function readU32(data: Uint8Array, at: number): number | undefined {
  if (at < 0 || at + 4 > data.length) return undefined;
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(at, true);
}

/** The u64 at the position as a bigint. */
export function readU64(data: Uint8Array, at: number): bigint | undefined {
  if (at < 0 || at + 8 > data.length) return undefined;
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(at, true);
}

/** The u64 at the position as a decimal string of raw base units. */
export function readU64String(data: Uint8Array, at: number): string | undefined {
  const value = readU64(data, at);
  return value === undefined ? undefined : value.toString(10);
}

/** The 32 bytes at the position as a base58 address. */
export function readAddress(data: Uint8Array, at: number): string | undefined {
  if (at < 0 || at + 32 > data.length) return undefined;
  return encodeBase58(data.subarray(at, at + 32));
}
