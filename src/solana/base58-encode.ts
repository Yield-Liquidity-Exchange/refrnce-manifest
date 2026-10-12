// Minimal base58 encoder (Bitcoin alphabet, as Solana uses), the counterpart of decodeBase58.
// Some decoded instructions carry an address inside their data (an account owner, a program owner), and the
// manifest prints addresses as base58 text. Isomorphic by design, like base58.ts: the `bs58` package is
// server-only under the Manifest boundary rule. Pure: no network, no Node-only imports.

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Encodes bytes as base58 text. Each leading zero byte is one leading "1", the inverse of decodeBase58. */
export function encodeBase58(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Little-endian base-58 digits of the value after the leading zero bytes.
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] * 256;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += ALPHABET[digits[i]];
  return out;
}
