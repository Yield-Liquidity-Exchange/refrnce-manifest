// Minimal base58 decoder (Bitcoin alphabet, as Solana uses). Instruction data arrives as base58 text in
// a getTransaction response with encoding json. This is isomorphic by design: the `bs58` package is
// server-only under the Manifest boundary rule, and decoding must also run in the verifier's browser.

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const INDEX: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) INDEX[ALPHABET[i]] = i;

/** Decodes base58 text to bytes. Each leading "1" is one leading zero byte. Throws on any other character. */
export function decodeBase58(text: string): Uint8Array {
  if (typeof text !== "string") throw new TypeError("base58 input must be a string");
  let zeros = 0;
  while (zeros < text.length && text[zeros] === "1") zeros++;

  // Little-endian base-256 digits of the value after the leading ones.
  const digits: number[] = [];
  for (let i = zeros; i < text.length; i++) {
    const value = INDEX[text[i]];
    if (value === undefined) throw new Error(`invalid base58 character at position ${i}`);
    let carry = value;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] * 58;
      digits[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      digits.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = new Uint8Array(zeros + digits.length);
  for (let i = 0; i < digits.length; i++) out[out.length - 1 - i] = digits[i];
  return out;
}
