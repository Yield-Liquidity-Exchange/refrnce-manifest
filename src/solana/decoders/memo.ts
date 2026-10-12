// Memo program decoder. The Memo program's instruction data is the memo text as UTF-8 bytes.
// Decoding is strict: bytes that are not valid UTF-8 are not guessed at, the decoder returns null and the
// registry keeps the raw bytes as unknown_variant. Pure and isomorphic (TextDecoder is in Node and browsers).
import { PROGRAM_IDS } from "../programs.js";
import type { Decoder } from "./index.js";

// fatal: reject invalid UTF-8 instead of substituting U+FFFD. ignoreBOM: keep a leading U+FEFF in the
// text rather than silently stripping it, so the decoded text always re-encodes to the original bytes.
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// Frozen: the decoder is shared by every caller, so none may reassign its version or decode.
export const memoDecoder: Decoder = Object.freeze<Decoder>({
  programId: PROGRAM_IDS.memo,
  name: "memo",
  version: "1.0.0",
  decode(node) {
    try {
      return { kind: "memo", fields: { text: strictUtf8.decode(node.data) } };
    } catch {
      return null;
    }
  },
});
