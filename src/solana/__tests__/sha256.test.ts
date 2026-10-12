// SHA-256. The Jupiter decoder computes Anchor discriminators from names at module load, which
// needs a synchronous hash that also runs in the browser, so one is written here. A hash that is wrong by
// one bit would give a wrong discriminator, and the decoder would silently match the wrong instruction or
// miss the right one. So it is proven three ways: against the NIST published vectors, against the
// platform's own crypto.subtle across every length around the padding and block boundaries, and for not
// touching its input.
import { describe, expect, it } from "vitest";
import { sha256 } from "../sha256.js";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const utf8 = (s: string) => new TextEncoder().encode(s);

async function reference(data: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(data))));
}

describe("sha256 against the NIST vectors", () => {
  it("hashes the empty message", () => {
    expect(hex(sha256(new Uint8Array(0)))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it('hashes "abc" (one block)', () => {
    expect(hex(sha256(utf8("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("hashes the 448-bit message (padding spills into a second block)", () => {
    expect(hex(sha256(utf8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
  });

  it("hashes the 896-bit message", () => {
    const msg =
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    expect(hex(sha256(utf8(msg)))).toBe(
      "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    );
  });

  it('hashes one million "a"', () => {
    expect(hex(sha256(new Uint8Array(1_000_000).fill(0x61)))).toBe(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    );
  });
});

describe("sha256 against crypto.subtle", () => {
  it("agrees for every length from 0 to 300, which crosses every padding and block boundary", async () => {
    for (let n = 0; n <= 300; n++) {
      const data = Uint8Array.from({ length: n }, (_, i) => (i * 131 + n * 7 + 13) & 0xff);
      expect(hex(sha256(data)), `length ${n}`).toBe(await reference(data));
    }
  });

  it("agrees on bytes with the high bit set and on a view into a larger buffer", async () => {
    const big = Uint8Array.from({ length: 1000 }, (_, i) => 255 - (i % 256));
    const view = big.subarray(37, 37 + 411);
    expect(hex(sha256(view))).toBe(await reference(Uint8Array.from(view)));
  });
});

describe("sha256 does not touch its input", () => {
  it("leaves the input bytes unchanged and returns a fresh 32-byte array", () => {
    const data = utf8("global:route");
    const copy = Uint8Array.from(data);
    const out = sha256(data);
    expect(Array.from(data)).toEqual(Array.from(copy));
    expect(out).toHaveLength(32);
    expect(out.buffer).not.toBe(data.buffer);
  });
});
