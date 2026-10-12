// Tests for hashManifest. The pinned digests were computed outside this code base with
// `printf '%s' '<canonical json>' | sha256sum`, so these tests fail if either the canonical form or
// the digest changes. node:crypto appears only here, as an independent reference: hash.ts itself
// uses Web Crypto so the same code runs in Node and in a browser.
import { afterEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { canonicalizeJcs } from "../canonical.js";
import { hashManifest } from "../hash.js";

const reference = (manifest: unknown) =>
  `sha256:${createHash("sha256")
    .update(Buffer.from(canonicalizeJcs(manifest), "utf8"))
    .digest("hex")}`;

describe("hashManifest: format and pinned digests", () => {
  it('returns "sha256:" plus 64 lower-case hex characters', async () => {
    expect(await hashManifest({ a: 1 })).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  // printf '%s' '{}' | sha256sum
  it("hashes the empty object to the SHA-256 of the two bytes {}", async () => {
    expect(await hashManifest({})).toBe(
      "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    );
  });

  // printf '%s' '{"a":1,"b":"x"}' | sha256sum  (input keys given in the opposite order)
  it("hashes the canonical text, not the input order", async () => {
    expect(await hashManifest({ b: "x", a: 1 })).toBe(
      "sha256:ecf9e98ec0641e23113ff3ce8bdc78d0ddd249886517fd4a7f68cc83d4e65667",
    );
  });

  // printf '{"\xe2\x82\xac":"\xf0\x9f\x98\x80"}' | sha256sum  (euro sign key, grinning-face value)
  it("hashes UTF-8 bytes, not UTF-16 code units, for non-ASCII content", async () => {
    expect(await hashManifest({ "€": "😀" })).toBe(
      "sha256:d6921b1d63c147cc81722cd7fc6b3eb51e1c2251e84990d88e4235a2d09ea021",
    );
  });
});

describe("hashManifest: canonical form drives the hash", () => {
  it("is the same for any key order, at any depth", async () => {
    const a = { z: 1, a: { y: "2", b: ["3"] } };
    const b = { a: { b: ["3"], y: "2" }, z: 1 };
    expect(await hashManifest(a)).toBe(await hashManifest(b));
  });

  it("changes when any value changes", async () => {
    const base = await hashManifest({ amount: "1000", mint: "So11" });
    expect(await hashManifest({ amount: "1001", mint: "So11" })).not.toBe(base);
    expect(await hashManifest({ amount: "1000", mint: "So12" })).not.toBe(base);
  });

  it("changes when array order changes, because array order is meaningful", async () => {
    expect(await hashManifest({ a: [1, 2] })).not.toBe(await hashManifest({ a: [2, 1] }));
  });

  it("rejects what canonicalizeJcs rejects, so a bad manifest never gets a hash", async () => {
    await expect(hashManifest({ a: 1.5 })).rejects.toThrow();
    await expect(hashManifest({ a: null })).rejects.toThrow();
    await expect(hashManifest({ a: undefined })).rejects.toThrow();
    await expect(hashManifest({ a: Number.NaN })).rejects.toThrow();
  });
});

describe("hashManifest: cross-runtime parity", () => {
  const manifests: unknown[] = [
    {},
    [],
    { a: 1 },
    { version: "1", chain: "solana", amounts: ["0", "18446744073709551615"], n: -3 },
    { b: { y: [true, false, "x"], x: "€" }, a: "😀" },
    { דּ: 1, "😀": 2, "€": 3, "\r": 4, "1": 5, "\u0080": 6 },
    { s: '\u0000\u001f\u007f"\\/\b\t\n\f\r ' },
    { deep: { a: { b: { c: { d: { e: ["f", { g: "h" }] } } } } } },
  ];

  it("matches the node:crypto reference over the same canonical bytes", async () => {
    for (const m of manifests) expect(await hashManifest(m)).toBe(reference(m));
  });

  describe("without Node-only globals", () => {
    afterEach(() => vi.unstubAllGlobals());

    it("gives the same hash when Buffer is not available, as in a browser", async () => {
      const expected = manifests.map(reference);
      vi.stubGlobal("Buffer", undefined);
      expect(typeof (globalThis as { Buffer?: unknown }).Buffer).toBe("undefined");
      const actual: string[] = [];
      for (const m of manifests) actual.push(await hashManifest(m));
      expect(actual).toEqual(expected);
    });

    it("fails loudly, instead of returning an empty or fake hash, when Web Crypto is missing", async () => {
      vi.stubGlobal("crypto", undefined);
      await expect(hashManifest({ a: 1 })).rejects.toThrow(/web crypto/i);
    });
  });
});
