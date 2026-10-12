// hashArtifact is the one function the package writes for itself (the application's copy of it is not
// published), and check C6 depends on it. These are known answers: the first two are the published SHA-256
// test vectors; the other two were computed once with the issuer's own function and are written down here, so
// the package is held to the issuer's answers without the issuer's code.
import { describe, expect, it } from "vitest";
import { hashArtifact } from "../src/manifest/artifact-hash.js";

const pattern = Uint8Array.from({ length: 1000 }, (_, i) => (i * 7 + 3) & 255);

describe("known answers", () => {
  it.each([
    [
      "the empty file",
      new Uint8Array(0),
      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ],
    [
      "abc",
      new TextEncoder().encode("abc"),
      "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ],
    [
      "1000 bytes of a fixed pattern",
      pattern,
      "sha256:1e9bc38cbf860b9ec31918b065f9b52476c549a782e0e7990bed8ce3868d2371",
    ],
    [
      "65 zero bytes (two blocks)",
      new Uint8Array(65),
      "sha256:98ce42deef51d40269d542f5314bef2c7468d401ad5d85168bfab4c0108f75f7",
    ],
  ])("%s", async (_name, bytes, expected) => {
    expect(await hashArtifact(bytes)).toBe(expected);
  });

  it("hashes a view into a larger buffer by its own bytes, not the buffer's", async () => {
    const big = new Uint8Array(16).fill(9);
    big.set(new TextEncoder().encode("abc"), 4);
    expect(await hashArtifact(big.subarray(4, 7))).toBe(
      "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("what is refused", () => {
  it.each([
    ["a string", "abc"],
    ["null", null],
    ["a plain array", [97, 98, 99]],
    ["an ArrayBuffer", new ArrayBuffer(3)],
    ["a Uint16Array", new Uint16Array(2)],
    ["an object posing as bytes", { length: 3, 0: 97, 1: 98, 2: 99 }],
  ])("%s", async (_name, input) => {
    await expect(hashArtifact(input as unknown as Uint8Array)).rejects.toThrow(
      /hashArtifact: an artifact must be a Uint8Array/,
    );
  });
});
