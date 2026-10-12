// SHA-256 of an artifact file, as the record lists it ("sha256:" and 64 lower-case hex digits).
//
// The verifier needs only this one function to check C6 (artifacts), so it is written out here. It must
// give the same answer as the issuer's own function for every input; the repository that produces this
// package tests that the two agree.
//
// Isomorphic: Web Crypto only (crypto.subtle), no Node imports.

// The getter of %TypedArray%.prototype[Symbol.toStringTag] reads the object's internal [[TypedArrayName]]
// slot. Unlike Object.prototype.toString, a Symbol.toStringTag property cannot fake it, and a Proxy has no
// such slot. Captured once, at load, before any caller code can replace it.
const typedArrayTag = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  Symbol.toStringTag,
)?.get;

/**
 * ONE synchronous copy of a genuine Uint8Array (a Buffer is one; a subclass is one), made with the engine's
 * own element copy, which reads the real internal length and not any `length` or `byteLength` the object
 * claims. The hash is taken from this copy. A detached or out-of-bounds buffer throws instead of reading as
 * an empty file.
 */
function snapshotUint8Array(value: unknown): Uint8Array<ArrayBuffer> {
  if (typedArrayTag?.call(value) !== "Uint8Array")
    throw new Error("an artifact must be a Uint8Array");
  try {
    return new Uint8Array(value as Uint8Array);
  } catch {
    throw new Error("an artifact must be a Uint8Array whose buffer can be read");
  }
}

async function sha256Prefixed(copy: Uint8Array<ArrayBuffer>): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("hashArtifact: Web Crypto (crypto.subtle) is not available");
  const digest = await subtle.digest("SHA-256", copy);
  if (digest.byteLength !== 32) throw new Error("hashArtifact: SHA-256 digest is not 32 bytes");
  const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}

/** "sha256:" and lower-case hex of SHA-256 over the bytes of the file. Throws unless given a genuine Uint8Array. */
export async function hashArtifact(bytes: Uint8Array): Promise<string> {
  let copy: Uint8Array<ArrayBuffer>;
  try {
    copy = snapshotUint8Array(bytes);
  } catch (e) {
    throw new Error(`hashArtifact: ${(e as Error).message}`);
  }
  return sha256Prefixed(copy);
}
