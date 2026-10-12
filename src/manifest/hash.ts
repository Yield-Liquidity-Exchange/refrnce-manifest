// src/manifest/hash.ts — SHA-256 manifest hash. Isomorphic: Web Crypto only, so the
// same code runs in Node and in the browser.
import { canonicalizeJcs } from "./canonical.js";

/**
 * "sha256:" plus lowercase hex of SHA-256 over the UTF-8 bytes of the RFC 8785 canonical form.
 * Throws if the manifest is not canonicalisable, or if Web Crypto is unavailable (a non-secure
 * browser context): a hash is never faked or returned empty.
 */
export async function hashManifest(manifest: unknown): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("hashManifest: Web Crypto (crypto.subtle) is not available");
  const bytes = new TextEncoder().encode(canonicalizeJcs(manifest));
  const digest = await subtle.digest("SHA-256", bytes);
  if (digest.byteLength !== 32) throw new Error("hashManifest: SHA-256 digest is not 32 bytes");
  const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}
