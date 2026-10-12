// Issuer-signature verification: Ed25519 over the signing message (a fixed prefix and the manifest hash),
// against the pinned issuer key list. Isomorphic: runs in Node and the browser.
//

import * as ed from "@noble/ed25519";
import { z } from "zod";
import { decodeBase58 } from "../../solana/base58.js";

/** The signed message is these UTF-8 bytes followed by the manifest hash. Changing it breaks every signature. */
export const SIGNING_PREFIX = "trace-manifest-v1:";

/** What hashManifest returns: "sha256:" and 64 lowercase hex characters. */
export const MANIFEST_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;

const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
// Longest base58 text a 32-byte (resp. 64-byte) value can have; stops a hostile envelope from making
// the quadratic base58 decoder chew on megabytes.
const MAX_PUBLIC_KEY_B58 = 44;
const MAX_SIGNATURE_B58 = 88;

/** Signature envelope placed in a manifest: base58 Ed25519 signature plus the id of the key that made it. */
export type ManifestSignature = { alg: "Ed25519"; key_id: string; value: string };

function decodesToBytes(text: string, maxChars: number, bytes: number): boolean {
  if (text.length === 0 || text.length > maxChars) return false;
  try {
    return decodeBase58(text).length === bytes;
  } catch {
    return false;
  }
}

/** One public key the verifier may trust. Public keys are never deleted: retire or revoke them instead. */
export const IssuerKeySchema = z
  .object({
    key_id: z.string().regex(/^[A-Za-z0-9._-]{1,64}$/, "key_id must be 1-64 of A-Z a-z 0-9 . _ -"),
    public_key: z
      .string()
      .refine(
        (v) => decodesToBytes(v, MAX_PUBLIC_KEY_B58, ED25519_PUBLIC_KEY_BYTES),
        "public_key must be base58 of 32 bytes",
      ),
    valid_from: z.string().datetime({ message: "valid_from must be an ISO UTC timestamp" }),
    status: z.enum(["active", "retired", "revoked"]),
    /**
     * Optional: when a retired key stopped vouching for new records. The verifier
     * then accepts a retired key only for anchors whose chain block time is not later than this.
     */
    retired_at: z
      .string()
      .datetime({ message: "retired_at must be an ISO UTC timestamp" })
      .optional(),
  })
  .strict();

/** The shape of issuer-keys.json. */
export const IssuerKeysSchema = z
  .object({ keys: z.array(IssuerKeySchema) })
  .strict()
  .superRefine((file, ctx) => {
    const seen = new Set<string>();
    file.keys.forEach((k, i) => {
      if (seen.has(k.key_id))
        ctx.addIssue({ code: "custom", path: ["keys", i, "key_id"], message: "duplicate key_id" });
      seen.add(k.key_id);
    });
  });

export type IssuerKey = z.infer<typeof IssuerKeySchema>;
export type IssuerKeys = z.infer<typeof IssuerKeysSchema>;

/** Validates untrusted JSON as an issuer key list. Throws a ZodError on any malformed entry or duplicate key_id. */
export function parseIssuerKeys(input: unknown): IssuerKeys {
  return IssuerKeysSchema.parse(input);
}

/** The exact bytes that are signed: UTF-8 of SIGNING_PREFIX + hash. Throws unless hash is a manifest hash. */
export function signingMessage(hash: string): Uint8Array {
  if (typeof hash !== "string" || !MANIFEST_HASH_PATTERN.test(hash))
    throw new Error("hash must be sha256: followed by 64 lowercase hex characters");
  return new TextEncoder().encode(SIGNING_PREFIX + hash);
}

/**
 * True only if `signature` is a valid Ed25519 signature over SIGNING_PREFIX + hash by the key listed
 * for `signature.key_id` in `issuerKeys` (the parsed issuer-keys.json, or its bare key array).
 *
 * The public key always comes from the list passed in, never from the envelope. An unknown or revoked
 * key fails; a retired key still verifies, so old records stay verifiable. Malformed input of any kind
 * (hash, envelope, key list) returns false and never throws. Verification uses the strict RFC 8032
 * branch of noble (not the ZIP-215 default), so non-canonical encodings are rejected.
 */
export async function verifySignature(
  hash: string,
  signature: unknown,
  issuerKeys: unknown,
): Promise<boolean> {
  try {
    if (typeof hash !== "string" || !MANIFEST_HASH_PATTERN.test(hash)) return false;
    if (typeof signature !== "object" || signature === null) return false;
    const { alg, key_id: keyId, value } = signature as Record<string, unknown>;
    if (alg !== "Ed25519" || typeof keyId !== "string" || typeof value !== "string") return false;

    const parsed = IssuerKeysSchema.safeParse(
      Array.isArray(issuerKeys) ? { keys: issuerKeys } : issuerKeys,
    );
    if (!parsed.success) return false;
    const entry = parsed.data.keys.find((k) => k.key_id === keyId);
    if (!entry || entry.status === "revoked") return false;

    if (!decodesToBytes(value, MAX_SIGNATURE_B58, ED25519_SIGNATURE_BYTES)) return false;
    return await ed.verifyAsync(
      decodeBase58(value),
      signingMessage(hash),
      decodeBase58(entry.public_key),
      { zip215: false },
    );
  } catch {
    return false;
  }
}
