// A complete, valid, synthetic record for the tests: a one-instruction System transfer that exists only in
// this file, a manifest built from it by the package's own normaliser, signed by a throwaway Ed25519 key that
// is generated in memory for each test run, and an anchor transaction that carries the manifest hash in a
// Memo. Nothing here is a real transaction, a real key or a real record, and nothing is read from disk.
//
// The pinned issuer list the verifier would normally use is replaced, in the tests, by a list holding only
// the throwaway public key (VerifyOptions.issuerKeys). The committed issuer-keys.json is never used to sign.
import * as ed from "@noble/ed25519";
import { hashArtifact } from "../../src/manifest/artifact-hash.js";
import { checkManifestRules } from "../../src/manifest/manifest-rules.js";
import { hashManifest } from "../../src/manifest/hash.js";
import { FORMULAS } from "../../src/manifest/formulas.js";
import {
  ManifestSchema,
  type Claim,
  type Envelope,
  type Manifest,
} from "../../src/manifest/types.js";
import { signingMessage } from "../../src/manifest/verify/signature.js";
import { encodeBase58 } from "../../src/solana/base58-encode.js";
import { sha256 } from "../../src/solana/sha256.js";
import { NORMALISER_ID, normaliseSolanaTransaction } from "../../src/solana/normalise.js";
import { PROGRAM_IDS, REGISTRY_VERSION } from "../../src/solana/programs.js";

const utf8 = (s: string) => new TextEncoder().encode(s);

export const TRACE_ID = "TRC-SYNTH0TEST12";
export const KEY_ID = "synthetic-test-key";
export const ARTIFACT = { name: "note.txt", text: "A synthetic artifact. Not a real report.\n" };
export const TRANSFER_LAMPORTS = 1_000_000n;
export const FEE_LAMPORTS = 5000;

/** A stable base58 address for a label. */
export function addressFor(label: string): string {
  return encodeBase58(sha256(utf8(`address:${label}`)));
}

/** A stable 64-byte base58 signature for a label. */
export function signatureFor(label: string): string {
  const out = new Uint8Array(64);
  out.set(sha256(utf8(`sig-a:${label}`)), 0);
  out.set(sha256(utf8(`sig-b:${label}`)), 32);
  out[0] |= 0x80; // never a leading zero byte, so the text is 87 or 88 characters
  return encodeBase58(out);
}

const u64le = (n: bigint) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
};

export const PAYER = addressFor("payer");
export const RECIPIENT = addressFor("recipient");
export const SUBJECT_SIGNATURE = signatureFor("subject");

/** The subject: a getTransaction answer (encoding json) for one System program transfer. */
export function subjectTransaction() {
  const data = new Uint8Array(12);
  new DataView(data.buffer).setUint32(0, 2, true); // System instruction 2: Transfer
  data.set(u64le(TRANSFER_LAMPORTS), 4);
  const pre = 2_000_000_000;
  return {
    slot: 300_000_000,
    blockTime: 1_790_726_400,
    version: "legacy",
    transaction: {
      signatures: [SUBJECT_SIGNATURE],
      message: {
        header: {
          numRequiredSignatures: 1,
          numReadonlySignedAccounts: 0,
          numReadonlyUnsignedAccounts: 1,
        },
        accountKeys: [PAYER, RECIPIENT, PROGRAM_IDS.system],
        recentBlockhash: addressFor("blockhash"),
        instructions: [
          { programIdIndex: 2, accounts: [0, 1], data: encodeBase58(data), stackHeight: null },
        ],
      },
    },
    meta: {
      err: null,
      status: { Ok: null },
      fee: FEE_LAMPORTS,
      preBalances: [pre, 0, 1],
      postBalances: [pre - FEE_LAMPORTS - Number(TRANSFER_LAMPORTS), Number(TRANSFER_LAMPORTS), 1],
      preTokenBalances: [],
      postTokenBalances: [],
      innerInstructions: [],
      loadedAddresses: { writable: [] as string[], readonly: [] as string[] },
      logMessages: [] as string[],
      rewards: [],
      computeUnitsConsumed: 150,
    },
  };
}

export interface TestKey {
  seed: Uint8Array;
  keyId: string;
  publicKey: string;
}

/** A throwaway key pair. The seed exists only in memory for this test run. */
export async function makeTestKey(keyId = KEY_ID): Promise<TestKey> {
  const seed = ed.utils.randomSecretKey();
  return { seed, keyId, publicKey: encodeBase58(await ed.getPublicKeyAsync(seed)) };
}

export async function signHash(key: TestKey, hash: string) {
  const sig = await ed.signAsync(signingMessage(hash), key.seed);
  return { alg: "Ed25519" as const, key_id: key.keyId, value: encodeBase58(sig) };
}

export const ANCHOR_SLOT = 300_000_100;
export const ANCHOR_BLOCK_TIME = 1_790_899_200;
const FEE_PAYER = addressFor("fee-payer");

/** A getTransaction answer for the anchor: fee payer and issuer sign, one Memo naming the issuer. */
export function anchorTransaction(
  signature: string,
  issuerAddress: string,
  memo: string,
  blockTime = ANCHOR_BLOCK_TIME,
) {
  const keys = [FEE_PAYER, issuerAddress, PROGRAM_IDS.computeBudget, PROGRAM_IDS.memo];
  return {
    slot: ANCHOR_SLOT,
    blockTime,
    version: 0,
    transaction: {
      signatures: [signature, signatureFor(`cosigner:${signature}`)],
      message: {
        header: {
          numRequiredSignatures: 2,
          numReadonlySignedAccounts: 1,
          numReadonlyUnsignedAccounts: 2,
        },
        accountKeys: keys,
        recentBlockhash: addressFor("blockhash"),
        instructions: [
          {
            programIdIndex: 2,
            accounts: [],
            data: encodeBase58(new Uint8Array([2, 0x40, 0x0d, 0x03, 0x00])),
            stackHeight: null,
          },
          { programIdIndex: 3, accounts: [1], data: encodeBase58(utf8(memo)), stackHeight: null },
        ],
        addressTableLookups: [],
      },
    },
    meta: {
      err: null,
      status: { Ok: null },
      fee: 10_000,
      preBalances: [1_000_000_000, 0, 1, 1],
      postBalances: [999_990_000, 0, 1, 1],
      innerInstructions: [],
      loadedAddresses: { writable: [] as string[], readonly: [] as string[] },
      logMessages: [] as string[],
      rewards: [],
    },
  };
}

export interface Fixture {
  key: TestKey;
  envelope: Envelope;
  /** Every transaction the fake chain knows, by first signature. */
  chain: Map<string, unknown>;
  issuerKeys: {
    keys: { key_id: string; public_key: string; valid_from: string; status: "active" }[];
  };
  artifactBytes: Uint8Array;
}

export interface FixtureOptions {
  cluster?: "devnet" | "mainnet-beta" | "testnet";
  /** Change the claims the normaliser gave BEFORE the record is hashed and signed (a forged but signed record). */
  alterClaims?: (claims: Claim[]) => Claim[];
}

/** A whole valid record. With `alterClaims` it is validly signed but its claims no longer match the chain. */
export async function makeFixture(options: FixtureOptions = {}): Promise<Fixture> {
  const cluster = options.cluster ?? "devnet";
  const key = await makeTestKey();
  const normalised = await normaliseSolanaTransaction(subjectTransaction() as never, {
    rpc: { getAccountInfo: () => Promise.reject(new Error("no network in unit tests")) },
  });
  const claims = options.alterClaims ? options.alterClaims(normalised.claims) : normalised.claims;
  const formulas = new Set(Object.keys(FORMULAS));
  for (const c of claims) if (c.provenance.type === "derived") formulas.add(c.provenance.formula);
  const artifactBytes = utf8(ARTIFACT.text);

  const manifest: Manifest = ManifestSchema.parse({
    schema: "trace-manifest/1.0",
    trace_id: TRACE_ID,
    issuer: { name: "Synthetic Test Issuer", key_id: key.keyId },
    issued_at: "2026-10-01T00:00:00Z",
    subject: { chain: "solana", cluster, signatures: [SUBJECT_SIGNATURE] },
    tooling: {
      normaliser: NORMALISER_ID,
      decoder_registry: REGISTRY_VERSION,
      formulas: [...formulas].sort(),
    },
    claims,
    artifacts: [
      {
        name: ARTIFACT.name,
        sha256: await hashArtifact(artifactBytes),
        bytes: artifactBytes.length,
      },
    ],
  });
  const violations = checkManifestRules(manifest);
  if (violations.length > 0)
    throw new Error(`the synthetic manifest breaks a rule: ${violations[0].rule}`);

  const manifest_hash = await hashManifest(manifest);
  const anchorSignature = signatureFor(`anchor:${manifest_hash}`);
  const memo = `trace-manifest:1:${manifest_hash}`;
  const envelope: Envelope = {
    manifest,
    manifest_hash,
    signature: await signHash(key, manifest_hash),
    anchor: {
      cluster,
      tx_signature: anchorSignature,
      slot: ANCHOR_SLOT,
      block_time: ANCHOR_BLOCK_TIME,
      memo,
    },
  };
  const chain = new Map<string, unknown>([
    [SUBJECT_SIGNATURE, subjectTransaction()],
    [anchorSignature, anchorTransaction(anchorSignature, key.publicKey, memo)],
  ]);
  return {
    key,
    envelope,
    chain,
    artifactBytes,
    issuerKeys: {
      keys: [
        {
          key_id: key.keyId,
          public_key: key.publicKey,
          valid_from: "2026-10-01T00:00:00.000Z",
          status: "active",
        },
      ],
    },
  };
}

/** A fake RPC for verifyEnvelope: answers from `chain`, "not found" for anything else. */
export function fakeRpc(chain: Map<string, unknown>) {
  const calls: string[] = [];
  return {
    calls,
    async getTransaction(signature: string) {
      calls.push(signature);
      const found = chain.get(signature);
      if (found === undefined) {
        const { RpcNotFoundError } = await import("../../src/solana/rpc.js");
        throw new RpcNotFoundError();
      }
      return structuredClone(found) as never;
    },
  };
}

/**
 * A fetch that behaves like a JSON-RPC node holding `chain`: getTransaction returns the transaction or null.
 * It records every URL it is asked.
 */
export function fakeFetch(chain: Map<string, unknown>, options: { down?: boolean } = {}) {
  const urls: string[] = [];
  const fetch = async (input: string, init: RequestInit): Promise<Response> => {
    urls.push(input);
    if (options.down) throw new TypeError("network down");
    const body = JSON.parse(String(init.body)) as { id: number; method: string; params: unknown[] };
    if (body.method !== "getTransaction") throw new Error(`unexpected method ${body.method}`);
    const found = chain.get(String(body.params[0]));
    return new Response(
      JSON.stringify({ jsonrpc: "2.0", id: body.id, result: found === undefined ? null : found }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  return { fetch, urls };
}

/**
 * A fetch for several endpoints: each host has its own chain, or is "down" (a network error). Records the host
 * of every request, in order.
 */
/** What a host answers: a chain, "down", or a function of the signature and how many times it was asked for it. */
export type HostSource =
  | Map<string, unknown>
  | "down"
  | ((signature: string, nth: number) => unknown | undefined | "down");

export function fakeFetchByHost(hosts: Record<string, HostSource>) {
  const asked: string[] = [];
  /** Every request: the host and the signature asked for. */
  const calls: { host: string; signature: string }[] = [];
  const fetch = async (input: string, init: RequestInit): Promise<Response> => {
    const host = new URL(input).host;
    asked.push(host);
    const source = hosts[host];
    if (source === undefined || source === "down") throw new TypeError("network down");
    const body = JSON.parse(String(init.body)) as { id: number; params: unknown[] };
    const signature = String(body.params[0]);
    const nth = calls.filter((c) => c.host === host && c.signature === signature).length;
    calls.push({ host, signature });
    const found = typeof source === "function" ? source(signature, nth) : source.get(signature);
    if (found === "down") throw new TypeError("network down");
    return new Response(
      JSON.stringify({ jsonrpc: "2.0", id: body.id, result: found === undefined ? null : found }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  return { fetch, asked, calls, urls: asked };
}
