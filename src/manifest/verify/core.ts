// The verifier core: checks C1 to C8 and the verdict. "verified" means the record is intact, signed by a
// pinned issuer key, anchored by it on chain, AND every Observed and Derived claim reproduces from the
// subject transactions read again (Attributed and Inferred claims are listed as not checked and do not
// affect the verdict).
//

// Isomorphic: Web Crypto, @noble/ed25519 (through signature.ts), zod and fetch only. No node: imports, no
// @solana/web3.js, no bs58, no Buffer or process, so the same code runs in the public page and in Node.
//
// The rules that keep a doubtful result from ever reading "verified":
//   - verifyEnvelope never throws, for any input. The envelope is read ONCE, through canonicalizeJcs's
//     validated snapshot (no getters, no Proxy re-reads, no toJSON, no cycles, no non-plain objects); every
//     check works on that copy. A C1 failure skips every other check and the verdict is does_not_match.
//   - "verified" needs C1, C2, C3, C4, C7 and C8 to PASS and C6 to pass or be skipped (no files supplied). A
//     skipped or unavailable required check can never be read as a pass.
//   - Any "fail" (C1 to C8) makes the verdict does_not_match. Otherwise any shortfall is unable_to_check. C5
//     unavailable (registry offline) is a warning only: it never blocks "verified".
//   - C7 and C8 run after C1 to C6, with the same RPC (C4 has already required the anchor and the subject to be
//     on one cluster). They are skipped when C1, C2, C3 or C4 failed (that failure decides the verdict, and the
//     subject transactions are not fetched) and when the caller turns re-derivation off (rederive: false); a
//     skipped C7 or C8 makes the verdict unable_to_check, never verified. Any claim that does not match the chain
//     fails its check; any claim that could not be checked (no usable answer, an unknown formula) makes it
//     unavailable. Every subject transaction counts even when the record has no claim in it: one the chain does
//     not have fails C7 and C8 (naming its signature), one that could not be read makes them unavailable, and
//     they pass only when every subject transaction was read and compared; a pass says how many claims and
//     transactions it compared. Claims not checked (Attributed, Inferred) are counted and listed in C7's
//     evidence only.
//   - Inside a check, transport-class trouble (an RPC that times out, cannot be reached, answers HTTP errors
//     or junk, or answers about another transaction; a registry that is offline; a missing Web Crypto) is
//     "unavailable". A definite answer that contradicts the record (the chain has no such transaction, the
//     memo or signer is wrong, the registry holds another hash) is "fail". Nothing is ever a pass by default.
//   - The issuer public key is looked up by key_id in the PINNED list the caller passes (default: the
//     committed issuer-keys.json). It is never read from the envelope.
//   - Every detail is fixed text. Upstream error text, RPC URLs and registry messages never reach the result.
//
// What callers must do:
//   - TRUST: the verifier trusts the RPC endpoint it is given; a lying endpoint can invent an anchor. Callers
//     must never take the RPC URL from the envelope, from a link or from anything the record's holder controls,
//     and the page should show which endpoint answered.
import { canonicalizeJcs } from "../canonical.js";
import { checkManifestRules, detectDuplicateKeys } from "../manifest-rules.js";
import { hashManifest } from "../hash.js";
import { hashArtifact } from "../artifact-hash.js";
import issuerKeysFile from "../issuer-keys.json" with { type: "json" };
import {
  EnvelopeSchema,
  MANIFEST_CLUSTERS,
  MAX_CANONICAL_CHARS,
  MAX_MANIFEST_ARTIFACTS,
  MAX_MANIFEST_CLAIMS,
  MAX_STRING_LENGTH,
  MAX_SUBJECT_SIGNATURES,
  type Envelope,
  type ManifestCluster,
} from "../types.js";
import { IssuerKeysSchema, verifySignature, type IssuerKey, type IssuerKeys } from "./signature.js";
import { encodeBase58 } from "../../solana/base58-encode.js";
import { PROGRAM_IDS } from "../../solana/programs.js";
import { resolveAccountKeys } from "../../solana/account-keys.js";
import {
  RpcError,
  RpcNotFoundError,
  parseTransactionResult,
  type RpcTransaction,
  type SolanaRpc,
} from "../../solana/rpc.js";
import {
  REDERIVE_TEXT,
  UNAVAILABLE_DETAIL,
  rederive,
  unavailableDetail,
  type ClaimCheck,
  type RederiveResult,
} from "./rederive.js";
import { recordRpcSources, type RpcEndpointUse } from "./rpc-sources.js";

// ─── Public types ────────────────────────────────────────────────────────────

export const CHECK_IDS = ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"] as const;
export type CheckId = (typeof CHECK_IDS)[number];

export const CHECK_NAMES: Readonly<Record<CheckId, string>> = Object.freeze({
  C1: "Schema",
  C2: "Hash",
  C3: "Signature",
  C4: "Anchor",
  C5: "Registry",
  C6: "Artifacts",
  C7: "Observed claims",
  C8: "Derived claims",
});

export type CheckStatus = "pass" | "fail" | "skipped" | "unavailable";

/** Plain data only: hashes, ids, slots, times, counts, names the record itself lists. */
export type CheckEvidence = Record<string, string | number | boolean | string[]>;

export interface CheckResult {
  id: CheckId;
  name: string;
  status: CheckStatus;
  /** Fixed, safe text. Never upstream text. */
  detail: string;
  evidence?: CheckEvidence;
}

export type Verdict = "verified" | "does_not_match" | "unable_to_check";

export interface VerifyResult {
  verdict: Verdict;
  /** Exactly C1..C8, in order. */
  checks: CheckResult[];
  /** The per-claim results behind C7 and C8, when the re-derivation ran. */
  rederive?: RederiveResult;
  /**
   * "RPC endpoint used": the endpoints that answered this verification's reads, by hostname only,
   * present when the rpc reports its sources (createResilientRpc). Empty when no endpoint answered.
   */
  rpc_endpoints?: RpcEndpointUse[];
}

/**
 * One row of the public registry. manifest_hash and status are required; the
 * other columns are compared when present.
 */
export interface RegistryRecord {
  manifest_hash: string;
  status: string;
  trace_id?: string;
  key_id?: string;
  cluster?: string;
  anchor_signature?: string;
}

/**
 * Looks up one Trace ID. Resolves to the row, null when there is no row, or "offline" when the registry
 * cannot answer (throwing means the same as "offline"). It must apply its own timeout.
 */
export type RegistryLookup = (traceId: string) => Promise<RegistryRecord | null | "offline">;

export interface VerifyFile {
  /** The file name as it appears in manifest.artifacts. */
  name: string;
  bytes: Uint8Array;
}

export interface VerifyOptions {
  /**
   * Reads the anchor transaction. getTransaction must ask at finalized, throw RpcNotFoundError (or resolve
   * null) when the chain has no such transaction, and apply its own timeout: createSolanaRpc does all three.
   * It must be an endpoint for envelope.anchor.cluster.
   */
  rpc: Pick<SolanaRpc, "getTransaction">;
  /** The pinned issuer key list (issuer-keys.json shape, or its bare array). Default: the committed list. */
  issuerKeys?: unknown;
  /** C5. Omit to skip the registry check. */
  registryLookup?: RegistryLookup;
  /**
   * C5's own deadline in ms (default 10 000). A lookup that has not answered by then is unavailable, so a
   * registry that never answers cannot hang the verifier. An invalid value falls back to the default.
   */
  registryTimeoutMs?: number;
  /**
   * The JSON text the envelope was parsed from, when the caller has it (the verify page does). C1 then refuses
   * a text over 16 MB, a text that repeats a key (JSON.parse keeps the last one silently), a text that writes a
   * number as -0, and a text that does not parse to `envelope`.
   */
  rawText?: string;
  /** C6. Omit (or pass none) to skip the artifact check. */
  files?: readonly VerifyFile[];
  /**
   * The cluster `rpc` serves. Callers must pass it (see the header). If it is not the anchor's cluster, C4 is
   * unavailable: asking the wrong cluster would come back "not found" and read as tampering. The same goes for C7 and C8.
   * When omitted, the rpc's own `cluster` (createResilientRpc has one) is used; when both are given and they
   * disagree, C4, C7 and C8 are unavailable.
   */
  cluster?: ManifestCluster;
  /**
   * C7 and C8: re-read the subject transactions through `rpc` and re-derive every claim (default). Only the
   * value false turns it off; C7 and C8 are then skipped and the verdict can be at best unable_to_check.
   */
  rederive?: boolean;
}

/** The anchor memo is this prefix and the manifest hash, nothing else.  */
export const MEMO_PREFIX = "trace-manifest:1:";

export const DEV_KEY_PREFIX = "trace-dev-";

/** Any key id that starts "trace-dev", in any case, with or without the dash, is a dev key.  */
export function isDevKeyId(keyId: string): boolean {
  return /^trace-dev/i.test(keyId);
}

/** C5's default deadline. */
export const DEFAULT_REGISTRY_TIMEOUT_MS = 10_000;
const MAX_TIMER_MS = 2 ** 31 - 1;

/** The largest envelope text C1 reads: the 16 MB canonical-manifest limit.  */
export const MAX_ENVELOPE_TEXT_CHARS = MAX_CANONICAL_CHARS;
/** Room for the envelope's own fields around a maximum-size manifest in the cheap canonical-length bound. */
const ENVELOPE_OVERHEAD_CHARS = 4096;

const MAINNET: ManifestCluster = "mainnet-beta";
const MAX_FILES = 1000;

// ─── Helpers ─────────────────────────────────────────────────────────────────

type Outcome = Omit<CheckResult, "id" | "name">;

const pass = (detail: string, evidence?: CheckEvidence): Outcome => ({
  status: "pass",
  detail,
  ...(evidence ? { evidence } : {}),
});
const fail = (detail: string, evidence?: CheckEvidence): Outcome => ({
  status: "fail",
  detail,
  ...(evidence ? { evidence } : {}),
});
const unavailable = (detail: string, evidence?: CheckEvidence): Outcome => ({
  status: "unavailable",
  detail,
  ...(evidence ? { evidence } : {}),
});
const skipped = (detail: string): Outcome => ({ status: "skipped", detail });

const hasWebCrypto = (): boolean => {
  try {
    return typeof globalThis.crypto?.subtle?.digest === "function";
  } catch {
    return false;
  }
};

const isUint8Array = (v: unknown): v is Uint8Array =>
  Object.prototype.toString.call(v) === "[object Uint8Array]";

/** The pinned key list, or undefined when what was passed is not a valid list. */
function pinnedKeys(input: unknown): IssuerKeys | undefined {
  try {
    const parsed = IssuerKeysSchema.safeParse(Array.isArray(input) ? { keys: input } : input);
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

// ─── C1 Schema ───────────────────────────────────────────────────────────────

const structuralPaths = (paths: readonly string[]) => paths.slice(0, 5).map((p) => p.slice(0, 200));

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * The cheap bounds, checked on the plain copy before the schema parse, which takes seconds on a
 * large record: list lengths, string lengths and the canonical length. Each is a size_limits rule the schema or
 * checkManifestRules enforces anyway, so nothing an honest record could pass is refused here.
 */
function exceedsBounds(canonical: string, plain: unknown): boolean {
  if (canonical.length > MAX_CANONICAL_CHARS + ENVELOPE_OVERHEAD_CHARS) return true;
  const manifest = isRecord(plain) ? plain.manifest : undefined;
  if (isRecord(manifest)) {
    const length = (v: unknown) => (Array.isArray(v) ? v.length : 0);
    if (length(manifest.claims) > MAX_MANIFEST_CLAIMS) return true;
    if (length(manifest.artifacts) > MAX_MANIFEST_ARTIFACTS) return true;
    if (isRecord(manifest.subject) && length(manifest.subject.signatures) > MAX_SUBJECT_SIGNATURES)
      return true;
  }
  const stack: unknown[] = [plain];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v === "string") {
      if (v.length > MAX_STRING_LENGTH) return true;
    } else if (Array.isArray(v)) {
      for (const item of v) stack.push(item);
    } else if (isRecord(v)) {
      for (const item of Object.values(v)) stack.push(item);
    }
  }
  return false;
}

function checkSchema(
  envelope: unknown,
  rawText: unknown,
): { outcome: Outcome; plain?: unknown; env?: Envelope } {
  // Before anything is parsed: a text too large to be a record is refused at once.
  if (rawText !== undefined) {
    if (typeof rawText !== "string") return { outcome: fail("the envelope text is not text") };
    if (rawText.length > MAX_ENVELOPE_TEXT_CHARS)
      return { outcome: fail("the envelope text is larger than a record can be") };
  }
  let canonical: string;
  let plain: unknown;
  try {
    // The one read of the caller's object. The JSON text holds exactly what was validated.
    canonical = canonicalizeJcs(envelope);
    plain = JSON.parse(canonical);
  } catch {
    return { outcome: fail("the envelope is not plain JSON data") };
  }
  if (typeof rawText === "string") {
    let fromText: string;
    let negativeZero = false;
    try {
      const duplicates = detectDuplicateKeys(rawText);
      if (duplicates.length > 0)
        return {
          outcome: fail("the envelope text repeats a key in one object", {
            duplicate_key_paths: structuralPaths(duplicates.map((d) => d.path)),
          }),
        };
      // JSON.parse keeps -0 and the canonical form writes 0, so "-0" and "0" would share one hash (L6).
      const parsedText: unknown = JSON.parse(rawText, (_key, value: unknown) => {
        if (Object.is(value, -0)) negativeZero = true;
        return value;
      });
      if (negativeZero) return { outcome: fail("the envelope text writes a number as -0") };
      fromText = canonicalizeJcs(parsedText);
    } catch {
      return { outcome: fail("the envelope text is not valid JSON data") };
    }
    if (fromText !== canonical)
      return { outcome: fail("the envelope is not the one its text describes") };
  }
  if (exceedsBounds(canonical, plain))
    return {
      outcome: fail("the envelope is larger than a record can be", { rules: ["size_limits"] }),
    };
  const parsed = EnvelopeSchema.safeParse(plain);
  if (!parsed.success) {
    const paths = parsed.error.issues
      .slice(0, 5)
      .map((i) => (i.path.join(".") || "(root)").slice(0, 200));
    return { outcome: fail("the envelope does not match trace-manifest/1.0", { issues: paths }) };
  }
  // The rules a schema cannot express (manifest-rules.ts, the one list): claim codes and types, observed
  // signatures in the subject, signature.key_id = issuer.key_id, anchor.memo = prefix + hash, tooling, limits.
  const violations = checkManifestRules(plain);
  if (violations.length > 0)
    return {
      outcome: fail("the envelope breaks a trace-manifest/1.0 rule", {
        rules: [...new Set(violations.map((v) => v.rule))].slice(0, 20),
        issues: structuralPaths(violations.flatMap((v) => (v.path === undefined ? [] : [v.path]))),
      }),
    };
  return { outcome: pass("the envelope matches trace-manifest/1.0"), plain, env: parsed.data };
}

// ─── C2 Hash ─────────────────────────────────────────────────────────────────

async function checkHash(plainManifest: unknown, claimed: string): Promise<Outcome> {
  if (!hasWebCrypto()) return unavailable("this environment cannot compute SHA-256 (Web Crypto)");
  let actual: string;
  try {
    // The validated snapshot as supplied, not the schema's output object: the hash covers what was given.
    actual = await hashManifest(plainManifest);
  } catch {
    return fail("the manifest cannot be canonicalised");
  }
  const evidence = { expected: claimed, actual };
  return actual === claimed
    ? pass("the manifest hashes to manifest_hash", evidence)
    : fail("the manifest does not hash to manifest_hash", evidence);
}

// ─── C3 Signature ────────────────────────────────────────────────────────────

/**
 * `anchorTime` is the anchor's chain block time (unix seconds) from a PASSING C4, or undefined when C4 could
 * not establish it. Only a retired key with a retired_at needs it.
 */
async function checkSignature(
  env: Envelope,
  keys: IssuerKeys | undefined,
  anchorTime: number | undefined,
): Promise<Outcome> {
  const keyId = env.signature.key_id;
  if (!keys) return unavailable("the pinned issuer key list is not valid");
  const entry = keys.keys.find((k) => k.key_id === keyId);
  const evidence: CheckEvidence = { key_id: keyId };
  if (!entry) return fail("the signing key is not in the pinned issuer key list", evidence);
  evidence.key_status = entry.status;
  if (entry.status === "revoked") return fail("the signing key is revoked", evidence);
  if (
    isDevKeyId(keyId) &&
    (env.manifest.subject.cluster === MAINNET || env.anchor.cluster === MAINNET)
  )
    return fail("a development key cannot vouch for a mainnet record", evidence);
  if (!hasWebCrypto()) return unavailable("this environment cannot verify Ed25519 (Web Crypto)");
  const ok = await verifySignature(env.manifest_hash, env.signature, { keys: [entry] });
  if (!ok) return fail("the signature does not verify against the pinned issuer key", evidence);
  if (entry.status === "retired") {
    evidence.warnings = ["key retired"];
    // Decision M2: with a retired_at in the list, a retired key vouches only for anchors made by then (the
    // chain's block time, never the issuer's issued_at). Without one, the time cannot be checked: pass, warned.
    if (entry.retired_at !== undefined) {
      evidence.retired_at = entry.retired_at;
      if (anchorTime === undefined)
        return unavailable(
          "the key is retired and the anchor's time could not be confirmed to compare",
          evidence,
        );
      if (anchorTime * 1000 > Date.parse(entry.retired_at))
        return fail("the key was retired before the anchor was made", evidence);
    }
    return pass("signed by a pinned issuer key that is now retired", evidence);
  }
  return pass("signed by a pinned, active issuer key", evidence);
}

// ─── C4 Anchor ───────────────────────────────────────────────────────────────

const RPC_UNAVAILABLE_DETAIL: Record<string, string> = {
  timeout: "the Solana RPC did not answer in time",
  network: "the Solana RPC could not be reached",
  http: "the Solana RPC answered with an HTTP error",
  protocol: "the Solana RPC gave an invalid answer",
  unconfirmed: "the Solana RPC said not found, but no second endpoint confirmed it",
};

function rpcFailure(e: unknown): Outcome {
  if (e instanceof RpcError) {
    const evidence: CheckEvidence = { rpc_error: e.code };
    if ("status" in e && typeof e.status === "number") evidence.http_status = e.status;
    return unavailable(RPC_UNAVAILABLE_DETAIL[e.code] ?? "the Solana RPC call failed", evidence);
  }
  return unavailable("the Solana RPC call failed");
}

async function checkAnchor(
  env: Envelope,
  issuer: IssuerKey | undefined,
  rpc: VerifyOptions["rpc"] | undefined,
  rpcCluster: ManifestCluster | undefined,
): Promise<Outcome> {
  const anchor = env.anchor;
  const expectedMemo = `${MEMO_PREFIX}${env.manifest_hash}`;
  const evidence: CheckEvidence = {
    tx_signature: anchor.tx_signature,
    cluster: anchor.cluster,
    // The issuer's own statement and the chain's independent time are reported side by side, never merged.
    issued_at: env.manifest.issued_at,
    envelope_slot: anchor.slot,
    envelope_block_time: anchor.block_time,
  };
  if (anchor.cluster !== env.manifest.subject.cluster)
    return fail("the anchor is on a different cluster than the record", evidence);
  if (!issuer)
    return skipped("no pinned issuer key for this key_id, so the anchor signer cannot be checked");
  if (rpcCluster !== undefined && rpcCluster !== anchor.cluster)
    return unavailable("the Solana RPC serves a different cluster than the anchor's", evidence);

  let raw: unknown;
  try {
    if (!rpc || typeof rpc.getTransaction !== "function")
      return unavailable("no Solana RPC was given", evidence);
    raw = await rpc.getTransaction(anchor.tx_signature);
  } catch (e) {
    // A just-anchored record needs the transaction to reach finalized (tens of seconds) before it is found.
    if (e instanceof RpcNotFoundError)
      return fail("anchor transaction not found at finalized", evidence);
    const failure = rpcFailure(e);
    return { ...failure, evidence: { ...evidence, ...failure.evidence } };
  }
  const parsed = parseTransactionResult(raw, anchor.tx_signature);
  if (!parsed.ok) {
    if (parsed.reason === "not_found")
      return fail("anchor transaction not found at finalized", evidence);
    return unavailable("the Solana RPC gave an invalid answer", evidence);
  }
  const tx: RpcTransaction = parsed.tx;
  if (tx.meta === null)
    return unavailable("the Solana RPC did not return the transaction status", evidence);
  if (tx.meta.err !== null) return fail("the anchor transaction failed on chain", evidence);

  let keys: string[];
  try {
    keys = resolveAccountKeys(tx);
  } catch {
    return unavailable("the Solana RPC gave an invalid answer", evidence);
  }
  const staticKeys = tx.transaction.message.accountKeys;
  // Only static keys can sign: the first numRequiredSignatures of them. A lookup-table address never signs.
  const signerCount = Math.min(
    tx.transaction.message.header.numRequiredSignatures,
    staticKeys.length,
  );
  const issuerAddress = issuer.public_key;
  const isIssuerSignerIndex = (i: number) =>
    Number.isInteger(i) && i >= 0 && i < signerCount && staticKeys[i] === issuerAddress;

  // Base58 is a bijection on byte strings, so comparing the encoded text is comparing the exact bytes:
  // no extra byte, no newline, no other encoding of the same text, and no decoding of hostile data.
  const expectedData = encodeBase58(new TextEncoder().encode(expectedMemo));
  let memoInstructions = 0;
  let matching = 0;
  let matchingWithIssuer = false;
  for (const ix of tx.transaction.message.instructions) {
    const programIndex = ix.programIdIndex;
    if (!Number.isInteger(programIndex) || programIndex < 0 || programIndex >= keys.length)
      continue;
    if (keys[programIndex] !== PROGRAM_IDS.memo) continue;
    memoInstructions += 1;
    if (ix.data !== expectedData) continue;
    matching += 1;
    if (ix.accounts.some(isIssuerSignerIndex)) matchingWithIssuer = true;
  }
  evidence.memo_instructions = memoInstructions;
  if (matching === 0)
    return fail(
      "no Memo instruction in the anchor transaction carries this record's hash",
      evidence,
    );
  if (!staticKeys.slice(0, signerCount).includes(issuerAddress))
    return fail("the issuer key did not sign the anchor transaction", evidence);
  if (!matchingWithIssuer)
    return fail("the matching Memo instruction does not list the issuer as a signer", evidence);

  evidence.chain_slot = tx.slot;
  if (tx.slot !== anchor.slot)
    return fail("the anchor slot in the envelope differs from the chain", evidence);
  // The chain's block time is needed to confirm the envelope's and to check the key's valid_from (L5).
  const blockTime = tx.blockTime;
  if (typeof blockTime !== "number")
    return unavailable("the Solana RPC did not report the anchor's block time", evidence);
  evidence.chain_block_time = blockTime;
  evidence.chain_block_time_iso = new Date(blockTime * 1000).toISOString();
  if (blockTime !== anchor.block_time)
    return fail("the anchor block time in the envelope differs from the chain", evidence);
  // A key cannot have signed before it existed.
  if (blockTime * 1000 < Date.parse(issuer.valid_from))
    return fail("the anchor is older than the issuer key's valid_from", evidence);
  return pass("anchored at finalized by the issuer key, memo carries this record's hash", evidence);
}

// ─── C5 Registry ─────────────────────────────────────────────────────────────

const REGISTRY_FIELDS = [
  "manifest_hash",
  "status",
  "trace_id",
  "key_id",
  "cluster",
  "anchor_signature",
];

/** Reads the known columns once into a plain object; undefined when the row is not a valid shape. */
function readRegistryRow(row: unknown): RegistryRecord | undefined {
  if (typeof row !== "object" || row === null || Array.isArray(row)) return undefined;
  const out: Record<string, string> = {};
  for (const field of REGISTRY_FIELDS) {
    const desc = Object.getOwnPropertyDescriptor(row, field);
    if (desc === undefined) continue;
    if (!("value" in desc) || typeof desc.value !== "string") return undefined;
    out[field] = desc.value;
  }
  if (out.manifest_hash === undefined || out.status === undefined) return undefined;
  return out as unknown as RegistryRecord;
}

const REGISTRY_TIMED_OUT = Symbol("registry timed out");

async function checkRegistry(
  env: Envelope,
  lookup: RegistryLookup | undefined,
  timeoutMs: number,
): Promise<Outcome> {
  if (lookup === undefined) return skipped("no registry lookup was given");
  let answer: unknown;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    if (typeof lookup !== "function") return unavailable("the registry could not be reached");
    const deadline = new Promise<typeof REGISTRY_TIMED_OUT>((resolve) => {
      timer = setTimeout(() => resolve(REGISTRY_TIMED_OUT), timeoutMs);
    });
    answer = await Promise.race([
      Promise.resolve().then(() => lookup(env.manifest.trace_id)),
      deadline,
    ]);
  } catch {
    return unavailable("the registry could not be reached");
  } finally {
    clearTimeout(timer);
  }
  if (answer === REGISTRY_TIMED_OUT) return unavailable("the registry did not answer in time");
  if (answer === "offline") return unavailable("the registry could not be reached");
  if (answer === null) return fail("the registry has no record for this Trace ID");
  let row: RegistryRecord | undefined;
  try {
    row = readRegistryRow(answer);
  } catch {
    row = undefined;
  }
  if (!row) return unavailable("the registry answer was not valid");

  const evidence: CheckEvidence = { registry_hash: row.manifest_hash };
  if (row.manifest_hash !== env.manifest_hash)
    return fail("the registry holds a different hash for this Trace ID", evidence);
  const mismatched = (
    [
      ["trace_id", env.manifest.trace_id],
      ["key_id", env.signature.key_id],
      ["cluster", env.anchor.cluster],
      ["anchor_signature", env.anchor.tx_signature],
    ] as const
  )
    .filter(([field, expected]) => row[field] !== undefined && row[field] !== expected)
    .map(([field]) => field);
  if (mismatched.length > 0) {
    evidence.mismatched = mismatched;
    return fail("the registry row disagrees with the record", evidence);
  }
  if (row.status !== "active") {
    evidence.registry_status = /^[a-z_]{1,32}$/.test(row.status) ? row.status : "other";
    return fail("the registry does not mark this record active", evidence);
  }
  return pass("the registry holds this hash as an active record", evidence);
}

// ─── C6 Artifacts ────────────────────────────────────────────────────────────

async function checkArtifacts(env: Envelope, files: unknown): Promise<Outcome> {
  if (files === undefined) return skipped("no files were supplied");
  if (!Array.isArray(files)) return fail("the supplied files are not a list");
  if (files.length === 0) return skipped("no files were supplied");
  if (files.length > MAX_FILES) return fail("more files were supplied than a record can list");
  if (!hasWebCrypto()) return unavailable("this environment cannot compute SHA-256 (Web Crypto)");

  const artifacts = new Map(env.manifest.artifacts.map((a) => [a.name, a]));
  const seen = new Set<string>();
  const matched: string[] = [];
  const mismatched: string[] = [];
  let unknown = 0;
  let duplicates = 0;
  let malformed = 0;
  for (const file of files) {
    let name: unknown;
    let bytes: unknown;
    try {
      name = (file as VerifyFile).name;
      bytes = (file as VerifyFile).bytes;
    } catch {
      malformed += 1;
      continue;
    }
    if (typeof name !== "string" || !isUint8Array(bytes)) {
      malformed += 1;
      continue;
    }
    if (seen.has(name)) {
      duplicates += 1;
      continue;
    }
    seen.add(name);
    const artifact = artifacts.get(name);
    if (!artifact) {
      unknown += 1;
      continue;
    }
    const hash = await hashArtifact(bytes);
    if (hash === artifact.sha256 && bytes.byteLength === artifact.bytes) matched.push(name);
    else mismatched.push(name);
  }
  const notSupplied = env.manifest.artifacts.map((a) => a.name).filter((n) => !seen.has(n));
  const evidence: CheckEvidence = { matched, mismatched, not_supplied: notSupplied };
  if (unknown > 0) evidence.unknown_files = unknown;
  if (duplicates > 0) evidence.duplicate_files = duplicates;
  if (malformed > 0) evidence.malformed_files = malformed;

  if (mismatched.length > 0) return fail("a supplied file does not match the record", evidence);
  if (unknown > 0) return fail("a supplied file is not listed in the record", evidence);
  if (duplicates > 0) return fail("a file name was supplied more than once", evidence);
  if (malformed > 0) return fail("a supplied file could not be read", evidence);
  return pass("every supplied file matches the record", evidence);
}

// ─── C7 Observed claims, C8 Derived claims ───────────────────────────────────

/** Ids listed in evidence, at most this many per list (the full rows are in VerifyResult.rederive). */
const MAX_EVIDENCE_IDS = 50;

const C7_C8_TEXT = {
  priorFailure: "an earlier check failed, so the claims were not re-derived",
  turnedOff: "re-derivation was turned off, so the claims were not checked against the chain",
  incomplete: "the check could not be completed",
  observedPass: "every Observed claim reproduces",
  observedFail: "an Observed claim does not match the chain",
  derivedPass: "every Derived claim recomputes and reproduces",
  derivedFail: "a Derived claim does not match",
  noneRead: "could not check: no subject transaction was read",
} as const;

/** C7 (observed) or C8 (derived) from the re-derivation rows. */
function claimsOutcome(result: RederiveResult, type: "observed" | "derived"): Outcome {
  if (result.status === "invalid") return unavailable(C7_C8_TEXT.incomplete);
  const counts = result.counts.by_type[type];
  const mine = (c: ClaimCheck) => c.type === type;
  const ids = (rows: ClaimCheck[]) =>
    rows.flatMap((c) => (c.claim_id === undefined ? [] : [c.claim_id])).slice(0, MAX_EVIDENCE_IDS);
  const missing = result.claims.filter((c) => mine(c) && c.claim_id === undefined).length;
  const evidence: CheckEvidence = {
    [type]: counts.reproduced + counts.mismatch + counts.unavailable,
    reproduced: counts.reproduced,
    mismatch: counts.mismatch,
    unavailable: counts.unavailable,
    missing_from_record: missing,
    mismatched_claims: ids(result.claims.filter((c) => mine(c) && c.status === "mismatch")),
  };
  if (type === "observed") {
    const notChecked = result.claims.filter((c) => c.status === "not_checked");
    evidence.not_checked = result.counts.by_status.not_checked;
    evidence.not_checked_claims = ids(notChecked);
    evidence.not_checked_reason = "outside independent verification";
    evidence.transactions_read = result.transactions.filter((t) => t.status === "read").length;
    evidence.transactions_not_found = result.transactions.filter(
      (t) => t.status === "not_found",
    ).length;
    evidence.transactions_unavailable = result.transactions.filter(
      (t) => t.status === "unavailable",
    ).length;
  }
  if (result.warnings.length > 0) evidence.warnings = result.warnings.map((w) => w.detail);
  if (result.truncated) evidence.rows_truncated = true;

  // Every subject transaction decides, whether or not the record has claims in it: C7 and C8 pass
  // only when every subject transaction was read and compared.
  const notFound = result.transactions.filter((t) => t.status === "not_found");
  const unread = result.transactions.filter((t) => t.status === "unavailable");
  const read = result.transactions.filter((t) => t.status === "read").length;
  if (notFound.length > 0) {
    evidence.not_found_signatures = notFound.map((t) => t.signature).slice(0, MAX_EVIDENCE_IDS);
    const more = notFound.length > 1 ? ` and ${notFound.length - 1} more` : "";
    return fail(`${REDERIVE_TEXT.notFound}: ${notFound[0].signature}${more}`, evidence);
  }
  if (counts.mismatch > 0)
    return fail(type === "observed" ? C7_C8_TEXT.observedFail : C7_C8_TEXT.derivedFail, evidence);
  if (unread.length > 0) return unavailable(unavailableDetail(unread[0].reason ?? ""), evidence);
  if (counts.unavailable > 0) {
    const row = result.claims.find((c) => mine(c) && c.status === "unavailable");
    return unavailable(row?.detail ?? UNAVAILABLE_DETAIL, evidence);
  }
  if (read === 0) return unavailable(C7_C8_TEXT.noneRead, evidence);
  // A pass says what was compared, so it can never be read as a pass over nothing.
  const n = counts.reproduced;
  const compared = `${n} claim${n === 1 ? "" : "s"} compared with ${read} transaction${read === 1 ? "" : "s"} read again`;
  return pass(
    `${type === "observed" ? C7_C8_TEXT.observedPass : C7_C8_TEXT.derivedPass}: ${compared}`,
    evidence,
  );
}

// ─── Verdict ─────────────────────────────────────────────────────────────────

/**
 * does_not_match on any fail; verified only when C1-C4, C7 and C8 pass and C6 passed or had no files; else
 * unable_to_check.
 */
export function verdictOf(checks: readonly CheckResult[]): Verdict {
  if (checks.some((c) => c.status === "fail")) return "does_not_match";
  const status = (id: CheckId) => checks.find((c) => c.id === id)?.status;
  const required = (["C1", "C2", "C3", "C4", "C7", "C8"] as const).every(
    (id) => status(id) === "pass",
  );
  const artifacts = status("C6") === "pass" || status("C6") === "skipped";
  return required && artifacts ? "verified" : "unable_to_check";
}

function withIds(outcomes: Record<CheckId, Outcome>): CheckResult[] {
  return CHECK_IDS.map((id) => ({ id, name: CHECK_NAMES[id], ...outcomes[id] }));
}

/** The anchor's chain block time, only from a C4 that passed (an unconfirmed time is no time). */
function anchorTimeOf(c4: Outcome): number | undefined {
  const t = c4.evidence?.chain_block_time;
  return c4.status === "pass" && typeof t === "number" ? t : undefined;
}

/** Runs one check; a throw it did not anticipate becomes unavailable (never pass). */
async function guarded(run: () => Promise<Outcome>): Promise<Outcome> {
  try {
    return await run();
  } catch {
    return unavailable("the check could not be completed");
  }
}

// ─── Cluster of the RPC ────────────────────────────────

/** Never equal to a real cluster, so C4 and the re-derivation both read it as "a different cluster". */
const UNKNOWN_CLUSTER = "unknown-cluster" as ManifestCluster;

/** The cluster the rpc says it serves (createResilientRpc's `cluster`): undefined when it says none. */
function rpcClusterOf(rpc: unknown): ManifestCluster | undefined {
  let value: unknown;
  try {
    if ((typeof rpc !== "object" && typeof rpc !== "function") || rpc === null) return undefined;
    if (!("cluster" in rpc)) return undefined;
    value = (rpc as { cluster?: unknown }).cluster;
  } catch {
    return UNKNOWN_CLUSTER;
  }
  if (value === undefined) return undefined;
  return typeof value === "string" && (MANIFEST_CLUSTERS as readonly string[]).includes(value)
    ? (value as ManifestCluster)
    : UNKNOWN_CLUSTER;
}

/**
 * The cluster C4, C7 and C8 compare with the anchor's. A client for another cluster would answer "not found" and
 * read as tampering, so: the caller's option when the rpc states none; the rpc's when the caller gave none; and
 * when both are given and disagree, whichever is not the anchor's (one of them cannot be), so the checks are
 * unavailable for a different cluster, never fail.
 */
function effectiveCluster(
  option: ManifestCluster | undefined,
  rpc: unknown,
  anchorCluster: ManifestCluster,
): ManifestCluster | undefined {
  const served = rpcClusterOf(rpc);
  if (served === undefined) return option;
  if (option === undefined || option === served) return served;
  return served !== anchorCluster ? served : option;
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/**
 * Verifies a Trace Manifest envelope (checks C1 to C8). Never throws. See the header for the verdict rules.
 * The RPC and the registry lookup are injected; nothing here opens a connection of its own.
 */
export async function verifyEnvelope(
  envelope: unknown,
  options: VerifyOptions,
): Promise<VerifyResult> {
  try {
    // Each option is read once, inside a guard, so a hostile options object cannot throw past this point.
    let opts: Partial<VerifyOptions> = {};
    let optionsReadable = true;
    try {
      const o = options as VerifyOptions;
      opts = {
        rpc: o.rpc,
        issuerKeys: o.issuerKeys === undefined ? issuerKeysFile : o.issuerKeys,
        registryLookup: o.registryLookup,
        registryTimeoutMs: o.registryTimeoutMs,
        files: o.files,
        cluster: o.cluster,
        rawText: o.rawText,
        rederive: o.rederive,
      };
    } catch {
      optionsReadable = false;
    }

    const c1 = checkSchema(envelope, opts.rawText);
    if (c1.outcome.status !== "pass" || !c1.env) {
      const rest = skipped("schema invalid");
      const checks = withIds({
        C1: c1.outcome,
        C2: rest,
        C3: rest,
        C4: rest,
        C5: rest,
        C6: rest,
        C7: rest,
        C8: rest,
      });
      return { verdict: verdictOf(checks), checks };
    }
    if (!optionsReadable) {
      const u = unavailable("the verifier options could not be read");
      const checks = withIds({ C1: c1.outcome, C2: u, C3: u, C4: u, C5: u, C6: u, C7: u, C8: u });
      return { verdict: verdictOf(checks), checks };
    }
    const env = c1.env;
    const plainManifest = (c1.plain as { manifest: unknown }).manifest;

    const keys = pinnedKeys(opts.issuerKeys);
    const issuer = keys?.keys.find((k) => k.key_id === env.signature.key_id);
    // Records which endpoint answered each read of this verification; never throws.
    const sources = recordRpcSources(opts.rpc);
    const rpc = sources.rpc as VerifyOptions["rpc"];
    const cluster = effectiveCluster(opts.cluster, opts.rpc, env.anchor.cluster);

    const registryTimeoutMs =
      typeof opts.registryTimeoutMs === "number" &&
      Number.isSafeInteger(opts.registryTimeoutMs) &&
      opts.registryTimeoutMs > 0 &&
      opts.registryTimeoutMs <= MAX_TIMER_MS
        ? opts.registryTimeoutMs
        : DEFAULT_REGISTRY_TIMEOUT_MS;

    // C3 waits for C4: a retired key with a retired_at is judged against the anchor's chain time (M2).
    const c4Promise = guarded(() => checkAnchor(env, issuer, rpc, cluster));
    const c3Promise = c4Promise.then((c4) =>
      guarded(() => checkSignature(env, keys, anchorTimeOf(c4))),
    );
    const [c2, c3, c4, c5, c6] = await Promise.all([
      guarded(() => checkHash(plainManifest, env.manifest_hash)),
      c3Promise,
      c4Promise,
      guarded(() => checkRegistry(env, opts.registryLookup, registryTimeoutMs)),
      guarded(() => checkArtifacts(env, opts.files)),
    ]);

    // C7 and C8 last: a failure of C1 to C4 already decides the verdict, and then nothing more is fetched.
    let c7: Outcome;
    let c8: Outcome;
    let rederived: RederiveResult | undefined;
    if ([c2, c3, c4].some((o) => o.status === "fail")) {
      c7 = c8 = skipped(C7_C8_TEXT.priorFailure);
    } else if (opts.rederive === false) {
      c7 = c8 = skipped(C7_C8_TEXT.turnedOff);
    } else {
      try {
        rederived = await rederive(plainManifest, {
          rpc,
          ...(cluster !== undefined ? { cluster } : {}),
        });
        c7 = claimsOutcome(rederived, "observed");
        c8 = claimsOutcome(rederived, "derived");
      } catch {
        rederived = undefined;
        c7 = c8 = unavailable(C7_C8_TEXT.incomplete);
      }
    }
    const checks = withIds({
      C1: c1.outcome,
      C2: c2,
      C3: c3,
      C4: c4,
      C5: c5,
      C6: c6,
      C7: c7,
      C8: c8,
    });
    return {
      verdict: verdictOf(checks),
      checks,
      ...(rederived ? { rederive: rederived } : {}),
      ...(sources.active ? { rpc_endpoints: sources.used() } : {}),
    };
  } catch {
    const u = unavailable("the verifier hit an internal error");
    const checks = withIds({ C1: u, C2: u, C3: u, C4: u, C5: u, C6: u, C7: u, C8: u });
    return { verdict: "unable_to_check", checks };
  }
}
