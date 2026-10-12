// A minimal fetch-based, read-only Solana JSON-RPC client (getTransaction and getAccountInfo at finalized),
// and, at the end of the file, a resilient client over an ordered endpoint list.
//

// Contract, because the verifier turns these outcomes into different verdicts:
//   - A successful answer is returned only after its shape is proven. A 200 is not an answer by itself: a
//     body that is not JSON, a JSON-RPC error object, a reply to another request id, a result of the wrong
//     shape, or a transaction other than the one asked for is an RpcProtocolError.
//   - "The chain has no such transaction" (a null getTransaction result) is RpcNotFoundError, distinct from
//     every transport failure (RpcTimeoutError, RpcNetworkError, RpcHttpError, RpcProtocolError).
//   - Error messages are fixed text with a stable `code`. They never carry the endpoint URL (it may embed a
//     provider key), request headers, or upstream text (a pasted endpoint is attacker-controlled).
//   - createSolanaRpc does not retry: one call is one fetch. The timeout covers the whole call, body included,
//     and settles the call even if the fetch implementation ignores the abort signal.
//   - Redirects are refused (fetch redirect: "error"): a 3xx answer, or an answer a fetch reached by following
//     one anyway, is an RpcNetworkError. The endpoint the caller chose is the only one ever read.
//   - A bad url, timeoutMs (not 1 to 2^31-1 ms, the platform timer's range) or maxBodyBytes is refused at
//     construction with an RpcConfigError.
//   - The response body is capped (default 4 MiB) by its declared length and again while it is read.
//   - createResilientRpc puts an ordered endpoint list, one retry and a
//     session cache around createSolanaRpc, keeping every rule above. Its own rules are in its header.
import { z } from "zod";
import type { RawInstruction, RawTransaction } from "./account-keys.js";
import type { AccountInfoResponse } from "./owner-resolution.js";

export const DEFAULT_RPC_TIMEOUT_MS = 15_000;
export const DEFAULT_RPC_MAX_BODY_BYTES = 4 * 1024 * 1024;
/** setTimeout's largest delay; a larger one fires at once on every platform. */
export const MAX_RPC_TIMEOUT_MS = 2 ** 31 - 1;

// ─── Errors ──────────────────────────────────────────────────────────────────

export type RpcErrorCode =
  | "timeout"
  | "network"
  | "http"
  | "protocol"
  | "not_found"
  | "unconfirmed";

/** Base class of every error this client throws for a call. `code` is stable; `message` is fixed text. */
export class RpcError extends Error {
  readonly code: RpcErrorCode;
  constructor(code: RpcErrorCode, message: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

/**
 * A bad client configuration (url, timeoutMs, maxBodyBytes), thrown by createSolanaRpc. It extends TypeError,
 * which the url check threw before it existed, and never carries the value it refused.
 */
export class RpcConfigError extends TypeError {
  readonly code = "config";
  constructor(message: string) {
    super(message);
    this.name = "RpcConfigError";
  }
}

/** The call did not finish within the timeout. */
export class RpcTimeoutError extends RpcError {
  constructor() {
    super("timeout", "Solana RPC request timed out");
  }
}

/** fetch itself failed (offline, DNS, TLS, CORS), or the endpoint answered with a redirect. */
export class RpcNetworkError extends RpcError {
  constructor() {
    super("network", "Solana RPC endpoint could not be reached");
  }
}

/** The endpoint answered with a non-2xx HTTP status. Only the status number is kept. */
export class RpcHttpError extends RpcError {
  readonly status: number;
  constructor(status: number) {
    super("http", `Solana RPC endpoint answered HTTP ${status}`);
    this.status = status;
  }
}

export type RpcProtocolReason =
  | "body_too_large"
  | "not_utf8"
  | "not_json"
  | "bad_envelope"
  | "rpc_error"
  | "bad_result"
  | "wrong_transaction";

/** The endpoint answered, but not with a valid answer to this request. */
export class RpcProtocolError extends RpcError {
  readonly reason: RpcProtocolReason;
  /** The JSON-RPC error code when reason is rpc_error (a number, never the upstream message). */
  readonly rpcCode?: number;
  constructor(reason: RpcProtocolReason, rpcCode?: number) {
    super("protocol", `Solana RPC endpoint gave an invalid answer (${reason})`);
    this.reason = reason;
    if (rpcCode !== undefined) this.rpcCode = rpcCode;
  }
}

/** The endpoint answered successfully that the transaction does not exist (at finalized). */
export class RpcNotFoundError extends RpcError {
  /** Set by createResilientRpc: the endpoint whose answer was final (hostname only). */
  readonly source?: RpcSource;
  constructor(source?: RpcSource) {
    super("not_found", "transaction not found at finalized");
    if (source !== undefined) this.source = source;
  }
}

/**
 * createResilientRpc: an endpoint said "not found" but no second endpoint confirmed it (the cross-check partner
 * failed, or the endpoint was reached only because the ones before it failed). Not an answer: unavailable.
 */
export class RpcUnconfirmedNotFoundError extends RpcError {
  constructor() {
    super("unconfirmed", "not found was not confirmed by a second endpoint");
  }
}

// ─── Result shapes ───────────────────────────────────────────────────────────

const int = () => z.number().int().safe();
const nonNegInt = () => int().nonnegative();

const InstructionSchema = z
  .object({
    programIdIndex: nonNegInt(),
    accounts: z.array(nonNegInt()),
    data: z.string(),
    stackHeight: int().nullable().optional(),
  })
  .passthrough();

const TransactionResultSchema = z
  .object({
    slot: nonNegInt(),
    blockTime: int().nullable().optional(),
    version: z.union([z.literal("legacy"), nonNegInt()]).optional(),
    transaction: z
      .object({
        signatures: z.array(z.string()).min(1),
        message: z
          .object({
            header: z
              .object({
                numRequiredSignatures: nonNegInt(),
                numReadonlySignedAccounts: nonNegInt(),
                numReadonlyUnsignedAccounts: nonNegInt(),
              })
              .passthrough(),
            accountKeys: z.array(z.string()),
            instructions: z.array(InstructionSchema),
          })
          .passthrough(),
      })
      .passthrough(),
    meta: z
      .object({
        err: z.unknown(),
        innerInstructions: z
          .array(
            z
              .object({ index: nonNegInt(), instructions: z.array(InstructionSchema) })
              .passthrough(),
          )
          .nullable()
          .optional(),
        loadedAddresses: z
          .object({ writable: z.array(z.string()), readonly: z.array(z.string()) })
          .partial()
          .passthrough()
          .nullable()
          .optional(),
      })
      .passthrough()
      // The success flag must be stated, not implied by a missing field.
      .refine((m) => Object.prototype.hasOwnProperty.call(m, "err"), "meta.err is missing")
      .nullable(),
  })
  .passthrough();

/** A getTransaction result (encoding json) whose shape has been checked. Unchecked fields are kept as they came. */
export type RpcTransaction = RawTransaction & {
  slot: number;
  blockTime?: number | null;
  transaction: {
    signatures: string[];
    message: {
      header: {
        numRequiredSignatures: number;
        numReadonlySignedAccounts: number;
        numReadonlyUnsignedAccounts: number;
      };
      accountKeys: string[];
      instructions: RawInstruction[];
      [key: string]: unknown;
    };
  };
};

export type ParsedTransactionResult =
  | { ok: true; tx: RpcTransaction }
  | { ok: false; reason: "not_found" | "malformed" | "wrong_transaction" };

/**
 * Checks an untrusted getTransaction result. null is not_found; anything not shaped like a transaction is
 * malformed; a transaction whose first signature is not `signature` is wrong_transaction. Never throws.
 */
export function parseTransactionResult(
  result: unknown,
  signature: string,
): ParsedTransactionResult {
  if (result === null) return { ok: false, reason: "not_found" };
  let parsed: z.SafeParseReturnType<unknown, unknown>;
  try {
    parsed = TransactionResultSchema.safeParse(result);
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (!parsed.success) return { ok: false, reason: "malformed" };
  const tx = parsed.data as RpcTransaction;
  if (tx.transaction.signatures[0] !== signature) return { ok: false, reason: "wrong_transaction" };
  return { ok: true, tx };
}

const AccountInfoResultSchema = z
  .object({
    context: z.object({ slot: nonNegInt() }).passthrough(),
    value: z
      .object({ owner: z.string(), data: z.tuple([z.string(), z.literal("base64")]) })
      .passthrough()
      .nullable(),
  })
  .passthrough();

// ─── Client ──────────────────────────────────────────────────────────────────

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface SolanaRpcOptions {
  /** http or https endpoint. Never echoed in an error. */
  url: string;
  /** Injected in tests; defaults to the platform fetch, looked up at call time. */
  fetch?: FetchLike;
  /** Whole-call timeout in milliseconds. Default 15 000. */
  timeoutMs?: number;
  /** Largest response body accepted, in bytes. Default 4 MiB. */
  maxBodyBytes?: number;
}

export interface SolanaRpc {
  /** getTransaction at finalized, encoding json. Throws RpcNotFoundError when the chain has no such transaction. */
  getTransaction(signature: string): Promise<RpcTransaction>;
  /** getAccountInfo at finalized, encoding base64. value is null for an account that does not exist. */
  getAccountInfo(address: string): Promise<AccountInfoResponse>;
}

const SIGNATURE_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{64,88}$/;
const ADDRESS_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

function checkPositiveInteger(value: number, what: string, max = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > max)
    throw new RpcConfigError(`${what} must be a whole number from 1 to ${max}`);
  return value;
}

function checkUrl(url: unknown): string {
  let parsed: URL | undefined;
  try {
    parsed = typeof url === "string" ? new URL(url) : undefined;
  } catch {
    parsed = undefined;
  }
  if (!parsed || (parsed.protocol !== "https:" && parsed.protocol !== "http:"))
    throw new RpcConfigError("rpc url must be an http or https URL");
  return url as string;
}

async function readCappedBody(response: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    void response.body?.cancel().catch(() => {});
    throw new RpcProtocolError("body_too_large");
  }
  const reader = response.body?.getReader();
  if (!reader) {
    const whole = new Uint8Array(await response.arrayBuffer());
    if (whole.byteLength > maxBytes) throw new RpcProtocolError("body_too_large");
    return whole;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      void reader.cancel().catch(() => {});
      throw new RpcProtocolError("body_too_large");
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** A read-only client for one endpoint. Throws (synchronously) only for a bad url, timeoutMs or maxBodyBytes. */
export function createSolanaRpc(options: SolanaRpcOptions): SolanaRpc {
  const url = checkUrl(options.url);
  const timeoutMs = checkPositiveInteger(
    options.timeoutMs ?? DEFAULT_RPC_TIMEOUT_MS,
    "timeoutMs",
    MAX_RPC_TIMEOUT_MS,
  );
  const maxBodyBytes = checkPositiveInteger(
    options.maxBodyBytes ?? DEFAULT_RPC_MAX_BODY_BYTES,
    "maxBodyBytes",
  );
  const doFetch: FetchLike = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  let nextId = 1;

  async function attempt(method: string, params: unknown[], signal: AbortSignal): Promise<unknown> {
    const id = nextId++;
    let response: Response;
    try {
      response = await doFetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
        redirect: "error",
        signal,
      });
    } catch {
      if (signal.aborted) throw new RpcTimeoutError();
      throw new RpcNetworkError();
    }
    // A fetch that did not honour redirect: "error" either hands back the 3xx or follows it; both are refused.
    if (
      response.redirected ||
      response.type === "opaqueredirect" ||
      (response.status >= 300 && response.status < 400)
    ) {
      void response.body?.cancel().catch(() => {});
      throw new RpcNetworkError();
    }
    if (!response.ok) {
      void response.body?.cancel().catch(() => {});
      throw new RpcHttpError(response.status);
    }
    let bytes: Uint8Array;
    try {
      bytes = await readCappedBody(response, maxBodyBytes);
    } catch (e) {
      if (e instanceof RpcError) throw e;
      if (signal.aborted) throw new RpcTimeoutError();
      throw new RpcNetworkError();
    }
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new RpcProtocolError("not_utf8");
    }
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      throw new RpcProtocolError("not_json");
    }
    if (!isPlainObject(body) || body.jsonrpc !== "2.0" || body.id !== id)
      throw new RpcProtocolError("bad_envelope");
    if (Object.prototype.hasOwnProperty.call(body, "error")) {
      const code = isPlainObject(body.error) ? body.error.code : undefined;
      throw new RpcProtocolError(
        "rpc_error",
        typeof code === "number" && Number.isSafeInteger(code) ? code : undefined,
      );
    }
    if (!Object.prototype.hasOwnProperty.call(body, "result"))
      throw new RpcProtocolError("bad_envelope");
    return body.result;
  }

  async function call(method: string, params: unknown[]): Promise<unknown> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new RpcTimeoutError());
      }, timeoutMs);
    });
    try {
      return await Promise.race([attempt(method, params, controller.signal), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    async getTransaction(signature) {
      if (typeof signature !== "string" || !SIGNATURE_PATTERN.test(signature))
        throw new TypeError("signature must be base58 text of a transaction signature");
      const result = await call("getTransaction", [
        signature,
        { encoding: "json", commitment: "finalized", maxSupportedTransactionVersion: 0 },
      ]);
      const parsed = parseTransactionResult(result, signature);
      if (parsed.ok) return parsed.tx;
      if (parsed.reason === "not_found") throw new RpcNotFoundError();
      throw new RpcProtocolError(
        parsed.reason === "malformed" ? "bad_result" : "wrong_transaction",
      );
    },

    async getAccountInfo(address) {
      if (typeof address !== "string" || !ADDRESS_PATTERN.test(address))
        throw new TypeError("address must be base58 text of an account address");
      const result = await call("getAccountInfo", [
        address,
        { encoding: "base64", commitment: "finalized" },
      ]);
      const parsed = AccountInfoResultSchema.safeParse(result);
      if (!parsed.success) throw new RpcProtocolError("bad_result");
      return parsed.data as AccountInfoResponse;
    },
  };
}

// ─── Resilient client: an ordered endpoint list ──────────────────
//
// The rules, each of which keeps an outage or a lagging node from ever reading as tampering:
//   - Each endpoint gets one call (timeout 8 s by default, clamped to 60 s). On HTTP 429 or a network error
//     (offline, DNS, TLS, a browser's CORS refusal) it gets ONE retry after a backoff (500 ms plus up to half
//     that again as jitter); then the next endpoint is asked. A timeout (8 s already spent), any other HTTP
//     status (403 included), and an invalid answer (not JSON, a JSON-RPC error object, a result of the wrong
//     shape or about another transaction) go straight to the next endpoint: each is a failure of that endpoint,
//     never an answer.
//   - A transaction from any endpoint is final. "Not found" is final only when it is corroborated:
//       - from the FIRST endpoint, it is cross-checked once against the second. A transaction from the second
//         wins; "not found" from both is reported, naming the second; if the second cannot answer, the result is
//         RpcUnconfirmedNotFoundError ("not found was not confirmed by a second endpoint"), which the verifier
//         reads as unavailable.
//       - from a LATER endpoint, reached only because the ones before it failed (429, 403, CORS, timeout...),
//         nothing corroborates it: RpcUnconfirmedNotFoundError, unavailable. No further endpoint is asked.
//   - When every endpoint fails, the last endpoint's transport error is thrown: unavailable ("Unable to check"),
//     never "Does not match".
//   - getTransaction answers are cached in memory for the session, keyed by cluster and signature: a bounded LRU
//     (128 entries and 16 MiB of JSON text; the JavaScript heap they take is roughly three times that), copied in
//     and out, holding only answers that carry a transaction status (meta not null; every read is at
//     finalized). "Not found", failures and getAccountInfo answers (current state) are never cached. A cached
//     answer reports the endpoint it first came from, with from_cache true. Make one client per session and per
//     user endpoint: a cache shared across endpoint lists would answer for the other list's endpoints.
//
// Worst-case latency at the defaults, one read: an endpoint that answers 429 just before the 8 s timeout, then
// hangs on the retry, costs 8 + 0.5 + 0.249 (jitter) + 8 = 16.75 s. Two endpoints: 33.5 s; three: 50.2 s. One
// verification reads the anchor, then the subject transactions four at a time, so it takes at most about
// (1 + ceil(N_subject / 4)) times the per-read figure.

export const DEFAULT_RESILIENT_TIMEOUT_MS = 8_000;
/** The resilient client clamps its per-request timeout to this (one dead endpoint must not stall a page for long). */
export const MAX_RESILIENT_TIMEOUT_MS = 60_000;
export const DEFAULT_RETRY_BACKOFF_MS = 500;
export const MAX_RETRY_BACKOFF_MS = 5_000;
export const DEFAULT_TX_CACHE_ENTRIES = 128;
/** Of JSON text. The heap the cached objects take is roughly three times this. */
export const DEFAULT_TX_CACHE_BYTES = 16 * 1024 * 1024;
const MAX_USER_ENDPOINT_LENGTH = 2048;

export type SolanaCluster = "mainnet-beta" | "devnet" | "testnet";

/**
 * The default endpoints per cluster: one public endpoint each.
 */
export const RPC_ENDPOINTS: Readonly<Record<SolanaCluster, readonly string[]>> = Object.freeze({
  "mainnet-beta": Object.freeze(["https://api.mainnet-beta.solana.com"]),
  devnet: Object.freeze(["https://api.devnet.solana.com"]),
  testnet: Object.freeze(["https://api.testnet.solana.com"]),
});

/** Which endpoint gave an answer: its host only. */
export interface RpcSource {
  /** The hostname, with ":port" when the port is not the scheme's default. Never a path or query. */
  hostname: string;
  /** The user pasted this endpoint: the page should say the user chose the source. */
  user_supplied: boolean;
  /** Served from this session's cache; hostname is where it first came from. */
  from_cache: boolean;
}

export interface SourcedTransaction {
  tx: RpcTransaction;
  source: RpcSource;
}

function checkCluster(cluster: unknown): SolanaCluster {
  if (typeof cluster !== "string" || !Object.prototype.hasOwnProperty.call(RPC_ENDPOINTS, cluster))
    throw new RpcConfigError("unknown Solana cluster");
  return cluster as SolanaCluster;
}

/** The http(s) origin of `origin`, or undefined (no origin, "null", a file: page). */
function webOrigin(origin: unknown): string | undefined {
  if (typeof origin !== "string") return undefined;
  try {
    const u = new URL(origin);
    return u.protocol === "https:" || u.protocol === "http:" ? u.origin : undefined;
  } catch {
    return undefined;
  }
}

export function defaultRpcEndpoints(cluster: SolanaCluster, origin?: string): string[] {
  const base = webOrigin(origin);
  return RPC_ENDPOINTS[checkCluster(cluster)].flatMap((u) =>
    u.startsWith("/") ? (base ? [new URL(u, base).href] : []) : [u],
  );
}

const BAD_USER_ENDPOINT = "the RPC endpoint must be an https URL";

/**
 * A host as the URL parser normalises it and as the page may show it: a DNS name of [a-z0-9-] labels (1 to 63
 * characters each, at most 253 in all, no empty label, so no trailing dot) or a bracketed IPv6 literal, with an
 * optional ":port" (1 to 65535). Anything else (underscore, "*", "!", "x..com") is not clean.
 */
export function isCleanHost(host: unknown): boolean {
  if (typeof host !== "string" || host.length > 300) return false;
  const m = /^(\[[0-9a-f:.]{2,45}\]|[a-z0-9.-]{1,253})(?::([1-9][0-9]{0,4}))?$/.exec(host);
  if (!m) return false;
  if (m[2] !== undefined && Number(m[2]) > 65535) return false;
  return m[1].startsWith("[") || m[1].split(".").every((l) => l.length >= 1 && l.length <= 63);
}

/**
 * Validates an endpoint a user pasted: https only, no credentials in the URL, a clean hostname (isCleanHost, so
 * the page can always show it), at most 2048 characters. Returns the normalised URL (it may hold the user's own
 * key: never display it, show its host). Throws an RpcConfigError (a TypeError) with fixed text that never
 * echoes the input.
 */
export function checkUserEndpoint(url: unknown): string {
  if (typeof url !== "string" || url.length > MAX_USER_ENDPOINT_LENGTH)
    throw new RpcConfigError(BAD_USER_ENDPOINT);
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new RpcConfigError(BAD_USER_ENDPOINT);
  }
  if (u.protocol !== "https:" || u.username !== "" || u.password !== "" || !isCleanHost(u.hostname))
    throw new RpcConfigError(BAD_USER_ENDPOINT);
  return u.href;
}

// ─── Session cache ───────────────────────────────────────────────────────────

export interface CachedTransaction {
  tx: RpcTransaction;
  hostname: string;
  user_supplied: boolean;
}

export interface TransactionCache {
  /** A copy of the cached answer, or undefined. */
  get(cluster: SolanaCluster, signature: string): CachedTransaction | undefined;
  /** Stores a copy. An answer larger than the whole byte budget is not kept. */
  set(cluster: SolanaCluster, signature: string, entry: CachedTransaction): void;
  readonly size: number;
}

/** A bounded LRU of getTransaction answers, by cluster and signature. */
export function createTransactionCache(
  options: { maxEntries?: number; maxBytes?: number } = {},
): TransactionCache {
  const maxEntries = checkPositiveInteger(
    options.maxEntries ?? DEFAULT_TX_CACHE_ENTRIES,
    "maxEntries",
  );
  const maxBytes = checkPositiveInteger(options.maxBytes ?? DEFAULT_TX_CACHE_BYTES, "maxBytes");
  const entries = new Map<string, { entry: CachedTransaction; bytes: number }>();
  let total = 0;
  const keyOf = (cluster: string, signature: string) => `${cluster}\u0000${signature}`;
  const drop = (key: string) => {
    const old = entries.get(key);
    if (!old) return;
    entries.delete(key);
    total -= old.bytes;
  };
  return {
    get(cluster, signature) {
      const key = keyOf(cluster, signature);
      const hit = entries.get(key);
      if (!hit) return undefined;
      entries.delete(key);
      entries.set(key, hit);
      return { ...hit.entry, tx: structuredClone(hit.entry.tx) };
    },
    set(cluster, signature, entry) {
      let copy: RpcTransaction;
      let bytes: number;
      try {
        bytes = JSON.stringify(entry.tx).length;
        copy = structuredClone(entry.tx);
      } catch {
        return;
      }
      const key = keyOf(cluster, signature);
      drop(key);
      if (bytes > maxBytes) return;
      entries.set(key, {
        entry: { tx: copy, hostname: entry.hostname, user_supplied: entry.user_supplied },
        bytes,
      });
      total += bytes;
      while (entries.size > maxEntries || total > maxBytes)
        drop(entries.keys().next().value as string);
    },
    get size() {
      return entries.size;
    },
  };
}

// ─── The client ──────────────────────────────────────────────────────────────

export interface ResilientRpcOptions {
  cluster: SolanaCluster;
  /** Absolute http(s) endpoints in order. Default: RPC_ENDPOINTS for the cluster, resolved against `origin`. */
  endpoints?: readonly string[];
  origin?: string;
  /** An endpoint the user pasted (https only). It is asked first and flagged user_supplied. */
  userEndpoint?: string;
  fetch?: FetchLike;
  /** Per-request timeout in milliseconds. Default 8 000, clamped to 60 000. */
  timeoutMs?: number;
  maxBodyBytes?: number;
  /** Wait before the one retry, in milliseconds. Default 500, clamped to 5 000. */
  backoffMs?: number;
  /** Add up to half the backoff at random (default true; tests turn it off). */
  jitter?: boolean;
  /** Injected in tests. */
  sleep?: (ms: number) => Promise<void>;
  /** Default: a new cache for this client. */
  cache?: TransactionCache;
}

export interface ResilientSolanaRpc extends SolanaRpc {
  readonly cluster: SolanaCluster;
  /** getTransaction, with the endpoint that answered. RpcNotFoundError carries the endpoint as `source`. */
  getTransactionWithSource(signature: string): Promise<SourcedTransaction>;
}

interface Endpoint {
  client: SolanaRpc;
  hostname: string;
  user_supplied: boolean;
}

const pageOrigin = (): string | undefined => {
  try {
    return (globalThis as { location?: { origin?: string } }).location?.origin;
  } catch {
    return undefined;
  }
};

const isRetryable = (e: unknown): boolean =>
  e instanceof RpcNetworkError || (e instanceof RpcHttpError && e.status === 429);

const typed = (e: unknown): RpcError => (e instanceof RpcError ? e : new RpcNetworkError());

/**
 * A fraction in [0, 1) for retry jitter, from Web Crypto (this directory bans Math.random so that no answer can
 * ever depend on it; jitter changes only how long a retry waits). 0, no jitter, where Web Crypto is missing.
 */
const jitterFraction = (): number => {
  try {
    const out: unknown = globalThis.crypto.getRandomValues(new Uint32Array(1));
    const v = (out as ArrayLike<unknown> | null | undefined)?.[0];
    const f = typeof v === "number" ? v / 2 ** 32 : Number.NaN;
    // An empty or odd answer is no jitter, never a NaN wait.
    return Number.isFinite(f) && f >= 0 && f < 1 ? f : 0;
  } catch {
    return 0;
  }
};

const sourceOf = (endpoint: Endpoint, fromCache: boolean): RpcSource => ({
  hostname: endpoint.hostname,
  user_supplied: endpoint.user_supplied,
  from_cache: fromCache,
});

/**
 * A read-only client over an ordered endpoint list (see the section header for every rule). Throws
 * (synchronously) only for a bad cluster, endpoint or setting: an RpcConfigError with fixed text.
 */
export function createResilientRpc(options: ResilientRpcOptions): ResilientSolanaRpc {
  const cluster = checkCluster(options.cluster);
  const timeoutMs = Math.min(
    checkPositiveInteger(options.timeoutMs ?? DEFAULT_RESILIENT_TIMEOUT_MS, "timeoutMs"),
    MAX_RESILIENT_TIMEOUT_MS,
  );
  const backoffRaw = options.backoffMs ?? DEFAULT_RETRY_BACKOFF_MS;
  if (!Number.isSafeInteger(backoffRaw) || backoffRaw < 0)
    throw new RpcConfigError("backoffMs must be a whole number of milliseconds");
  const backoffMs = Math.min(backoffRaw, MAX_RETRY_BACKOFF_MS);
  const jitter = options.jitter !== false;
  const sleep =
    options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const cache = options.cache ?? createTransactionCache();

  const urls: { href: string; user: boolean }[] = [];
  if (options.userEndpoint !== undefined)
    urls.push({ href: checkUserEndpoint(options.userEndpoint), user: true });
  const configured =
    options.endpoints ?? defaultRpcEndpoints(cluster, options.origin ?? pageOrigin());
  for (const url of configured) {
    const href = new URL(checkUrl(url)).href;
    if (!urls.some((u) => u.href === href)) urls.push({ href, user: false });
  }
  if (urls.length === 0)
    throw new RpcConfigError("the RPC endpoint list needs at least one endpoint");
  const endpoints: Endpoint[] = urls.map(({ href, user }) => ({
    client: createSolanaRpc({
      url: href,
      fetch: options.fetch,
      timeoutMs,
      maxBodyBytes: options.maxBodyBytes,
    }),
    // host: the hostname, with the port only when it is not the scheme's default.
    hostname: new URL(href).host,
    user_supplied: user,
  }));

  const wait = () => backoffMs + (jitter ? Math.floor((jitterFraction() * backoffMs) / 2) : 0);

  /** One endpoint: one call, and one retry after a backoff on 429 or a network error. */
  async function ask<T>(endpoint: Endpoint, op: (c: SolanaRpc) => Promise<T>): Promise<T> {
    try {
      return await op(endpoint.client);
    } catch (e) {
      if (!isRetryable(e)) throw e;
    }
    try {
      await sleep(wait());
    } catch {
      // A failed wait is still a wait: retry anyway.
    }
    return op(endpoint.client);
  }

  /** The endpoints in order, until one gives a definite answer (see the header for the not-found rule). */
  async function run<T>(
    op: (c: SolanaRpc) => Promise<T>,
  ): Promise<{ value: T; endpoint: Endpoint }> {
    let last: RpcError = new RpcNetworkError();
    for (let i = 0; i < endpoints.length; i++) {
      let failure: unknown;
      try {
        return { value: await ask(endpoints[i], op), endpoint: endpoints[i] };
      } catch (e) {
        failure = e;
      }
      if (failure instanceof RpcNotFoundError) {
        // A single endpoint has nothing to cross-check: its "not found" is definite.
        if (endpoints.length === 1) throw new RpcNotFoundError(sourceOf(endpoints[0], false));
        // Reached only because the endpoints before it failed: nothing corroborates it.
        if (i !== 0) throw new RpcUnconfirmedNotFoundError();
        const second = endpoints[1];
        try {
          return { value: await ask(second, op), endpoint: second };
        } catch (e) {
          if (e instanceof RpcNotFoundError) throw new RpcNotFoundError(sourceOf(second, false));
          throw new RpcUnconfirmedNotFoundError();
        }
      }
      last = typed(failure);
    }
    throw last;
  }

  async function getTransactionWithSource(signature: string): Promise<SourcedTransaction> {
    if (typeof signature !== "string" || !SIGNATURE_PATTERN.test(signature))
      throw new TypeError("signature must be base58 text of a transaction signature");
    const hit = cache.get(cluster, signature);
    if (hit)
      return {
        tx: hit.tx,
        source: { hostname: hit.hostname, user_supplied: hit.user_supplied, from_cache: true },
      };
    const { value: tx, endpoint } = await run((c) => c.getTransaction(signature));
    if (tx.meta !== null)
      cache.set(cluster, signature, {
        tx,
        hostname: endpoint.hostname,
        user_supplied: endpoint.user_supplied,
      });
    return { tx, source: sourceOf(endpoint, false) };
  }

  return {
    cluster,
    getTransactionWithSource,
    async getTransaction(signature) {
      return (await getTransactionWithSource(signature)).tx;
    },
    async getAccountInfo(address) {
      if (typeof address !== "string" || !ADDRESS_PATTERN.test(address))
        throw new TypeError("address must be base58 text of an account address");
      return (await run((c) => c.getAccountInfo(address))).value;
    },
  };
}
