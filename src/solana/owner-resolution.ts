// Token account owner resolution. A token account is not a wallet: the address that holds the
// tokens and the address that owns the account are different, and a manifest that names flows by owner has
// to say how it knows each owner. resolveOwner tries five ordered methods, strongest evidence first, and
// every result names the method that produced it so the normaliser can pick the claim code and claim type
// from the signed rules table (see OWNER_METHOD_CLAIM_CODE):
//   1 tx_meta          the owner the node recorded in meta.preTokenBalances / postTokenBalances
//   2 tx_instruction   an InitializeAccount, InitializeAccount2 or InitializeAccount3 decoded in the same transaction
//   3 ata_derivation   the account is exactly the associated token address of a signer or known owner
//   4 current_state    getAccountInfo now (a later state, not the state at the transaction's slot)
//   5 unresolved       none of the above, with the reason each one gave
// Methods 1 to 3 read only the transaction in hand and make no network call; only method 4 touches ctx.rpc,
// and only when the earlier methods found nothing. Evidence that disagrees (the owner before and after, two
// different initialisations) is never settled by picking a side: the result is unresolved and says so.
// Pure apart from the injected rpc and cache clock; isomorphic: no Node-only imports.
import { resolveAccountKeys, type RawTransaction } from "./account-keys.js";
import { deriveAssociatedTokenAddress } from "./ata.js";
import { decodeBase58 } from "./base58.js";
import { encodeBase58 } from "./base58-encode.js";
import type { DecodeResult } from "./decoders/index.js";
import { PROGRAM_IDS } from "./programs.js";

// ─── Result ──────────────────────────────────────────────────────────────────

export type OwnerMethod =
  | "tx_meta"
  | "tx_instruction"
  | "ata_derivation"
  | "current_state"
  | "unresolved";

export interface OwnerResolution {
  /** Base58 owner address, or null when unresolved. */
  owner: string | null;
  method: OwnerMethod;
  /** Why the result is unresolved. Plain text, never a raw error object. */
  reason?: string;
  /** current_state only: the slot of the getAccountInfo response. */
  slot?: number;
  /** Set when the evidence is weaker than the method name suggests. */
  caveat?: string;
}

/**
 * The statement code each resolving method is reported under. The codes and their claim types are the
 * signed rules in src/manifest/claim-rules.ts (OWNER_FROM_TX_META and OWNER_FROM_TX_INSTRUCTION are
 * observed, OWNER_FROM_ATA_DERIVATION derived, OWNER_CURRENT_STATE attributed). A test pins this map to
 * that table so a rename on either side cannot drift. unresolved produces no claim.
 */
export const OWNER_METHOD_CLAIM_CODE: Readonly<Record<Exclude<OwnerMethod, "unresolved">, string>> =
  Object.freeze({
    tx_meta: "OWNER_FROM_TX_META",
    tx_instruction: "OWNER_FROM_TX_INSTRUCTION",
    ata_derivation: "OWNER_FROM_ATA_DERIVATION",
    current_state: "OWNER_CURRENT_STATE",
  });

export const RPC_TIMEOUT_ERROR_NAME = "RpcDeadlineExceeded";

export const CURRENT_STATE_CAVEAT = "current state, not state at transaction slot";

// ─── Cache ───────────────────────────────────────────────────────────────────

/** How long a current_state answer is reused. Methods 1 to 3 never expire: they depend only on the transaction. */
export const CURRENT_STATE_TTL_MS = 60_000;

export interface OwnerCache {
  get(key: string): OwnerResolution | undefined;
  /** ttlMs omitted means the entry does not expire. */
  set(key: string, value: OwnerResolution, ttlMs?: number): void;
  readonly size: number;
}

/**
 * Least-recently-used cache of resolved owners, bounded to maxEntries. Reading an entry makes it the newest;
 * adding one past the bound drops the oldest. An entry with a ttl is dropped when the injected clock passes
 * it. Values are copied on the way in and out, so a caller cannot change what later callers receive.
 */
export function createOwnerCache(
  options: { maxEntries?: number; now?: () => number } = {},
): OwnerCache {
  const maxEntries = options.maxEntries ?? 1024;
  const now = options.now ?? Date.now;
  if (!Number.isInteger(maxEntries) || maxEntries < 1)
    throw new RangeError("maxEntries must be a positive integer");
  const entries = new Map<string, { value: OwnerResolution; expiresAt: number | null }>();
  return {
    get(key) {
      const entry = entries.get(key);
      if (!entry) return undefined;
      if (entry.expiresAt !== null && now() >= entry.expiresAt) {
        entries.delete(key);
        return undefined;
      }
      entries.delete(key);
      entries.set(key, entry);
      return { ...entry.value };
    },
    set(key, value, ttlMs) {
      entries.delete(key);
      entries.set(key, {
        value: { ...value },
        expiresAt: ttlMs === undefined ? null : now() + ttlMs,
      });
      while (entries.size > maxEntries) entries.delete(entries.keys().next().value as string);
    },
    get size() {
      return entries.size;
    },
  };
}

// ─── Inputs ──────────────────────────────────────────────────────────────────

interface TokenBalance {
  accountIndex: number;
  mint?: string;
  /** Absent in transactions from older nodes. */
  owner?: string;
}

/** A raw getTransaction result (encoding json) with the fields owner resolution reads. */
export type OwnerTransaction = RawTransaction & {
  transaction: {
    signatures: string[];
    message: { header: { numRequiredSignatures: number } };
  };
  meta: {
    preTokenBalances?: TokenBalance[] | null;
    postTokenBalances?: TokenBalance[] | null;
  } | null;
};

/** The result of the JSON-RPC getAccountInfo call (encoding base64). Treated as untrusted. */
export interface AccountInfoResponse {
  context: { slot: number };
  value: { owner: string; data: [string, "base64"] } | null;
}

export interface OwnerRpc {
  getAccountInfo(address: string): Promise<AccountInfoResponse>;
}

export interface OwnerResolutionContext {
  tx: OwnerTransaction;
  /** decodeTransaction output for the same transaction. */
  decoded: readonly DecodeResult[];
  /** Only method 4 uses it. Without it, method 4 is skipped. */
  rpc?: OwnerRpc;
  /** Without it nothing is cached. */
  cache?: OwnerCache;
}

// ─── SPL token account unpacker ──────────────────────────────────────────────

const TOKEN_ACCOUNT_LENGTH = 165;
const OWNER_OFFSET = 32;
const STATE_OFFSET = 108;
const ACCOUNT_TYPE_OFFSET = 165;
const ACCOUNT_TYPE_ACCOUNT = 2;
const MULTISIG_LENGTH = 355;

export type UnpackedTokenAccount = { ok: true; owner: string } | { ok: false; reason: string };

/**
 * Reads the owner (bytes 32 to 64) of an SPL Token or Token-2022 token account (solana-program/token
 * interface state.rs Account: mint 0..32, owner 32..64, amount 64..72, ..., state at 108). Length alone does
 * not make bytes 32 to 64 an owner: a Token-2022 mint with extensions and a multisig are also 165 bytes or
 * longer, and their bytes there mean something else. So the layout is checked first:
 *   SPL Token    exactly 165 bytes (the program has no extensions; a mint is 82, a multisig 355)
 *   Token-2022   165 bytes, or longer with the account-type byte at offset 165 equal to 2 (Account), and not
 *                the 355-byte multisig size
 * and the state byte must be 1 (initialised) or 2 (frozen): 0 is uninitialised and has no owner yet, and
 * anything above 2 is not a token account state.
 */
export function unpackTokenAccountOwner(data: Uint8Array, programId: string): UnpackedTokenAccount {
  if (programId !== PROGRAM_IDS.splToken && programId !== PROGRAM_IDS.token2022)
    return { ok: false, reason: "account is not owned by SPL Token or Token-2022" };
  if (data.length < TOKEN_ACCOUNT_LENGTH)
    return {
      ok: false,
      reason: `account data is ${data.length} bytes, shorter than a token account`,
    };
  if (programId === PROGRAM_IDS.splToken) {
    if (data.length !== TOKEN_ACCOUNT_LENGTH)
      return { ok: false, reason: `account data is ${data.length} bytes, not a token account` };
  } else if (data.length > TOKEN_ACCOUNT_LENGTH) {
    if (data.length === MULTISIG_LENGTH || data[ACCOUNT_TYPE_OFFSET] !== ACCOUNT_TYPE_ACCOUNT)
      return { ok: false, reason: "account data is not a Token-2022 token account" };
  }
  const state = data[STATE_OFFSET];
  if (state === 0) return { ok: false, reason: "token account is not initialised" };
  if (state !== 1 && state !== 2)
    return { ok: false, reason: "token account has an invalid state byte" };
  return { ok: true, owner: encodeBase58(data.subarray(OWNER_OFFSET, OWNER_OFFSET + 32)) };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const TOKEN_PROGRAMS = [PROGRAM_IDS.splToken, PROGRAM_IDS.token2022] as const;

/** True for base58 text that decodes to exactly 32 bytes. Total: never throws. */
function isAddress(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 32 || value.length > 44) return false;
  try {
    return decodeBase58(value).length === 32;
  } catch {
    return false;
  }
}

/**
 * Only the error's class name, and only when it is a plain identifier. The message is never used: it can
 * carry an RPC URL, a host and path, a header or a key in a shape no filter can list, and matching it
 * against patterns is slow on a hostile message. Anything else (no name, a long or odd name, a throwing
 * getter, a value that is not an Error) is reported as "Error".
 */
function errorClass(e: unknown): string {
  try {
    const name = e instanceof Error ? e.name : undefined;
    if (typeof name === "string" && /^[A-Za-z][A-Za-z0-9]{0,39}$/.test(name)) return name;
  } catch {
    // fall through to the fixed name
  }
  return "Error";
}

function unresolved(reason: string): OwnerResolution {
  return { owner: null, method: "unresolved", reason };
}

/** A method either found the owner, found conflicting evidence (final), or found nothing (try the next). */
type Attempt =
  | { kind: "found"; result: OwnerResolution }
  | { kind: "conflict"; reason: string }
  | { kind: "none"; reason: string };

function asList<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function balancesOf(tx: OwnerTransaction): TokenBalance[] {
  return [
    ...asList<TokenBalance>(tx.meta?.preTokenBalances),
    ...asList<TokenBalance>(tx.meta?.postTokenBalances),
  ];
}

/** Decoded, successful SPL Token / Token-2022 instructions, with their fields. */
function tokenInstructions(decoded: readonly DecodeResult[]) {
  const out: { kind: string; fields: Record<string, unknown> }[] = [];
  for (const r of asList<DecodeResult>(decoded)) {
    if (
      !r ||
      r.decode_status !== "decoded" ||
      r.failed ||
      (r.program_id !== PROGRAM_IDS.splToken && r.program_id !== PROGRAM_IDS.token2022)
    )
      continue;
    out.push({ kind: r.kind, fields: r.fields });
  }
  return out;
}

// ─── Method 1: transaction metadata ─────────────────────────────────────────

function fromTxMeta(index: number, tx: OwnerTransaction): Attempt {
  const owners = new Set<string>();
  for (const b of balancesOf(tx))
    if (b && b.accountIndex === index && isAddress(b.owner)) owners.add(b.owner);
  if (owners.size === 1)
    return { kind: "found", result: { owner: [...owners][0], method: "tx_meta" } };
  if (owners.size > 1)
    return {
      kind: "conflict",
      reason: "transaction metadata names different owners before and after the transaction",
    };
  return { kind: "none", reason: "no owner in the transaction's token balances" };
}

// ─── Method 2: in-transaction instruction ───────────────────────────────────

const INITIALISE_KINDS = new Set([
  "token_initialize_account",
  "token_initialize_account2",
  "token_initialize_account3",
]);

const OWNER_NEUTRAL_UNDECODED_TAGS = new Set([4, 5, 10, 11, 13, 22]);

/** True when a successful token instruction on the account was not decoded and may have changed its owner. */
function hasUndecodedTokenInstruction(account: string, decoded: readonly DecodeResult[]): boolean {
  for (const r of asList<DecodeResult>(decoded)) {
    if (!r || r.failed || r.decode_status === "decoded") continue;
    if (r.program_id !== PROGRAM_IDS.splToken && r.program_id !== PROGRAM_IDS.token2022) continue;
    if (!Array.isArray(r.accounts) || !r.accounts.includes(account)) continue;
    const tag = typeof r.data === "string" ? Number.parseInt(r.data.slice(0, 2), 16) : Number.NaN;
    if (!OWNER_NEUTRAL_UNDECODED_TAGS.has(tag)) return true;
  }
  return false;
}

/**
 *   - A CloseAccount authority is the owner only unless a separate close authority was set, and no signed
 *     claim code covers that weaker evidence, so it is reported in the reason ("close authority seen, owner
 *     not proven") and never as an owner. The close destination, which only receives the lamports, is not
 *     used at all.
 *   - If any other successful token instruction on the account was not decoded (SetAuthority is the one that
 *     matters), the initialised owner may no longer be the owner, so no owner is returned and the chain goes
 *     on to the next method.
 *   - Instructions of a failed transaction did not take effect and are ignored.
 */
function fromInstructions(account: string, decoded: readonly DecodeResult[]): Attempt {
  const initialised = new Set<string>();
  const closers = new Set<string>();
  for (const { kind, fields } of tokenInstructions(decoded)) {
    if (fields.account !== account) continue;
    if (INITIALISE_KINDS.has(kind) && isAddress(fields.owner)) initialised.add(fields.owner);
    else if (kind === "token_close_account" && isAddress(fields.authority))
      closers.add(fields.authority);
  }
  if (initialised.size > 0) {
    if (hasUndecodedTokenInstruction(account, decoded))
      return {
        kind: "none",
        reason: "a token instruction on the account was not decoded, so its owner may have changed",
      };
    if (initialised.size === 1)
      return { kind: "found", result: { owner: [...initialised][0], method: "tx_instruction" } };
    return {
      kind: "conflict",
      reason: "the transaction initialises the account with different owners",
    };
  }
  if (closers.size > 0)
    return {
      kind: "none",
      reason: `close authority seen, owner not proven (candidate ${[...closers].join(", ")})`,
    };
  return {
    kind: "none",
    reason: "no initialise instruction for the account in the transaction",
  };
}

// ─── Method 3: associated token address derivation ──────────────────────────

/** Mints the transaction says the account holds: from token balances and from decoded token instructions. */
function mintCandidates(
  index: number,
  account: string,
  tx: OwnerTransaction,
  decoded: readonly DecodeResult[],
): string[] {
  const mints = new Set<string>();
  for (const b of balancesOf(tx))
    if (b && b.accountIndex === index && isAddress(b.mint)) mints.add(b.mint);
  // Every decoded instruction that names a mint names it for the token accounts listed beside it.
  for (const { fields } of tokenInstructions(decoded))
    if (
      isAddress(fields.mint) &&
      (fields.account === account || fields.source === account || fields.destination === account)
    )
      mints.add(fields.mint);
  return [...mints];
}

/** The signers first, then every owner the transaction itself names. Order is fixed so the result is repeatable. */
function ownerCandidates(
  keys: string[],
  tx: OwnerTransaction,
  decoded: readonly DecodeResult[],
): string[] {
  const owners = new Set<string>();
  const signerCount = tx.transaction.message.header?.numRequiredSignatures;
  if (Number.isInteger(signerCount))
    for (const key of keys.slice(0, signerCount)) if (isAddress(key)) owners.add(key);
  for (const b of balancesOf(tx)) if (b && isAddress(b.owner)) owners.add(b.owner);
  for (const { kind, fields } of tokenInstructions(decoded))
    if (INITIALISE_KINDS.has(kind) && isAddress(fields.owner)) owners.add(fields.owner);
  return [...owners];
}

function fromAtaDerivation(
  index: number,
  account: string,
  keys: string[],
  tx: OwnerTransaction,
  decoded: readonly DecodeResult[],
): Attempt {
  // Same rule as method 2: an address derived for an owner says nothing about who owns it now if a
  // successful token instruction that may have changed the owner (SetAuthority) was not decoded.
  if (hasUndecodedTokenInstruction(account, decoded))
    return {
      kind: "none",
      reason: "a token instruction on the account was not decoded, so its owner may have changed",
    };
  const mints = mintCandidates(index, account, tx, decoded);
  if (mints.length === 0)
    return { kind: "none", reason: "the transaction does not say which mint the account holds" };
  for (const owner of ownerCandidates(keys, tx, decoded))
    for (const mint of mints)
      for (const program of TOKEN_PROGRAMS)
        if (deriveAssociatedTokenAddress(owner, mint, program) === account)
          return { kind: "found", result: { owner, method: "ata_derivation" } };
  return {
    kind: "none",
    reason: "the account is not the associated token address of any signer or known owner",
  };
}

// ─── Method 4: current state ────────────────────────────────────────────────

function decodeBase64(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return undefined;
  try {
    return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
  } catch {
    return undefined;
  }
}

async function fromCurrentState(
  account: string,
  rpc: OwnerRpc | undefined,
  knownMints: readonly string[],
): Promise<Attempt> {
  if (!rpc) return { kind: "none", reason: "no rpc supplied for a current-state lookup" };
  let response: AccountInfoResponse;
  try {
    response = await rpc.getAccountInfo(account);
  } catch (e) {
    // The caller's deadline (see RPC_TIMEOUT_ERROR_NAME): a fixed text, nothing from the error.
    if (errorClass(e) === RPC_TIMEOUT_ERROR_NAME)
      return { kind: "none", reason: "current-state lookup timed out" };
    return { kind: "none", reason: `current-state lookup failed (${errorClass(e)})` };
  }
  const slot = response?.context?.slot;
  if (typeof slot !== "number" || !Number.isSafeInteger(slot) || slot < 0)
    return { kind: "none", reason: "current-state lookup returned no valid slot" };
  const value = response.value;
  if (value === null) return { kind: "none", reason: "the account does not exist now" };
  const encoded =
    Array.isArray(value?.data) && value.data[1] === "base64" ? value.data[0] : undefined;
  const data = typeof encoded === "string" ? decodeBase64(encoded) : undefined;
  if (typeof value?.owner !== "string" || !data)
    return { kind: "none", reason: "current-state lookup returned an unexpected account shape" };
  const unpacked = unpackTokenAccountOwner(data, value.owner);
  if (!unpacked.ok) return { kind: "none", reason: unpacked.reason };
  // The first 32 bytes are the account's mint. If the transaction says which mint the account held, an
  // account of another mint is not the account the transaction used (the address was closed and reused).
  if (knownMints.length > 0 && !knownMints.includes(encodeBase58(data.subarray(0, 32))))
    return {
      kind: "none",
      reason: "the account's mint now differs from the mint in the transaction",
    };
  return {
    kind: "found",
    result: { owner: unpacked.owner, method: "current_state", slot, caveat: CURRENT_STATE_CAVEAT },
  };
}

// ─── Resolver ────────────────────────────────────────────────────────────────

async function resolve(
  tokenAccount: string,
  ctx: OwnerResolutionContext,
): Promise<OwnerResolution> {
  if (!isAddress(tokenAccount)) return unresolved("the token account is not a valid address");
  const { tx, decoded, rpc, cache } = ctx;
  const signature = tx.transaction.signatures?.[0];
  if (typeof signature !== "string" || signature.length === 0)
    return unresolved("the transaction has no signature to identify it by");

  // Same signature means same transaction, so the key never mixes transactions; ":" is not base58.
  const key = `${signature}:${tokenAccount}`;
  const cached = cache?.get(key);
  if (cached) return cached;

  const keys = resolveAccountKeys(tx);
  const index = keys.indexOf(tokenAccount);
  if (index === -1) return unresolved("the account is not part of this transaction");

  const reasons: string[] = [];
  const attempts: (() => Attempt | Promise<Attempt>)[] = [
    () => fromTxMeta(index, tx),
    () => fromInstructions(tokenAccount, decoded),
    () => fromAtaDerivation(index, tokenAccount, keys, tx, decoded),
    () => fromCurrentState(tokenAccount, rpc, mintCandidates(index, tokenAccount, tx, decoded)),
  ];
  for (const attempt of attempts) {
    const outcome = await attempt();
    if (outcome.kind === "found") {
      const { result } = outcome;
      cache?.set(key, result, result.method === "current_state" ? CURRENT_STATE_TTL_MS : undefined);
      return result;
    }
    // Conflicting evidence is reported as it is, not settled by a weaker method that might pick a side.
    if (outcome.kind === "conflict") return unresolved(outcome.reason);
    reasons.push(outcome.reason);
  }
  return unresolved(reasons.join("; "));
}

/**
 * Resolves the owner of one token account of one transaction. Never throws: bad input or a failing rpc comes
 * back as an unresolved result with a reason. Only successful results are cached; unresolved ones are not,
 * because a later call may carry an rpc or a fresher answer. An rpc error is reported by its class name only,
 * never its message. There is no timeout here: the caller's rpc implementation must supply one (for example
 * an AbortSignal on its fetch), because a getAccountInfo that never settles would never settle this call.
 */
export async function resolveOwner(
  tokenAccount: string,
  ctx: OwnerResolutionContext,
): Promise<OwnerResolution> {
  try {
    return await resolve(tokenAccount, ctx);
  } catch (e) {
    return unresolved(`owner resolution failed (${errorClass(e)})`);
  }
}
