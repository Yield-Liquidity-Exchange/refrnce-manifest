// Reconciliation of decoded claims against the chain's own balances.
//
// A raw getTransaction result carries what every account held before and after the transaction
// (meta.preBalances / postBalances in lamports, meta.preTokenBalances / postTokenBalances in raw token
// units). The decoded claims say what moved. reconcile() reads the first and hands both to the pure
// comparison in manifest/formulas.ts (reconcileBalances), which returns every account where they differ.
// This file only turns the transaction into exact BigInt balances. It refuses a transaction whose balance
// arrays are missing or do not match its account list: a reconciliation that silently compared nothing
// would pass, and a pass that checked nothing is worse than an error.
//
// Pure and isomorphic: no network, no Node-only imports.
import {
  reconcileBalances,
  type BalanceGap,
  type ChainBalances,
  type FormulaClaim,
} from "../manifest/formulas.js";
import { resolveAccountKeys, type RawTransaction } from "./account-keys.js";

interface TokenBalanceEntry {
  accountIndex: number;
  mint: string;
  uiTokenAmount: { amount: string };
}

/** A raw getTransaction result (encoding json) with the balance fields reconciliation reads. */
export type ReconcileTransaction = RawTransaction & {
  meta: {
    preBalances?: number[];
    postBalances?: number[];
    preTokenBalances?: TokenBalanceEntry[] | null;
    postTokenBalances?: TokenBalanceEntry[] | null;
  } | null;
};

const RAW_AMOUNT = /^(0|[1-9][0-9]*)$/;

export class InexactLamportBalance extends Error {
  constructor(what: string) {
    super(`transaction ${what} is not an exact lamport count`);
    this.name = "InexactLamportBalance";
  }
}

function lamportList(list: unknown, what: string, length: number): bigint[] {
  if (!Array.isArray(list) || list.length !== length)
    throw new Error(`transaction ${what} must list one balance per account (${length})`);
  return list.map((n, i) => {
    if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 0)
      throw new InexactLamportBalance(`${what}[${i}]`);
    return BigInt(n);
  });
}

function tokenSide(list: unknown, what: string, keys: readonly string[]) {
  // A node may leave the list out for a transaction with no token accounts; present entries must be exact.
  const out = new Map<string, { mint: string; amount: bigint }>();
  for (const b of Array.isArray(list) ? (list as TokenBalanceEntry[]) : []) {
    const account = Number.isInteger(b?.accountIndex) ? keys[b.accountIndex] : undefined;
    const amount = b?.uiTokenAmount?.amount;
    if (account === undefined || typeof b.mint !== "string")
      throw new Error(`transaction ${what} has an entry that names no account or mint`);
    if (typeof amount !== "string" || !RAW_AMOUNT.test(amount))
      throw new Error(`transaction ${what} has a token amount that is not a raw decimal`);
    if (out.has(account)) throw new Error(`transaction ${what} lists ${account} twice`);
    out.set(account, { mint: b.mint, amount: BigInt(amount) });
  }
  return out;
}

/** The transaction's balances before and after, per account, as exact BigInt. Throws on anything it cannot read exactly. */
export function chainBalances(tx: ReconcileTransaction): ChainBalances {
  const keys = resolveAccountKeys(tx); // throws without meta
  // One balance per account: a repeated address would silently keep only the last entry's balance.
  if (new Set(keys).size !== keys.length) throw new Error("transaction lists an account twice");
  const pre = lamportList(tx.meta?.preBalances, "preBalances", keys.length);
  const post = lamportList(tx.meta?.postBalances, "postBalances", keys.length);
  const lamports = new Map<string, { pre: bigint; post: bigint }>();
  keys.forEach((key, i) => lamports.set(key, { pre: pre[i], post: post[i] }));

  const before = tokenSide(tx.meta?.preTokenBalances, "preTokenBalances", keys);
  const after = tokenSide(tx.meta?.postTokenBalances, "postTokenBalances", keys);
  const tokens = new Map<string, { mint: string; pre: bigint; post: bigint }>();
  for (const account of new Set([...before.keys(), ...after.keys()])) {
    const a = after.get(account);
    const b = before.get(account);
    tokens.set(account, {
      mint: (a ?? b)!.mint,
      pre: b?.amount ?? 0n,
      post: a?.amount ?? 0n,
    });
  }
  return { tokens, lamports };
}

/**
 * Every account whose balance change on the chain the claims do not explain, token accounts and lamports,
 * with the numbers as signed decimal strings. An empty list means the decoded claims account for every
 * balance change of the transaction. See manifest/formulas.ts for exactly what is counted and what is not.
 */
export function reconcile(claims: readonly FormulaClaim[], tx: ReconcileTransaction): BalanceGap[] {
  return reconcileBalances(claims, chainBalances(tx));
}
