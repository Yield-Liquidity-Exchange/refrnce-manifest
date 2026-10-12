// src/manifest/formulas.ts — versioned Derived claim formulas and the reconciliation arithmetic.
//
// Isomorphic: runs in Node and the browser. No node: imports, no @solana/web3.js, no bs58.
//
// A Derived claim is a number computed from other claims. Its provenance names the formula (name@version)
// and the IDs of the claims it was computed from, and anyone holding those claims must be able to compute
// it again and get the same bytes (recompute). So every formula here is a pure function of claims: no
// clock, no randomness, no network, no state. Amounts are decimal strings of raw base units, parsed
// strictly (no sign, no leading zeros, ASCII digits only) and added as BigInt; a float never appears.
//
//   net_flow@1         TOKEN_TRANSFER and SOL_TRANSFER claims in, one NET_FLOW_BY_OWNER_MINT per owner and mint out.
//   effective_rate@1   one SWAP_EVENT claim in, numerator and denominator strings out. No division, no reduction.
//   reconcile@1        the comparison behind a RECONCILIATION_WARNING: decoded movements against the chain's balances.
//   ata-derivation@1.0.0 re-checked by deriving the associated token address again.
// swap-completeness@1.0.0 and swap-leg-reconciliation@1.0.0 say that something is
// ABSENT (no matching transfer, no swap event, an undecoded node). A verifier re-derives them by re-reading the
// transaction, not by recomputing from claims, so recompute refuses them with reason "requires_transaction":
// a typed refusal that is never a skip and never a pass.
//
// Decisions:
//  - An owner the transaction cannot name is grouped as "unresolved:<token account>", and a mint it cannot
//    name as "unresolved:<token account>", so a movement is never dropped and two unknown mints are never summed.
//    An owner known only from current state (Attributed, not transaction evidence) is treated as unresolved.
//  - Net flow counts transfers only. It leaves out the transaction fee and the lamports a CloseAccount returns,
//    because those are not TOKEN_TRANSFER or SOL_TRANSFER claims. Reconciliation counts both. Every row says so
//    in its `basis` text, and the "owner" of a native row is the account that held the lamports.
//  - A row's inputs are the transfers that moved it and the owner claims its grouping relied on
//    (from_owner_claim, to_owner_claim of those transfers), so a tainted owner claim taints the row.
//
// Reconciliation (reconcileBalances), per account, compares what the decoded claims say moved with what the
// chain says moved (post minus pre):
//  - token accounts: TOKEN_TRANSFER, TOKEN_MINT, TOKEN_BURN.
//  - lamports: SOL_TRANSFER (create_account included), the fee (taken from the fee payer), a transfer of
//    wrapped SOL (the SPL Token program moves lamports with a native account's tokens), and ACCOUNT_CLOSED
//    (the closed account's whole lamport balance goes to the destination; the balance is the chain's
//    pre-balance plus the earlier decoded movements, and the amount is recorded as `close_adjustment`).
//  - a wrapped-SOL token account closed inside the transaction is not compared on its token side: the close
//    drops whatever tokens it held and no claim carries that amount. Its lamports ARE compared, and so is
//    every other account's balance. Any other closed token account must be empty (the SPL rule), so it is compared.
//  - a close carries no amount, so it is inferred (the chain's pre-balance plus the decoded movements so far)
//    and the closed account reconciles by construction. An implausible inferred close is therefore a gap of its
//    own (close_check, with close_amount_inferred true): amount_not_positive (inferred amount <= 0),
//    no_rent_reserve (a closed wrapped-SOL account whose inferred lamports minus its decoded token amount is
//    <= 0), unfunded_account (the account held no lamports before the transaction and no decoded
//    create_account funds it). The first that applies is reported, in the order unfunded_account,
//    amount_not_positive, no_rent_reserve. For these, `expected` is the inferred figure (the decoded funding, "0", for
//    unfunded_account) and `actual` is "1", the least a real close needs, so `difference` is never zero.
//    What this cannot see: a well-formed round trip that never happened, and a transfer dropped between two
//    accounts that close to the same wallet with a rent reserve on both: the sums are conserved.
//  - failed claims are left out, and the chain's own balances already exclude a failed transaction's effects.
// Anything else that moves a balance (a program that edits lamports directly, SyncNative, a Token-2022
// transfer fee) is a gap, and a gap is reported, never absorbed.
import { deriveAssociatedTokenAddress } from "../solana/ata.js";
import {
  compareIxPath,
  type Claim,
  type ClaimValue,
  type DerivedProvenance,
  type Provenance,
} from "./types.js";

// ─── Names and constants ─────────────────────────────────────────────────────

export const NET_FLOW_FORMULA = "net_flow@1";
export const EFFECTIVE_RATE_FORMULA = "effective_rate@1";
export const RECONCILE_FORMULA = "reconcile@1";
export const ATA_FORMULA = "ata-derivation@1.0.0";
const SWAP_COMPLETENESS_FORMULA = "swap-completeness@1.0.0";
const SWAP_LEG_FORMULA = "swap-leg-reconciliation@1.0.0";

/** The asset of a SOL_TRANSFER: lamports. Not the wrapped-SOL mint. */
export const NATIVE_ASSET = "native";
export const WRAPPED_SOL_MINT = "So11111111111111111111111111111111111111112";
/** Printed on every NET_FLOW_BY_OWNER_MINT row of lamports (mint NATIVE_ASSET). */
export const NET_FLOW_BASIS_NATIVE =
  "Net of decoded transfers only, not the balance change. SOL: System transfers and account creations; excludes the transaction fee (see TX_FEE) and lamports returned when accounts are closed (see ACCOUNT_CLOSED). Token mints and burns are not included.";
/** Printed on every other NET_FLOW_BY_OWNER_MINT row. */
export const NET_FLOW_BASIS_TOKEN =
  "Net of decoded transfers only, not the balance change. Tokens: decoded token transfers only. Token mints and burns are not included.";
/** What the normaliser writes where an owner or a mint cannot be named. */
const UNRESOLVED_LABEL = "unresolved";

// ─── Types ───────────────────────────────────────────────────────────────────

/** The part of a claim a formula reads. A full Claim fits, and so does a draft the normaliser has not numbered yet. */
export interface FormulaClaim {
  id: string;
  code: string;
  value: ClaimValue;
  provenance?: Provenance;
}

/** What a formula returns for one Derived claim: its code, value and the IDs of the claims it came from. */
export interface FormulaOutput {
  code: string;
  value: Record<string, ClaimValue>;
  inputs: string[];
}

/** Thrown when a claim a formula is given is not in the shape its code promises. Never a half answer. */
export class FormulaInputError extends Error {
  readonly claimId: string | undefined;
  constructor(message: string, claimId?: string) {
    super(claimId === undefined ? message : `claim ${claimId}: ${message}`);
    this.name = "FormulaInputError";
    this.claimId = claimId;
  }
}

export type RecomputeReason =
  | "not_derived"
  | "unknown_formula"
  | "requires_transaction"
  | "code_mismatch"
  | "value_mismatch"
  | "missing_input"
  | "duplicate_id"
  | "inputs_mismatch"
  | "no_output";

/** Thrown by recompute. `reason` says which check failed. */
export class RecomputeError extends Error {
  readonly reason: RecomputeReason;
  constructor(reason: RecomputeReason, message: string) {
    super(message);
    this.name = "RecomputeError";
    this.reason = reason;
  }
}

// ─── Strict reading ──────────────────────────────────────────────────────────

const UNSIGNED = /^(0|[1-9][0-9]*)$/;
const SIGNED = /^(0|-?[1-9][0-9]*)$/;

function record(c: FormulaClaim): Record<string, ClaimValue> {
  const v = c.value;
  if (v === null || typeof v !== "object" || Array.isArray(v))
    throw new FormulaInputError(`${c.code} value is not an object`, c.id);
  return v;
}

function text(c: FormulaClaim, name: string): string {
  const v = record(c)[name];
  if (typeof v !== "string")
    throw new FormulaInputError(`${c.code} has no text field "${name}"`, c.id);
  return v;
}

/** An unsigned decimal string: no sign, no spaces, no leading zero, no "0x", no exponent. */
function amount(c: FormulaClaim, name: string): bigint {
  const v = text(c, name);
  if (!UNSIGNED.test(v))
    throw new FormulaInputError(`${c.code} field "${name}" is not a plain decimal amount`, c.id);
  return BigInt(v);
}

function signedField(c: FormulaClaim, name: string): bigint {
  const v = text(c, name);
  if (!SIGNED.test(v))
    throw new FormulaInputError(`${c.code} field "${name}" is not a signed decimal amount`, c.id);
  return BigInt(v);
}

const isFailed = (c: FormulaClaim): boolean => record(c).failed === true;

const compareText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

const sortedUnique = (ids: Iterable<string>): string[] => [...new Set(ids)].sort(compareText);

// ─── net_flow@1 ──────────────────────────────────────────────────────────────

/** The owner a transfer side counts for, or "unresolved:<account>" when the transaction does not prove one. */
function sideOwner(c: FormulaClaim, side: "from" | "to", account: string): string {
  const owner = text(c, `${side}_owner`);
  const method = text(c, `${side}_owner_method`);
  if (owner === UNRESOLVED_LABEL || method === "unresolved" || method === "current_state")
    return `${UNRESOLVED_LABEL}:${account}`;
  return owner;
}

/**
 * One NET_FLOW_BY_OWNER_MINT per owner and mint: what the owner received minus what it sent, over the
 * non-failed TOKEN_TRANSFER and SOL_TRANSFER claims given. `net` is a signed decimal string ("-123", "0").
 * Sorted by owner then mint; each output lists the claims that moved something for that owner and mint.
 */
export function netFlow(claims: readonly FormulaClaim[]): FormulaOutput[] {
  const groups = new Map<string, { owner: string; mint: string; net: bigint; inputs: string[] }>();
  const add = (id: string, owner: string, mint: string, delta: bigint, ownerClaim?: string) => {
    const key = JSON.stringify([owner, mint]);
    const group = groups.get(key) ?? { owner, mint, net: 0n, inputs: [] };
    group.net += delta;
    group.inputs.push(id);
    // The owner claim this side's owner came from (an unresolved side has none).
    if (ownerClaim !== undefined && !owner.startsWith(`${UNRESOLVED_LABEL}:`))
      group.inputs.push(ownerClaim);
    groups.set(key, group);
  };
  const ownerClaimOf = (c: FormulaClaim, side: "from" | "to"): string | undefined => {
    const id = record(c)[`${side}_owner_claim`];
    return typeof id === "string" ? id : undefined;
  };
  for (const c of claims) {
    if (c.code === "TOKEN_TRANSFER") {
      if (isFailed(c)) continue;
      const value = amount(c, "amount");
      const source = text(c, "source");
      const destination = text(c, "destination");
      const mint = text(c, "mint");
      // Per account, not per transfer: a mint the transaction does not name belongs to no other account.
      const mintFor = (account: string) =>
        mint === UNRESOLVED_LABEL ? `${UNRESOLVED_LABEL}:${account}` : mint;
      add(c.id, sideOwner(c, "from", source), mintFor(source), -value, ownerClaimOf(c, "from"));
      add(
        c.id,
        sideOwner(c, "to", destination),
        mintFor(destination),
        value,
        ownerClaimOf(c, "to"),
      );
    } else if (c.code === "SOL_TRANSFER") {
      if (isFailed(c)) continue;
      const lamports = amount(c, "lamports");
      add(c.id, text(c, "from"), NATIVE_ASSET, -lamports);
      add(c.id, text(c, "to"), NATIVE_ASSET, lamports);
    }
  }
  return [...groups.values()]
    .sort((a, b) => compareText(a.owner, b.owner) || compareText(a.mint, b.mint))
    .map((g) => ({
      code: "NET_FLOW_BY_OWNER_MINT",
      // BigInt prints 0n as "0" and never "-0".
      value: {
        owner: g.owner,
        mint: g.mint,
        net: g.net.toString(),
        basis: g.mint === NATIVE_ASSET ? NET_FLOW_BASIS_NATIVE : NET_FLOW_BASIS_TOKEN,
      },
      inputs: sortedUnique(g.inputs),
    }));
}

// ─── effective_rate@1 ────────────────────────────────────────────────────────

/**
 * The rate one swap leg reported, as output over input: numerator is the output amount, denominator the
 * input amount, each with its mint. Nothing is divided or reduced, so no digit is lost. Needs exactly one
 * non-failed SWAP_EVENT claim with a non-zero input amount (a zero input has no rate, and none is invented).
 */
export function effectiveRate(claims: readonly FormulaClaim[]): FormulaOutput[] {
  if (claims.length !== 1 || claims[0].code !== "SWAP_EVENT")
    throw new FormulaInputError("effective_rate@1 takes exactly one SWAP_EVENT claim");
  const c = claims[0];
  if (isFailed(c)) throw new FormulaInputError("a failed swap event has no rate", c.id);
  const input = amount(c, "input_amount");
  const output = amount(c, "output_amount");
  if (input === 0n) throw new FormulaInputError("input amount is zero, so there is no rate", c.id);
  return [
    {
      code: "EFFECTIVE_RATE",
      value: {
        numerator: output.toString(),
        numerator_mint: text(c, "output_mint"),
        denominator: input.toString(),
        denominator_mint: text(c, "input_mint"),
      },
      inputs: [c.id],
    },
  ];
}

// ─── Movements and reconciliation ────────────────────────────────────────────

type Unit = "token" | "lamports";

interface Effect {
  account: string;
  unit: Unit;
  delta: bigint;
}

/**
 * What one claim moves, as signed deltas per account. ACCOUNT_CLOSED is not here: how much a close moves
 * depends on the balance at that moment, which only the sequence (and the chain's pre-balance) gives.
 * The fee is the one claim that counts even when the transaction failed: the fee is charged either way.
 */
function movementEffects(c: FormulaClaim): Effect[] {
  switch (c.code) {
    case "TX_FEE":
      return [{ account: text(c, "fee_payer"), unit: "lamports", delta: -amount(c, "lamports") }];
    case "SOL_TRANSFER": {
      if (isFailed(c)) return [];
      const l = amount(c, "lamports");
      return [
        { account: text(c, "from"), unit: "lamports", delta: -l },
        { account: text(c, "to"), unit: "lamports", delta: l },
      ];
    }
    case "TOKEN_TRANSFER": {
      if (isFailed(c)) return [];
      const a = amount(c, "amount");
      const source = text(c, "source");
      const destination = text(c, "destination");
      const effects: Effect[] = [
        { account: source, unit: "token", delta: -a },
        { account: destination, unit: "token", delta: a },
      ];
      // A native (wrapped SOL) token account holds its tokens as lamports: the transfer moves both.
      if (text(c, "mint") === WRAPPED_SOL_MINT)
        effects.push(
          { account: source, unit: "lamports", delta: -a },
          { account: destination, unit: "lamports", delta: a },
        );
      return effects;
    }
    case "TOKEN_MINT":
      return isFailed(c)
        ? []
        : [{ account: text(c, "destination"), unit: "token", delta: amount(c, "amount") }];
    case "TOKEN_BURN":
      return isFailed(c)
        ? []
        : [{ account: text(c, "account"), unit: "token", delta: -amount(c, "amount") }];
    default:
      return [];
  }
}

/** The chain's balances for one transaction: raw base units, a missing account counting as zero. */
export interface ChainBalances {
  /** Token account address to its mint and its pre and post amounts. */
  tokens: ReadonlyMap<string, { mint: string; pre: bigint; post: bigint }>;
  /** Account address to its pre and post lamports. */
  lamports: ReadonlyMap<string, { pre: bigint; post: bigint }>;
}

export type CloseCheck = "amount_not_positive" | "no_rent_reserve" | "unfunded_account";
export const CLOSE_CHECKS: readonly CloseCheck[] = [
  "amount_not_positive",
  "no_rent_reserve",
  "unfunded_account",
];

/** One account whose chain balance change the decoded claims do not explain. All amounts are signed decimal strings. */
export interface BalanceGap {
  kind: Unit;
  account: string;
  /** The token mint, or NATIVE_ASSET for lamports, or "unresolved" when nothing names it. */
  mint: string;
  /** What the decoded claims say the balance changed by (for a close_check gap, see the header). */
  expected: string;
  /** What the chain says it changed by: post minus pre (for a close_check gap, "1"). */
  actual: string;
  /** actual minus expected. Never "0". */
  difference: string;
  /** The part of `expected` that came from decoded CloseAccount claims (lamports only; "0" otherwise). */
  close_adjustment: string;
  /** True when the gap involves a close whose amount was inferred, not read from the chain. */
  close_amount_inferred: boolean;
  /** Set only on a gap that is about an implausible inferred close. */
  close_check?: CloseCheck;
  reason: string;
  /** The claims the comparison used for this account; the fee claim stands in when no decoded claim touches it. */
  inputs: string[];
}

const REASON: Record<Unit, string> = {
  token:
    "the decoded token movements do not explain this token account's balance change on the chain",
  lamports:
    "the decoded lamport movements and fee do not explain this account's balance change on the chain",
};

const CLOSE_REASON: Record<CloseCheck, string> = {
  amount_not_positive:
    "the decoded movements imply this closed account held no lamports when it was closed, which no real account does",
  no_rent_reserve:
    "the decoded movements imply this closed wrapped-SOL account held no lamports beyond its tokens, but a native account always holds a rent reserve",
  unfunded_account:
    "this account held no lamports before the transaction and no decoded create_account funds it, yet it was closed",
};

/** Observed claims in execution order (ix_path, numerically); others keep their place after them. */
function inExecutionOrder(claims: readonly FormulaClaim[]): FormulaClaim[] {
  const path = (c: FormulaClaim) =>
    c.provenance?.type === "observed" ? c.provenance.ix_path : undefined;
  return claims
    .map((c, index) => ({ c, index }))
    .sort((a, b) => {
      const pa = path(a.c);
      const pb = path(b.c);
      if (pa !== undefined && pb === undefined) return -1;
      if (pa === undefined && pb !== undefined) return 1;
      if (pa !== undefined && pb !== undefined) {
        const byPath = compareIxPath(pa, pb);
        if (byPath !== 0) return byPath;
      }
      return a.index - b.index;
    })
    .map((x) => x.c);
}

/** True when a decoded, non-failed create_account funds this account. */
const fundsAccount = (c: FormulaClaim, account: string): boolean =>
  c.code === "SOL_TRANSFER" &&
  !isFailed(c) &&
  record(c).instruction === "create_account" &&
  record(c).to === account;

/**
 * Compares the decoded claims with the chain's own balance changes and returns every account where they
 * differ, in a fixed order (token accounts by address, then lamport accounts by address). An empty list
 * means every balance change on the chain is explained by the claims. Amounts are exact (BigInt).
 */
export function reconcileBalances(
  claims: readonly FormulaClaim[],
  chain: ChainBalances,
): BalanceGap[] {
  const ordered = inExecutionOrder(claims);
  const tokenMoves = new Map<string, bigint>();
  const lamportMoves = new Map<string, bigint>();
  const closeAdjustment = new Map<string, bigint>();
  const lamportsHeld = new Map<string, bigint>();
  const tokensHeld = new Map<string, bigint>();
  const touched: Record<Unit, Map<string, string[]>> = { token: new Map(), lamports: new Map() };
  const closedAccounts = new Set<string>();
  const mintOfAccount = new Map<string, string>();
  const closeProblems: { account: string; check: CloseCheck; shown: bigint; held: bigint }[] = [];
  let feeClaimId: string | undefined;

  const heldLamports = (a: string) => lamportsHeld.get(a) ?? chain.lamports.get(a)?.pre ?? 0n;
  const heldTokens = (a: string) => tokensHeld.get(a) ?? chain.tokens.get(a)?.pre ?? 0n;
  const bump = (m: Map<string, bigint>, a: string, d: bigint) => m.set(a, (m.get(a) ?? 0n) + d);
  const touch = (unit: Unit, account: string, id: string) =>
    touched[unit].set(account, [...(touched[unit].get(account) ?? []), id]);
  const move = (id: string, e: Effect) => {
    if (e.unit === "token") {
      bump(tokenMoves, e.account, e.delta);
      tokensHeld.set(e.account, heldTokens(e.account) + e.delta);
    } else {
      bump(lamportMoves, e.account, e.delta);
      lamportsHeld.set(e.account, heldLamports(e.account) + e.delta);
    }
    touch(e.unit, e.account, id);
  };

  // The mint a claim names for an account, used to find wrapped-SOL accounts the chain no longer lists.
  for (const c of claims) {
    if (c.code === "TX_FEE" || isFailed(c)) continue;
    if (c.code === "TOKEN_TRANSFER") {
      const mint = text(c, "mint");
      if (mint !== UNRESOLVED_LABEL)
        for (const a of [text(c, "source"), text(c, "destination")]) mintOfAccount.set(a, mint);
    } else if (c.code === "TOKEN_MINT") mintOfAccount.set(text(c, "destination"), text(c, "mint"));
    else if (c.code === "TOKEN_BURN") mintOfAccount.set(text(c, "account"), text(c, "mint"));
  }
  const mintOf = (account: string): string =>
    chain.tokens.get(account)?.mint ?? mintOfAccount.get(account) ?? UNRESOLVED_LABEL;

  // The fee is charged before anything runs.
  for (const c of ordered)
    if (c.code === "TX_FEE") {
      feeClaimId ??= c.id;
      for (const e of movementEffects(c)) move(c.id, e);
    }
  for (const c of ordered) {
    if (c.code === "TX_FEE") continue;
    for (const e of movementEffects(c)) move(c.id, e);
    if (c.code === "ACCOUNT_CLOSED" && !isFailed(c)) {
      const account = text(c, "account");
      const destination = text(c, "destination");
      const held = heldLamports(account);
      // The inferred amount must be plausible: positive, with a rent reserve above a wrapped-SOL account's
      // tokens, and an account that did not exist before must have been funded by a decoded create_account.
      const rent = held - heldTokens(account);
      if (
        (chain.lamports.get(account)?.pre ?? 0n) === 0n &&
        !claims.some((x) => fundsAccount(x, account))
      )
        closeProblems.push({ account, check: "unfunded_account", shown: 0n, held });
      else if (held <= 0n)
        closeProblems.push({ account, check: "amount_not_positive", shown: held, held });
      else if (mintOf(account) === WRAPPED_SOL_MINT && rent <= 0n)
        closeProblems.push({ account, check: "no_rent_reserve", shown: rent, held });
      move(c.id, { account, unit: "lamports", delta: -held });
      move(c.id, { account: destination, unit: "lamports", delta: held });
      bump(closeAdjustment, account, -held);
      bump(closeAdjustment, destination, held);
      closedAccounts.add(account);
    }
  }

  const gaps: BalanceGap[] = [];
  const inputsFor = (unit: Unit, account: string): string[] => {
    const own = sortedUnique(touched[unit].get(account) ?? []);
    return own.length > 0 ? own : feeClaimId === undefined ? [] : [feeClaimId];
  };

  for (const account of sortedUnique([...chain.tokens.keys(), ...tokenMoves.keys()])) {
    // A wrapped-SOL account closed in this transaction: the dropped tokens have no claim (see the header).
    if (closedAccounts.has(account) && mintOf(account) === WRAPPED_SOL_MINT) continue;
    const entry = chain.tokens.get(account);
    const actual = (entry?.post ?? 0n) - (entry?.pre ?? 0n);
    const expected = tokenMoves.get(account) ?? 0n;
    if (actual !== expected)
      gaps.push({
        kind: "token",
        account,
        mint: mintOf(account),
        expected: expected.toString(),
        actual: actual.toString(),
        difference: (actual - expected).toString(),
        close_adjustment: "0",
        close_amount_inferred: false,
        reason: REASON.token,
        inputs: inputsFor("token", account),
      });
  }

  const lamportGaps: BalanceGap[] = [];
  for (const account of sortedUnique([...chain.lamports.keys(), ...lamportMoves.keys()])) {
    const entry = chain.lamports.get(account);
    const actual = (entry?.post ?? 0n) - (entry?.pre ?? 0n);
    const expected = lamportMoves.get(account) ?? 0n;
    const adjustment = closeAdjustment.get(account) ?? 0n;
    if (actual !== expected)
      lamportGaps.push({
        kind: "lamports",
        account,
        mint: NATIVE_ASSET,
        expected: expected.toString(),
        actual: actual.toString(),
        difference: (actual - expected).toString(),
        close_adjustment: adjustment.toString(),
        close_amount_inferred: adjustment !== 0n,
        reason: REASON.lamports,
        inputs: inputsFor("lamports", account),
      });
  }
  for (const p of closeProblems)
    lamportGaps.push({
      kind: "lamports",
      account: p.account,
      mint: NATIVE_ASSET,
      expected: p.shown.toString(),
      actual: "1",
      difference: (1n - p.shown).toString(),
      close_adjustment: (-p.held).toString(),
      close_amount_inferred: true,
      close_check: p.check,
      reason: CLOSE_REASON[p.check],
      inputs: inputsFor("lamports", p.account),
    });
  lamportGaps.sort(
    (a, b) =>
      compareText(a.account, b.account) || compareText(a.close_check ?? "", b.close_check ?? ""),
  );
  return [...gaps, ...lamportGaps];
}

/** One RECONCILIATION_WARNING output per gap, formula reconcile@1. */
export function reconciliationOutputs(gaps: readonly BalanceGap[]): FormulaOutput[] {
  return gaps.map((g) => ({
    code: "RECONCILIATION_WARNING",
    value: {
      account: g.account,
      mint: g.mint,
      expected: g.expected,
      actual: g.actual,
      difference: g.difference,
      close_adjustment: g.close_adjustment,
      close_amount_inferred: g.close_amount_inferred,
      ...(g.close_check !== undefined ? { close_check: g.close_check } : {}),
      reason: g.reason,
    },
    inputs: g.inputs,
  }));
}

// ─── Registry ────────────────────────────────────────────────────────────────

type Compute = (claims: readonly FormulaClaim[]) => FormulaOutput[];

const computeTable: Record<string, Compute> = Object.create(null) as Record<string, Compute>;
computeTable[NET_FLOW_FORMULA] = netFlow;
computeTable[EFFECTIVE_RATE_FORMULA] = effectiveRate;

/** The pure compute functions, keyed by name@version. Frozen and prototype-free: "toString" is not a formula. */
export const FORMULAS: Readonly<Record<string, Compute>> = Object.freeze(computeTable);

// ─── recompute ───────────────────────────────────────────────────────────────

type Recomputer = (
  claim: Claim,
  provenance: DerivedProvenance,
  inputs: FormulaClaim[],
) => ClaimValue;

function claimField(claim: Claim, name: string): string {
  const v = (claim.value as Record<string, ClaimValue> | null)?.[name];
  if (typeof v !== "string")
    throw new RecomputeError("no_output", `claim ${claim.id} has no text field "${name}"`);
  return v;
}

/** A formula whose compute function returns every claim of its kind: pick the one this claim is, and check its inputs. */
function viaCompute(formula: string, identity: readonly string[]): Recomputer {
  const compute = FORMULAS[formula];
  return (claim, provenance, inputs) => {
    const wanted = identity.map((f) => claimField(claim, f));
    const hit = compute(inputs).find((o) => identity.every((f, i) => o.value[f] === wanted[i]));
    if (!hit)
      throw new RecomputeError("no_output", `the inputs of ${claim.id} do not produce this claim`);
    if (hit.code !== claim.code)
      throw new RecomputeError(
        "code_mismatch",
        `${formula} produces ${hit.code}, not ${claim.code}`,
      );
    // Exactly the contributing claims: an extra input would let a claim cite evidence it did not use.
    const listed = [...provenance.inputs].sort(compareText);
    if (listed.length !== hit.inputs.length || !listed.every((id, i) => id === hit.inputs[i]))
      throw new RecomputeError(
        "inputs_mismatch",
        `${claim.id} must list exactly the claims that contribute to it`,
      );
    return hit.value;
  };
}

/** The sum of the movements the inputs make to one account and unit. */
function sumEffects(inputs: readonly FormulaClaim[], account: string, unit: Unit): bigint {
  let sum = 0n;
  for (const c of inputs)
    for (const e of movementEffects(c))
      if (e.account === account && e.unit === unit) sum += e.delta;
  return sum;
}

/** True when the claim is one a reconcile@1 comparison of this account and unit uses (see reconcileBalances). */
function contributes(c: FormulaClaim, account: string, unit: Unit): boolean {
  if (movementEffects(c).some((e) => e.account === account && e.unit === unit)) return true;
  if (c.code === "ACCOUNT_CLOSED" && !isFailed(c) && unit === "lamports")
    return text(c, "account") === account || text(c, "destination") === account;
  return false;
}

/** Same keys, same strings and booleans. Claim values here are flat, so nothing deeper is compared. */
function sameFlatValue(a: Record<string, ClaimValue>, b: Record<string, ClaimValue>): boolean {
  const ak = Object.keys(a).sort();
  const bk = Object.keys(b).sort();
  return ak.length === bk.length && ak.every((k, i) => k === bk[i] && a[k] === b[k]);
}

const valueMismatch = (claim: Claim, what: string) =>
  new RecomputeError("value_mismatch", `${claim.id}: ${what}`);

/**
 * reconcile@1. `expected` is recomputed from the inputs. Two figures come from the transaction's own
 * balances and are carried, not checked (a verifier holding the transaction re-derives the whole claim):
 * `actual`, and `close_adjustment` (the lamports a close moved, inferred from the chain's pre-balance).
 * Everything else must hold: difference is exactly actual minus expected and never zero, every listed input
 * contributes to the account, a close_check claim is consistent with its inputs, and every field of the
 * stored value equals the rebuilt one (reason and flags included, no extra and no missing key).
 */
const recomputeReconcile: Recomputer = (claim, _provenance, inputs) => {
  if (claim.code !== "RECONCILIATION_WARNING")
    throw new RecomputeError(
      "code_mismatch",
      `${RECONCILE_FORMULA} produces RECONCILIATION_WARNING, not ${claim.code}`,
    );
  const stored = claim.value as Record<string, ClaimValue>;
  const account = claimField(claim, "account");
  const mint = claimField(claim, "mint");
  const unit: Unit = mint === NATIVE_ASSET ? "lamports" : "token";
  const actual = signedField(claim, "actual");
  const closeAdj = signedField(claim, "close_adjustment");
  const checkRaw = stored.close_check;
  if (checkRaw !== undefined && !CLOSE_CHECKS.includes(checkRaw as CloseCheck))
    throw valueMismatch(claim, "close_check is not a known check");
  const check = checkRaw as CloseCheck | undefined;
  if (check !== undefined && unit !== "lamports")
    throw valueMismatch(claim, "a close check is about lamports");

  // Every input must be a claim this comparison used; the fee claim may stand alone as the fallback.
  const soleFee = inputs.length === 1 && inputs[0].code === "TX_FEE";
  if (!soleFee && !inputs.every((c) => contributes(c, account, unit)))
    throw new RecomputeError(
      "inputs_mismatch",
      `${claim.id} lists a claim that does not touch ${account}`,
    );

  let expected: bigint;
  let reasonText: string;
  if (check === undefined) {
    if (unit === "token" && closeAdj !== 0n)
      throw valueMismatch(claim, "a token account has no close adjustment");
    expected = sumEffects(inputs, account, unit) + closeAdj;
    reasonText = REASON[unit];
  } else {
    // The inferred figure comes from the chain's pre-balance, so it is checked for plausibility, not recomputed.
    expected = signedField(claim, "expected");
    reasonText = CLOSE_REASON[check];
    const closes = inputs.some(
      (c) => c.code === "ACCOUNT_CLOSED" && !isFailed(c) && text(c, "account") === account,
    );
    if (!closes || actual !== 1n)
      throw valueMismatch(claim, "a close check needs its close claim and an actual of 1");
    if (check === "no_rent_reserve" && closeAdj >= 0n)
      throw valueMismatch(claim, "no_rent_reserve needs a positive amount leaving the account");
    if (check === "amount_not_positive" && !(expected <= 0n && closeAdj === -expected))
      throw valueMismatch(claim, "amount_not_positive is not consistent with its figures");
    if (check === "no_rent_reserve" && expected > 0n)
      throw valueMismatch(claim, "no_rent_reserve needs a rent reserve of zero or less");
    if (
      check === "unfunded_account" &&
      (expected !== 0n || inputs.some((c) => fundsAccount(c, account)))
    )
      throw valueMismatch(claim, "unfunded_account contradicts its inputs");
  }
  const difference = actual - expected;
  if (difference === 0n) throw valueMismatch(claim, "a warning's difference is never zero");

  const rebuilt: Record<string, ClaimValue> = {
    account,
    mint,
    expected: expected.toString(),
    actual: actual.toString(),
    difference: difference.toString(),
    close_adjustment: closeAdj.toString(),
    close_amount_inferred: check !== undefined || (unit === "lamports" && closeAdj !== 0n),
    ...(check !== undefined ? { close_check: check } : {}),
    reason: reasonText,
  };
  if (!sameFlatValue(rebuilt, stored))
    throw valueMismatch(claim, "the stored value is not what its inputs give");
  return rebuilt;
};

const recomputeAta: Recomputer = (claim, _provenance, inputs) => {
  if (claim.code !== "OWNER_FROM_ATA_DERIVATION")
    throw new RecomputeError(
      "code_mismatch",
      `${ATA_FORMULA} produces OWNER_FROM_ATA_DERIVATION, not ${claim.code}`,
    );
  const account = claimField(claim, "account");
  const owner = claimField(claim, "owner");
  // The owner cannot be read back out of an address, so this checks the claim: the address derived from
  // (owner, mint, token program) of an input transfer must be the account. A throw means it is not. Only
  // account and owner are taken from the claim; the rest is rebuilt, so a tampered field fails.
  for (const c of inputs) {
    if (c.code !== "TOKEN_TRANSFER") continue;
    const v = record(c);
    if (v.source !== account && v.destination !== account) continue;
    const mint = v.mint;
    const program = v.token_program;
    if (typeof mint !== "string" || typeof program !== "string" || mint === UNRESOLVED_LABEL)
      continue;
    let derived: string | undefined;
    try {
      derived = deriveAssociatedTokenAddress(owner, mint, program);
    } catch {
      // An input that is not an address derives nothing; the claim stays unproven.
    }
    if (derived === account) {
      const rebuilt: Record<string, ClaimValue> = { account, owner, method: "ata_derivation" };
      if (!sameFlatValue(rebuilt, claim.value as Record<string, ClaimValue>))
        throw valueMismatch(claim, "the stored value is not what the derivation gives");
      return rebuilt;
    }
  }
  throw new RecomputeError(
    "no_output",
    `no input transfer of ${claim.id} lets ${account} be derived from its owner`,
  );
};

const RECOMPUTERS = new Map<string, Recomputer>([
  [NET_FLOW_FORMULA, viaCompute(NET_FLOW_FORMULA, ["owner", "mint"])],
  [EFFECTIVE_RATE_FORMULA, viaCompute(EFFECTIVE_RATE_FORMULA, [])],
  [RECONCILE_FORMULA, recomputeReconcile],
  [ATA_FORMULA, recomputeAta],
]);

/** Formulas a verifier re-derives by re-reading the transaction: never recomputed from claims, never skipped. */
const NEEDS_TRANSACTION = new Set([SWAP_COMPLETENESS_FORMULA, SWAP_LEG_FORMULA]);

export function recompute(claim: Claim, allClaims: readonly Claim[]): ClaimValue {
  const provenance = claim?.provenance;
  if (!claim || claim.type !== "derived" || provenance?.type !== "derived")
    throw new RecomputeError("not_derived", `claim ${claim?.id} is not a Derived claim`);
  const formula = provenance.formula;
  if (NEEDS_TRANSACTION.has(formula)) {
    // Bind the formula to its code first, so a claim of another code cannot hide behind this refusal.
    if (claim.code !== "RECONCILIATION_WARNING")
      throw new RecomputeError(
        "code_mismatch",
        `${formula} produces RECONCILIATION_WARNING, not ${claim.code}`,
      );
    throw new RecomputeError(
      "requires_transaction",
      `${formula} is re-derived from the transaction (it reports something absent), not recomputed from the claims it lists`,
    );
  }
  const recomputer = RECOMPUTERS.get(formula);
  if (!recomputer)
    throw new RecomputeError("unknown_formula", `formula ${JSON.stringify(formula)} is not known`);
  const byId = new Map<string, Claim>();
  const duplicated = new Set<string>();
  for (const c of allClaims) {
    if (byId.has(c.id)) duplicated.add(c.id);
    byId.set(c.id, c);
  }
  const inputs = provenance.inputs.map((id) => {
    if (duplicated.has(id))
      throw new RecomputeError("duplicate_id", `claim id ${id} appears more than once`);
    const found = byId.get(id);
    if (!found)
      throw new RecomputeError(
        "missing_input",
        `input ${id} of ${claim.id} is not among the claims`,
      );
    return found;
  });
  return recomputer(claim, provenance, inputs);
}
