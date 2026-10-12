// The re-derivation engine behind checks C7 (Observed claims) and C8 (Derived claims). For every subject
// transaction it reads the transaction again (getTransaction, encoding json, finalized), runs the same
// normaliser the issuer used and compares the claims it gives with the claims in the record, in both
// directions, as sets:
//
//   - every Observed and Derived claim of the record must be among the claims the transaction gives, and
//   - every Observed and Derived claim the transaction gives (the reconcile@1, swap-completeness@1.0.0 and
//     swap-leg-reconciliation@1.0.0 warnings and the net flows included) must be in the record.
// A claim dropped from the record, added to it, or changed is a mismatch.
//
// Matching key. Claim ids differ between the record and the regenerated set (the builder numbers across
// transactions and merges PROGRAM_LABEL), so a claim is matched by (transaction, type, code, canonical value with
// each reference field replaced by a placeholder, provenance without its references): for an Observed claim that
// provenance is signature, slot, ix_path and decoder name@version; for a Derived claim it is the formula. Then
// the references are checked: from_owner_claim and to_owner_claim must point at the claim the matched one points
// at, and a Derived claim's inputs must be exactly the claims its match was computed from (each id resolved
// through the record's own claims, then through the pairing). Identical claims (the same key twice in one
// transaction) are matched one to one, so a duplicate in the record finds no second partner; claims that other
// claims rely on pair first, then by id, so of an original and an added copy the copy is the one named.
//
// Derived claims (C8). recompute (formulas.ts) runs on each with the record's own claims. A claim that does not
// recompute is a mismatch whatever the chain says. The formulas recompute cannot decide (the two swap warnings,
// requires_transaction) are never skipped: the regenerated-set equality above IS their check, and their results
// say "re-derived from the transaction", never "recomputed". reconcile@1 is both: recomputed as far as the claims
// allow, and re-derived for the figures that come from the chain (actual, close_adjustment).
//
// Results per claim: reproduced, mismatch, unavailable, not_checked. The words differ by design and never
// overlap: a mismatch says "does not match", an unavailable result says "could not check: no usable answer from
// the data source (<the reason, spelled out>)". Transport trouble (timeout, network, HTTP errors, an answer that
// is not a transaction or is another transaction, an answer the normaliser cannot read, an answer larger than any
// real transaction) is unavailable. The chain answering that the transaction does not exist at finalized is a
// mismatch ("transaction not found at finalized"). A mismatch row carries the first field that differs ("with a
// different value", or the field's name when it is outside the value) and the expected (what the chain or the
// recomputation gives) and found (what the record holds) values as canonical JSON text. A claim that fails only
// because a claim it relies on fails is a mismatch whose `cause` names that root claim. A Derived claim that
// lists an input twice is a mismatch whatever its formula. A formula this verifier does not know is another
// tool version, not tampering: its claim is "could not check: this verifier does not know the formula ...".
//
// Every subject transaction has an outcome, whether or not the record has claims in it: one the chain
// does not have makes the result a mismatch, one that could not be read makes it unavailable, and a transaction
// read fine that gives no claim at all (a real one always gives its TX_FEE) counts as unreadable.
//
// Hostile sizes. An answer is refused as unreadable BEFORE it is decoded when it exceeds what a real
// transaction can be (instruction data over 2048 characters, more than 256 account keys or 1500 instructions,
// any string over 10 000 characters): base58 decoding is super-linear, so such an answer could hold the verifier.
// Attributed and Inferred claims are not_checked with the reason "outside independent verification" (a
// PROGRAM_LABEL says its label comes from the Refrnce program registry). They are counted and listed, never
// passed and never counted as reproduced.
//
// Owners known only from current state. The normaliser's last owner method reads the account as it
// is NOW (getAccountInfo); its result is Attributed and cannot be re-checked. The verifier never makes that call.
// It re-runs the normaliser with an owner rpc that refuses and records which accounts reached that step; only for
// those accounts does it (a) take the owner from the record's own OWNER_CURRENT_STATE claim (re-running with a
// seeded owner cache) and (b) compare an "unresolved" owner reason without its last, current-state part, which
// describes the issuer's own lookup. An account the transaction itself resolves is never seeded, so a record
// cannot turn an Observed owner into an Attributed one. Rows that rely on this carry a note.
//
// Tooling. manifest.tooling is compared with the running NORMALISER_ID, REGISTRY_VERSION and formula list (the
// list this verifier's own registry gives for the record, never taken from the record's citations); a difference
// is a warning, and every mismatch row then notes that the version difference is a likely cause. It never turns
// a mismatch into a pass.
//
// Known limit: this re-runs the SAME decoders the issuer ran. A decoder that silently misses an
// instruction misses it here too; such a gap is visible only when the instruction shows up as a non-decoded
// PROGRAM_INVOKED claim (unknown_program, unknown_variant, error), which the record must then list as well.
//
// rederive never throws. A record that is not a valid manifest (schema, manifest rules, and when the text is given,
// a repeated key) is "invalid" and nothing is fetched. The result is bounded: rows are capped per status, counts
// are complete.
import { canonicalizeJcs } from "../canonical.js";
import { checkManifestRules, detectDuplicateKeys } from "../manifest-rules.js";
import {
  ATA_FORMULA,
  FORMULAS,
  RECONCILE_FORMULA,
  RecomputeError,
  recompute,
} from "../formulas.js";
import {
  CLAIM_ID_VALUE_FIELDS,
  ManifestSchema,
  type Claim,
  type ClaimType,
  type ClaimValue,
  type Manifest,
  type ManifestCluster,
} from "../types.js";
import {
  NORMALISER_ID,
  normaliseSolanaTransaction,
  type NormaliseTransaction,
} from "../../solana/normalise.js";
import { REGISTRY_VERSION } from "../../solana/programs.js";
import type { OwnerCache, OwnerResolution, OwnerRpc } from "../../solana/owner-resolution.js";
import { RpcError, parseTransactionResult, type SolanaRpc } from "../../solana/rpc.js";

// ─── Public types ────────────────────────────────────────────────────────────

export type ClaimStatus = "reproduced" | "mismatch" | "unavailable" | "not_checked";

export type CheckMethod =
  | "re-read from the transaction"
  | "recomputed from its inputs and re-derived from the transaction"
  | "re-derived from the transaction";

/** One claim's result. Every text field is fixed wording; expected and found are canonical JSON of claim data. */
export interface ClaimCheck {
  /** The record's claim id. Absent on a row for a claim the transaction gives and the record lacks. */
  claim_id?: string;
  type: ClaimType;
  code: string;
  /** The transaction the claim belongs to, when it belongs to one. */
  signature?: string;
  ix_path?: string;
  formula?: string;
  status: ClaimStatus;
  detail: string;
  /** How a reproduced claim was checked. */
  method?: CheckMethod;
  /** mismatch: the first field that differs, as a path ("value.amount", "provenance.ix_path", "code"). */
  field?: string;
  /** mismatch: what the chain or the recomputation gives for `field` (canonical JSON). */
  expected?: string;
  /** mismatch: what the record holds for `field` (canonical JSON). */
  found?: string;
  /** mismatch: how many fields differ in all. */
  differing_fields?: number;
  /** mismatch: the root claim whose mismatch this one follows from. */
  cause?: string;
  /** unavailable: why (an RPC error code or another fixed word); not_checked: the reason. */
  reason?: string;
  /** not_checked Attributed claims: the source the record names. */
  source?: string;
  /** not_checked Inferred claims: the analyst the record names. */
  analyst_id?: string;
  notes?: string[];
}

export interface RederiveWarning {
  code: "tool_version_differs";
  field: "normaliser" | "decoder_registry" | "formulas";
  record: string;
  verifier: string;
  detail: string;
}

export interface TransactionRead {
  signature: string;
  status: "read" | "not_found" | "unavailable";
  reason?: string;
}

export type StatusCounts = Record<ClaimStatus, number>;

export interface RederiveCounts {
  by_type: Record<ClaimType, StatusCounts>;
  by_status: StatusCounts;
  /** Rows for claims the transaction gives and the record does not have (also counted as mismatch). */
  missing_from_record: number;
}

export interface RederiveResult {
  /** invalid: the record is not a valid trace-manifest/1.0 manifest; nothing was fetched. */
  status: "reproduced" | "mismatch" | "unavailable" | "invalid";
  /** Record claims in record order, then claims missing from the record. Capped per status (see truncated). */
  claims: ClaimCheck[];
  truncated: boolean;
  counts: RederiveCounts;
  warnings: RederiveWarning[];
  transactions: TransactionRead[];
}

export interface RederiveOptions {
  /** Reads subject transactions: getTransaction at finalized, encoding json; createSolanaRpc does that. */
  rpc: Pick<SolanaRpc, "getTransaction">;
  /** The cluster `rpc` serves, when known. If it is not the record's cluster, every read is unavailable. */
  cluster?: ManifestCluster;
  /** The JSON text the manifest was parsed from, when the caller has it: a repeated key is then refused. */
  rawText?: string;
}

// ─── Fixed wording ───────────────────────────────────────────────────────────

/** The unavailable family's text for a read that gave no usable answer; rows add the reason in brackets. */
export const UNAVAILABLE_DETAIL = "could not check: no usable answer from the data source";
export const NOT_CHECKED_REASON = "outside independent verification";

const DIFFERS =
  "does not match the chain: the transaction read again gives this claim with a different";

const TEXT = {
  reproducedObserved: "reproduced: the transaction read again gives the same claim",
  reproducedRecomputed:
    "reproduced: recomputed from its inputs, and the transaction read again gives the same claim",
  reproducedRederived: "reproduced: re-derived from the transaction, which gives the same claim",
  notFound: "does not match the chain: transaction not found at finalized",
  differs: `${DIFFERS} value`,
  notProduced: "does not match the chain: the transaction read again gives no such claim",
  missingFromRecord:
    "does not match the chain: the transaction gives a claim the record does not have",
  otherReference:
    "does not match the chain: it refers to a different claim than the transaction read again gives",
  otherInputs:
    "does not match the chain: the transaction read again gives this claim from other inputs",
  dependsOn: "does not match the chain: it depends on a claim that does not match the chain",
  noTransaction: "does not match: it is not computed from claims of one transaction",
  inputTwice: "does not match its inputs: an input is listed twice",
  notChecked: `not checked: ${NOT_CHECKED_REASON}`,
  label: "not checked: label from the Refrnce program registry, not independently checked",
  unknownFormula: "could not check: this verifier does not know the formula",
  unknownFormulaGiven:
    "could not check: the record uses a formula this verifier does not know, so this claim the transaction gives cannot be compared",
} as const;

/** "with a different <field>" for a difference outside the value: the last part of the field path. */
const DIFFERS_IN: Readonly<Record<string, string>> = Object.freeze(
  Object.fromEntries(
    ["type", "code", "signature", "slot", "ix_path", "decoder", "formula"].map((f) => [
      f,
      `${DIFFERS} ${f}`,
    ]),
  ),
);

/** The detail of a "differs" mismatch on `field` (a path such as value.amount or provenance.ix_path). */
function differsText(field: string): string {
  if (field === "value" || field.startsWith("value.") || field.startsWith("value["))
    return TEXT.differs;
  return DIFFERS_IN[field.slice(field.lastIndexOf(".") + 1)] ?? TEXT.differs;
}

const RECOMPUTE_TEXT: Readonly<Record<string, string>> = {
  value_mismatch: "does not match its inputs: recomputing it gives a different value",
  no_output: "does not match its inputs: recomputing it gives no such claim",
  inputs_mismatch:
    "does not match its inputs: it does not list exactly the claims it is computed from",
  code_mismatch: "does not match its inputs: its formula does not produce a claim of this code",
  missing_input: "does not match its inputs: an input it names is missing",
  duplicate_id: "does not match its inputs: an input it names is missing",
  not_derived: "does not match its inputs: it is not a Derived claim",
  formula_input: "does not match its inputs: an input is not in the shape its formula reads",
};

/** Why a read gave no usable answer, spelled out. Keys are the `reason` codes on unavailable rows. */
const REASON_TEXT: Readonly<Record<string, string>> = {
  timeout: "the request timed out",
  network: "the data source could not be reached",
  http: "the data source answered with an HTTP error",
  protocol: "the data source gave an answer that is not valid JSON-RPC",
  unconfirmed: "not found was not confirmed by a second endpoint",
  malformed: "the answer is not a transaction in the expected form",
  wrong_transaction: "the answer is about another transaction",
  no_meta: "the answer has no transaction status and balances",
  unreadable_answer: "the answer could not be read as a transaction",
  no_rpc: "no data source was given",
  different_cluster: "the data source serves another cluster than the record names",
  not_read: "the transaction was not read",
  failed: "the request failed",
};

/** The text an unavailable row or check gives for a read that failed with `reason` (a REASON_TEXT key). */
export const unavailableDetail = (reason: string): string =>
  `${UNAVAILABLE_DETAIL} (${REASON_TEXT[reason] ?? REASON_TEXT.failed})`;

const NOTE = {
  tooling:
    "tool version differs: this verifier runs other tool versions than the record names, which is a likely cause",
  currentState: "owner from current state is Attributed: taken from the record, not re-checked",
  currentStateReason:
    "the current-state part of an owner reason is the issuer's own lookup, not re-checked",
} as const;

/** Every wording a person can read, for the verify page and the tests that pin it.  */
export const REDERIVE_TEXT = Object.freeze({
  ...TEXT,
  unavailable: UNAVAILABLE_DETAIL,
  differsIn: DIFFERS_IN,
  recompute: Object.freeze({ ...RECOMPUTE_TEXT }),
  reasons: Object.freeze({ ...REASON_TEXT }),
  notes: Object.freeze({ ...NOTE }),
});

/** Rows kept per status; counts are never capped. */
export const MAX_ROWS_PER_STATUS = 500;
/** Diagnostic pairing is skipped beyond this many comparisons per transaction.  */
const MAX_DIAGNOSTIC_COMPARISONS = 50_000;
const MAX_SHOWN_CHARS = 500;
const FETCH_CONCURRENCY = 4;
const REF_PLACEHOLDER = "(claim reference)";
const ABSENT = "(absent)";

// ─── Small helpers ───────────────────────────────────────────────────────────

type Fields = Record<string, ClaimValue>;

const isRecord = (v: unknown): v is Fields =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const shown = (text: string): string =>
  text.length > MAX_SHOWN_CHARS ? `${text.slice(0, MAX_SHOWN_CHARS)}…` : text;

function refFieldsOf(c: Claim): [string, string][] {
  const out: [string, string][] = [];
  if (!isRecord(c.value)) return out;
  for (const f of CLAIM_ID_VALUE_FIELDS) {
    const v = c.value[f];
    if (typeof v === "string") out.push([f, v]);
  }
  return out;
}

const inputsOf = (c: Claim): string[] =>
  c.provenance.type === "derived" ? c.provenance.inputs : [];

/** Claim ids in numbering order (c-0002 before c-0010 before c-10000). */
const byIdOrder = (a: string, b: string): number =>
  a.length - b.length || (a < b ? -1 : a > b ? 1 : 0);

/** Every claim id a claim relies on: its reference fields, then its Derived inputs. */
const dependenciesOf = (c: Claim): string[] => [
  ...refFieldsOf(c).map(([, id]) => id),
  ...inputsOf(c),
];

/** Flattens a JSON value into path -> canonical JSON of each leaf (empty arrays and objects are leaves). */
function flatten(value: unknown, path: string, out: Map<string, string>): void {
  if (Array.isArray(value) && value.length > 0) {
    value.forEach((v, i) => flatten(v, `${path}[${i}]`, out));
  } else if (isRecord(value) && Object.keys(value).length > 0) {
    for (const k of Object.keys(value).sort())
      flatten(value[k], path === "" ? k : `${path}.${k}`, out);
  } else out.set(path, canonicalizeJcs(value));
}

interface Difference {
  field: string;
  expected: string;
  found: string;
  count: number;
}

/** The differing leaves of two flattened forms, the first by path order. undefined when they are equal. */
function difference(
  expected: Map<string, string>,
  found: Map<string, string>,
): Difference | undefined {
  const paths = [...new Set([...expected.keys(), ...found.keys()])].sort();
  const differing = paths.filter((p) => expected.get(p) !== found.get(p));
  if (differing.length === 0) return undefined;
  const first = differing[0];
  return {
    field: first,
    expected: shown(expected.get(first) ?? ABSENT),
    found: shown(found.get(first) ?? ABSENT),
    count: differing.length,
  };
}

function countDifferences(a: Map<string, string>, b: Map<string, string>): number {
  let n = 0;
  for (const [k, v] of a) if (b.get(k) !== v) n++;
  for (const k of b.keys()) if (!a.has(k)) n++;
  return n;
}

// ─── Comparison form ─────────────────────────────────────────────────────────

interface Comparable {
  key: string;
  leaves: Map<string, string>;
  notes: string[];
}

/** An owner reason without its last "; " part: the current-state step, when that step was reached. */
function withoutCurrentStatePart(reason: string): string {
  const at = reason.lastIndexOf("; ");
  return at === -1 ? "" : reason.slice(0, at);
}

/**
 * The form two claims are compared in: type, code, the value with references replaced by a placeholder, and the
 * provenance without its references. For a TOKEN_TRANSFER side whose account reached the current-state step
 * (`currentState`), an unresolved owner's reason loses its current-state part (the issuer's own lookup).
 */
function comparable(c: Claim, currentState: ReadonlySet<string>): Comparable {
  const notes: string[] = [];
  let value: ClaimValue = c.value;
  if (isRecord(value)) {
    const copy: Fields = { ...value };
    for (const f of CLAIM_ID_VALUE_FIELDS)
      if (Object.prototype.hasOwnProperty.call(copy, f)) copy[f] = REF_PLACEHOLDER;
    if (c.code === "TOKEN_TRANSFER")
      for (const [side, accountField] of [
        ["from", "source"],
        ["to", "destination"],
      ] as const) {
        const account = copy[accountField];
        if (typeof account !== "string" || !currentState.has(account)) continue;
        const method = copy[`${side}_owner_method`];
        const reason = copy[`${side}_owner_reason`];
        if (method === "current_state") notes.push(NOTE.currentState);
        if (method === "unresolved" && typeof reason === "string") {
          copy[`${side}_owner_reason`] = withoutCurrentStatePart(reason);
          notes.push(NOTE.currentStateReason);
        }
      }
    value = copy;
  }
  const p = c.provenance;
  const provenance =
    p.type === "derived"
      ? { type: p.type, formula: p.formula }
      : p.type === "inferred"
        ? { type: p.type, analyst_id: p.analyst_id }
        : p;
  const form = { type: c.type, code: c.code, value, provenance };
  const leaves = new Map<string, string>();
  flatten(form, "", leaves);
  return { key: canonicalizeJcs(form), leaves, notes: [...new Set(notes)] };
}

// ─── Reading and regenerating one transaction ────────────────────────────────

type Regenerated =
  | { kind: "read"; claims: Claim[]; currentState: Set<string> }
  | { kind: "not_found" }
  | { kind: "unavailable"; reason: string };

type GetTransaction = (signature: string) => Promise<unknown>;

/** What the verifier's owner rpc throws: it never reads current state, it only records who asked. */
class CurrentStateNotReplayed extends Error {
  constructor() {
    super("the verifier does not read current state");
    this.name = "CurrentStateNotReplayed";
  }
}

function seededCache(entries: ReadonlyMap<string, OwnerResolution>): OwnerCache {
  const map = new Map<string, OwnerResolution>(entries);
  return {
    get: (key) => {
      const v = map.get(key);
      return v === undefined ? undefined : { ...v };
    },
    set: (key, value) => {
      map.set(key, { ...value });
    },
    get size() {
      return map.size;
    },
  };
}

// Limits no real transaction can exceed. A transaction is at most 1232 bytes, so instruction data is at most
// ~1700 base58 characters; an answer beyond these limits is refused BEFORE it is decoded (base58 decoding is
// super-linear, so a hostile multi-megabyte data string would otherwise hold the verifier for hours).
const MAX_IX_DATA_CHARS = 2048;
const MAX_ACCOUNT_KEYS = 256;
const MAX_INSTRUCTIONS = 1500;
const MAX_STRING_CHARS = 10_000;

/** Whether an RPC transaction answer stays within what a real transaction can be. Linear in the answer. */
function withinRealLimits(tx: unknown): boolean {
  const t = tx as {
    transaction?: { message?: { accountKeys?: unknown; instructions?: unknown } };
    meta?: { innerInstructions?: unknown; loadedAddresses?: unknown };
  };
  const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
  const message = t.transaction?.message;
  const loaded = t.meta?.loadedAddresses as { writable?: unknown; readonly?: unknown } | undefined;
  const keys =
    arr(message?.accountKeys).length + arr(loaded?.writable).length + arr(loaded?.readonly).length;
  if (keys > MAX_ACCOUNT_KEYS) return false;
  const instructions = [
    ...arr(message?.instructions),
    ...arr(t.meta?.innerInstructions).flatMap((g) =>
      arr((g as { instructions?: unknown } | null)?.instructions),
    ),
  ];
  if (instructions.length > MAX_INSTRUCTIONS) return false;
  for (const ix of instructions) {
    const data = (ix as { data?: unknown } | null)?.data;
    if (typeof data === "string" && data.length > MAX_IX_DATA_CHARS) return false;
  }
  // Every other string, anywhere in the answer.
  const stack: unknown[] = [tx];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v === "string") {
      if (v.length > MAX_STRING_CHARS) return false;
    } else if (Array.isArray(v)) for (const x of v) stack.push(x);
    else if (typeof v === "object" && v !== null) for (const x of Object.values(v)) stack.push(x);
  }
  return true;
}

async function regenerate(
  signature: string,
  getTransaction: GetTransaction,
  seedsFor: (signature: string, accounts: ReadonlySet<string>) => Map<string, OwnerResolution>,
): Promise<Regenerated> {
  let raw: unknown;
  try {
    raw = await getTransaction(signature);
  } catch (e) {
    if (e instanceof RpcError && e.code === "not_found") return { kind: "not_found" };
    return { kind: "unavailable", reason: e instanceof RpcError ? e.code : "failed" };
  }
  const parsed = parseTransactionResult(raw, signature);
  if (!parsed.ok) {
    if (parsed.reason === "not_found") return { kind: "not_found" };
    return { kind: "unavailable", reason: parsed.reason };
  }
  if (parsed.tx.meta === null) return { kind: "unavailable", reason: "no_meta" };
  if (!withinRealLimits(parsed.tx)) return { kind: "unavailable", reason: "unreadable_answer" };
  const tx = parsed.tx as unknown as NormaliseTransaction;

  const currentState = new Set<string>();
  const recorder: OwnerRpc = {
    getAccountInfo: async (account: string) => {
      currentState.add(account);
      throw new CurrentStateNotReplayed();
    },
  };
  try {
    let out = await normaliseSolanaTransaction(tx, { rpc: recorder });
    const seeds = seedsFor(signature, currentState);
    if (seeds.size > 0)
      out = await normaliseSolanaTransaction(tx, { rpc: recorder, cache: seededCache(seeds) });
    if (out.signature !== signature) return { kind: "unavailable", reason: "wrong_transaction" };
    // Every real transaction gives at least its TX_FEE claim: an answer that gives none was not read.
    if (out.claims.length === 0) return { kind: "unavailable", reason: "unreadable_answer" };
    return { kind: "read", claims: out.claims, currentState };
  } catch {
    // The normaliser refuses a transaction it cannot read (no fee, a key index out of range...): the answer
    // was not a usable transaction, which says nothing about the record.
    return { kind: "unavailable", reason: "unreadable_answer" };
  }
}

/** Runs `work` over `items` with at most `limit` in flight. Results are keyed, so finishing order does not matter. */
async function pool<T>(items: readonly T[], limit: number, work: (item: T) => Promise<void>) {
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const item = items[next++];
      await work(item);
    }
  });
  await Promise.all(runners);
}

// ─── Validation ──────────────────────────────────────────────────────────────

function readManifest(manifest: unknown, rawText: unknown): Manifest | undefined {
  try {
    if (rawText !== undefined) {
      if (typeof rawText !== "string" || detectDuplicateKeys(rawText).length > 0) return undefined;
      if (canonicalizeJcs(JSON.parse(rawText)) !== canonicalizeJcs(manifest)) return undefined;
    }
    // One read of the caller's object; everything after works on this copy.
    const plain: unknown = JSON.parse(canonicalizeJcs(manifest));
    if (checkManifestRules(plain).length > 0) return undefined;
    const parsed = ManifestSchema.safeParse(plain);
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

// ─── Tooling ─────────────────────────────────────────────────────────────────

/**
 * Every formula this verifier can check: the compute table, the formulas recompute handles on its own, and the
 * two swap warnings it re-derives from the transaction (formulas.ts and normalise.ts keep those names private).
 */
const KNOWN_FORMULAS: ReadonlySet<string> = new Set([
  ...Object.keys(FORMULAS),
  RECONCILE_FORMULA,
  ATA_FORMULA,
  "swap-completeness@1.0.0",
  "swap-leg-reconciliation@1.0.0",
]);

function toolingWarnings(m: Manifest): RederiveWarning[] {
  // What this verifier's builder would list for this record: its own compute table plus the formulas the
  // record cites that this verifier knows. A formula it does not know is never added, so it shows as a difference.
  const cited = m.claims.flatMap((c) =>
    c.provenance.type === "derived" && KNOWN_FORMULAS.has(c.provenance.formula)
      ? [c.provenance.formula]
      : [],
  );
  const running = [...new Set([...Object.keys(FORMULAS), ...cited])].sort();
  const pairs: [RederiveWarning["field"], string, string][] = [
    ["normaliser", m.tooling.normaliser, NORMALISER_ID],
    ["decoder_registry", m.tooling.decoder_registry, REGISTRY_VERSION],
    ["formulas", [...m.tooling.formulas].sort().join(", "), running.join(", ")],
  ];
  return pairs
    .filter(([, record, verifier]) => record !== verifier)
    .map(([field, record, verifier]) => ({
      code: "tool_version_differs" as const,
      field,
      record,
      verifier,
      detail: `tool version differs: the record names ${field} ${record}, this verifier runs ${verifier}`,
    }));
}

// ─── Recompute (C8) ──────────────────────────────────────────────────────────

type Recomputed =
  | { kind: "ok" }
  | { kind: "requires_transaction" }
  | { kind: "failed"; reason: string; diff?: Difference };

/** recompute with the claim and its own inputs only (linear in the record, as in the builder). */
function recomputeOne(c: Claim, byId: ReadonlyMap<string, Claim>): Recomputed {
  const inputs = inputsOf(c).flatMap((id) => {
    const found = byId.get(id);
    return found ? [found] : [];
  });
  try {
    const value = recompute(c, [c, ...inputs]);
    if (canonicalizeJcs(value) === canonicalizeJcs(c.value)) return { kind: "ok" };
    const expected = new Map<string, string>();
    const found = new Map<string, string>();
    flatten({ value }, "", expected);
    flatten({ value: c.value }, "", found);
    const diff = difference(expected, found);
    return { kind: "failed", reason: "value_mismatch", ...(diff ? { diff } : {}) };
  } catch (e) {
    if (e instanceof RecomputeError) {
      if (e.reason === "requires_transaction") return { kind: "requires_transaction" };
      return { kind: "failed", reason: e.reason };
    }
    return { kind: "failed", reason: "formula_input" };
  }
}

// ─── The engine ──────────────────────────────────────────────────────────────

type Own =
  | { status: "reproduced"; method: CheckMethod; detail: string; notes: string[] }
  | { status: "unavailable"; reason: string; notes: string[]; detail?: string }
  | {
      status: "mismatch";
      detail: string;
      diff?: Difference;
      notes: string[];
      /** A mismatch on its own terms that no failing dependency explains (no such transaction, no transaction). */
      final?: boolean;
    }
  | {
      /** Matched, but a dependency it names did not match: decided once that dependency's result is known. */
      status: "deferred";
      method: CheckMethod;
      detail: string;
      notes: string[];
      /** The dependencies it waits on, each with the field that names it and how the record writes it. */
      waitingOn: { id: string; field: string; found: string }[];
    };

type Final = Own | { status: "depends"; cause: string; notes: string[] };

function emptyCounts(): StatusCounts {
  return { reproduced: 0, mismatch: 0, unavailable: 0, not_checked: 0 };
}

function invalidResult(): RederiveResult {
  return {
    status: "invalid",
    claims: [],
    truncated: false,
    counts: {
      by_type: {
        observed: emptyCounts(),
        derived: emptyCounts(),
        attributed: emptyCounts(),
        inferred: emptyCounts(),
      },
      by_status: emptyCounts(),
      missing_from_record: 0,
    },
    warnings: [],
    transactions: [],
  };
}

/**
 * Re-derives every Observed and Derived claim of a manifest from the chain (checks C7 and C8). Never throws. A
 * record that is not a valid manifest gives status "invalid" and no network call is made. See the header.
 */
export async function rederive(
  manifest: unknown,
  options: RederiveOptions,
): Promise<RederiveResult> {
  try {
    // Each option is read once, inside a guard.
    let getTransaction: GetTransaction | undefined;
    let cluster: unknown;
    let rawText: unknown;
    try {
      const rpc = options.rpc;
      const fn: unknown = rpc?.getTransaction;
      if (typeof fn === "function")
        getTransaction = (signature) => (fn as GetTransaction).call(rpc, signature);
      cluster = options.cluster;
      rawText = options.rawText;
    } catch {
      getTransaction = undefined;
    }
    const m = readManifest(manifest, rawText);
    if (!m) return invalidResult();
    return await compare(m, getTransaction, cluster);
  } catch {
    return invalidResult();
  }
}

async function compare(
  m: Manifest,
  getTransaction: GetTransaction | undefined,
  cluster: unknown,
): Promise<RederiveResult> {
  const claims = m.claims;
  const byId = new Map(claims.map((c) => [c.id, c]));
  const recordIndex = new Map(claims.map((c, i) => [c.id, i]));
  const referenced = new Set(claims.flatMap(dependenciesOf));

  // ── Which transaction each claim belongs to.
  const txOf = new Map<string, string | null>();
  for (const c of claims)
    if (c.provenance.type === "observed") txOf.set(c.id, c.provenance.signature);
  // A Derived claim: the one transaction its inputs (followed through other Derived claims) were observed in.
  // Each claim's summary is computed once (memoised, iterative post-order), so a chain of Derived claims is
  // linear. A summary is "" (no transaction), a signature, or null (more than one). An input still being
  // walked (a cycle) adds nothing; a claim in a cycle cannot reproduce anyway, since the transaction gives none.
  const summary = new Map<string, string | null>();
  const join = (a: string | null, b: string | null): string | null =>
    a === null || b === null ? null : a === "" ? b : b === "" || a === b ? a : null;
  const summarise = (root: Claim): string | null => {
    const walking = new Set<string>([root.id]);
    const stack: { c: Claim; i: number; acc: string | null }[] = [{ c: root, i: 0, acc: "" }];
    let result: string | null = "";
    while (stack.length > 0) {
      const top = stack[stack.length - 1];
      const ids = inputsOf(top.c);
      if (top.i < ids.length) {
        const input = byId.get(ids[top.i++]);
        if (input?.provenance.type === "observed")
          top.acc = join(top.acc, input.provenance.signature);
        else if (input?.provenance.type === "derived") {
          const known = summary.get(input.id);
          if (known !== undefined) top.acc = join(top.acc, known);
          else if (!walking.has(input.id)) {
            walking.add(input.id);
            stack.push({ c: input, i: 0, acc: "" });
          }
        }
      } else {
        stack.pop();
        summary.set(top.c.id, top.acc);
        if (stack.length > 0)
          stack[stack.length - 1].acc = join(stack[stack.length - 1].acc, top.acc);
        else result = top.acc;
      }
    }
    return result;
  };
  for (const c of claims)
    if (c.provenance.type === "derived") {
      const s = summary.has(c.id) ? summary.get(c.id)! : summarise(c);
      txOf.set(c.id, s === null || s === "" ? null : s);
    }
  // An Attributed owner claim belongs to the transaction whose transfers point at it.
  for (const c of claims) {
    const sig = txOf.get(c.id);
    if (c.provenance.type !== "observed" || !sig) continue;
    for (const [, id] of refFieldsOf(c)) {
      const target = byId.get(id);
      if (target?.type === "attributed" && !txOf.has(id)) txOf.set(id, sig);
    }
  }

  // ── The current-state owners the record states, per transaction and account.
  const seedsFor = (signature: string, accounts: ReadonlySet<string>) => {
    const seeds = new Map<string, OwnerResolution>();
    if (accounts.size === 0) return seeds;
    for (const c of claims) {
      if (c.code !== "TOKEN_TRANSFER" || txOf.get(c.id) !== signature || !isRecord(c.value))
        continue;
      for (const [side, accountField] of [
        ["from", "source"],
        ["to", "destination"],
      ] as const) {
        const account = c.value[accountField];
        if (typeof account !== "string" || !accounts.has(account)) continue;
        if (c.value[`${side}_owner_method`] !== "current_state") continue;
        const ref = c.value[`${side}_owner_claim`];
        const owner = typeof ref === "string" ? byId.get(ref) : undefined;
        if (!owner || owner.code !== "OWNER_CURRENT_STATE" || !isRecord(owner.value)) continue;
        const v = owner.value;
        if (
          v.account !== account ||
          typeof v.owner !== "string" ||
          typeof v.slot !== "number" ||
          !Number.isSafeInteger(v.slot) ||
          typeof v.caveat !== "string"
        )
          continue;
        seeds.set(`${signature}:${account}`, {
          owner: v.owner,
          method: "current_state",
          slot: v.slot,
          caveat: v.caveat,
        });
      }
    }
    return seeds;
  };

  // ── Read every transaction.
  const signatures = m.subject.signatures;
  const reads = new Map<string, Regenerated>();
  if (cluster !== undefined && cluster !== m.subject.cluster) {
    for (const s of signatures) reads.set(s, { kind: "unavailable", reason: "different_cluster" });
  } else if (!getTransaction) {
    for (const s of signatures) reads.set(s, { kind: "unavailable", reason: "no_rpc" });
  } else {
    await pool(signatures, FETCH_CONCURRENCY, async (s) => {
      reads.set(s, await regenerate(s, getTransaction, seedsFor));
    });
  }

  // ── Pair record claims with regenerated claims, per transaction, one to one.
  const regenOf = new Map<string, { signature: string; claim: Claim }>();
  const extras: ClaimCheck[] = [];
  const recordNotes = new Map<string, string[]>();
  const diagnostics = new Map<string, Difference>();

  const bySignature = new Map<string, Claim[]>();
  for (const c of claims) {
    const sig = txOf.get(c.id);
    if (!sig) continue;
    const list = bySignature.get(sig);
    if (list) list.push(c);
    else bySignature.set(sig, [c]);
  }

  for (const signature of signatures) {
    const read = reads.get(signature);
    if (read?.kind !== "read") continue;
    const mine = (bySignature.get(signature) ?? []).filter((c) => c.type !== "inferred");
    // A PROGRAM_LABEL is per program, not per transaction (the builder merges them): not compared here.
    const regen = read.claims.filter((c) => c.code !== "PROGRAM_LABEL" && c.type !== "inferred");

    const forms = new Map<Claim, Comparable>();
    for (const c of [...mine, ...regen]) forms.set(c, comparable(c, read.currentState));
    for (const c of mine) recordNotes.set(c.id, forms.get(c)!.notes);

    const waiting = new Map<string, Claim[]>();
    for (const r of regen) {
      const k = forms.get(r)!.key;
      const list = waiting.get(k);
      if (list) list.push(r);
      else waiting.set(k, [r]);
    }
    // Identical claims pair one to one. Claims other claims rely on pair first, then by id (the builder numbers
    // in order), so of an original and an added copy the copy is the one named, and the claims that rely on
    // the original are not dragged down with it.
    const pairingOrder = [...mine].sort(
      (a, b) =>
        Number(referenced.has(b.id)) - Number(referenced.has(a.id)) || byIdOrder(a.id, b.id),
    );
    const unpairedRecord: Claim[] = [];
    for (const c of pairingOrder) {
      const partner = waiting.get(forms.get(c)!.key)?.shift();
      if (partner) regenOf.set(c.id, { signature, claim: partner });
      else if (c.type !== "attributed") unpairedRecord.push(c);
    }
    unpairedRecord.sort((a, b) => recordIndex.get(a.id)! - recordIndex.get(b.id)!);
    // A record claim whose formula this verifier does not know: the Derived claims the transaction gives
    // cannot be set against the record, so those left over are "could not check", not missing.
    const unknownFormulaHere = mine.some(
      (c) => c.provenance.type === "derived" && !KNOWN_FORMULAS.has(c.provenance.formula),
    );
    // A regenerated Attributed claim exists only when it was seeded from the record: it is not reported.
    const unpairedRegen = [...waiting.values()].flat().filter((r) => r.type !== "attributed");

    // Diagnostics, for the message only: each unmatched record claim is set beside the closest unmatched
    // regenerated claim of the same type and the same code (or, if Observed, the same ix_path).
    const used = new Set<Claim>();
    if (unpairedRecord.length * unpairedRegen.length <= MAX_DIAGNOSTIC_COMPARISONS)
      for (const c of unpairedRecord) {
        if (c.provenance.type === "derived" && !KNOWN_FORMULAS.has(c.provenance.formula)) continue;
        const fc = forms.get(c)!;
        let best: { r: Claim; n: number } | undefined;
        for (const r of unpairedRegen) {
          if (used.has(r) || r.type !== c.type) continue;
          const sameSpot =
            r.code === c.code ||
            (c.provenance.type === "observed" &&
              r.provenance.type === "observed" &&
              r.provenance.ix_path === c.provenance.ix_path);
          if (!sameSpot) continue;
          const n = countDifferences(forms.get(r)!.leaves, fc.leaves);
          if (!best || n < best.n) best = { r, n };
        }
        if (best) {
          used.add(best.r);
          const d = difference(forms.get(best.r)!.leaves, fc.leaves);
          if (d) diagnostics.set(c.id, d);
        }
      }
    for (const r of unpairedRegen) {
      if (used.has(r)) continue;
      const p = r.provenance;
      const base = {
        type: r.type,
        code: r.code,
        signature,
        ...(p.type === "observed" ? { ix_path: p.ix_path } : {}),
        ...(p.type === "derived" ? { formula: p.formula } : {}),
      };
      if (unknownFormulaHere && r.type === "derived")
        extras.push({
          ...base,
          status: "unavailable",
          detail: TEXT.unknownFormulaGiven,
          reason: "unknown_formula",
        });
      else
        extras.push({
          ...base,
          status: "mismatch",
          detail: TEXT.missingFromRecord,
          expected: shown(canonicalizeJcs({ value: r.value })),
        });
    }
  }

  // ── Each Observed and Derived record claim on its own terms, before its dependencies are known.
  const regenIdIn = (recordId: string, signature: string): string | undefined => {
    const p = regenOf.get(recordId);
    return p && p.signature === signature ? p.claim.id : undefined;
  };
  /** A reported claim (Observed or Derived) whose own result will say why it did not match. */
  const reported = (id: string): boolean => {
    const t = byId.get(id)?.type;
    return t === "observed" || t === "derived";
  };

  const own = new Map<string, Own>();
  for (const c of claims) {
    if (c.type === "attributed" || c.type === "inferred") continue;
    const notes = recordNotes.get(c.id) ?? [];
    const p = c.provenance;
    if (p.type === "derived" && !KNOWN_FORMULAS.has(p.formula)) {
      // Another tool version, not tampering: the formula name is shown only when it cannot read as a verdict.
      const named = /match/i.test(p.formula) ? "" : ` ${shown(p.formula)}`;
      own.set(c.id, {
        status: "unavailable",
        reason: "unknown_formula",
        detail: `${TEXT.unknownFormula}${named}`,
        notes,
      });
      continue;
    }
    if (p.type === "derived" && new Set(p.inputs).size !== p.inputs.length) {
      own.set(c.id, {
        status: "mismatch",
        detail: TEXT.inputTwice,
        diff: {
          field: "provenance.inputs",
          expected: REF_PLACEHOLDER,
          found: shown(canonicalizeJcs(p.inputs)),
          count: 1,
        },
        notes,
      });
      continue;
    }
    const sig = txOf.get(c.id) ?? null;
    if (sig === null) {
      own.set(c.id, { status: "mismatch", detail: TEXT.noTransaction, notes, final: true });
      continue;
    }
    let method: CheckMethod = "re-read from the transaction";
    let okDetail: string = TEXT.reproducedObserved;
    if (c.type === "derived") {
      const rc = recomputeOne(c, byId);
      if (rc.kind === "failed") {
        own.set(c.id, {
          status: "mismatch",
          detail: RECOMPUTE_TEXT[rc.reason] ?? RECOMPUTE_TEXT.formula_input,
          ...(rc.diff ? { diff: rc.diff } : {}),
          ...(rc.reason === "inputs_mismatch"
            ? {
                diff: {
                  field: "provenance.inputs",
                  expected: REF_PLACEHOLDER,
                  found: shown(canonicalizeJcs(inputsOf(c))),
                  count: 1,
                },
              }
            : {}),
          notes,
        });
        continue;
      }
      method =
        rc.kind === "ok"
          ? "recomputed from its inputs and re-derived from the transaction"
          : "re-derived from the transaction";
      okDetail = rc.kind === "ok" ? TEXT.reproducedRecomputed : TEXT.reproducedRederived;
    }
    const read = reads.get(sig);
    if (!read || read.kind === "unavailable") {
      own.set(c.id, {
        status: "unavailable",
        reason: read?.kind === "unavailable" ? read.reason : "not_read",
        notes,
      });
      continue;
    }
    if (read.kind === "not_found") {
      own.set(c.id, { status: "mismatch", detail: TEXT.notFound, notes, final: true });
      continue;
    }
    const partner = regenOf.get(c.id);
    if (!partner) {
      const d = diagnostics.get(c.id);
      own.set(c.id, {
        status: "mismatch",
        detail: d ? differsText(d.field) : TEXT.notProduced,
        ...(d ? { diff: d } : {}),
        notes,
      });
      continue;
    }
    // References: each must resolve, through the pairing, to the claim the regenerated one points at. A
    // reference to a reported claim that did not match waits for that claim's result.
    const waitingOn: { id: string; field: string; found: string }[] = [];
    let problem: Own | undefined;
    const theirValue = isRecord(partner.claim.value) ? partner.claim.value : {};
    for (const [field, target] of refFieldsOf(c)) {
      const mapped = regenIdIn(target, sig);
      if (mapped === undefined && reported(target))
        waitingOn.push({ id: target, field: `value.${field}`, found: target });
      else if (mapped === undefined || mapped !== theirValue[field]) {
        problem = {
          status: "mismatch",
          detail: TEXT.otherReference,
          diff: { field: `value.${field}`, expected: REF_PLACEHOLDER, found: target, count: 1 },
          notes,
        };
        break;
      }
    }
    if (!problem && c.provenance.type === "derived") {
      const mapped: string[] = [];
      let complete = true;
      for (const id of c.provenance.inputs) {
        const r = regenIdIn(id, sig);
        if (r !== undefined) mapped.push(r);
        else if (reported(id)) {
          waitingOn.push({
            id,
            field: "provenance.inputs",
            found: shown(canonicalizeJcs(c.provenance.inputs)),
          });
          complete = false;
        } else mapped.push(`(unmatched ${id})`);
      }
      const theirs =
        partner.claim.provenance.type === "derived" ? partner.claim.provenance.inputs : [];
      const same = (a: string[], b: string[]) =>
        [...new Set(a)].sort().join(",") === [...new Set(b)].sort().join(",");
      if (complete && !same(mapped, theirs))
        problem = {
          status: "mismatch",
          detail: TEXT.otherInputs,
          diff: {
            field: "provenance.inputs",
            expected: REF_PLACEHOLDER,
            found: shown(canonicalizeJcs(c.provenance.inputs)),
            count: 1,
          },
          notes,
        };
    }
    if (problem) own.set(c.id, problem);
    else if (waitingOn.length > 0)
      own.set(c.id, { status: "deferred", method, detail: okDetail, notes, waitingOn });
    else own.set(c.id, { status: "reproduced", method, detail: okDetail, notes });
  }

  // ── Dependencies, in dependency order (an iterative depth-first walk; a cycle edge is ignored, so the first
  // claim of a cycle is decided on its own terms). A claim that relies on a mismatched claim is a mismatch whose
  // cause is that claim's root.
  const order: string[] = [];
  const state = new Map<string, 1 | 2>();
  for (const start of own.keys()) {
    if (state.has(start)) continue;
    state.set(start, 1);
    const stack: { id: string; deps: string[]; i: number }[] = [
      { id: start, deps: dependenciesOf(byId.get(start)!), i: 0 },
    ];
    while (stack.length > 0) {
      const top = stack[stack.length - 1];
      if (top.i < top.deps.length) {
        const d = top.deps[top.i++];
        if (!state.has(d) && own.has(d)) {
          state.set(d, 1);
          stack.push({ id: d, deps: dependenciesOf(byId.get(d)!), i: 0 });
        }
      } else {
        state.set(top.id, 2);
        order.push(top.id);
        stack.pop();
      }
    }
  }
  const finals = new Map<string, Final>();
  const isMismatch = (f: Final | undefined) => f?.status === "mismatch" || f?.status === "depends";
  const rootOf = (id: string): string => {
    const f = finals.get(id);
    return f?.status === "depends" ? f.cause : id;
  };
  for (const id of order) {
    const o = own.get(id)!;
    let result: Final = o;
    if (!(o.status === "mismatch" && o.final)) {
      const failing = dependenciesOf(byId.get(id)!).find((d) => isMismatch(finals.get(d)));
      if (failing !== undefined)
        result = { status: "depends", cause: rootOf(failing), notes: o.notes };
      else if (o.status === "deferred") {
        // Every awaited dependency is decided and none is a mismatch. A claim of this same transaction that did
        // not pair would be a mismatch, so each awaited one lies in another transaction (or closes a cycle). The
        // transaction read again names a claim of its own there, so the reference is wrong whatever that other
        // transaction's read gave: a mismatch even when the other transaction could not be read.
        const first = o.waitingOn[0];
        result = {
          status: "mismatch",
          detail: TEXT.otherReference,
          diff: {
            field: first.field,
            expected: REF_PLACEHOLDER,
            found: first.found,
            count: o.waitingOn.length,
          },
          notes: o.notes,
        };
      }
    }
    finals.set(id, result);
  }

  // ── Rows.
  const warnings = toolingWarnings(m);
  const toolingDiffers = warnings.length > 0;
  const rows: ClaimCheck[] = [];
  for (const c of claims) {
    const p = c.provenance;
    const sig = txOf.get(c.id);
    const base: ClaimCheck = {
      claim_id: c.id,
      type: c.type,
      code: c.code,
      ...(sig ? { signature: sig } : {}),
      ...(p.type === "observed" ? { ix_path: p.ix_path } : {}),
      ...(p.type === "derived" ? { formula: p.formula } : {}),
      status: "not_checked",
      detail: TEXT.notChecked,
    };
    if (c.type === "attributed" || c.type === "inferred") {
      base.reason = NOT_CHECKED_REASON;
      if (c.code === "PROGRAM_LABEL") base.detail = TEXT.label;
      if (p.type === "attributed") base.source = p.source;
      if (p.type === "inferred") base.analyst_id = p.analyst_id;
      rows.push(base);
      continue;
    }
    const f = finals.get(c.id)!;
    if (f.status === "depends") {
      rows.push({
        ...base,
        status: "mismatch",
        detail: TEXT.dependsOn,
        cause: f.cause,
        ...notesOf(f.notes, toolingDiffers),
      });
    } else if (f.status === "mismatch") {
      rows.push({
        ...base,
        status: "mismatch",
        detail: f.detail,
        ...(f.diff
          ? {
              field: f.diff.field,
              expected: f.diff.expected,
              found: f.diff.found,
              differing_fields: f.diff.count,
            }
          : {}),
        ...notesOf(f.notes, toolingDiffers),
      });
    } else if (f.status === "unavailable") {
      rows.push({
        ...base,
        status: "unavailable",
        detail: f.detail ?? unavailableDetail(f.reason),
        reason: f.reason,
        ...notesOf(f.notes, false),
      });
    } else {
      rows.push({
        ...base,
        status: "reproduced",
        detail: f.detail,
        method: f.method,
        ...notesOf(f.notes, false),
      });
    }
  }
  for (const e of extras) rows.push({ ...e, ...notesOf([], toolingDiffers) });

  // ── Counts, status, cap.
  const byType: Record<ClaimType, StatusCounts> = {
    observed: emptyCounts(),
    derived: emptyCounts(),
    attributed: emptyCounts(),
    inferred: emptyCounts(),
  };
  const byStatus = emptyCounts();
  for (const r of rows) {
    byType[r.type][r.status] += 1;
    byStatus[r.status] += 1;
  }
  const kept: ClaimCheck[] = [];
  const keptPerStatus = emptyCounts();
  for (const r of rows) {
    if (keptPerStatus[r.status] >= MAX_ROWS_PER_STATUS) continue;
    keptPerStatus[r.status] += 1;
    kept.push(r);
  }
  // Every subject transaction has an outcome, whether or not the record has claims in it: one the chain does
  // not have is a mismatch, one that could not be read leaves the record unchecked. A definite mismatch
  // outranks an unanswered read, as in the verdict (any fail is does_not_match).
  const transactions = signatures.map((signature): TransactionRead => {
    const read = reads.get(signature);
    if (read?.kind === "read") return { signature, status: "read" };
    if (read?.kind === "not_found") return { signature, status: "not_found" };
    return { signature, status: "unavailable", reason: read?.reason ?? "not_read" };
  });
  const anyTx = (s: TransactionRead["status"]) => transactions.some((t) => t.status === s);
  const status: RederiveResult["status"] =
    byStatus.mismatch > 0 || anyTx("not_found")
      ? "mismatch"
      : byStatus.unavailable > 0 || anyTx("unavailable") || transactions.length === 0
        ? "unavailable"
        : "reproduced";

  return {
    status,
    claims: kept,
    truncated: kept.length < rows.length,
    counts: {
      by_type: byType,
      by_status: byStatus,
      missing_from_record: extras.filter((e) => e.status === "mismatch").length,
    },
    warnings,
    transactions,
  };
}

function notesOf(notes: readonly string[], toolingDiffers: boolean): { notes?: string[] } {
  const all = [...new Set([...notes, ...(toolingDiffers ? [NOTE.tooling] : [])])];
  return all.length > 0 ? { notes: all } : {};
}
