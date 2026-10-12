// src/manifest/claim-rules.ts — the claim rules table and guard.
//
// Isomorphic: runs in Node and the browser. No node: imports.
//
// assertClaimAllowed is the guard the normaliser and the builder call before a claim goes into a
// manifest, so a computed number can never be labelled "observed".
import type { Claim, ClaimType } from "./types.js";

export interface ClaimRule {
  readonly code: string;
  readonly type: ClaimType;
  /** True when the verifier re-checks this claim itself (Observed and Derived). */
  readonly rechecked: boolean;
  /** One line explaining the rule. "-" when the rule needs no remark. */
  readonly note: string;
}

/** Which claim types the verifier re-checks. Attributed and Inferred claims are shown with provenance and marked not independently verified. */
export const VERIFIER_RECHECKS: Readonly<Record<ClaimType, boolean>> = Object.freeze(
  // Prototype-free, so an unvalidated key such as "toString" or "__proto__" never reads truthy.
  Object.assign(Object.create(null) as Record<ClaimType, boolean>, {
    observed: true,
    derived: true,
    attributed: false,
    inferred: false,
  }),
);

function rule(code: string, type: ClaimType, note = "-"): ClaimRule {
  return Object.freeze({ code, type, rechecked: VERIFIER_RECHECKS[type], note });
}

/** The signed rules, in sheet order. Frozen: a caller cannot add, remove or change a rule. */
export const CLAIM_RULES: readonly ClaimRule[] = Object.freeze([
  rule("SOL_TRANSFER", "observed"),
  rule("TOKEN_TRANSFER", "observed"),
  rule("TOKEN_MINT", "observed"),
  rule("TOKEN_BURN", "observed"),
  rule("ACCOUNT_CLOSED", "observed"),
  rule(
    "SWAP_EVENT",
    "observed",
    'Worded "Jupiter reported X"; must reconcile to the token transfers',
  ),
  rule("PROGRAM_INVOKED", "observed"),
  rule("TX_FEE", "observed"),
  rule("OWNER_FROM_TX_META", "observed"),
  rule("OWNER_FROM_TX_INSTRUCTION", "observed"),
  rule("OWNER_FROM_ATA_DERIVATION", "derived"),
  rule("NET_FLOW_BY_OWNER_MINT", "derived"),
  rule(
    "EFFECTIVE_RATE",
    "derived",
    "Formula effective_rate@1; registered in the table, not emitted by the normaliser",
  ),
  rule(
    "RECONCILIATION_WARNING",
    "derived",
    "A computed comparison of transfers against balance deltas",
  ),
  rule(
    "OWNER_CURRENT_STATE",
    "attributed",
    'Source "RPC state at slot N"; never overrides transaction evidence',
  ),
  rule("PROGRAM_LABEL", "attributed"),
  rule("ENTITY_LABEL", "attributed"),
  rule("ANALYST_FINDING", "inferred"),
]);

/** Statement code to its one allowed claim type. Frozen and prototype-free, so an inherited key never reads as a code. */
export const CLAIM_TYPE_BY_CODE: Readonly<Record<string, ClaimType>> = Object.freeze(
  Object.assign(
    Object.create(null) as Record<string, ClaimType>,
    Object.fromEntries(CLAIM_RULES.map((r) => [r.code, r.type])),
  ),
);

/** The allowed claim type for a code, or undefined when the code is not in the rules. */
export function claimTypeForCode(code: string): ClaimType | undefined {
  // A non-string key would be coerced by the lookup (an object whose toString answers "SOL_TRANSFER").
  if (typeof code !== "string") return undefined;
  return CLAIM_TYPE_BY_CODE[code];
}

// ─── Guard ───────────────────────────────────────────────────────────────────

const MAX_CODE_CHARS_IN_MESSAGE = 64;

const NON_STRING = "<non-string>";

/** Total: never throws. A string is clipped and escaped; anything else prints a fixed placeholder, never its content. */
function shown(text: unknown): string {
  if (typeof text !== "string") return JSON.stringify(NON_STRING);
  const clipped =
    text.length > MAX_CODE_CHARS_IN_MESSAGE
      ? `${text.slice(0, MAX_CODE_CHARS_IN_MESSAGE)}...`
      : text;
  // JSON.stringify leaves U+2028 and U+2029 raw; escape them so a code cannot add a line break.
  return JSON.stringify(clipped)
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/** Thrown by assertClaimAllowed. `reason` says which rule failed; the message never contains the claim value. */
export class ClaimRuleError extends Error {
  readonly reason: "unknown_code" | "type_mismatch";
  readonly code: string;
  /** The type the rules allow for this code. Absent for an unknown code. */
  readonly expected?: ClaimType;
  /** The type the claim carried. */
  readonly actual: string;

  constructor(
    reason: "unknown_code" | "type_mismatch",
    code: unknown,
    actual: unknown,
    expected?: ClaimType,
  ) {
    super(
      reason === "unknown_code"
        ? `claim code ${shown(code)} is not in the claim rules (claim type ${shown(actual)})`
        : `claim code ${shown(code)} must be type "${expected}" but the claim is type ${shown(actual)}`,
    );
    this.name = "ClaimRuleError";
    this.reason = reason;
    this.code = typeof code === "string" ? code : NON_STRING;
    this.actual = typeof actual === "string" ? actual : NON_STRING;
    if (expected !== undefined) this.expected = expected;
  }
}

/**
 * Throws ClaimRuleError when the claim's code is not in the rules, or its type differs from the one
 * type the rules allow for that code. Reads only `code` and `type`; the value is never inspected or printed.
 */
export function assertClaimAllowed(claim: Pick<Claim, "code" | "type">): void {
  // Read each field exactly once; judge and report those same locals, never the claim again. A getter or
  // Proxy that answers differently on a second read cannot make the message describe another claim.
  // A null or undefined claim has no code and no type. A getter that throws propagates: it never passes.
  const code: unknown = claim == null ? undefined : claim.code;
  const type: unknown = claim == null ? undefined : claim.type;
  if (typeof code !== "string") throw new ClaimRuleError("unknown_code", code, type);
  const expected = claimTypeForCode(code);
  if (expected === undefined) throw new ClaimRuleError("unknown_code", code, type);
  if (type !== expected) throw new ClaimRuleError("type_mismatch", code, type, expected);
}
