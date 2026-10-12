// Derived formulas. A Derived claim is a computed number, so the rule that matters is
// that anyone holding only its input claims can compute it again and get the same bytes. These tests
// exist to catch the ways that could go wrong silently:
//   - an amount parsed as a float or by a lenient parser (BigInt("0x10") is 16, BigInt("") is 0);
//   - a signed net flow rendered as "-0", or an amount near the u64 maximum losing digits;
//   - a failed transfer counted as a movement, or an unresolved owner dropped instead of shown;
//   - a recompute that quietly uses a claim that is not one of the listed inputs;
//   - a reconciliation that passes because both sides were computed the same wrong way.
// No network. Claims here are hand-made, in the shape the normaliser emits.
import { describe, expect, it } from "vitest";
import {
  ATA_FORMULA,
  EFFECTIVE_RATE_FORMULA,
  FORMULAS,
  FormulaInputError,
  NATIVE_ASSET,
  NET_FLOW_FORMULA,
  RECONCILE_FORMULA,
  NET_FLOW_BASIS_TOKEN,
  RecomputeError,
  WRAPPED_SOL_MINT,
  effectiveRate,
  netFlow,
  reconcileBalances,
  reconciliationOutputs,
  recompute,
  type ChainBalances,
  type FormulaClaim,
} from "../formulas.js";
import { claimTypeForCode } from "../claim-rules.js";
import type { Claim, ClaimValue } from "../types.js";

const U64_MAX = "18446744073709551615";
const MINT_X = "MintXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const MINT_Y = "MintYyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

// ─── Builders ────────────────────────────────────────────────────────────────

interface TransferOptions {
  id: string;
  source: string;
  destination: string;
  amount: string;
  mint?: string;
  fromOwner?: string;
  toOwner?: string;
  fromMethod?: string;
  toMethod?: string;
  failed?: boolean;
  ix?: string;
}

function observed(ix: string): FormulaClaim["provenance"] {
  return { type: "observed", signature: "sig", slot: 1, ix_path: ix, decoder: "test@1" };
}

function tokenTransfer(o: TransferOptions): FormulaClaim {
  return {
    id: o.id,
    code: "TOKEN_TRANSFER",
    value: {
      instruction: "transfer",
      source: o.source,
      destination: o.destination,
      authority: "authority",
      amount: o.amount,
      mint: o.mint ?? MINT_X,
      failed: o.failed ?? false,
      from_owner: o.fromOwner ?? "unresolved",
      from_owner_method: o.fromMethod ?? (o.fromOwner === undefined ? "unresolved" : "tx_meta"),
      to_owner: o.toOwner ?? "unresolved",
      to_owner_method: o.toMethod ?? (o.toOwner === undefined ? "unresolved" : "tx_meta"),
    },
    provenance: observed(o.ix ?? "1"),
  };
}

function solTransfer(
  id: string,
  from: string,
  to: string,
  lamports: string,
  failed = false,
  ix = "1",
): FormulaClaim {
  return {
    id,
    code: "SOL_TRANSFER",
    value: { instruction: "transfer", from, to, lamports, failed },
    provenance: observed(ix),
  };
}

function swapEvent(id: string, input: string, output: string, failed = false): FormulaClaim {
  return {
    id,
    code: "SWAP_EVENT",
    value: {
      amm: "amm",
      input_mint: MINT_X,
      input_amount: input,
      output_mint: MINT_Y,
      output_amount: output,
      event: "swap_event",
      leg_index: 0,
      failed,
    },
    provenance: observed("2.3"),
  };
}

/** What the normaliser does with one formula output: a Derived claim whose inputs are claim IDs. */
function asClaim(
  id: string,
  formula: string,
  out: { code: string; value: Record<string, ClaimValue>; inputs: string[] },
): Claim {
  return {
    id,
    type: "derived",
    code: out.code,
    value: out.value,
    provenance: { type: "derived", formula, inputs: out.inputs },
  };
}

const netOf = (claims: readonly FormulaClaim[], owner: string, mint: string) => {
  const hit = netFlow(claims).find((o) => o.value.owner === owner && o.value.mint === mint);
  return hit?.value.net;
};

// ─── net_flow@1 ──────────────────────────────────────────────────────────────

describe("net_flow@1", () => {
  const swap: FormulaClaim[] = [
    tokenTransfer({
      id: "c-0001",
      source: "acctA1",
      destination: "acctB1",
      amount: "100",
      mint: MINT_X,
      fromOwner: "ownerA",
      toOwner: "ownerB",
    }),
    tokenTransfer({
      id: "c-0002",
      source: "acctB2",
      destination: "acctA2",
      amount: "98",
      mint: MINT_Y,
      fromOwner: "ownerB",
      toOwner: "ownerA",
    }),
  ];

  it("returns one NET_FLOW_BY_OWNER_MINT per owner and mint, signed, with the contributing claims as inputs", () => {
    const out = netFlow(swap);
    expect(out.map((o) => o.code)).toEqual(Array(4).fill("NET_FLOW_BY_OWNER_MINT"));
    expect(out.map((o) => o.value)).toEqual([
      { owner: "ownerA", mint: MINT_X, net: "-100", basis: NET_FLOW_BASIS_TOKEN },
      { owner: "ownerA", mint: MINT_Y, net: "98", basis: NET_FLOW_BASIS_TOKEN },
      { owner: "ownerB", mint: MINT_X, net: "100", basis: NET_FLOW_BASIS_TOKEN },
      { owner: "ownerB", mint: MINT_Y, net: "-98", basis: NET_FLOW_BASIS_TOKEN },
    ]);
    expect(out[0].inputs).toEqual(["c-0001"]);
    expect(out[1].inputs).toEqual(["c-0002"]);
    // The code is the signed rules' Derived code, so the builder accepts it.
    expect(claimTypeForCode("NET_FLOW_BY_OWNER_MINT")).toBe("derived");
  });

  it("is registered under net_flow@1 and is the same pure function", () => {
    expect(FORMULAS[NET_FLOW_FORMULA]).toBe(netFlow);
    expect(NET_FLOW_FORMULA).toBe("net_flow@1");
  });

  it("an owner who both sends and receives the same amount nets to the string 0, never -0", () => {
    const out = netFlow([
      tokenTransfer({
        id: "c-0001",
        source: "a1",
        destination: "b1",
        amount: "50",
        fromOwner: "ownerA",
        toOwner: "ownerB",
      }),
      tokenTransfer({
        id: "c-0002",
        source: "b1",
        destination: "a1",
        amount: "50",
        fromOwner: "ownerB",
        toOwner: "ownerA",
      }),
    ]);
    expect(out.map((o) => o.value.net)).toEqual(["0", "0"]);
    for (const o of out) expect(Object.is(Number(o.value.net), -0)).toBe(false);
  });

  it("a negative net flow is a plain decimal string with a leading minus", () => {
    expect(netOf(swap, "ownerA", MINT_X)).toBe("-100");
    expect(netOf(swap, "ownerB", MINT_Y)).toBe("-98");
  });

  it("keeps every digit near the u64 maximum, and sums that go beyond it", () => {
    const big = tokenTransfer({
      id: "c-0001",
      source: "a1",
      destination: "b1",
      amount: U64_MAX,
      fromOwner: "ownerA",
      toOwner: "ownerB",
    });
    expect(netOf([big], "ownerA", MINT_X)).toBe(`-${U64_MAX}`);
    expect(netOf([big], "ownerB", MINT_X)).toBe(U64_MAX);
    const twice = [big, { ...big, id: "c-0002", provenance: observed("2") }];
    // 2 * (2^64 - 1): more than a u64 and far more than 2^53, so a Number would be wrong.
    expect(netOf(twice, "ownerB", MINT_X)).toBe("36893488147419103230");
    expect(netOf(twice, "ownerA", MINT_X)).toBe("-36893488147419103230");
    // 2^53 + 1 is the first integer a double cannot hold.
    const odd = tokenTransfer({
      id: "c-0003",
      source: "a1",
      destination: "b1",
      amount: "9007199254740993",
      fromOwner: "ownerA",
      toOwner: "ownerB",
    });
    expect(netOf([odd], "ownerB", MINT_X)).toBe("9007199254740993");
  });

  it("an owner with several token accounts is one owner; different mints stay separate", () => {
    const out = netFlow([
      tokenTransfer({
        id: "c-0001",
        source: "a1",
        destination: "b1",
        amount: "10",
        fromOwner: "ownerA",
        toOwner: "ownerB",
      }),
      tokenTransfer({
        id: "c-0002",
        source: "a2",
        destination: "b1",
        amount: "5",
        fromOwner: "ownerA",
        toOwner: "ownerB",
      }),
      tokenTransfer({
        id: "c-0003",
        source: "a3",
        destination: "b2",
        amount: "7",
        mint: MINT_Y,
        fromOwner: "ownerA",
        toOwner: "ownerB",
      }),
    ]);
    expect(out.map((o) => [o.value.owner, o.value.mint, o.value.net])).toEqual([
      ["ownerA", MINT_X, "-15"],
      ["ownerA", MINT_Y, "-7"],
      ["ownerB", MINT_X, "15"],
      ["ownerB", MINT_Y, "7"],
    ]);
    expect(out[0].inputs).toEqual(["c-0001", "c-0002"]);
  });

  it("native SOL moves are their own asset: not the wrapped-SOL mint, so a wrapped balance is never mixed with lamports", () => {
    const claims = [
      solTransfer("c-0001", "ownerA", "ownerB", "1000"),
      tokenTransfer({
        id: "c-0002",
        source: "w1",
        destination: "w2",
        amount: "400",
        mint: WRAPPED_SOL_MINT,
        fromOwner: "ownerA",
        toOwner: "ownerB",
      }),
    ];
    expect(NATIVE_ASSET).not.toBe(WRAPPED_SOL_MINT);
    expect(netOf(claims, "ownerA", NATIVE_ASSET)).toBe("-1000");
    expect(netOf(claims, "ownerA", WRAPPED_SOL_MINT)).toBe("-400");
    expect(netOf(claims, "ownerB", NATIVE_ASSET)).toBe("1000");
    expect(netFlow(claims)).toHaveLength(4);
  });

  it("a failed transfer moves nothing and is not an input", () => {
    const out = netFlow([
      tokenTransfer({
        id: "c-0001",
        source: "a1",
        destination: "b1",
        amount: "10",
        fromOwner: "ownerA",
        toOwner: "ownerB",
        failed: true,
      }),
      solTransfer("c-0002", "ownerA", "ownerB", "9", true),
    ]);
    expect(out).toEqual([]);
  });

  it("an owner the transaction cannot name is grouped by its token account, never dropped", () => {
    const out = netFlow([
      tokenTransfer({
        id: "c-0001",
        source: "acctU1",
        destination: "acctB1",
        amount: "10",
        toOwner: "ownerB",
      }),
    ]);
    expect(out.map((o) => [o.value.owner, o.value.net])).toEqual([
      ["ownerB", "10"],
      ["unresolved:acctU1", "-10"],
    ]);
  });

  it("an owner known only from current state is not evidence from this transaction, so it is grouped as unresolved", () => {
    const out = netFlow([
      tokenTransfer({
        id: "c-0001",
        source: "acctS1",
        destination: "acctB1",
        amount: "10",
        fromOwner: "ownerS",
        fromMethod: "current_state",
        toOwner: "ownerB",
        toMethod: "ata_derivation",
      }),
    ]);
    expect(out.map((o) => o.value.owner)).toEqual(["ownerB", "unresolved:acctS1"]);
  });

  it("a mint the transaction does not name is grouped by its account: two unknown mints are never summed together", () => {
    const out = netFlow([
      tokenTransfer({
        id: "c-0001",
        source: "acctA1",
        destination: "acctB1",
        amount: "10",
        mint: "unresolved",
        fromOwner: "ownerA",
        toOwner: "ownerB",
      }),
      tokenTransfer({
        id: "c-0002",
        source: "acctA2",
        destination: "acctB2",
        amount: "3",
        mint: "unresolved",
        fromOwner: "ownerA",
        toOwner: "ownerB",
      }),
    ]);
    expect(out.map((o) => [o.value.owner, o.value.mint, o.value.net])).toEqual([
      ["ownerA", "unresolved:acctA1", "-10"],
      ["ownerA", "unresolved:acctA2", "-3"],
      ["ownerB", "unresolved:acctB1", "10"],
      ["ownerB", "unresolved:acctB2", "3"],
    ]);
  });

  it("a transfer from an owner to themselves counts once as an input and nets to zero", () => {
    const out = netFlow([
      tokenTransfer({
        id: "c-0001",
        source: "a1",
        destination: "a2",
        amount: "10",
        fromOwner: "ownerA",
        toOwner: "ownerA",
      }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].value.net).toBe("0");
    expect(out[0].inputs).toEqual(["c-0001"]);
  });

  it("ignores claims of other codes, and returns nothing for no claims", () => {
    expect(netFlow([])).toEqual([]);
    expect(
      netFlow([
        { id: "c-0001", code: "TOKEN_MINT", value: { amount: "5", failed: false } },
        { id: "c-0002", code: "PROGRAM_INVOKED", value: { failed: false } },
      ]),
    ).toEqual([]);
  });

  it("does not depend on the order of its input claims", () => {
    const shuffled = [swap[1], swap[0]];
    expect(netFlow(shuffled)).toEqual(netFlow(swap));
  });

  it("does not change the claims it is given", () => {
    const frozen = JSON.parse(JSON.stringify(swap)) as FormulaClaim[];
    netFlow(swap);
    expect(swap).toEqual(frozen);
  });

  it.each(["", " 5", "5 ", "0x10", "1e3", "1.5", "-5", "+5", "05", "٣", "NaN", "Infinity"])(
    "refuses the amount %j: a lenient parse would turn it into a different number",
    (amount) => {
      expect(() =>
        netFlow([
          tokenTransfer({
            id: "c-0001",
            source: "a1",
            destination: "b1",
            amount,
            fromOwner: "ownerA",
            toOwner: "ownerB",
          }),
        ]),
      ).toThrow(FormulaInputError);
    },
  );

  it("refuses an amount that is not a string, and a lamport count that is a number", () => {
    const bad = { ...solTransfer("c-0001", "a", "b", "1") };
    (bad.value as Record<string, ClaimValue>).lamports = 5;
    expect(() => netFlow([bad])).toThrow(FormulaInputError);
  });
});

// ─── effective_rate@1 ────────────────────────────────────────────────────────

describe("effective_rate@1", () => {
  it("keeps the rate as two strings and never divides: output over input, not reduced", () => {
    const [out] = effectiveRate([swapEvent("c-0005", "4", "6")]);
    expect(out.code).toBe("EFFECTIVE_RATE");
    expect(out.value).toEqual({
      numerator: "6",
      numerator_mint: MINT_Y,
      denominator: "4",
      denominator_mint: MINT_X,
    });
    expect(out.inputs).toEqual(["c-0005"]);
    expect(FORMULAS[EFFECTIVE_RATE_FORMULA]).toBe(effectiveRate);
    expect(EFFECTIVE_RATE_FORMULA).toBe("effective_rate@1");
  });

  it("keeps all digits of amounts near the u64 maximum", () => {
    const [out] = effectiveRate([swapEvent("c-0005", U64_MAX, "9007199254740993")]);
    expect(out.value.numerator).toBe("9007199254740993");
    expect(out.value.denominator).toBe(U64_MAX);
  });

  it("takes exactly one SWAP_EVENT: none, two, another code or a failed event is refused", () => {
    const ok = swapEvent("c-0005", "4", "6");
    expect(() => effectiveRate([])).toThrow(FormulaInputError);
    expect(() => effectiveRate([ok, { ...ok, id: "c-0006" }])).toThrow(FormulaInputError);
    expect(() => effectiveRate([{ ...ok, code: "TOKEN_TRANSFER" }])).toThrow(FormulaInputError);
    expect(() => effectiveRate([swapEvent("c-0005", "4", "6", true)])).toThrow(FormulaInputError);
  });

  it("refuses a zero input amount: the rate is undefined, and an invented one would be a false claim", () => {
    expect(() => effectiveRate([swapEvent("c-0005", "0", "6")])).toThrow(FormulaInputError);
  });

  it("refuses a lenient amount", () => {
    expect(() => effectiveRate([swapEvent("c-0005", "0x4", "6")])).toThrow(FormulaInputError);
    expect(() => effectiveRate([swapEvent("c-0005", "4", "")])).toThrow(FormulaInputError);
  });
});

// ─── recompute ───────────────────────────────────────────────────────────────

describe("recompute", () => {
  const inputs: FormulaClaim[] = [
    tokenTransfer({
      id: "c-0001",
      source: "acctA1",
      destination: "acctB1",
      amount: "100",
      mint: MINT_X,
      fromOwner: "ownerA",
      toOwner: "ownerB",
    }),
    tokenTransfer({
      id: "c-0002",
      source: "acctB2",
      destination: "acctA2",
      amount: "98",
      mint: MINT_Y,
      fromOwner: "ownerB",
      toOwner: "ownerA",
    }),
    swapEvent("c-0003", "100", "98"),
  ];
  const netClaims: Claim[] = netFlow(inputs).map((o, i) =>
    asClaim(`c-${String(10 + i).padStart(4, "0")}`, NET_FLOW_FORMULA, o),
  );
  const rateClaim = asClaim("c-0020", EFFECTIVE_RATE_FORMULA, effectiveRate([inputs[2]])[0]);
  const all = [...(inputs as unknown as Claim[]), ...netClaims, rateClaim];

  it("every Derived claim recomputes to exactly its own value, from its inputs alone", () => {
    expect(netClaims.length).toBe(4);
    for (const claim of [...netClaims, rateClaim])
      expect(recompute(claim, all)).toEqual(claim.value);
  });

  it("uses only the listed inputs: an unrelated claim in the list changes nothing", () => {
    const extra = tokenTransfer({
      id: "c-0099",
      source: "acctA1",
      destination: "acctB1",
      amount: "1",
      mint: MINT_X,
      fromOwner: "ownerA",
      toOwner: "ownerB",
    });
    const claim = netClaims[0];
    expect(recompute(claim, [...all, extra as unknown as Claim])).toEqual(claim.value);
    // And a claim that was removed from the list is missing, not replaced by a similar one.
    const without = all.filter((c) => c.id !== "c-0001");
    expect(() => recompute(claim, without)).toThrow(RecomputeError);
  });

  it("returns a different value from a tampered claim, so comparing the two exposes the edit", () => {
    const tampered: Claim = {
      ...netClaims[0],
      value: { ...(netClaims[0].value as Record<string, ClaimValue>), net: "-101" },
    };
    const recomputed = recompute(tampered, all);
    expect(recomputed).toEqual(netClaims[0].value);
    expect(recomputed).not.toEqual(tampered.value);
  });

  it("refuses a claim that is not Derived, with a typed error", () => {
    const observedClaim = inputs[0] as unknown as Claim;
    expect(() => recompute(observedClaim, all)).toThrow(RecomputeError);
    try {
      recompute(observedClaim, all);
    } catch (e) {
      expect((e as RecomputeError).reason).toBe("not_derived");
    }
  });

  it("refuses a formula it does not know, naming it", () => {
    const claim: Claim = {
      ...netClaims[0],
      provenance: { type: "derived", formula: "made_up@9", inputs: ["c-0001"] },
    };
    try {
      recompute(claim, all);
      throw new Error("did not throw");
    } catch (e) {
      expect(e).toBeInstanceOf(RecomputeError);
      expect((e as RecomputeError).reason).toBe("unknown_formula");
      expect((e as Error).message).toContain("made_up@9");
    }
  });

  it("refuses a claim whose input is missing, naming the id", () => {
    const claim: Claim = {
      ...netClaims[0],
      provenance: { type: "derived", formula: NET_FLOW_FORMULA, inputs: ["c-0001", "c-0777"] },
    };
    try {
      recompute(claim, all);
      throw new Error("did not throw");
    } catch (e) {
      expect(e).toBeInstanceOf(RecomputeError);
      expect((e as RecomputeError).reason).toBe("missing_input");
      expect((e as Error).message).toContain("c-0777");
    }
  });

  it("refuses an input that does not contribute to the claim: the listed inputs must be the contributing ones", () => {
    // ownerA / MINT_X never touches c-0002 (which is MINT_Y).
    const claim: Claim = {
      ...netClaims[0],
      provenance: { type: "derived", formula: NET_FLOW_FORMULA, inputs: ["c-0001", "c-0002"] },
    };
    expect(claim.value).toMatchObject({ owner: "ownerA", mint: MINT_X });
    try {
      recompute(claim, all);
      throw new Error("did not throw");
    } catch (e) {
      expect(e).toBeInstanceOf(RecomputeError);
      expect((e as RecomputeError).reason).toBe("inputs_mismatch");
    }
  });

  it("refuses a claim for an owner and mint its inputs do not produce", () => {
    const claim: Claim = {
      ...netClaims[0],
      value: { owner: "ownerZ", mint: MINT_X, net: "1" },
    };
    expect(() => recompute(claim, all)).toThrow(RecomputeError);
  });

  it("the swap-completeness and leg warnings are named as needing the transaction, never silently passed", () => {
    for (const formula of ["swap-completeness@1.0.0", "swap-leg-reconciliation@1.0.0"]) {
      const claim: Claim = {
        id: "c-0030",
        type: "derived",
        code: "RECONCILIATION_WARNING",
        value: { reason: "x" },
        provenance: { type: "derived", formula, inputs: ["c-0001"] },
      };
      try {
        recompute(claim, all);
        throw new Error("did not throw");
      } catch (e) {
        expect(e).toBeInstanceOf(RecomputeError);
        expect((e as RecomputeError).reason).toBe("requires_transaction");
      }
    }
    expect(ATA_FORMULA).toBe("ata-derivation@1.0.0");
  });
});

// ─── reconcileBalances ───────────────────────────────────────────────────────

describe("reconcileBalances", () => {
  const chain = (
    tokens: Record<string, [string, string, string]>,
    lamports: Record<string, [string, string]>,
  ): ChainBalances => ({
    tokens: new Map(
      Object.entries(tokens).map(([account, [mint, pre, post]]) => [
        account,
        { mint, pre: BigInt(pre), post: BigInt(post) },
      ]),
    ),
    lamports: new Map(
      Object.entries(lamports).map(([account, [pre, post]]) => [
        account,
        { pre: BigInt(pre), post: BigInt(post) },
      ]),
    ),
  });
  const fee = (lamports: string, payer: string): FormulaClaim => ({
    id: "c-0100",
    code: "TX_FEE",
    value: { lamports, fee_payer: payer, failed: false },
    provenance: observed("0"),
  });
  const transfer = tokenTransfer({
    id: "c-0001",
    source: "acctA1",
    destination: "acctB1",
    amount: "100",
    mint: MINT_X,
    fromOwner: "ownerA",
    toOwner: "ownerB",
  });
  const balanced = chain(
    { acctA1: [MINT_X, "500", "400"], acctB1: [MINT_X, "10", "110"] },
    { ownerA: ["1000", "995"] },
  );

  it("passes when the decoded movements explain every balance change, fee included", () => {
    expect(reconcileBalances([transfer, fee("5", "ownerA")], balanced)).toEqual([]);
  });

  it("a transfer missing from the claims is a gap with the numbers, the account and the mint", () => {
    const gaps = reconcileBalances([fee("5", "ownerA")], balanced);
    expect(gaps).toHaveLength(2);
    const a = gaps.find((g) => g.account === "acctA1")!;
    expect(a).toMatchObject({
      kind: "token",
      mint: MINT_X,
      expected: "0",
      actual: "-100",
      difference: "-100",
    });
    const b = gaps.find((g) => g.account === "acctB1")!;
    expect(b).toMatchObject({ expected: "0", actual: "100", difference: "100" });
    // No decoded claim touches the account, so the gap points at the transaction fee claim instead of nothing.
    expect(a.inputs).toEqual(["c-0100"]);
  });

  it("an amount that differs from the chain is a gap on both accounts, and names the transfer claim", () => {
    const altered = tokenTransfer({
      id: "c-0001",
      source: "acctA1",
      destination: "acctB1",
      amount: "99",
      mint: MINT_X,
      fromOwner: "ownerA",
      toOwner: "ownerB",
    });
    const gaps = reconcileBalances([altered, fee("5", "ownerA")], balanced);
    expect(gaps.map((g) => [g.account, g.expected, g.actual, g.difference])).toEqual([
      ["acctA1", "-99", "-100", "-1"],
      ["acctB1", "99", "100", "1"],
    ]);
    expect(gaps[0].inputs).toEqual(["c-0001"]);
  });

  it("a fee that the claims do not carry is a gap on the fee payer's lamports; a fee claim that is wrong is too", () => {
    const noFee = reconcileBalances([transfer], balanced);
    expect(noFee).toHaveLength(1);
    expect(noFee[0]).toMatchObject({
      kind: "lamports",
      account: "ownerA",
      mint: NATIVE_ASSET,
      expected: "0",
      actual: "-5",
      difference: "-5",
    });
    const wrongFee = reconcileBalances([transfer, fee("4", "ownerA")], balanced);
    expect(wrongFee[0]).toMatchObject({ expected: "-4", actual: "-5", difference: "-1" });
    expect(wrongFee[0].inputs).toEqual(["c-0100"]);
  });

  it("System transfers and create_account explain lamport changes", () => {
    const c = chain({}, { ownerA: ["1000", "495"], ownerB: ["0", "500"] });
    expect(
      reconcileBalances([solTransfer("c-0001", "ownerA", "ownerB", "500"), fee("5", "ownerA")], c),
    ).toEqual([]);
    const gaps = reconcileBalances(
      [solTransfer("c-0001", "ownerA", "ownerB", "499"), fee("5", "ownerA")],
      c,
    );
    expect(gaps.map((g) => [g.account, g.difference])).toEqual([
      ["ownerA", "-1"],
      ["ownerB", "1"],
    ]);
  });

  it("a failed instruction is excluded from both sides: the fee is all that moved", () => {
    const failed = { ...transfer, value: { ...(transfer.value as object), failed: true } };
    const afterFailure = chain(
      { acctA1: [MINT_X, "500", "500"], acctB1: [MINT_X, "10", "10"] },
      { ownerA: ["1000", "995"] },
    );
    expect(reconcileBalances([failed as FormulaClaim, fee("5", "ownerA")], afterFailure)).toEqual(
      [],
    );
    // The same failed claim counted as a movement would be a gap: the exclusion is what makes it pass.
    const counted = { ...transfer };
    expect(reconcileBalances([counted, fee("5", "ownerA")], afterFailure)).toHaveLength(2);
  });

  it("mint and burn explain a balance change", () => {
    const c = chain({ acctA1: [MINT_X, "10", "17"], acctB1: [MINT_X, "9", "4"] }, {});
    const claims: FormulaClaim[] = [
      {
        id: "c-0001",
        code: "TOKEN_MINT",
        value: { mint: MINT_X, destination: "acctA1", amount: "7", failed: false },
        provenance: observed("1"),
      },
      {
        id: "c-0002",
        code: "TOKEN_BURN",
        value: { mint: MINT_X, account: "acctB1", amount: "5", failed: false },
        provenance: observed("2"),
      },
    ];
    expect(reconcileBalances(claims, c)).toEqual([]);
    expect(reconcileBalances([claims[0]], c)).toHaveLength(1);
  });

  it("a wrapped-SOL transfer moves lamports as well as tokens, and the close of a wrapped-SOL account hands its lamports to the destination", () => {
    // ownerA: create_account 100 (rent), wrapped transfer 400 into the new account, then close returns 500.
    // A create_account: an account closed in the same transaction needs one.
    const created: FormulaClaim = {
      ...solTransfer("c-0001", "ownerA", "temp1", "100", false, "1"),
      value: {
        instruction: "create_account",
        from: "ownerA",
        to: "temp1",
        lamports: "100",
        space: "165",
        failed: false,
      },
    };
    const wrapped = tokenTransfer({
      id: "c-0002",
      source: "src1",
      destination: "temp1",
      amount: "400",
      mint: WRAPPED_SOL_MINT,
      fromOwner: "ownerS",
      toOwner: "ownerA",
      ix: "2",
    });
    const closed: FormulaClaim = {
      id: "c-0003",
      code: "ACCOUNT_CLOSED",
      value: { account: "temp1", destination: "ownerA", authority: "ownerA", failed: false },
      provenance: observed("3"),
    };
    const c = chain(
      { src1: [WRAPPED_SOL_MINT, "1000", "600"] },
      { ownerA: ["50", "445"], ownerS: ["5", "5"], src1: ["2000", "1600"], temp1: ["0", "0"] },
    );
    // ownerA: -100 (create) -5 (fee) +500 (close) = +395. src1 is a wrapped-SOL account: the transfer
    // takes 400 lamports with it. temp1 is created and closed inside the transaction.
    expect(reconcileBalances([created, wrapped, closed, fee("5", "ownerA")], c)).toEqual([]);
    // Without the close claim the destination's gain is unexplained, and the temp account never emptied.
    const gaps = reconcileBalances([created, wrapped, fee("5", "ownerA")], c);
    expect(gaps.map((g) => `${g.kind}:${g.account}`)).toEqual([
      "token:temp1",
      "lamports:ownerA",
      "lamports:temp1",
    ]);
  });

  it("a closed account that the chain still shows with lamports is a gap, not a pass", () => {
    // A create_account: an account closed in the same transaction needs one.
    const created: FormulaClaim = {
      ...solTransfer("c-0001", "ownerA", "temp1", "100", false, "1"),
      value: {
        instruction: "create_account",
        from: "ownerA",
        to: "temp1",
        lamports: "100",
        space: "165",
        failed: false,
      },
    };
    const closed: FormulaClaim = {
      id: "c-0003",
      code: "ACCOUNT_CLOSED",
      value: { account: "temp1", destination: "ownerA", authority: "ownerA", failed: false },
      provenance: observed("3"),
    };
    const c = chain({}, { ownerA: ["1000", "995"], temp1: ["0", "100"] });
    const gaps = reconcileBalances([created, closed, fee("5", "ownerA")], c);
    expect(gaps.map((g) => [g.account, g.difference])).toEqual([["temp1", "100"]]);
  });

  it("gaps are exact beyond a double: the difference of two u64 values keeps every digit", () => {
    const c = chain({ acctA1: [MINT_X, "0", U64_MAX] }, {});
    const gaps = reconcileBalances([], c);
    expect(gaps).toHaveLength(1);
    expect(gaps[0].actual).toBe(U64_MAX);
    expect(gaps[0].difference).toBe(U64_MAX);
  });

  it("reports an account in a fixed order, so the same transaction always yields the same list", () => {
    const c = chain(
      { b: [MINT_X, "0", "1"], a: [MINT_X, "0", "1"] },
      { z: ["0", "1"], y: ["0", "1"] },
    );
    const first = reconcileBalances([], c).map((g) => `${g.kind}:${g.account}`);
    expect(first).toEqual(["token:a", "token:b", "lamports:y", "lamports:z"]);
    const reversed = chain(
      { a: [MINT_X, "0", "1"], b: [MINT_X, "0", "1"] },
      { y: ["0", "1"], z: ["0", "1"] },
    );
    expect(reconcileBalances([], reversed).map((g) => `${g.kind}:${g.account}`)).toEqual(first);
  });

  it("a gap claim recomputes from its inputs: expected is re-derived, the chain figure is carried", () => {
    const claims = [
      tokenTransfer({
        id: "c-0001",
        source: "acctA1",
        destination: "acctB1",
        amount: "99",
        mint: MINT_X,
        fromOwner: "ownerA",
        toOwner: "ownerB",
      }),
      fee("5", "ownerA"),
    ];
    const [gap] = reconcileBalances(claims, balanced);
    expect(gap.account).toBe("acctA1");
    const value = reconciliationOutputs([gap])[0].value;
    const warning = asClaim("c-0050", RECONCILE_FORMULA, {
      code: "RECONCILIATION_WARNING",
      value,
      inputs: gap.inputs,
    });
    const all = [...(claims as unknown as Claim[]), warning];
    expect(recompute(warning, all)).toEqual(value);
    // A warning whose expected figure was edited is refused: recomputing it does not give the stored value.
    const edited: Claim = { ...warning, value: { ...value, expected: "-98", difference: "-2" } };
    expect(() => recompute(edited, [...(claims as unknown as Claim[]), edited])).toThrow(
      RecomputeError,
    );
  });
});
