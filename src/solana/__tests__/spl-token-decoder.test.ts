// SPL Token and Token-2022 base instruction decoder. Token transfers are the movements the
// manifest reports, so a swapped account position (source for destination, mint for authority), a wrong
// tag or an amount that went through a float would put a false movement into the evidence. One hand-built
// byte array per instruction, laid out per the official TokenInstruction pack format (u8 tag, then little-
// endian u64 amount, u8 decimals, or a 32-byte owner), including the maximum u64 and zero. Every malformed
// shape returns null so the registry keeps the raw bytes as unknown_variant, and the tags the decoder does
// not list, including the Token-2022 extension instructions, are flagged that way and never decoded.
// Pure: no network.
import { describe, expect, it } from "vitest";
import type { InstructionNode } from "../instruction-tree.js";
import { PROGRAM_IDS } from "../programs.js";
import { decodeTransaction, defaultRegistry, type DecodeResult } from "../decoders/index.js";
import { splTokenDecoder, token2022Decoder } from "../decoders/spl-token.js";
import { encodeBase58 } from "../base58-encode.js";

const MAX_U64 = "18446744073709551615";
const OWNER_BYTES = Uint8Array.from({ length: 32 }, (_, i) => 200 - i);
const OWNER_B58 = encodeBase58(OWNER_BYTES);

const u64 = (n: bigint) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
};
const cat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
const tagged = (tag: number, ...rest: Uint8Array[]) => cat(Uint8Array.of(tag), ...rest);

const PROGRAMS: [string, string][] = [
  ["SPL Token", PROGRAM_IDS.splToken],
  ["Token-2022", PROGRAM_IDS.token2022],
];

const node = (
  programId: string,
  data: Uint8Array,
  accounts: string[],
  over: Partial<InstructionNode> = {},
): InstructionNode => ({
  ix_path: "0",
  program_id: programId,
  accounts,
  data,
  failed: false,
  ...over,
});
const run = (n: InstructionNode): DecodeResult => decodeTransaction([n], {})[0];
const decoded = (n: InstructionNode) => {
  const r = run(n);
  if (r.decode_status !== "decoded") throw new Error(`expected decoded, got ${r.decode_status}`);
  return r;
};

/** Account names in the official layout order, so a swapped position shows up as a wrong name. */
const A = {
  one: ["acct0", "acct1", "acct2", "acct3"],
};

interface Case {
  name: string;
  kind: string;
  data: Uint8Array;
  /** accounts for the single-owner form, in layout order */
  accounts: string[];
  fields: Record<string, string | number | boolean | string[]>;
}

const cases = (amount: bigint, amountText: string): Case[] => [
  {
    name: "InitializeAccount (1)",
    kind: "token_initialize_account",
    data: Uint8Array.of(1),
    accounts: ["account", "mint", "owner", "rent"],
    fields: { account: "account", mint: "mint", owner: "owner", rent: "rent" },
  },
  {
    name: "Transfer (3)",
    kind: "token_transfer",
    data: tagged(3, u64(amount)),
    accounts: ["source", "destination", "authority"],
    fields: {
      source: "source",
      destination: "destination",
      authority: "authority",
      amount: amountText,
      extra_accounts: [],
    },
  },
  {
    name: "MintTo (7)",
    kind: "token_mint_to",
    data: tagged(7, u64(amount)),
    accounts: ["mint", "destination", "authority"],
    fields: {
      mint: "mint",
      destination: "destination",
      authority: "authority",
      amount: amountText,
      extra_accounts: [],
    },
  },
  {
    name: "Burn (8)",
    kind: "token_burn",
    data: tagged(8, u64(amount)),
    accounts: ["account", "mint", "authority"],
    fields: {
      account: "account",
      mint: "mint",
      authority: "authority",
      amount: amountText,
      extra_accounts: [],
    },
  },
  {
    name: "CloseAccount (9)",
    kind: "token_close_account",
    data: Uint8Array.of(9),
    accounts: ["account", "destination", "authority"],
    fields: {
      account: "account",
      destination: "destination",
      authority: "authority",
      extra_accounts: [],
    },
  },
  {
    name: "TransferChecked (12)",
    kind: "token_transfer_checked",
    data: tagged(12, u64(amount), Uint8Array.of(6)),
    accounts: ["source", "mint", "destination", "authority"],
    fields: {
      source: "source",
      mint: "mint",
      destination: "destination",
      authority: "authority",
      amount: amountText,
      decimals: 6,
      extra_accounts: [],
    },
  },
  {
    name: "MintToChecked (14)",
    kind: "token_mint_to_checked",
    data: tagged(14, u64(amount), Uint8Array.of(9)),
    accounts: ["mint", "destination", "authority"],
    fields: {
      mint: "mint",
      destination: "destination",
      authority: "authority",
      amount: amountText,
      decimals: 9,
      extra_accounts: [],
    },
  },
  {
    name: "BurnChecked (15)",
    kind: "token_burn_checked",
    data: tagged(15, u64(amount), Uint8Array.of(0)),
    accounts: ["account", "mint", "authority"],
    fields: {
      account: "account",
      mint: "mint",
      authority: "authority",
      amount: amountText,
      decimals: 0,
      extra_accounts: [],
    },
  },
  {
    name: "InitializeAccount2 (16)",
    kind: "token_initialize_account2",
    data: tagged(16, OWNER_BYTES),
    accounts: ["account", "mint", "rent"],
    fields: { account: "account", mint: "mint", rent: "rent", owner: OWNER_B58 },
  },
  {
    name: "SyncNative (17)",
    kind: "token_sync_native",
    data: Uint8Array.of(17),
    accounts: ["account"],
    fields: { account: "account" },
  },
  {
    name: "InitializeAccount3 (18)",
    kind: "token_initialize_account3",
    data: tagged(18, OWNER_BYTES),
    accounts: ["account", "mint"],
    fields: { account: "account", mint: "mint", owner: OWNER_B58 },
  },
];

describe("registration", () => {
  it("one decoder named spl-token is registered under both the SPL Token and the Token-2022 program IDs", () => {
    expect(splTokenDecoder.programId).toBe(PROGRAM_IDS.splToken);
    expect(token2022Decoder.programId).toBe(PROGRAM_IDS.token2022);
    for (const d of [splTokenDecoder, token2022Decoder]) {
      expect(d.name).toBe("spl-token");
      expect(d.version).toMatch(/^\d+\.\d+\.\d+$/);
    }
    expect(token2022Decoder.version).toBe(splTokenDecoder.version);
    expect(defaultRegistry.get(PROGRAM_IDS.splToken)).toBe(splTokenDecoder);
    expect(defaultRegistry.get(PROGRAM_IDS.token2022)).toBe(token2022Decoder);
  });
});

describe.each(PROGRAMS)("%s base instructions", (label, programId) => {
  const amounts: [bigint, string][] = [
    [2466848462n, "2466848462"],
    [0n, "0"],
    [2n ** 53n + 1n, "9007199254740993"], // would round to ...992 if it passed through a double
    [2n ** 64n - 1n, MAX_U64],
  ];

  for (const [amount, text] of amounts) {
    describe(`amount ${text}`, () => {
      it.each(cases(amount, text).map((c) => [c.name, c] as const))("%s", (_name, c) => {
        const r = decoded(node(programId, c.data, c.accounts));
        expect(r.kind).toBe(c.kind);
        expect(r.fields).toEqual(c.fields);
        expect(r.program).toBe(label);
        expect(r.decoder).toBe("spl-token@" + splTokenDecoder.version);
        // Amounts, and only amounts, are strings of raw base units.
        if ("amount" in r.fields) expect(typeof r.fields.amount).toBe("string");
      });
    });
  }

  it("reads the amount little-endian (byte-order check): 01 02 03 04 05 06 07 08 is 0x0807060504030201", () => {
    const r = decoded(
      node(programId, tagged(3, Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8)), ["s", "d", "o"]),
    );
    expect(r.fields.amount).toBe("578437695752307201");
  });

  it("decimals is a plain integer: 0 and 255 survive on a checked variant", () => {
    for (const dec of [0, 255]) {
      const r = decoded(
        node(programId, tagged(12, u64(1n), Uint8Array.of(dec)), ["s", "m", "d", "o"]),
      );
      expect(r.fields.decimals).toBe(dec);
    }
  });

  it("multisig: accounts past the fixed positions are kept, in order, as extra_accounts", () => {
    const r = decoded(node(programId, tagged(3, u64(5n)), ["s", "d", "multisig", "sig1", "sig2"]));
    expect(r.fields).toMatchObject({ authority: "multisig", extra_accounts: ["sig1", "sig2"] });
    const c = decoded(
      node(programId, tagged(12, u64(5n), Uint8Array.of(6)), ["s", "m", "d", "ms", "x"]),
    );
    expect(c.fields).toMatchObject({ authority: "ms", extra_accounts: ["x"] });
    const close = decoded(node(programId, Uint8Array.of(9), ["a", "d", "ms", "x", "y", "z"]));
    expect(close.fields).toMatchObject({ authority: "ms", extra_accounts: ["x", "y", "z"] });
  });

  describe("malformed shapes return null (unknown_variant, raw bytes kept)", () => {
    const all = cases(5n, "5");
    it.each(all.map((c) => [c.name, c] as const))("%s: wrong data lengths", (_name, c) => {
      const lengths = new Set([c.data.length - 1, c.data.length + 1, c.data.length + 8]);
      lengths.delete(c.data.length);
      for (const len of lengths) {
        if (len < 1) continue; // an empty array is tested separately
        const data =
          len < c.data.length
            ? c.data.slice(0, len)
            : cat(c.data, new Uint8Array(len - c.data.length));
        const r = run(node(programId, data, c.accounts));
        expect(r.decode_status, `${len} bytes`).toBe("unknown_variant");
      }
    });

    it.each(all.map((c) => [c.name, c] as const))("%s: too few accounts", (_name, c) => {
      for (let n = 0; n < c.accounts.length; n++) {
        // SyncNative needs one account; anything below its layout must not decode.
        const r = run(node(programId, c.data, c.accounts.slice(0, n)));
        expect(r.decode_status, `${n} accounts`).toBe("unknown_variant");
      }
    });

    it("empty data returns null", () => {
      expect(run(node(programId, new Uint8Array(0), ["a", "b", "c"])).decode_status).toBe(
        "unknown_variant",
      );
    });

    it("fixed-size layouts reject extra accounts: InitializeAccount (4), InitializeAccount2 (3), InitializeAccount3 (2)", () => {
      const byName = new Map(all.map((c) => [c.name, c]));
      for (const name of [
        "InitializeAccount (1)",
        "InitializeAccount2 (16)",
        "InitializeAccount3 (18)",
      ]) {
        const c = byName.get(name);
        if (!c) throw new Error(name);
        const r = run(node(programId, c.data, [...c.accounts, "extra"]));
        expect(r.decode_status, name).toBe("unknown_variant");
      }
    });

    it("SyncNative accepts the one-account form and the older form that also passes the Rent sysvar", () => {
      expect(decoded(node(programId, Uint8Array.of(17), ["w"])).fields).toEqual({ account: "w" });
      expect(decoded(node(programId, Uint8Array.of(17), ["w", "rent"])).fields).toEqual({
        account: "w",
        rent: "rent",
      });
      expect(run(node(programId, Uint8Array.of(17), ["w", "rent", "x"])).decode_status).toBe(
        "unknown_variant",
      );
    });
  });

  describe("tags the decoder does not list are null, never partially decoded", () => {
    const listed = new Set([1, 3, 7, 8, 9, 12, 14, 15, 16, 17, 18]);
    it("every other tag 0..255 returns unknown_variant with the raw hex, whatever the payload", () => {
      for (let tag = 0; tag <= 255; tag++) {
        if (listed.has(tag)) continue;
        const data = tagged(tag, u64(7n), Uint8Array.of(6), new Uint8Array(32));
        const r = run(node(programId, data, ["a", "b", "c", "d"]));
        expect(r.decode_status, `tag ${tag}`).toBe("unknown_variant");
        if (r.decode_status === "decoded") throw new Error("unreachable");
        expect(r.data).toBe(Array.from(data, (b) => b.toString(16).padStart(2, "0")).join(""));
      }
    });

    it("the base instructions this task leaves out stay unknown: approve (4), revoke (5), set authority (6), freeze (10), thaw (11), approve checked (13)", () => {
      for (const tag of [0, 2, 4, 5, 6, 10, 11, 13, 19, 20, 21, 22, 23, 24, 38, 45, 255]) {
        expect(run(node(programId, tagged(tag, u64(1n)), ["a", "b", "c", "d"])).decode_status).toBe(
          "unknown_variant",
        );
      }
    });
  });
});

describe("Token-2022 extension instructions are flagged, not decoded", () => {
  // Official Token-2022 tags 25 to 46 (TransferFee 26, ConfidentialTransfer 27, DefaultAccountState 28,
  // Reallocate 29, MemoTransfer 30, CreateNativeMint 31, NonTransferableMint 32, InterestBearingMint 33,
  // CpiGuard 34, InitializePermanentDelegate 35, TransferHook 36, ...). A transfer made through an
  // extension (TransferFee 26 with its own sub-instruction byte) must not be mistaken for tag 3 or 12.
  it("tags 25 to 46 on the Token-2022 program are unknown_variant with the raw bytes and the program label", () => {
    for (let tag = 25; tag <= 46; tag++) {
      const data = tagged(tag, Uint8Array.of(1), u64(9n), Uint8Array.of(6));
      const r = run(node(PROGRAM_IDS.token2022, data, ["a", "b", "c", "d"]));
      expect(r.decode_status, `tag ${tag}`).toBe("unknown_variant");
      if (r.decode_status === "decoded") throw new Error("unreachable");
      expect(r.program).toBe("Token-2022");
      expect(r.decoder).toBe("spl-token@" + token2022Decoder.version); // tried, not decoded
      expect(r.accounts).toEqual(["a", "b", "c", "d"]);
    }
  });

  it("a TransferFee transfer-checked-with-fee (tag 26, sub 1) is not read as a plain transfer", () => {
    const data = tagged(26, Uint8Array.of(1), u64(1000n), Uint8Array.of(6), u64(10n));
    expect(run(node(PROGRAM_IDS.token2022, data, ["s", "m", "d", "o"])).decode_status).toBe(
      "unknown_variant",
    );
  });
});

describe("decoder hygiene", () => {
  it("never throws on any prefix of a valid instruction or on arbitrary bytes, with any account count", () => {
    const sample = tagged(12, u64(2n ** 64n - 1n), Uint8Array.of(6));
    for (const d of [splTokenDecoder, token2022Decoder]) {
      for (let n = 0; n <= sample.length; n++) {
        for (let k = 0; k <= 6; k++) {
          const accounts = Array.from({ length: k }, (_, i) => `a${i}`);
          expect(() => d.decode(node(d.programId, sample.slice(0, n), accounts), {})).not.toThrow();
        }
      }
      let seed = 4242;
      for (let i = 0; i < 500; i++) {
        const data = Uint8Array.from({ length: i % 50 }, () => {
          seed = (Math.imul(seed, 1103515245) + 12345) & 0x7fffffff;
          return seed & 0xff;
        });
        expect(() => d.decode(node(d.programId, data, A.one), {})).not.toThrow();
      }
    }
  });

  it("decoded fields hold only strings, integers, booleans and string arrays: no float, no null", () => {
    for (const c of cases(2n ** 64n - 1n, MAX_U64)) {
      const r = decoded(node(PROGRAM_IDS.splToken, c.data, c.accounts));
      expect(JSON.parse(JSON.stringify(r.fields))).toEqual(r.fields);
      const walk = (v: unknown) => {
        expect(v !== null && v !== undefined).toBe(true);
        if (typeof v === "number") expect(Number.isSafeInteger(v)).toBe(true);
        if (Array.isArray(v)) v.forEach(walk);
      };
      Object.values(r.fields).forEach(walk);
    }
  });

  it("decoding does not change the node it is given", () => {
    const n = node(PROGRAM_IDS.splToken, tagged(3, u64(5n)), ["s", "d", "o", "x"]);
    const before = JSON.stringify([n.accounts, Array.from(n.data)]);
    splTokenDecoder.decode(n, {});
    expect(JSON.stringify([n.accounts, Array.from(n.data)])).toBe(before);
  });
});
