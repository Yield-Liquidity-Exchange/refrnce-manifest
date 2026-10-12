// System program decoder. A System Transfer or CreateAccount is where native SOL moves, so a
// wrong index, a wrong byte offset or a lamports figure that went through a float would put a false
// amount into the evidence. Each variant is tested from a hand-built byte array laid out per the bincode
// encoding of the official SystemInstruction enum (u32 little-endian index, then fields; a String is a
// u64 length plus bytes), including the maximum u64, and every malformed shape must return null so the
// registry keeps the raw bytes as unknown_variant. Pure: no network.
import { describe, expect, it } from "vitest";
import type { InstructionNode } from "../instruction-tree.js";
import { PROGRAM_IDS } from "../programs.js";
import { decodeTransaction, defaultRegistry, type DecodeResult } from "../decoders/index.js";
import { systemDecoder } from "../decoders/system.js";
import { decodeBase58 } from "../base58.js";
import { encodeBase58 } from "../base58-encode.js";

const MAX_U64 = "18446744073709551615";
const OWNER_BYTES = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const OWNER_B58 = encodeBase58(OWNER_BYTES);

const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
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
const utf8 = (s: string) => new TextEncoder().encode(s);

const node = (data: Uint8Array, accounts: string[], over: Partial<InstructionNode> = {}) =>
  ({
    ix_path: "0",
    program_id: PROGRAM_IDS.system,
    accounts,
    data,
    failed: false,
    ...over,
  }) satisfies InstructionNode;
const run = (n: InstructionNode): DecodeResult => decodeTransaction([n], {})[0];
const decoded = (n: InstructionNode) => {
  const r = run(n);
  if (r.decode_status !== "decoded") throw new Error(`expected decoded, got ${r.decode_status}`);
  return r;
};

const createAccount = (lamports: bigint, space: bigint) =>
  cat(u32(0), u64(lamports), u64(space), OWNER_BYTES);
const transfer = (lamports: bigint) => cat(u32(2), u64(lamports));
const transferWithSeed = (lamports: bigint, seed: Uint8Array) =>
  cat(u32(11), u64(lamports), u64(BigInt(seed.length)), seed, OWNER_BYTES);

describe("system decoder registration", () => {
  it("is named system, versioned, and registered for the System program only", () => {
    expect(systemDecoder.programId).toBe(PROGRAM_IDS.system);
    expect(systemDecoder.name).toBe("system");
    expect(systemDecoder.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(defaultRegistry.get(PROGRAM_IDS.system)).toBe(systemDecoder);
  });
});

describe("System Transfer (index 2)", () => {
  it("decodes lamports and the [from, to] accounts to named fields", () => {
    const r = decoded(node(transfer(22316n), ["payer", "recipient"]));
    expect(r.kind).toBe("system_transfer");
    expect(r.decoder).toBe(`system@${systemDecoder.version}`);
    expect(r.program).toBe("System");
    expect(r.fields).toEqual({ from: "payer", to: "recipient", lamports: "22316" });
  });

  it("amounts are decimal strings, never numbers: zero, one, 2^53, 2^53+1 and the maximum u64", () => {
    const cases: [bigint, string][] = [
      [0n, "0"],
      [1n, "1"],
      [2n ** 53n, "9007199254740992"],
      [2n ** 53n + 1n, "9007199254740993"], // would round to ...992 if it passed through a double
      [2n ** 64n - 1n, MAX_U64],
    ];
    for (const [value, text] of cases) {
      const { fields } = decoded(node(transfer(value), ["a", "b"]));
      expect(typeof fields.lamports).toBe("string");
      expect(fields.lamports).toBe(text);
    }
  });

  it("reads the u32 index little-endian and the u64 amount little-endian (byte-order check)", () => {
    // 0x0102030405060708 little-endian is 08 07 06 05 04 03 02 01.
    const data = Uint8Array.from([2, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]);
    expect(decoded(node(data, ["a", "b"])).fields.lamports).toBe("72623859790382856");
  });

  it("wrong data length returns null (unknown_variant keeps the raw bytes): short, long, empty", () => {
    const good = transfer(5n);
    for (const data of [
      good.slice(0, 11),
      cat(good, Uint8Array.of(0)),
      new Uint8Array(0),
      u32(2),
      Uint8Array.of(2, 0, 0),
    ]) {
      const r = run(node(data, ["a", "b"]));
      expect(r.decode_status, `${data.length} bytes`).toBe("unknown_variant");
    }
  });

  it("wrong account count returns null: none, one, three", () => {
    for (const accounts of [[], ["a"], ["a", "b", "c"]]) {
      expect(run(node(transfer(5n), accounts)).decode_status, `${accounts.length} accounts`).toBe(
        "unknown_variant",
      );
    }
  });

  it("a high u32 index byte is a different instruction, not a transfer: 0x00000102 is unknown", () => {
    const data = cat(Uint8Array.of(2, 1, 0, 0), u64(5n));
    expect(run(node(data, ["a", "b"])).decode_status).toBe("unknown_variant");
  });
});

describe("System CreateAccount (index 0)", () => {
  it("decodes lamports, space and the owner program as base58, with [from, to] accounts", () => {
    const r = decoded(node(createAccount(2039280n, 165n), ["funder", "new-account"]));
    expect(r.kind).toBe("system_create_account");
    expect(r.fields).toEqual({
      from: "funder",
      to: "new-account",
      lamports: "2039280",
      space: "165",
      owner: OWNER_B58,
    });
  });

  it("the owner is the base58 of the 32 bytes: the Token program ID round-trips", () => {
    const owner = decodeBase58(PROGRAM_IDS.splToken);
    const r = decoded(node(cat(u32(0), u64(1n), u64(82n), owner), ["a", "b"]));
    expect(r.fields.owner).toBe(PROGRAM_IDS.splToken);
  });

  it("the maximum u64 is kept exactly in both lamports and space", () => {
    const r = decoded(node(createAccount(2n ** 64n - 1n, 2n ** 64n - 1n), ["a", "b"]));
    expect(r.fields.lamports).toBe(MAX_U64);
    expect(r.fields.space).toBe(MAX_U64);
  });

  it("zero lamports and zero space decode as the string 0", () => {
    const r = decoded(node(createAccount(0n, 0n), ["a", "b"]));
    expect(r.fields.lamports).toBe("0");
    expect(r.fields.space).toBe("0");
  });

  it("a System-program owner (32 zero bytes) is the 32-character address of ones", () => {
    const data = cat(u32(0), u64(1n), u64(0n), new Uint8Array(32));
    expect(decoded(node(data, ["a", "b"])).fields.owner).toBe(PROGRAM_IDS.system);
  });

  it("wrong lengths or account counts return null", () => {
    const good = createAccount(1n, 2n);
    expect(good.length).toBe(52);
    for (const data of [good.slice(0, 51), cat(good, Uint8Array.of(0)), good.slice(0, 20)]) {
      expect(run(node(data, ["a", "b"])).decode_status).toBe("unknown_variant");
    }
    for (const accounts of [[], ["a"], ["a", "b", "c"]]) {
      expect(run(node(good, accounts)).decode_status).toBe("unknown_variant");
    }
  });
});

describe("System TransferWithSeed (index 11)", () => {
  it("decodes lamports, seed and the seed owner, with [from, base, to] accounts", () => {
    const r = decoded(node(transferWithSeed(1000n, utf8("vault-1")), ["from", "base", "to"]));
    expect(r.kind).toBe("system_transfer_with_seed");
    expect(r.fields).toEqual({
      from: "from",
      base: "base",
      to: "to",
      lamports: "1000",
      seed: "vault-1",
      owner: OWNER_B58,
    });
  });

  it("an empty seed and a multi-byte UTF-8 seed decode; the maximum u64 lamports is exact", () => {
    expect(
      decoded(node(transferWithSeed(1n, new Uint8Array(0)), ["f", "b", "t"])).fields.seed,
    ).toBe("");
    const text = "é世😀";
    const r = decoded(node(transferWithSeed(2n ** 64n - 1n, utf8(text)), ["f", "b", "t"]));
    expect(r.fields.seed).toBe(text);
    expect(r.fields.lamports).toBe(MAX_U64);
  });

  it("a seed that is not valid UTF-8 returns null: a lone continuation byte, an overlong form, a surrogate", () => {
    for (const seed of [
      Uint8Array.of(0x80),
      Uint8Array.of(0xc0, 0x80),
      Uint8Array.of(0xed, 0xa0, 0x80),
      Uint8Array.of(0x61, 0xff),
    ]) {
      expect(run(node(transferWithSeed(1n, seed), ["f", "b", "t"])).decode_status).toBe(
        "unknown_variant",
      );
    }
  });

  it("a seed length that disagrees with the data returns null, including a length too big to be real", () => {
    const seed = utf8("abc");
    const good = transferWithSeed(1n, seed);
    // Declared length shorter than the bytes that follow (so the owner would be misread).
    const shorter = Uint8Array.from(good);
    new DataView(shorter.buffer).setBigUint64(12, 2n, true);
    // Declared length longer than the data.
    const longer = Uint8Array.from(good);
    new DataView(longer.buffer).setBigUint64(12, 4n, true);
    // The maximum u64, which no real buffer holds.
    const huge = Uint8Array.from(good);
    new DataView(huge.buffer).setBigUint64(12, 2n ** 64n - 1n, true);
    // A length whose low 32 bits are small: must not be truncated to a smaller number.
    const wrapped = Uint8Array.from(good);
    new DataView(wrapped.buffer).setBigUint64(12, 2n ** 32n + 3n, true);
    for (const data of [shorter, longer, huge, wrapped]) {
      expect(run(node(data, ["f", "b", "t"])).decode_status).toBe("unknown_variant");
    }
  });

  it("truncated or over-long data returns null", () => {
    const good = transferWithSeed(1n, utf8("abc"));
    for (const data of [
      good.slice(0, good.length - 1),
      cat(good, Uint8Array.of(0)),
      good.slice(0, 15),
    ]) {
      expect(run(node(data, ["f", "b", "t"])).decode_status).toBe("unknown_variant");
    }
  });

  it("wrong account count returns null: [from, to] is the Transfer shape, not this one", () => {
    const data = transferWithSeed(1n, utf8("abc"));
    for (const accounts of [[], ["f", "t"], ["f", "b", "t", "x"]]) {
      expect(run(node(data, accounts)).decode_status).toBe("unknown_variant");
    }
  });
});

describe("other System instructions", () => {
  it("every index other than 0, 2 and 11 returns null and keeps the raw bytes as hex", () => {
    // Assign 1, CreateAccountWithSeed 3, Advance 4, Withdraw 5, InitNonce 6, AuthNonce 7, Allocate 8,
    // AllocateWithSeed 9, AssignWithSeed 10, UpgradeNonce 12, AllowPrefund 13, and indexes beyond the enum.
    for (const index of [1, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 255, 65536, 0xffffffff]) {
      const data = cat(u32(index), u64(5n));
      const r = run(node(data, ["a", "b"]));
      expect(r.decode_status, String(index)).toBe("unknown_variant");
      if (r.decode_status === "decoded") throw new Error("unreachable");
      expect(r.data).toBe(Array.from(data, (b) => b.toString(16).padStart(2, "0")).join(""));
      expect(r.program).toBe("System");
    }
  });

  it("the decoder itself returns null (not an exception) for empty data and non-System nodes' shapes", () => {
    expect(systemDecoder.decode(node(new Uint8Array(0), []), {})).toBeNull();
    expect(systemDecoder.decode(node(Uint8Array.of(2), ["a", "b"]), {})).toBeNull();
  });

  it("never throws on any prefix of a valid instruction or on arbitrary bytes", () => {
    const full = transferWithSeed(7n, utf8("seed"));
    for (let n = 0; n <= full.length; n++) {
      for (const accounts of [[], ["a", "b"], ["a", "b", "c"]]) {
        expect(() => systemDecoder.decode(node(full.slice(0, n), accounts), {})).not.toThrow();
      }
    }
    let seed = 99;
    for (let i = 0; i < 500; i++) {
      const data = Uint8Array.from({ length: i % 70 }, () => {
        seed = (Math.imul(seed, 1103515245) + 12345) & 0x7fffffff;
        return seed & 0xff;
      });
      expect(() => systemDecoder.decode(node(data, ["a", "b", "c"]), {})).not.toThrow();
    }
  });

  it("decoding does not change the node it is given", () => {
    const n = node(transferWithSeed(1n, utf8("abc")), ["f", "b", "t"]);
    const before = JSON.stringify([n.accounts, Array.from(n.data)]);
    systemDecoder.decode(n, {});
    expect(JSON.stringify([n.accounts, Array.from(n.data)])).toBe(before);
  });
});

describe("decoded output is manifest-safe", () => {
  it("holds only strings (no number, no null, no float) for every variant", () => {
    const outs = [
      decoded(node(transfer(1n), ["a", "b"])),
      decoded(node(createAccount(1n, 2n), ["a", "b"])),
      decoded(node(transferWithSeed(1n, utf8("s")), ["a", "b", "c"])),
    ];
    for (const r of outs) {
      for (const [key, value] of Object.entries(r.fields)) {
        expect(typeof value, `${r.kind}.${key}`).toBe("string");
      }
      expect(JSON.parse(JSON.stringify(r))).toEqual(r);
    }
  });
});
