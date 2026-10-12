// Adversarial audit tests for canonicalizeJcs, written by audit-tester.
import { describe, expect, it } from "vitest";
import vm from "node:vm";
import canonicalize from "canonicalize";
import { canonicalizeJcs } from "../canonical.js";

describe("audit: key ordering at every depth with non-ASCII, astral and mixed keys", () => {
  // Code-unit order: "\r" 0x0D, "1" 0x31, "A" 0x41, "_" 0x5F, "a" 0x61, U+0080, "ö" U+00F6,
  // U+20AC, U+D83D.. (astral, surrogate lead), U+FB33.
  const keys = ["ö", "€", "😀", "דּ", "a", "A", "_", "1", "\r", "\u0080", "🌀"];
  const expectedOrder = [...keys].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));

  it("sorted order really is UTF-16 code unit order (astral before U+FB33, after U+20AC)", () => {
    expect(expectedOrder.indexOf("😀")).toBeGreaterThan(expectedOrder.indexOf("€"));
    expect(expectedOrder.indexOf("😀")).toBeLessThan(expectedOrder.indexOf("דּ"));
  });

  it("emits keys in that order at depth 1, 2 and 3 and inside arrays, from reversed insertion", () => {
    const mk = (order: string[]) => Object.fromEntries(order.map((k) => [k, keys.indexOf(k)]));
    const nested = (order: string[]) => ({
      top: mk(order),
      arr: [{ deeper: mk(order) }],
      ...mk(order),
    });
    const out = canonicalizeJcs(nested([...keys].reverse()));
    expect(out).toBe(canonicalizeJcs(nested(keys)));
    const parsed = JSON.parse(out);
    expect(Object.keys(parsed.top).sort()).toEqual([...keys].sort());
    // Every object of 11 keys must appear in code-unit order in the text.
    const re = /"(?:[^"\\]|\\.)*"(?=:)/g;
    const seq = Array.from(out.matchAll(re), (m) => JSON.parse(m[0]) as string);
    const slice = (from: number) => seq.slice(from, from + keys.length);
    const firstTop = seq.indexOf("top");
    expect(slice(firstTop + 1)).toEqual(expectedOrder);
  });

  it("does not treat keys that look alike as equal (composed vs decomposed, case)", () => {
    const out = canonicalizeJcs({ é: 1, é: 2, E: 3, e: 4 });
    expect(Object.keys(JSON.parse(out))).toHaveLength(4);
  });

  it("integer-like keys sort as strings, not numerically", () => {
    expect(canonicalizeJcs({ 10: 1, 9: 2, 1: 3 })).toBe('{"1":3,"10":1,"9":2}');
  });
});

describe("audit: prototype-pollution style keys and toJSON", () => {
  it("serialises __proto__, constructor and prototype as ordinary own keys from JSON.parse", () => {
    const parsed = JSON.parse('{"__proto__":{"polluted":1},"constructor":"c","prototype":"p"}');
    expect(canonicalizeJcs(parsed)).toBe(
      '{"__proto__":{"polluted":1},"constructor":"c","prototype":"p"}',
    );
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("refuses an object literal that sets the prototype via __proto__", () => {
    expect(() => canonicalizeJcs({ __proto__: { a: 1 }, b: 2 })).toThrow();
  });

  it("refuses an object that carries a toJSON method", () => {
    expect(() => canonicalizeJcs({ toJSON: () => "x" })).toThrow();
  });

  it("refuses a Date (which has toJSON) rather than honouring it", () => {
    expect(() => canonicalizeJcs({ d: new Date(0) })).toThrow();
  });

  // The engine honours toJSON on any object, arrays included; the validator now refuses it.
  it("must not silently honour toJSON on an array (own property)", () => {
    const arr = [1, 2] as unknown[] & { toJSON?: () => string };
    arr.toJSON = () => "substituted";
    expect(() => canonicalizeJcs({ list: arr })).toThrow();
  });

  it("must not silently honour toJSON on an Array subclass", () => {
    class Sneaky extends Array<number> {
      toJSON() {
        return "substituted";
      }
    }
    expect(() => canonicalizeJcs({ list: Sneaky.from([1, 2]) })).toThrow();
  });
});

describe("audit: accessors and proxies (validation must see what the engine serialises)", () => {
  // Validation and serialisation work on one snapshot, so a second read can never differ.
  it("rejects an accessor property that returns a valid value first and an invalid one later", () => {
    let reads = 0;
    const sneaky = {
      get a() {
        reads += 1;
        return reads === 1 ? 1 : 1.5;
      },
    };
    expect(() => canonicalizeJcs(sneaky)).toThrow();
  });

  it("a Proxy whose get answers differently each time cannot put an unchecked value in the output", () => {
    // Values are read once, through the property descriptor, into a snapshot; the get trap is never
    // consulted, so the output is the validated snapshot and never the later null.
    let reads = 0;
    const proxy = new Proxy(
      { a: "x" },
      { get: (t, k) => (k === "a" ? (++reads === 1 ? "x" : null) : Reflect.get(t, k)) },
    );
    expect(canonicalizeJcs(proxy)).toBe('{"a":"x"}');
  });

  it("refuses any accessor property, even a stable one, and names its path", () => {
    expect(() =>
      canonicalizeJcs({
        get a() {
          return 1;
        },
      }),
    ).toThrow(/accessor.*\$\.a/);
  });
});

describe("audit: arrays carry nothing but their elements, and objects are read once", () => {
  it("rejects an array with any extra own property, enumerable or not", () => {
    const a = [1] as unknown[] & { x?: number };
    a.x = 1;
    expect(() => canonicalizeJcs({ a })).toThrow(/extra array property/);
    const b = [1];
    Object.defineProperty(b, "hidden", { value: 1, enumerable: false });
    expect(() => canonicalizeJcs({ b })).toThrow(/extra array property/);
  });

  it("rejects an array with an inherited toJSON, such as a polluted Array.prototype", () => {
    (Array.prototype as unknown as { toJSON?: () => string }).toJSON = () => "x";
    try {
      expect(() => canonicalizeJcs({ a: [1] })).toThrow(/toJSON/);
    } finally {
      delete (Array.prototype as unknown as { toJSON?: unknown }).toJSON;
    }
  });

  it("ignores a polluted Object.prototype.toJSON because the engine only sees a null-prototype copy", () => {
    (Object.prototype as unknown as { toJSON?: () => string }).toJSON = () => "x";
    try {
      expect(canonicalizeJcs({ a: 1 })).toBe('{"a":1}');
    } finally {
      delete (Object.prototype as unknown as { toJSON?: unknown }).toJSON;
    }
  });

  it("keeps a JSON.parse own __proto__ key as an ordinary key and never sets a prototype", () => {
    const parsed = JSON.parse('{"__proto__":{"polluted":1},"a":2}');
    expect(canonicalizeJcs(parsed)).toBe('{"__proto__":{"polluted":1},"a":2}');
    expect(({} as { polluted?: number }).polluted).toBeUndefined();
  });

  it("serialises only the value read through the descriptor, never a later get", () => {
    const proxy = new Proxy({ a: 1 }, { get: (t, k) => (k === "a" ? 1.5 : Reflect.get(t, k)) });
    expect(canonicalizeJcs(proxy)).toBe('{"a":1}');
  });
});

describe("audit: numbers", () => {
  it("accepts -0 and canonicalises it to 0, the same bytes as 0 (RFC Appendix B)", () => {
    expect(canonicalizeJcs(-0)).toBe("0");
    expect(canonicalizeJcs({ a: -0 })).toBe(canonicalizeJcs({ a: 0 }));
  });

  it("rejects 1e-7, 5e-324 and other non-integers, and 1e21 as outside the safe range", () => {
    expect(() => canonicalizeJcs(1e-7)).toThrow(/integer/);
    expect(() => canonicalizeJcs(5e-324)).toThrow(/integer/);
    expect(() => canonicalizeJcs(1e21)).toThrow(/safe range/);
  });

  it("the engine prints the RFC Appendix B integers beyond 2**53 exactly, and canonicalizeJcs refuses them", () => {
    const fromBits = (hex: string) => {
      const v = new DataView(new ArrayBuffer(8));
      v.setBigUint64(0, BigInt(`0x${hex}`));
      return v.getFloat64(0);
    };
    for (const [bits, text] of [
      ["44b52d02c7e14af5", "9.999999999999997e+22"],
      ["44b52d02c7e14af7", "1.0000000000000001e+23"],
    ]) {
      expect(canonicalize(fromBits(bits))).toBe(text);
      expect(() => canonicalizeJcs(fromBits(bits))).toThrow(/safe range/);
    }
  });

  // Two different integers collapse to one double above 2**53, and a manifest holds token amounts
  // as strings, so a number beyond Number.MAX_SAFE_INTEGER is a bug in the caller: fail loud.
  it("rejects integers outside the safe range (2**53, 2**53+1, 1e21, MAX_VALUE)", () => {
    for (const n of [2 ** 53, 2 ** 53 + 1, 1e21, Number.MAX_VALUE]) {
      expect(() => canonicalizeJcs(n)).toThrow();
    }
  });

  it("2**53 and 2**53+1 are the same double, which is why both are refused; the safe bounds are accepted", () => {
    expect(2 ** 53 + 1).toBe(2 ** 53);
    expect(() => canonicalizeJcs(2 ** 53)).toThrow();
    expect(canonicalizeJcs(Number.MAX_SAFE_INTEGER)).toBe("9007199254740991");
    expect(canonicalizeJcs(Number.MIN_SAFE_INTEGER)).toBe("-9007199254740991");
    expect(() => canonicalizeJcs(Number.MIN_SAFE_INTEGER - 1)).toThrow();
  });
});

describe("audit: rejected inputs give path-only messages that never contain the value", () => {
  const SECRET = "SECRET-case-note-9f3a";
  const cases: Array<[string, unknown]> = [
    ["float", { note: SECRET, v: 0.1 }],
    ["NaN", { note: SECRET, v: Number.NaN }],
    ["Infinity", { note: SECRET, v: Number.POSITIVE_INFINITY }],
    ["-Infinity", { note: SECRET, v: Number.NEGATIVE_INFINITY }],
    ["undefined", { note: SECRET, v: undefined }],
    ["null", { note: SECRET, v: null }],
    ["bigint", { note: SECRET, v: 123456789012345678901234567890n }],
    ["symbol", { note: SECRET, v: Symbol(SECRET) }],
    ["function", { note: SECRET, v: function leak_SECRET() {} }],
    ["Date", { note: SECRET, v: new Date(1234567890123) }],
    ["Map", { note: SECRET, v: new Map([[SECRET, SECRET]]) }],
    ["Set", { note: SECRET, v: new Set([SECRET]) }],
    [
      "class instance",
      {
        note: SECRET,
        v: new (class Leaky {
          secret = SECRET;
        })(),
      },
    ],
    ["sparse array", { note: SECRET, v: [SECRET, , SECRET] }], // eslint-disable-line no-sparse-arrays
    [
      "cycle",
      (() => {
        const o: Record<string, unknown> = { note: SECRET };
        o.v = o;
        return o;
      })(),
    ],
  ];
  for (const [label, value] of cases) {
    it(`${label}: throws, names a path, does not echo the value`, () => {
      let msg = "";
      try {
        canonicalizeJcs(value);
      } catch (e) {
        msg = (e as Error).message;
      }
      expect(msg).not.toBe("");
      expect(msg).toMatch(/\$/);
      expect(msg).not.toContain(SECRET);
      expect(msg).not.toMatch(/1234567890|0\.1|leak_SECRET/);
    });
  }

  it("lone surrogates throw without echoing the string (message comes from the engine)", () => {
    const secret = `${SECRET}\ud800`;
    let msg = "";
    try {
      canonicalizeJcs({ v: secret });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).not.toBe("");
    expect(msg).not.toContain(SECRET);
  });

  // Keys are part of the path. If a key is itself case data (an address, a person's name) it ends up
  // in the message. Documented as low severity; test pins current behaviour so a change is noticed.
  it("echoes the property NAME in the path (keys are not treated as sensitive)", () => {
    expect(() => canonicalizeJcs({ "0xCaseSpecificAddress": 1.5 })).toThrow(
      /0xCaseSpecificAddress/,
    );
  });
});

describe("audit: control characters and string edge cases", () => {
  it("escapes every C0 control per RFC 3.2.2.2 and leaves DEL, U+2028 and U+2029 raw", () => {
    let all = "";
    for (let i = 0; i < 0x20; i += 1) all += String.fromCharCode(i);
    const out = canonicalizeJcs(all);
    const expected =
      '"' +
      Array.from({ length: 0x20 }, (_, i) =>
        i === 8
          ? "\\b"
          : i === 9
            ? "\\t"
            : i === 10
              ? "\\n"
              : i === 12
                ? "\\f"
                : i === 13
                  ? "\\r"
                  : `\\u${i.toString(16).padStart(4, "0")}`,
      ).join("") +
      '"';
    expect(out).toBe(expected);
    expect(canonicalizeJcs("\u007f  ")).toBe('"\u007f  "');
  });

  it("rejects a lone surrogate at any position, accepts valid pairs", () => {
    for (const s of ["\ud800", "\udc00", "a\ud800b", "\udc00\ud800", "\ud83d"]) {
      expect(() => canonicalizeJcs(s)).toThrow();
      expect(() => canonicalizeJcs({ [s]: 1 })).toThrow();
    }
    expect(canonicalizeJcs("😀")).toBe('"😀"');
  });
});

describe("audit: only plain data is accepted", () => {
  it("rejects typed arrays, boxed primitives, Map, Set, Date, class instances and RegExp", () => {
    for (const v of [
      new Uint8Array(1),
      new Number(1),
      new String("x"),
      new Boolean(true),
      new Map(),
      new Set(),
      new Date(0),
      /x/,
      new (class A {})(),
      new ArrayBuffer(1),
    ]) {
      expect(() => canonicalizeJcs({ v })).toThrow(/plain objects/);
    }
  });

  it("accepts null-prototype and frozen objects", () => {
    const np = Object.assign(Object.create(null), { a: 1 });
    expect(canonicalizeJcs(np)).toBe('{"a":1}');
    expect(canonicalizeJcs(Object.freeze({ a: Object.freeze([1]) }))).toBe('{"a":[1]}');
  });

  it("refuses symbol keys and non-enumerable properties, which a copy would silently drop", () => {
    const o = { a: 1, [Symbol("s")]: 1.5 };
    expect(() => canonicalizeJcs(o)).toThrow(/non-enumerable or symbol property/);
    const h = { a: 1 };
    Object.defineProperty(h, "hidden", { value: 1.5, enumerable: false });
    expect(() => canonicalizeJcs(h)).toThrow(/non-enumerable or symbol property/);
  });

  it("rejects an object created in another realm (documents a false positive for iframes)", () => {
    expect(() => canonicalizeJcs(vm.runInNewContext("({a:1})"))).toThrow(/plain objects/);
  });
});

describe("audit: size and depth fail loud or stay bounded", () => {
  const nest = (depth: number) => {
    let v: unknown = { x: 1 };
    for (let i = 0; i < depth; i += 1) v = { a: v };
    return v;
  };

  it("handles depth 2000", () => {
    expect(canonicalizeJcs(nest(2000)).length).toBeGreaterThan(2000);
  });

  it("depth 200000 throws an error (stack overflow is loud) and does not hang or return text", () => {
    const started = Date.now();
    expect(() => canonicalizeJcs(nest(200_000))).toThrow();
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it("a 500k element array and a 10 MB string canonicalise in bounded time", () => {
    const started = Date.now();
    const arr = Array.from({ length: 500_000 }, (_, i) => i);
    expect(canonicalizeJcs(arr).length).toBeGreaterThan(500_000);
    expect(canonicalizeJcs("a".repeat(10_000_000)).length).toBe(10_000_002);
    expect(Date.now() - started).toBeLessThan(10_000);
  });

  it("a sparse array of length 2**32-1 fails at the first hole instead of looping 4 billion times", () => {
    const started = Date.now();
    expect(() => canonicalizeJcs(new Array(2 ** 32 - 1))).toThrow(/undefined/);
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

describe("audit: determinism", () => {
  it("gives identical bytes over 50 runs and after re-building the input in another order", () => {
    const build = (flip: boolean) => {
      const entries: Array<[string, unknown]> = [
        ["z", ["€", { b: 1, a: "😀" }]],
        ["a", { "😀": 1, "€": 2, ö: 3 }],
        ["m", "\u0000"],
      ];
      return Object.fromEntries(flip ? entries.reverse() : entries);
    };
    const first = canonicalizeJcs(build(false));
    const firstBytes = Array.from(new TextEncoder().encode(first)).join(",");
    for (let i = 0; i < 50; i += 1) {
      const t = canonicalizeJcs(build(i % 2 === 0));
      expect(Array.from(new TextEncoder().encode(t)).join(",")).toBe(firstBytes);
    }
  });
});
