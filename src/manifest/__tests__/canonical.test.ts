// Tests for canonicalizeJcs. The vectors below are copied from RFC 8785 itself
// (https://www.rfc-editor.org/rfc/rfc8785.txt): section 3.2.2 / 3.2.3 (primitive serialisation and
// the sorted result), section 3.2.3 (property sorting), section 3.2.4 (UTF-8 bytes) and Appendix B
// (number samples). Nothing here is written from memory.
//
// Why two layers: the RFC's own sample contains floats and a null, which canonicalizeJcs rejects on
// purpose (a manifest has neither). So the full sample is run through the `canonicalize` package to
// prove the engine we wrap is RFC-conformant, and the same sample minus floats and null is run
// through canonicalizeJcs to prove the wrapper does not change what the engine produces.
import { describe, expect, it } from "vitest";
import canonicalize from "canonicalize";
import { canonicalizeJcs } from "../canonical.js";

const toHex = (s: string) =>
  Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join("");

// RFC 8785 section 3.2.2: the input as JSON text, parsed (so the \u escapes are real characters).
const RFC_3_2_2_INPUT = `{
  "numbers": [333333333.33333329, 1E30, 4.50,
              2e-3, 0.000000000000000000000000001],
  "string": "\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\"\\/",
  "literals": [null, true, false]
}`;

// RFC 8785 section 3.2.3: the properly canonicalised version of the sample above.
const RFC_3_2_3_STRING_MEMBER = `"string":"€$\\u000f\\nA'B\\"\\\\\\\\\\"/"`;
const RFC_3_2_3_OUTPUT = `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],${RFC_3_2_3_STRING_MEMBER}}`;

// RFC 8785 section 3.2.4: the same output as UTF-8 bytes.
const RFC_3_2_4_HEX = [
  "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72",
  "75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a",
  "5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31",
  "65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37",
  "5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30",
  "30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d",
]
  .join(" ")
  .replace(/ /g, "");

// RFC 8785 section 3.2.3: property-sorting vector.
const RFC_SORT_INPUT = `{
  "\\u20ac": "Euro Sign",
  "\\r": "Carriage Return",
  "\\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\\ud83d\\ude00": "Emoji: Grinning Face",
  "\\u0080": "Control",
  "\\u00f6": "Latin Small Letter O With Diaeresis"
}`;
const RFC_SORT_ORDER = [
  "Carriage Return",
  "One",
  "Control",
  "Latin Small Letter O With Diaeresis",
  "Euro Sign",
  "Emoji: Grinning Face",
  "Hebrew Letter Dalet With Dagesh",
];

describe("RFC 8785 conformance of the engine we wrap (section 3.2.2 to 3.2.4)", () => {
  const sample = JSON.parse(RFC_3_2_2_INPUT);

  it("canonicalises the section 3.2.2 sample to the section 3.2.3 output", () => {
    expect(canonicalize(sample)).toBe(RFC_3_2_3_OUTPUT);
  });

  it("emits the exact UTF-8 bytes shown in section 3.2.4", () => {
    expect(toHex(canonicalize(sample) as string)).toBe(RFC_3_2_4_HEX);
  });

  it("naive JSON.stringify is NOT the canonical form (insertion order, lower-case numbers)", () => {
    expect(JSON.stringify(sample)).not.toBe(RFC_3_2_3_OUTPUT);
  });
});

describe("canonicalizeJcs: RFC 8785 vectors", () => {
  it("rejects the full section 3.2.2 sample because it holds floats and a null", () => {
    expect(() => canonicalizeJcs(JSON.parse(RFC_3_2_2_INPUT))).toThrow();
  });

  it("matches the RFC string-escaping example (section 3.2.2 to 3.2.4)", () => {
    const { string } = JSON.parse(RFC_3_2_2_INPUT);
    const out = canonicalizeJcs({ string });
    expect(out).toBe(`{${RFC_3_2_3_STRING_MEMBER}}`);
    // Section 3.2.4 bytes: the "string" member is the tail of the RFC hex, then the closing brace.
    const memberHex = RFC_3_2_4_HEX.slice(RFC_3_2_4_HEX.indexOf(toHex('"string":')), -2);
    expect(toHex(out)).toBe(`7b${memberHex}7d`);
  });

  it("matches the RFC sample once floats and null are removed (booleans, escapes, order)", () => {
    const sample = JSON.parse(RFC_3_2_2_INPUT);
    const reduced = { string: sample.string, literals: [true, false], numbers: [] };
    expect(canonicalizeJcs(reduced)).toBe(
      `{"literals":[true,false],"numbers":[],${RFC_3_2_3_STRING_MEMBER}}`,
    );
  });

  it("sorts the section 3.2.3 property-sorting vector by UTF-16 code units", () => {
    const out = canonicalizeJcs(JSON.parse(RFC_SORT_INPUT));
    const values = Array.from(out.matchAll(/:"([^"]*)"/g), (m) => m[1]);
    expect(values).toEqual(RFC_SORT_ORDER);
    expect(out).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
    );
  });

  // Appendix B gives each sample as IEEE 754 bits plus its JSON text. The doubles are built from the
  // bits, so no decimal literal in this file can round differently from the RFC's own value.
  const fromBits = (hex: string) => {
    const view = new DataView(new ArrayBuffer(8));
    view.setBigUint64(0, BigInt(`0x${hex}`));
    return view.getFloat64(0);
  };

  it("matches the RFC Appendix B integer samples inside the safe range", () => {
    expect(canonicalizeJcs(fromBits("0000000000000000"))).toBe("0"); // zero
    expect(canonicalizeJcs(fromBits("8000000000000000"))).toBe("0"); // minus zero
  });

  it("refuses the Appendix B integer samples beyond the safe range, which the engine prints as the RFC does", () => {
    const rows: Array<[string, string]> = [
      ["4340000000000000", "9007199254740992"], // 2**53, max pos int
      ["c340000000000000", "-9007199254740992"], // max neg int
      ["4430000000000000", "295147905179352830000"], // ~2**68
      ["44b52d02c7e14af6", "1e+23"],
      ["444b1ae4d6e2ef4e", "999999999999999700000"],
      ["444b1ae4d6e2ef4f", "999999999999999900000"],
      ["444b1ae4d6e2ef50", "1e+21"],
      ["7fefffffffffffff", "1.7976931348623157e+308"], // max pos number
      ["ffefffffffffffff", "-1.7976931348623157e+308"], // max neg number
    ];
    for (const [bits, text] of rows) {
      const n = fromBits(bits);
      expect(canonicalize(n)).toBe(text); // the wrapped engine is RFC-exact
      expect(() => canonicalizeJcs(n)).toThrow(/safe range/); // a manifest never holds these
    }
  });

  it("refuses the Appendix B float rows, which the engine alone prints exactly as the RFC does", () => {
    const rows: Array<[string, string]> = [
      ["0000000000000001", "5e-324"], // min pos number
      ["8000000000000001", "-5e-324"], // min neg number
      ["3eb0c6f7a0b5ed8c", "9.999999999999997e-7"],
      ["3eb0c6f7a0b5ed8d", "0.000001"],
      ["41b3de4355555553", "333333333.3333332"],
      ["41b3de4355555554", "333333333.33333325"],
      ["41b3de4355555555", "333333333.3333333"],
      ["41b3de4355555556", "333333333.3333334"],
      ["41b3de4355555557", "333333333.33333343"],
      ["becbf647612f3696", "-0.0000033333333333333333"],
      ["43143ff3c1cb0959", "1424953923781206.2"], // round to even
    ];
    for (const [bits, text] of rows) {
      const n = fromBits(bits);
      expect(canonicalize(n)).toBe(text);
      expect(() => canonicalizeJcs(n)).toThrow(/integer/i);
    }
  });

  it("refuses NaN and Infinity, the two Appendix B rows with no JSON representation", () => {
    expect(() => canonicalizeJcs(fromBits("7fffffffffffffff"))).toThrow(/NaN/);
    expect(() => canonicalizeJcs(fromBits("7ff0000000000000"))).toThrow(/Infinity/);
  });
});

describe("canonicalizeJcs: ordering, escaping and structure", () => {
  it("is independent of insertion order, at every depth and inside arrays", () => {
    const a = { z: 1, a: { y: 2, b: [{ q: 1, p: 2 }] } };
    const b = { a: { b: [{ p: 2, q: 1 }], y: 2 }, z: 1 };
    expect(canonicalizeJcs(a)).toBe('{"a":{"b":[{"p":2,"q":1}],"y":2},"z":1}');
    expect(canonicalizeJcs(a)).toBe(canonicalizeJcs(b));
  });

  it("keeps array order", () => {
    expect(canonicalizeJcs([3, 1, 2])).toBe("[3,1,2]");
  });

  it("orders keys by UTF-16 code unit, not by locale or code point", () => {
    // localeCompare gives _ 1 a a-umlaut B z Z; code units give 1 B Z _ a z a-umlaut.
    const keys = ["a", "B", "Z", "ä", "z", "1", "_"];
    const obj = Object.fromEntries(keys.map((k) => [k, 0]));
    expect(canonicalizeJcs(obj)).toBe('{"1":0,"B":0,"Z":0,"_":0,"a":0,"z":0,"ä":0}');
  });

  it("orders astral keys by surrogate code units: U+1F600 sorts before U+FB33", () => {
    // By code point U+FB33 < U+1F600; by UTF-16 code unit 0xD83D < 0xFB33. JCS is the latter.
    const out = canonicalizeJcs({ דּ: 1, "😀": 2, "€": 3 });
    expect(out).toBe('{"€":3,"😀":2,"דּ":1}');
  });

  it("orders non-ASCII keys the same whatever order they were inserted in", () => {
    const keys = ["ö", "€", "😀", "דּ", "a", "\u0080"];
    const forward = Object.fromEntries(keys.map((k, i) => [k, i]));
    const backward = Object.fromEntries([...keys].reverse().map((k) => [k, keys.indexOf(k)]));
    expect(canonicalizeJcs(forward)).toBe(canonicalizeJcs(backward));
  });

  it("escapes control characters in lower-case hex, quote and backslash, and leaves the rest raw", () => {
    expect(canonicalizeJcs("\b\t\n\f\r")).toBe('"\\b\\t\\n\\f\\r"');
    expect(canonicalizeJcs("\u0000\u001f\u007f")).toBe('"\\u0000\\u001f\u007f"');
    expect(canonicalizeJcs('"\\/')).toBe('"\\"\\\\/"');
    expect(canonicalizeJcs("  ")).toBe('"  "');
    expect(canonicalizeJcs("€😀")).toBe('"€😀"');
  });

  it("escapes property names the same way as values", () => {
    expect(canonicalizeJcs({ "a\nb": 1, 'q"': 2 })).toBe('{"a\\nb":1,"q\\"":2}');
  });

  it("serialises strings, booleans, empty containers and the empty key", () => {
    expect(canonicalizeJcs("x")).toBe('"x"');
    expect(canonicalizeJcs(true)).toBe("true");
    expect(canonicalizeJcs(false)).toBe("false");
    expect(canonicalizeJcs({})).toBe("{}");
    expect(canonicalizeJcs([])).toBe("[]");
    expect(canonicalizeJcs({ "": 1, a: 2, aa: 3, ab: 4 })).toBe('{"":1,"a":2,"aa":3,"ab":4}');
  });

  it("rejects lone surrogates in values and in property names (RFC 3.2.2.2)", () => {
    expect(() => canonicalizeJcs("\ud800")).toThrow();
    expect(() => canonicalizeJcs({ k: "x\udead" })).toThrow();
    expect(() => canonicalizeJcs({ "\udead": 1 })).toThrow();
  });

  it("keeps a token amount as a string of raw base units and refuses a bigint", () => {
    expect(canonicalizeJcs({ amount: "18446744073709551615" })).toBe(
      '{"amount":"18446744073709551615"}',
    );
    expect(() => canonicalizeJcs({ amount: 18446744073709551615n })).toThrow();
  });

  it("accepts negative integers, zero and integer-valued doubles", () => {
    expect(canonicalizeJcs({ a: -1, b: 0, c: 1e3, d: 12 })).toBe('{"a":-1,"b":0,"c":1000,"d":12}');
  });

  it("serialises the same value to the same text every time", () => {
    const v = { b: [1, "x", true], a: { d: "€", c: 2 } };
    const first = canonicalizeJcs(v);
    for (let i = 0; i < 20; i += 1) expect(canonicalizeJcs(v)).toBe(first);
  });
});

describe("canonicalizeJcs: refusals anywhere in the value", () => {
  const bad: Array<[string, unknown]> = [
    ["a float", 1.5],
    ["a negative float", -0.25],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["-Infinity", Number.NEGATIVE_INFINITY],
    ["undefined", undefined],
    ["null", null],
    ["a bigint", 10n],
    ["a function", () => 1],
    ["a symbol", Symbol("x")],
    ["a Date", new Date(0)],
    ["a Map", new Map()],
    ["a Set", new Set()],
    ["a class instance", new (class Foo {})()],
  ];

  for (const [label, value] of bad) {
    it(`throws on ${label} at the top level`, () => {
      expect(() => canonicalizeJcs(value)).toThrow();
    });
    it(`throws on ${label} nested in an object`, () => {
      expect(() => canonicalizeJcs({ a: { b: value } })).toThrow();
    });
    it(`throws on ${label} nested in an array`, () => {
      expect(() => canonicalizeJcs({ a: [1, value] })).toThrow();
    });
  }

  it("throws on an undefined property rather than letting the engine drop it silently", () => {
    // The engine alone would give {"b":1}; that would let two different manifests share a hash.
    expect(canonicalize({ a: undefined, b: 1 })).toBe('{"b":1}');
    expect(() => canonicalizeJcs({ a: undefined, b: 1 })).toThrow(/undefined/);
  });

  it("throws on an array hole rather than letting the engine turn it into null", () => {
    // eslint-disable-next-line no-sparse-arrays
    expect(() => canonicalizeJcs([1, , 3])).toThrow();
  });

  it("throws on a cycle", () => {
    const a: Record<string, unknown> = {};
    a.self = a;
    expect(() => canonicalizeJcs(a)).toThrow(/cycl|circular/i);
  });

  it("allows the same object to appear twice as a sibling (a DAG is not a cycle)", () => {
    const shared = { x: 1 };
    expect(canonicalizeJcs({ a: shared, b: shared })).toBe('{"a":{"x":1},"b":{"x":1}}');
  });

  it("names the path of the offending value but never prints the value itself", () => {
    const secret = "client-confidential-4242";
    const value = { a: [{ b: 1.5, note: secret }] };
    expect(() => canonicalizeJcs(value)).toThrow(/\$\.a\[0\]\.b/);
    try {
      canonicalizeJcs(value);
    } catch (e) {
      expect((e as Error).message).not.toContain(secret);
      expect((e as Error).message).not.toContain("1.5");
    }
  });
});
