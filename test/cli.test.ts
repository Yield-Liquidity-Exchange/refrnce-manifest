// The command line, run in-process with a fake chain. What these tests protect: a person reads the exit code
// and the printed verdict, so a tampered record must never print VERIFIED or exit 0, an outage must never read
// as tampering (exit 2, not 1), and no RPC URL (it may hold a provider key) may ever be printed.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EXIT, parseArgs, runCli, safe, USAGE } from "../src/cli-core.js";
import type { Claim } from "../src/manifest/types.js";
import { VERSION } from "../src/version.js";
import {
  ARTIFACT,
  PAYER,
  RECIPIENT,
  fakeFetch,
  fakeFetchByHost,
  makeFixture,
  type Fixture,
} from "./helpers/fixture.js";

let dir: string;
let fx: Fixture;
beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "trace-verify-test-"));
  fx = await makeFixture();
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const write = (name: string, content: string | Uint8Array) => {
  const p = join(dir, name);
  writeFileSync(p, content);
  return p;
};

async function run(
  argv: string[],
  fetchArg = fakeFetch(fx.chain),
  issuerKeys: unknown = fx.issuerKeys,
) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await runCli(
    argv,
    { out: (l) => out.push(l), err: (l) => err.push(l) },
    { fetch: fetchArg.fetch, issuerKeys },
  );
  return { code, out: out.join("\n"), err: err.join("\n"), urls: fetchArg.urls };
}

describe("an honest record", () => {
  it("exits 0, prints every check C1 to C8 and every claim, and names the verdict VERIFIED", async () => {
    const file = write("honest.json", JSON.stringify(fx.envelope));
    const r = await run([file]);
    expect(r.code).toBe(EXIT.verified);
    for (const id of ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"])
      expect(r.out).toMatch(new RegExp(`^${id}  `, "m"));
    expect(r.out).toMatch(/^C5 .*skipped/m);
    expect(r.out).toContain("Verdict: VERIFIED");
    // every claim of the record has a result row
    for (const c of fx.envelope.manifest.claims) expect(r.out).toContain(c.id);
    expect(r.out).toMatch(/reproduced/);
    expect(r.out).toContain("Trace ID: TRC-SYNTH0TEST12");
    expect(r.err).toBe("");
  });

  it("with the artifact it lists, checks C6 too", async () => {
    const file = write("honest2.json", JSON.stringify(fx.envelope));
    const art = write(ARTIFACT.name, fx.artifactBytes);
    const r = await run([file, art]);
    expect(r.code).toBe(EXIT.verified);
    expect(r.out).toMatch(/^C6 .*pass/m);
  });

  it("takes the cluster from the record and says so; --cluster says it came from the user", async () => {
    const file = write("honest3.json", JSON.stringify(fx.envelope));
    expect((await run([file])).out).toContain("Cluster:  devnet (named by the record)");
    expect((await run([file, "--cluster", "devnet"])).out).toContain(
      "Cluster:  devnet (from --cluster)",
    );
  });
});

describe("a record that does not match", () => {
  it("one byte of an amount changed in the file: exit 1, C2 fails, never VERIFIED", async () => {
    const text = JSON.stringify(fx.envelope);
    const changed = text.replace("1000000", "1000001");
    expect(changed).not.toBe(text);
    const r = await run([write("tampered.json", changed)]);
    expect(r.code).toBe(EXIT.does_not_match);
    expect(r.out).toMatch(/^C2 .*FAIL/m);
    expect(r.out).toContain("Verdict: DOES NOT MATCH");
    expect(r.out).not.toContain("VERIFIED");
    expect(r.out).not.toContain("Verdict: VERIFIED");
  });

  it("a validly signed record whose claim is not what the chain says: exit 1, the claim row names the field", async () => {
    const forged = await makeFixture({
      alterClaims: (claims) =>
        claims.map((c) =>
          c.code === "SOL_TRANSFER"
            ? ({ ...c, value: { ...(c.value as object), amount: "999999" } } as Claim)
            : c,
        ),
    });
    const r = await run(
      [write("forged.json", JSON.stringify(forged.envelope))],
      fakeFetch(forged.chain),
      forged.issuerKeys,
    );
    // C1 to C4 pass (it is signed and anchored); the chain contradicts the claim.
    expect(r.out).toMatch(/^C3 .*pass/m);
    expect(r.out).toMatch(/^C7 .*FAIL/m);
    expect(r.code).toBe(EXIT.does_not_match);
    expect(r.out).toContain("DOES NOT MATCH");
    expect(r.out).toContain("field:    value.amount");
    expect(r.out).toContain('"999999"');
    expect(r.out).toContain("Verdict: DOES NOT MATCH");
  });

  it("an artifact whose bytes differ from the record: exit 1, C6 fails", async () => {
    const file = write("honest4.json", JSON.stringify(fx.envelope));
    const art = write(ARTIFACT.name, new TextEncoder().encode("another file\n"));
    const r = await run([file, art]);
    expect(r.code).toBe(EXIT.does_not_match);
    expect(r.out).toMatch(/^C6 .*FAIL/m);
  });

  it("a signature by a key that is not pinned: exit 1", async () => {
    const file = write("honest5.json", JSON.stringify(fx.envelope));
    const r = await run([file], fakeFetch(fx.chain), { keys: [] });
    expect(r.code).toBe(EXIT.does_not_match);
    expect(r.out).toMatch(/^C3 .*FAIL/m);
  });
});

describe("when the check cannot be completed", () => {
  it("an RPC outage is exit 2, UNABLE TO CHECK, never a finding about the record", async () => {
    const file = write("honest6.json", JSON.stringify(fx.envelope));
    const r = await run([file], fakeFetch(fx.chain, { down: true }));
    expect(r.code).toBe(EXIT.unable_to_check);
    expect(r.out).toContain("Verdict: UNABLE TO CHECK");
    expect(r.out).not.toContain("DOES NOT MATCH");
    expect(r.out).not.toContain("FAIL");
  });

  it("an endpoint for another cluster than the record is exit 2, not a tamper verdict", async () => {
    const file = write("honest7.json", JSON.stringify(fx.envelope));
    const r = await run([file, "--cluster", "mainnet-beta"]);
    expect(r.code).toBe(EXIT.unable_to_check);
    expect(r.out).not.toContain("Verdict: DOES NOT MATCH");
  });
});

describe("usage errors are exit 3 and check nothing", () => {
  const file = () => write("any.json", JSON.stringify(fx.envelope));

  it.each([
    ["no arguments", () => []],
    ["an unknown option", () => [file(), "--frobnicate"]],
    ["an unknown cluster", () => [file(), "--cluster", "moon"]],
    ["--rpc without --cluster", () => [file(), "--rpc", "https://rpc.example.test"]],
    ["--rpc with no value", () => [file(), "--cluster", "devnet", "--rpc"]],
    [
      "a plain http endpoint",
      () => [file(), "--cluster", "devnet", "--rpc", "http://rpc.example.test"],
    ],
    [
      "a URL with credentials",
      () => [
        file(),
        "--cluster",
        "devnet",
        "--rpc",
        ["https://user:pw", "rpc.example.test"].join("@"),
      ],
    ],
    ["a value that is not a URL", () => [file(), "--cluster", "devnet", "--rpc", "not a url"]],
    ["a missing file", () => [join(dir, "does-not-exist.json")]],
  ])("%s", async (_name, args) => {
    const fetchArg = fakeFetch(fx.chain);
    const r = await run(args(), fetchArg);
    expect(r.code).toBe(EXIT.usage);
    expect(r.err).toContain("error:");
    expect(r.err).toContain("usage: trace-verify");
    expect(fetchArg.urls).toEqual([]); // nothing was asked of any endpoint
    expect(r.out).toBe("");
  });

  it("a file that is not JSON says nothing was checked", async () => {
    const r = await run([write("readme.txt", "hello, this is not json")]);
    expect(r.code).toBe(EXIT.usage);
    expect(r.err).toContain("not JSON");
    expect(r.err).toContain("nothing was checked");
  });

  it("valid JSON that is not a record is a failed C1, exit 1 (it is a record that does not match)", async () => {
    const r = await run([write("notrecord.json", JSON.stringify({ hello: "world" }))]);
    expect(r.code).toBe(EXIT.does_not_match);
    expect(r.out).toMatch(/^C1 .*FAIL/m);
  });
});

describe("the RPC endpoint", () => {
  const url = "https://rpc.example.test/v2/SECRETKEY123?api-key=SECRETQUERY456";

  it("is the endpoint asked, and neither its path nor its key is ever printed (host only)", async () => {
    const file = write("honest8.json", JSON.stringify(fx.envelope));
    const fetchArg = fakeFetch(fx.chain);
    const r = await run([file, "--cluster", "devnet", "--rpc", url], fetchArg);
    expect(r.code).toBe(EXIT.verified);
    expect(fetchArg.urls[0]).toBe(url);
    const everything = `${r.out}\n${r.err}`;
    expect(everything).not.toContain("SECRETKEY123");
    expect(everything).not.toContain("SECRETQUERY456");
    expect(everything).not.toContain("api-key");
    expect(everything).not.toContain("/v2/");
    expect(r.out).toContain("rpc.example.test (your --rpc, the only endpoint asked)");
    expect(r.out).toContain("RPC endpoint used: rpc.example.test (supplied by you)");
  });

  it("an error about the URL never repeats it", async () => {
    const file = write("honest9.json", JSON.stringify(fx.envelope));
    for (const bad of [
      "http://rpc.example.test/SECRETKEY123",
      ["https://user:SECRETKEY123", "rpc.example.test/"].join("@"),
      "https://rpc_bad_host.example.test/SECRETKEY123",
    ]) {
      const r = await run([file, "--cluster", "devnet", "--rpc", bad]);
      expect(r.code).toBe(EXIT.usage);
      expect(`${r.out}\n${r.err}`).not.toContain("SECRETKEY123");
    }
  });

  it("an http URL is accepted for localhost only, for tests against a local node", async () => {
    const file = write("honest10.json", JSON.stringify(fx.envelope));
    const fetchArg = fakeFetch(fx.chain);
    const r = await run([file, "--cluster", "devnet", "--rpc", "http://localhost:8899"], fetchArg);
    expect(r.code).toBe(EXIT.verified);
    expect(fetchArg.urls.every((u) => u.startsWith("http://localhost:8899"))).toBe(true);
    for (const host of ["127.0.0.1:8899", "[::1]:8899"]) {
      const again = await run([file, "--cluster", "devnet", "--rpc", `http://${host}`]);
      expect(again.code).toBe(EXIT.verified);
    }
    const remote = await run([
      file,
      "--cluster",
      "devnet",
      "--rpc",
      "http://localhost.example.test:8899",
    ]);
    expect(remote.code).toBe(EXIT.usage);
  });

  it("the endpoint is never taken from the record", async () => {
    const hostile = structuredClone(fx.envelope) as unknown as Record<string, unknown>;
    (hostile.anchor as Record<string, unknown>).rpc = "https://evil.example.test/";
    const file = write("hostile.json", JSON.stringify(hostile));
    const fetchArg = fakeFetch(fx.chain);
    const r = await run([file], fetchArg);
    expect(r.code).toBe(EXIT.does_not_match); // the extra field fails the strict schema
    expect(fetchArg.urls.some((u) => u.includes("evil"))).toBe(false);
  });
});

describe("what is printed from the record is safe for a terminal", () => {
  const ch = (...codes: number[]) => String.fromCharCode(...codes);
  // escape, bell, right-to-left override, line separator, next line (a C1 control)
  const ESC = ch(0x1b);
  const hostile = `ok${ESC}[2J${ESC}]0;pwned${ch(7)}${ch(0x202e)}txt.exe${ch(0x2028)}next${ch(0x85)}end`;
  const hasUnsafe = (s: string) =>
    Array.from(s).some((c) => {
      const n = c.codePointAt(0) ?? 0;
      return (
        n <= 0x1f ||
        (n >= 0x7f && n <= 0x9f) ||
        n === 0x2028 ||
        n === 0x2029 ||
        (n >= 0x202a && n <= 0x202e)
      );
    });

  it("control characters, bidirectional overrides and line separators are replaced", () => {
    expect(hasUnsafe(hostile)).toBe(true); // the test input really is hostile
    const shown = safe(hostile);
    expect(hasUnsafe(shown)).toBe(false);
    expect(shown).toContain("ok");
    expect(shown.length).toBe(Array.from(hostile).length);
  });

  it("a long value is cut", () => {
    expect(safe("x".repeat(1000), 50)).toBe(`${"x".repeat(50)}...`);
  });

  it("nothing a hostile envelope puts in a text field reaches the output unescaped", async () => {
    const record = structuredClone(fx.envelope) as unknown as { manifest: { trace_id: string } };
    record.manifest.trace_id = `TRC-${ESC}[31mRED${ESC}[0m`;
    const r = await run([write("escapes.json", JSON.stringify(record))]);
    expect(`${r.out}${r.err}`.includes(ESC)).toBe(false);
  });
});

describe("arguments", () => {
  it("--help prints the usage and the exit codes, exit 0; --version prints the package version", async () => {
    const help = await run(["--help"]);
    expect(help.code).toBe(0);
    expect(help.out).toBe(USAGE);
    expect(USAGE).toContain("0 verified, 1 does not match, 2 unable to check, 3 usage error");
    const version = await run(["--version"]);
    expect(version.out).toBe(`trace-verify ${VERSION}`);
  });

  it("accepts --rpc=URL and --cluster=NAME forms, and -- before a file name that starts with a dash", () => {
    expect(parseArgs(["a.json", "--rpc=https://x.test", "--cluster=devnet"])).toEqual({
      kind: "run",
      envelopePath: "a.json",
      artifactPaths: [],
      rpc: ["https://x.test"],
      cluster: "devnet",
    });
    expect(parseArgs(["--", "-odd.json"])).toMatchObject({
      kind: "run",
      envelopePath: "-odd.json",
    });
  });
});

describe("the synthetic fixture is what it claims to be", () => {
  it("is a transfer between two generated addresses, with a key that exists only in memory", () => {
    expect(PAYER).not.toBe(RECIPIENT);
    expect(fx.envelope.signature.key_id).toBe("synthetic-test-key");
  });
});

describe("endpoint lists: --rpc more than once", () => {
  const A = "https://a.example.test/key-aaa111";
  const B = "https://b.example.test/key-bbb222";
  const subject = () => fx.envelope.manifest.subject.signatures[0];
  const without = (sig: string) => {
    const m = new Map(fx.chain);
    m.delete(sig);
    return m;
  };
  const record = () => write("lists.json", JSON.stringify(fx.envelope));

  it("by default ONE public endpoint is asked, and a transaction it reports missing is a mismatch", async () => {
    const f = fakeFetchByHost({ "api.devnet.solana.com": without(subject()) });
    const r = await run([record()], f);
    expect(new Set(f.asked)).toEqual(new Set(["api.devnet.solana.com"]));
    expect(r.code).toBe(EXIT.does_not_match);
    expect(r.out).toContain("not found at finalized");
    expect(r.out).toContain("(one endpoint)");
  });

  it("a single --rpc is the only endpoint asked: its 'missing' is definite too", async () => {
    const f = fakeFetchByHost({ "a.example.test": without(subject()) });
    const r = await run([record(), "--cluster", "devnet", "--rpc", A], f);
    expect(new Set(f.asked)).toEqual(new Set(["a.example.test"]));
    expect(r.code).toBe(EXIT.does_not_match);
  });

  it("two --rpc: a transaction the first reports missing is confirmed against the second", async () => {
    const f = fakeFetchByHost({ "a.example.test": without(subject()), "b.example.test": fx.chain });
    const r = await run([record(), "--cluster", "devnet", "--rpc", A, "--rpc", B], f);
    expect(r.code, r.out).toBe(EXIT.verified);
    expect(f.asked).toContain("b.example.test");
    expect(r.out).toContain("a.example.test, b.example.test (your --rpc, in this order)");
    const everything = `${r.out}\n${r.err}`;
    for (const secret of ["key-aaa111", "key-bbb222"]) expect(everything).not.toContain(secret);
  });

  it("two --rpc that both report it missing: a mismatch", async () => {
    const f = fakeFetchByHost({
      "a.example.test": without(subject()),
      "b.example.test": without(subject()),
    });
    const r = await run([record(), "--cluster", "devnet", "--rpc", A, "--rpc", B], f);
    expect(r.code).toBe(EXIT.does_not_match);
  });

  it("the first reports it missing and the second cannot answer: unable to check, never a mismatch", async () => {
    const f = fakeFetchByHost({ "a.example.test": without(subject()), "b.example.test": "down" });
    const r = await run([record(), "--cluster", "devnet", "--rpc", A, "--rpc", B], f);
    expect(r.code).toBe(EXIT.unable_to_check);
  }, 60_000);

  it("the first endpoint is down: the second answers", async () => {
    const f = fakeFetchByHost({ "a.example.test": "down", "b.example.test": fx.chain });
    const r = await run([record(), "--cluster", "devnet", "--rpc", A, "--rpc", B], f);
    expect(r.code, r.out).toBe(EXIT.verified);
  }, 60_000);

  it("the same URL twice is one endpoint", async () => {
    const f = fakeFetchByHost({ "a.example.test": fx.chain });
    const r = await run([record(), "--cluster", "devnet", "--rpc", A, "--rpc", A], f);
    expect(r.code).toBe(EXIT.verified);
    expect(r.out).toContain("(your --rpc, the only endpoint asked)");
  });

  it("the same URL twice, reporting the subject missing: asked once, a mismatch (not confirmed by itself)", async () => {
    const missing = new Map(fx.chain);
    const subjectSig = fx.envelope.manifest.subject.signatures[0];
    missing.delete(subjectSig);
    const f = fakeFetchByHost({ "a.example.test": missing });
    const r = await run([record(), "--cluster", "devnet", "--rpc", A, "--rpc", A], f);
    expect(r.code).toBe(EXIT.does_not_match);
    expect(f.calls.filter((c) => c.signature === subjectSig)).toHaveLength(1);
  });

  it("a plain http endpoint anywhere in the list, or too many endpoints, is a usage error", async () => {
    const bad = await run([
      record(),
      "--cluster",
      "devnet",
      "--rpc",
      A,
      "--rpc",
      "http://b.example.test",
    ]);
    expect(bad.code).toBe(EXIT.usage);
    const many = Array.from({ length: 9 }, (_, i) => [
      "--rpc",
      `https://h${i}.example.test`,
    ]).flat();
    const tooMany = await run([record(), "--cluster", "devnet", ...many]);
    expect(tooMany.code).toBe(EXIT.usage);
    expect(tooMany.err).toContain("at most 8");
  });
});

describe("files the command reads", () => {
  it("a byte order mark at the start of the envelope is dropped, not 'not JSON'", async () => {
    const bytes = Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from(JSON.stringify(fx.envelope)),
    ]);
    const r = await run([write("bom.json", bytes)]);
    expect(r.code, r.out + r.err).toBe(EXIT.verified);
  });

  it("a directory (or any non-regular file) is refused before it is read", async () => {
    const r = await run([dir]);
    expect(r.code).toBe(EXIT.usage);
    expect(r.err).toContain("not a regular file");
    const art = await run([write("ok.json", JSON.stringify(fx.envelope)), dir]);
    expect(art.code).toBe(EXIT.usage);
    expect(art.err).toContain("not a regular file");
  });
});

describe("invisible characters from a record are replaced when printed", () => {
  const codes = [
    0x61c, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2060, 0x2064, 0xfeff, 0xad, 0x34f, 0xe0041,
    0xfe0f, 0xe0100, 0x180e, 0x202e, 0x2066, 0x2028,
  ];
  it.each(codes.map((c) => [c.toString(16), c] as const))("U+%s", (_hex, code) => {
    expect(safe(`a${String.fromCodePoint(code)}b`)).toBe("a?b");
  });
  it("ordinary text, including non-Latin letters, is untouched", () => {
    expect(safe("a b é 日本")).toBe("a b é 日本");
  });
});

describe("the same endpoint written twice is one endpoint (audit L4)", () => {
  const record = () => write("dedupe.json", JSON.stringify(fx.envelope));
  const subject = () => fx.envelope.manifest.subject.signatures[0];

  it.each([
    ["host in another case", "https://A.Example.Test/key", "https://a.example.test/key"],
    ["a trailing slash on the path", "https://a.example.test/key/", "https://a.example.test/key"],
    ["the bare host with and without a slash", "https://a.example.test", "https://a.example.test/"],
    [
      "the default port written out",
      "https://a.example.test:443/key",
      "https://a.example.test/key",
    ],
  ])("%s", async (_name, first, second) => {
    const missing = new Map(fx.chain);
    missing.delete(subject());
    const f = fakeFetchByHost({ "a.example.test": missing });
    const r = await run([record(), "--cluster", "devnet", "--rpc", first, "--rpc", second], f);
    // one endpoint: it is the only one asked, it cannot confirm its own "missing", and "missing" is final
    expect(r.out).toContain("(your --rpc, the only endpoint asked)");
    expect(new Set(f.asked)).toEqual(new Set(["a.example.test"]));
    expect(r.code).toBe(EXIT.does_not_match);
    expect(r.out).toContain("not found at finalized");
    // the request count is what tells one endpoint from two that are the same: asked ONCE for the subject, not
    // once and then again to "confirm" it
    expect(f.calls.filter((c) => c.signature === subject())).toHaveLength(1);
  });

  it.each([
    ["host in another case", "https://A.Example.Test/key", "https://a.example.test/key"],
    ["a trailing slash", "https://a.example.test/key/", "https://a.example.test/key"],
  ])(
    "%s: the copy is not a second endpoint that could outvote or fail the first (exit 1, not 2)",
    async (_name, first, second) => {
      // the host says "missing" the first time it is asked about the subject, and cannot answer after that
      const f = fakeFetchByHost({
        "a.example.test": (signature, nth) => {
          if (signature !== subject()) return fx.chain.get(signature);
          return nth === 0 ? undefined : "down";
        },
      });
      const r = await run([record(), "--cluster", "devnet", "--rpc", first, "--rpc", second], f);
      // one endpoint: "missing" is final and nothing else is asked. With the copy kept as a second endpoint, the
      // "confirmation" would fail and the result would read "unable to check" (exit 2) instead.
      expect(r.code).toBe(EXIT.does_not_match);
      expect(f.calls.filter((c) => c.signature === subject())).toHaveLength(1);
    },
    60_000,
  );

  it("two different endpoints on one host are two endpoints", async () => {
    const f = fakeFetchByHost({ "a.example.test": fx.chain });
    const r = await run(
      [
        record(),
        "--cluster",
        "devnet",
        "--rpc",
        "https://a.example.test/one",
        "--rpc",
        "https://a.example.test/two",
      ],
      f,
    );
    expect(r.code).toBe(EXIT.verified);
  });
});

describe("endpoint order: the first endpoint that answers wins (documented)", () => {
  const record = () => write("order.json", JSON.stringify(fx.envelope));
  const A = "https://a.example.test/x";
  const B = "https://b.example.test/x";
  /** The chain with the subject transaction's fee changed: an endpoint that gives another answer. */
  const altered = () => {
    const m = new Map(fx.chain);
    const sig = fx.envelope.manifest.subject.signatures[0];
    const tx = structuredClone(m.get(sig)) as { meta: { fee: number } };
    tx.meta.fee += 1;
    m.set(sig, tx);
    return m;
  };

  it("an endpoint that answers differently first decides, and the second is not asked for that transaction", async () => {
    const f = fakeFetchByHost({ "a.example.test": altered(), "b.example.test": fx.chain });
    const r = await run([record(), "--cluster", "devnet", "--rpc", A, "--rpc", B], f);
    expect(r.code).toBe(EXIT.does_not_match);
    expect(r.out).toMatch(/^C7 .*FAIL/m);
    // B answers nothing: A answered every read
    expect(f.asked.every((h) => h === "a.example.test")).toBe(true);
  });

  it("the same two endpoints the other way round give the other result", async () => {
    const f = fakeFetchByHost({ "a.example.test": altered(), "b.example.test": fx.chain });
    const r = await run([record(), "--cluster", "devnet", "--rpc", B, "--rpc", A], f);
    expect(r.code, r.out).toBe(EXIT.verified);
    expect(f.asked.every((h) => h === "b.example.test")).toBe(true);
  });

  it("the endpoints are asked in the order given, as the output says", async () => {
    const f = fakeFetchByHost({ "a.example.test": fx.chain, "b.example.test": fx.chain });
    const r = await run([record(), "--cluster", "devnet", "--rpc", B, "--rpc", A], f);
    expect(r.out).toContain("b.example.test, a.example.test (your --rpc, in this order)");
    expect(f.asked[0]).toBe("b.example.test");
  });
});
