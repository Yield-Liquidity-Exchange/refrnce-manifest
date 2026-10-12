// The command as a user runs it: compiled by tsc, started by Node as a real process, talking to a real (local)
// HTTP server that answers JSON-RPC. This is what catches what in-process tests cannot: an import path that
// only works under the test runner, a JSON import Node refuses, a missing shebang, an exit code lost on the
// way out of the process.
//
// The issuer key list is the committed one, which the tests cannot sign with. So the record here names a
// pinned key by its id and is signed by a throwaway key: the real binary must read the anchor over HTTP (C4
// passes), refuse the signature (C3 fails) and exit 1. That also proves a forged signature cannot verify
// through the real binary.
import { spawn, spawnSync } from "node:child_process";
import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { hashManifest } from "../src/manifest/hash.js";
import type { Envelope } from "../src/manifest/types.js";
import { anchorTransaction, makeFixture, signHash, signatureFor } from "./helpers/fixture.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "dist", "cli.js");
let dir: string;
let server: Server;
let port: number;
let envelope: Envelope;
const chain = new Map<string, unknown>();
const asked: string[] = [];

beforeAll(async () => {
  const tsc = join(ROOT, "node_modules", "typescript", "bin", "tsc");
  const build = spawnSync(process.execPath, [tsc, "-p", "tsconfig.build.json"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  expect(build.status, build.stdout + build.stderr).toBe(0);
  expect(existsSync(CLI)).toBe(true);

  // A record that names the first pinned key (a development key, fine for devnet) and is signed by another.
  const pinned = JSON.parse(readFileSync(join(ROOT, "src/manifest/issuer-keys.json"), "utf8"))
    .keys[0];
  const fx = await makeFixture();
  envelope = structuredClone(fx.envelope);
  envelope.manifest.issuer.key_id = pinned.key_id;
  envelope.manifest_hash = await hashManifest(envelope.manifest);
  envelope.signature = await signHash({ ...fx.key, keyId: pinned.key_id }, envelope.manifest_hash);
  envelope.anchor.memo = `trace-manifest:1:${envelope.manifest_hash}`;
  envelope.anchor.tx_signature = signatureFor(`anchor:${envelope.manifest_hash}`);
  // After the pinned key's valid_from (2026-10-06), as an anchor made with it would be.
  const blockTime = Date.parse("2026-10-07T00:00:00Z") / 1000;
  envelope.anchor.block_time = blockTime;
  for (const [sig, tx] of fx.chain) if (sig !== fx.envelope.anchor.tx_signature) chain.set(sig, tx);
  chain.set(
    envelope.anchor.tx_signature,
    anchorTransaction(
      envelope.anchor.tx_signature,
      pinned.public_key,
      envelope.anchor.memo,
      blockTime,
    ),
  );

  dir = mkdtempSync(join(tmpdir(), "trace-built-"));
  writeFileSync(join(dir, "record.json"), JSON.stringify(envelope));
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      asked.push(String(body.params?.[0]));
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: body.id,
          result: chain.get(String(body.params?.[0])) ?? null,
        }),
      );
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  port = (server.address() as { port: number }).port;
}, 120_000);

afterAll(async () => {
  await new Promise((ok) => server.close(ok));
  rmSync(dir, { recursive: true, force: true });
});

function node(args: string[]): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((ok) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd: dir });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("close", (code) => ok({ code, out, err }));
  });
}

describe("the compiled command", () => {
  it("starts under Node, prints its version and the usage", async () => {
    expect((await node(["--version"])).out.trim()).toMatch(/^trace-verify \d+\.\d+\.\d+$/);
    const help = await node(["--help"]);
    expect(help.code).toBe(0);
    expect(help.out).toContain(
      "exit codes: 0 verified, 1 does not match, 2 unable to check, 3 usage error",
    );
  });

  it("exit 3 for a usage error, and nothing is printed on stdout", async () => {
    const r = await node([]);
    expect(r.code).toBe(3);
    expect(r.out).toBe("");
    expect(r.err).toContain("an envelope file is required");
  });

  it("reads the anchor over real HTTP from a localhost endpoint; a forged signature exits 1 with C3 failing", async () => {
    asked.length = 0;
    const r = await node([
      "record.json",
      "--cluster",
      "devnet",
      "--rpc",
      `http://127.0.0.1:${port}`,
    ]);
    expect(r.code, r.out + r.err).toBe(1);
    expect(r.out).toMatch(/^C4 .*pass/m);
    expect(r.out).toMatch(/^C3 .*FAIL/m);
    expect(r.out).toContain("the signature does not verify against the pinned issuer key");
    expect(r.out).toContain("Verdict: DOES NOT MATCH");
    expect(r.out).not.toContain("Verdict: VERIFIED");
    // the local endpoint was asked for the anchor, over a real socket
    expect(asked).toContain(envelope.anchor.tx_signature);
    // and only its host and port are printed, no path
    expect(r.out).toContain(`127.0.0.1:${port} (your --rpc, the only endpoint asked)`);
  });

  it("an endpoint that is not up leaves C4 unable to check; the definite C3 failure still decides the verdict", async () => {
    const r = await node(["record.json", "--cluster", "devnet", "--rpc", "http://127.0.0.1:1"]);
    expect(r.out).toMatch(/^C4 .*could not check/m);
    expect(r.out).toMatch(/^C3 .*FAIL/m);
    expect(r.code, r.out + r.err).toBe(1);
    expect(r.out).not.toContain("Verdict: VERIFIED");
  }, 60_000);
});
