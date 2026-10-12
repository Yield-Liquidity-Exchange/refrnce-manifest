// The demo record is either the real thing or visibly absent, never a placeholder dressed as a record.
//
//   - While examples/demo-envelope.json does not exist, the placeholder must exist, must say it is one, must
//     not parse as an envelope, and the command must not verify it.
//   - Once examples/demo-envelope.json exists it must be a real, well-formed mainnet record: it parses as an
//     envelope, its hash recomputes, its anchor memo carries that hash, it names a mainnet anchor, and the
//     placeholder has been removed. These checks are offline; the on-chain check is `npm run verify:demo`
//     (a live call), which refuses to run on the placeholder.
import { existsSync, readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { EXIT, runCli } from "../src/cli-core.js";
import { hashManifest } from "../src/manifest/hash.js";
import { EnvelopeSchema } from "../src/manifest/types.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REAL = join(ROOT, "examples", "demo-envelope.json");
const PLACEHOLDER = join(ROOT, "examples", "demo-envelope.PLACEHOLDER.json");

describe.runIf(!existsSync(REAL))("while the demo record is not yet published", () => {
  it("the placeholder exists and says it is not a record", () => {
    expect(existsSync(PLACEHOLDER)).toBe(true);
    const body = JSON.parse(readFileSync(PLACEHOLDER, "utf8"));
    expect(body.placeholder).toBe(true);
    expect(body.todo).toContain("NOT a record");
    expect(EnvelopeSchema.safeParse(body).success).toBe(false);
    console.warn(
      "open: examples/demo-envelope.json is not published; only the placeholder is present",
    );
  });

  it("the command does not verify it (exit 1, never 0)", async () => {
    const out: string[] = [];
    const code = await runCli([PLACEHOLDER], { out: (l) => out.push(l), err: (l) => out.push(l) });
    expect(code).toBe(EXIT.does_not_match);
    expect(out.join("\n")).not.toContain("Verdict: VERIFIED");
  });

  it("`npm run verify:demo` refuses to run (exit 3)", () => {
    const r = spawnSync(process.execPath, [join(ROOT, "tools", "verify-demo.mjs")], {
      encoding: "utf8",
    });
    expect(r.status).toBe(3);
    expect(r.stdout).toContain("only the placeholder is present");
  });
});

describe.runIf(existsSync(REAL))("once the demo record is published", () => {
  const text = existsSync(REAL) ? readFileSync(REAL, "utf8") : "{}";

  it("is a well-formed envelope on mainnet, not a placeholder", () => {
    const body = JSON.parse(text);
    expect(body.placeholder).toBeUndefined();
    const parsed = EnvelopeSchema.safeParse(body);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.anchor.cluster).toBe("mainnet-beta");
      expect(parsed.data.manifest.subject.cluster).toBe("mainnet-beta");
    }
  });

  it("its hash recomputes and its anchor memo carries that hash", async () => {
    const env = EnvelopeSchema.parse(JSON.parse(text));
    expect(await hashManifest(env.manifest)).toBe(env.manifest_hash);
    expect(env.anchor.memo).toBe(`trace-manifest:1:${env.manifest_hash}`);
  });

  it("the placeholder has been removed", () => {
    expect(existsSync(PLACEHOLDER)).toBe(false);
  });
});

describe("the guard itself", () => {
  it("a placeholder renamed to the real file name is not accepted as a record", () => {
    const dir = mkdtempSync(join(tmpdir(), "trace-demo-"));
    try {
      const fake = join(dir, "demo-envelope.json");
      writeFileSync(fake, readFileSync(PLACEHOLDER, "utf8"));
      const body = JSON.parse(readFileSync(fake, "utf8"));
      expect(EnvelopeSchema.safeParse(body).success).toBe(false);
      expect(body.placeholder).toBe(true); // the 'once published' test above would fail on this
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
