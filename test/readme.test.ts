// The README is the first thing a reader meets and the place the trust claims are made, so its structure and
// its facts are tested: the sections are the promised ones in the promised order, the check table lists the
// same checks the code runs, the claim labels are the real labels, and the exit codes it documents are the
// ones the command returns. Open TODO markers are reported as warnings here and fail only the release gate
// (`npm run todos`), so a package with an open item can still be built and tested.
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { EXIT } from "../src/cli-core.js";
import { CHECK_IDS, CHECK_NAMES } from "../src/manifest/verify/core.js";
import { defaultRpcEndpoints } from "../src/solana/rpc.js";
// @ts-expect-error plain JavaScript tool, no declaration file
import { listTodos } from "../tools/list-todos.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// Read with LF line endings, whatever the checkout did to them.
const readme = readFileSync(join(ROOT, "README.md"), "utf8").replace(/\r\n/g, "\n");
const flat = readme.replace(/\s+/g, " ");
const headings = [...readme.matchAll(/^## (.+)$/gm)].map((m) => m[1]);

describe("sections", () => {
  it("has the promised sections, in order", () => {
    const wanted = [
      "What the tool checks (C1 to C8)",
      "What a Manifest proves",
      "What a Manifest does not prove",
      "Quick start",
      "Schema reference",
      "Claim labels",
      "Trust assumptions",
      "The demo envelope",
      "About the demo record",
      "Licence",
    ];
    expect(headings).toEqual(wanted);
  });
});

describe("the checks", () => {
  it("lists C1 to C8 with the names the code uses", () => {
    for (const id of CHECK_IDS) {
      const row = readme.split("\n").find((l) => l.startsWith(`| ${id} `));
      expect(row, id).toBeDefined();
      expect(row).toContain(CHECK_NAMES[id]);
    }
  });

  it("says plainly that the command line tool skips the registry check", () => {
    expect(readme).toMatch(/C5 is always `skipped` there/);
  });
});

describe("claim labels and boundary lists", () => {
  it("names the four labels", () => {
    for (const label of ["Observed", "Derived", "Attributed", "Inferred"])
      expect(readme).toMatch(new RegExp(`^- \\*\\*${label}\\*\\*: .+`, "m"));
  });

  it("has a non-empty list under 'proves' and 'does not prove'", () => {
    const section = (name: string) => {
      const start = readme.indexOf(`## ${name}`);
      const next = readme.indexOf("\n## ", start + 1);
      return readme
        .slice(start, next)
        .split("\n")
        .filter((l) => l.startsWith("- "));
    };
    expect(section("What a Manifest proves").length).toBeGreaterThanOrEqual(3);
    expect(section("What a Manifest does not prove").length).toBeGreaterThanOrEqual(3);
    expect(section("What a Manifest does not prove").join("\n")).toMatch(/identity/);
  });
});

describe("the documented command", () => {
  it("documents the exit codes the command returns", () => {
    expect(readme).toMatch(/\| 0 +\| Verified/);
    expect(readme).toMatch(/\| 1 +\| Does not match/);
    expect(readme).toMatch(/\| 2 +\| Unable to check/);
    expect(readme).toMatch(/\| 3 +\| Usage error/);
    expect(EXIT).toEqual({ verified: 0, does_not_match: 1, unable_to_check: 2, usage: 3 });
  });

  it("states that --rpc needs --cluster and that only host names are printed", () => {
    expect(flat).toContain("**`--rpc` needs `--cluster`**");
    expect(flat).toMatch(/Only the host names are ever printed/);
  });

  it("tells the truth about the endpoints: one by default, so 'missing' is a mismatch; a list cross-checks", () => {
    // The claim in the README is only true while the default really is one endpoint per cluster.
    for (const c of ["mainnet-beta", "devnet", "testnet"] as const)
      expect(defaultRpcEndpoints(c).length, c).toBe(1);
    expect(flat).toContain("asks **one** endpoint");
    expect(flat).toMatch(/reports as missing is reported as a mismatch/);
    expect(flat).toMatch(/pruned from the one you asked can look exactly like/);
    expect(flat).toMatch(/Give it more than once for an ordered list/);
    // The claim that was false for the command's default must not come back.
    expect(flat).not.toContain("counts as missing only when a second endpoint agrees; otherwise");
  });
});

describe("open items", () => {
  it("reports every open TODO marker as a warning (the release gate is `npm run todos`)", () => {
    const todos = listTodos(ROOT) as { file: string; line: number; tag: string }[];
    for (const t of todos) console.warn(`open: ${t.file}:${t.line} TODO(${t.tag})`);
    // Whatever is open, each marker names what it is waiting for.
    for (const t of todos) expect(t.tag).toMatch(/^[a-z][a-z-]+$/);
  });

  it("the gate cannot be tripped by the workflow that runs it (its own comments name no open item)", () => {
    const todos = listTodos(ROOT) as { file: string }[];
    expect(todos.filter((t) => t.file.startsWith(".github/"))).toEqual([]);
  });

  it("the public CI runs the open-items gate and does not let it pass on error", () => {
    const ci = readFileSync(join(ROOT, ".github/workflows/ci.yml"), "utf8");
    expect(ci).toContain("run: bun run todos");
    expect(ci).not.toContain("continue-on-error");
    expect(ci).toMatch(/permissions:\s+contents: read/);
    expect(ci).toContain("--frozen-lockfile");
    // every action is pinned by a full commit
    for (const m of ci.matchAll(/uses: ([^\s@]+)@(\S+)/g))
      expect(m[2], m[1]).toMatch(/^[0-9a-f]{40}$/);
  });
});
