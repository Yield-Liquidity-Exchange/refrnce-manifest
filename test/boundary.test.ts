// The package imports nothing from outside itself, and pulls in no module that belongs to the issuing side.
// The guard (tools/check-boundary.mjs) is only worth having if it fails when a violation is present, so each
// test plants one in a temporary copy of the package and expects the guard to name it.
//
// The planted code is built by small helpers rather than written out as literal import lines, because the
// guard scans this very file too and must find nothing in it.
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error plain JavaScript tool, no declaration file
import { checkBoundary, importsOf, opaqueImportsOf } from "../tools/check-boundary.mjs";
// @ts-expect-error plain JavaScript tool, no declaration file
import { FORBIDDEN_RUNTIME, dependencyReport } from "../tools/dependency-report.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temps: string[] = [];

function copyOfPackage(): string {
  const dir = mkdtempSync(join(tmpdir(), "trace-boundary-"));
  temps.push(dir);
  cpSync(ROOT, dir, {
    recursive: true,
    filter: (src) => !/[\\/](?:node_modules|dist|\.git)(?:[\\/]|$)/.test(src),
  });
  return dir;
}
afterEach(() => {
  for (const d of temps.splice(0)) rmSync(d, { recursive: true, force: true });
});

const plant = (dir: string, file: string, content: string) => {
  mkdirSync(dirname(join(dir, file)), { recursive: true });
  writeFileSync(join(dir, file), content);
};

// Pieces, so that this file holds no literal application alias, server-only file name or import call.
const ALIAS = ["@", "/"].join("");
const SERVER_ONLY = ["sign", "server"].join(".");
const IMPORT = ["imp", "ort"].join("");
const REQUIRE = ["req", "uire"].join("");
const CREATE = ["create", "Require"].join("");
const q = (spec: string) => JSON.stringify(spec);
const staticImport = (spec: string) => `${IMPORT} x from ${q(spec)};\nexport default x;\n`;
const sideEffectImport = (spec: string) => `${IMPORT} ${q(spec)};\n`;
const reExport = (spec: string) => `export * from ${q(spec)};\n`;
const dynamicImport = (spec: string) => `export const load = () => ${IMPORT}(${q(spec)});\n`;
const requireCall = (spec: string) => `const x = ${REQUIRE}(${q(spec)});\nexport default x;\n`;
const requireResolve = (spec: string) => `export const at = ${REQUIRE}.resolve(${q(spec)});\n`;
const tripleSlash = (spec: string) => `/// <reference path=${q(spec)} />\nexport {};\n`;

type Violation = { file: string; line: number; spec: string; reason: string };

describe("the package as it is", () => {
  it("has no import that reaches outside it", () => {
    const { violations, graph } = checkBoundary(ROOT) as { violations: Violation[]; graph: object };
    expect(violations).toEqual([]);
    expect(Object.keys(graph).length).toBeGreaterThan(30);
  });

  it("depends at runtime on exactly three pinned packages, none of them a server or wallet library", () => {
    const report = dependencyReport(ROOT) as {
      problems: string[];
      runtime: { name: string; version: string }[];
      markdown: string;
    };
    expect(report.problems).toEqual([]);
    expect(report.runtime.map((d) => `${d.name}@${d.version}`)).toEqual([
      "@noble/ed25519@3.2.0",
      "canonicalize@5.1.0",
      "zod@3.25.76",
    ]);
    for (const name of FORBIDDEN_RUNTIME as string[])
      expect(report.markdown).not.toContain(`| ${name} |`);
  });

  it("the dependency report names no private module", () => {
    const { markdown } = dependencyReport(ROOT) as { markdown: string };
    for (const word of ["builder", ".server", "registry", "anchor.", "sign.", "issue."])
      expect(markdown, word).not.toContain(word);
  });
});

describe("a planted violation is caught", () => {
  const cases: [string, string, string, string][] = [
    [
      "a relative import that leaves the package",
      "src/manifest/planted.ts",
      staticImport("../../../outside/secret.js"),
      "outside",
    ],
    [
      "an application path alias",
      "src/manifest/planted.ts",
      staticImport(ALIAS + "lib/other-module"),
      "alias",
    ],
    [
      "a package that is not declared",
      "src/manifest/planted.ts",
      staticImport("bs58"),
      "does not list",
    ],
    [
      "a Node built-in in code that also runs in the browser",
      "src/solana/planted.ts",
      staticImport("node:fs"),
      "Node built-in",
    ],
    ["the manifest builder", "src/manifest/planted.ts", reExport("./builder.js"), "stays private"],
    [
      "a server-only module",
      "src/manifest/planted.ts",
      sideEffectImport(`./${SERVER_ONLY}.js`),
      "stays private",
    ],
    [
      "a dynamic import that leaves the package",
      "src/solana/planted.ts",
      dynamicImport("../../../../app/secret"),
      "outside",
    ],
    ["a require call", "tools/planted.mjs", requireCall("../../elsewhere/file"), "outside"],
    [
      "a require.resolve call",
      "tools/planted.mjs",
      requireResolve("../../elsewhere/file"),
      "outside",
    ],
    [
      "a triple-slash path reference",
      "src/manifest/planted.ts",
      tripleSlash("../../../x.d.ts"),
      "outside",
    ],
    ["a .cjs file", "tools/planted.cjs", requireCall("../../elsewhere/file"), "outside"],
    ["a .cts file", "src/manifest/planted.cts", requireCall("../../../elsewhere/file"), "outside"],
    ["a .tsx file", "src/manifest/planted.tsx", staticImport("../../../outside/x.js"), "outside"],
    ["a .jsx file", "tools/planted.jsx", staticImport("../../outside/x.js"), "outside"],
    [
      "a dynamic import with a template literal",
      "src/manifest/planted.ts",
      `export const load = (n: string) => ${IMPORT}(\`./\${n}.js\`);\n`,
      "not a string literal",
    ],
    [
      "a dynamic import with a variable",
      "src/manifest/planted.ts",
      `export const load = (p: string) => ${IMPORT}(p);\n`,
      "not a string literal",
    ],
    [
      "a require with a variable",
      "tools/planted.mjs",
      `export const load = (p) => ${REQUIRE}(p);\n`,
      "not a string literal",
    ],
    [
      "createRequire",
      "tools/planted.mjs",
      `${IMPORT} { ${CREATE} } from "node:module";\nexport const r = ${CREATE}(${IMPORT}.meta.url);\n`,
      "createRequire",
    ],
  ];
  it.each(cases)("%s", (_name, file, content, reason) => {
    const dir = copyOfPackage();
    // The private targets must exist, so that the rule (and not 'unresolved') is what fires.
    plant(dir, "src/manifest/builder.ts", "export const buildManifest = 1;\n");
    plant(dir, `src/manifest/${SERVER_ONLY}.ts`, "export const sign = 1;\n");
    plant(dir, file, content);
    const { violations } = checkBoundary(dir) as { violations: Violation[] };
    const hit = violations.find((v) => v.file === file);
    expect(hit, JSON.stringify(violations)).toBeDefined();
    expect(hit?.reason.toLowerCase()).toContain(reason.toLowerCase());
    expect(hit?.line).toBeGreaterThan(0);
  });

  it.each([
    ["extends", { extends: "../../other/tsconfig.json" }],
    ["include", { include: ["../../other/**/*.ts"] }],
    ["references", { references: [{ path: "../../other" }] }],
    ["files", { files: ["/etc/passwd"] }],
  ])("a tsconfig that names a path outside the package (%s)", (_name, body) => {
    const dir = copyOfPackage();
    plant(dir, "tsconfig.planted.json", JSON.stringify(body));
    const { violations } = checkBoundary(dir) as { violations: Violation[] };
    const hit = violations.find((v) => v.file === "tsconfig.planted.json");
    expect(hit, JSON.stringify(violations)).toBeDefined();
    expect(hit?.reason).toContain("leads outside the package");
  });

  it("the command exits 1 and names the file, and exits 0 on the clean package", () => {
    const dir = copyOfPackage();
    const node = process.execPath;
    const clean = spawnSync(node, [join(dir, "tools", "check-boundary.mjs"), dir], {
      encoding: "utf8",
    });
    expect(clean.status).toBe(0);
    plant(dir, "src/manifest/planted.ts", staticImport(ALIAS + "lib/x"));
    const bad = spawnSync(node, [join(dir, "tools", "check-boundary.mjs"), dir], {
      encoding: "utf8",
    });
    expect(bad.status).toBe(1);
    expect(bad.stdout).toContain("src/manifest/planted.ts:1");
    expect(bad.stdout).toContain("boundary check FAILED");
  });

  it("the dependency report fails on a forbidden dependency, an unpinned one and an unused one", () => {
    const dir = copyOfPackage();
    const pkgPath = join(dir, "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    pkg.dependencies = { ...pkg.dependencies, bs58: "6.0.0", ethers: "^6.0.0" };
    writeFileSync(pkgPath, JSON.stringify(pkg));
    const { problems } = dependencyReport(dir) as { problems: string[] };
    const text = problems.join("\n");
    expect(text).toContain("bs58: a verifier must not depend on this package");
    expect(text).toContain("ethers@^6.0.0: a runtime dependency must be pinned");
    expect(text).toContain("imported by no file in src/");
  });
});

describe("the import scan", () => {
  it("finds static, side-effect, re-export, dynamic, require, require.resolve and reference forms, with line numbers", () => {
    const text = [
      staticImport("./a.js").split("\n")[0],
      `${IMPORT} type { B } from ${q("./b.js")};`,
      sideEffectImport("./c.js").trim(),
      reExport("./d.js").trim(),
      `export { e } from ${q("./e.js")};`,
      dynamicImport("./f.js").trim(),
      requireCall("./g.js").split("\n")[0],
      requireResolve("./h.js").trim(),
      tripleSlash("./i.d.ts").split("\n")[0],
    ].join("\n");
    const found = importsOf(text) as { spec: string; line: number }[];
    expect(found.map((f) => f.spec).sort()).toEqual(
      [
        "./a.js",
        "./b.js",
        "./c.js",
        "./d.js",
        "./e.js",
        "./f.js",
        "./g.js",
        "./h.js",
        "./i.d.ts",
      ].sort(),
    );
    expect(found.find((f) => f.spec === "./g.js")?.line).toBe(7);
    expect(found.find((f) => f.spec === "./i.d.ts")?.line).toBe(9);
  });

  it("finds a computed target and passes a literal one", () => {
    expect(opaqueImportsOf(dynamicImport("./x.js"))).toEqual([]);
    expect(opaqueImportsOf(requireCall("./x.js"))).toEqual([]);
    expect((opaqueImportsOf(`const a = ${IMPORT}(name);\n`) as unknown[]).length).toBe(1);
  });
});
