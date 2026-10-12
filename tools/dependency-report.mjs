// Prints the dependency graph of this package as Markdown and fails if it is not the graph a verifier
// should have.
//
//   node tools/dependency-report.mjs [package-root]
//
// The report lists every runtime dependency (name, pinned version, licence, install scripts, the files that
// import it) and, for every source file, the files it imports. It exits 1 when
//   - a runtime dependency is not pinned to an exact version,
//   - a runtime dependency is on the list of packages a verifier must not need (server, database, wallet,
//     web framework), or is declared and never imported by src/, or is imported by src/ and not declared,
//   - checkBoundary finds an import that reaches outside the package.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { checkBoundary } from "./check-boundary.mjs";

/** Packages that a verify-only package must never depend on, directly. */
export const FORBIDDEN_RUNTIME = [
  "@solana/web3.js",
  "@solana/spl-token",
  "bs58",
  "ethers",
  ["@supa", "base/supa", "base-js"].join(""),
  "react",
  "react-dom",
  "stripe",
  "@tanstack/react-start",
  "@tanstack/react-router",
  "ai",
];

const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/** @returns {{ markdown: string, problems: string[], runtime: { name: string, version: string, files: string[] }[] }} */
export function dependencyReport(root, options = {}) {
  // details: false leaves out the licence and install-script columns, which depend on what is installed here.
  const details = options.details !== false;
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const { violations, graph } = checkBoundary(root);
  const problems = violations.map((v) => `${v.file}:${v.line} ${v.spec}: ${v.reason}`);

  const importers = new Map();
  for (const [file, entry] of Object.entries(graph)) {
    if (!file.startsWith("src/") || entry.test) continue;
    for (const name of entry.external) {
      if (!importers.has(name)) importers.set(name, new Set());
      importers.get(name).add(file);
    }
  }

  const declared = Object.entries(pkg.dependencies ?? {});
  const runtime = declared
    .map(([name, version]) => ({ name, version, files: [...(importers.get(name) ?? [])].sort() }))
    .sort((a, b) => a.name.localeCompare(b.name));

  for (const d of runtime) {
    if (!EXACT_VERSION.test(d.version))
      problems.push(
        `${d.name}@${d.version}: a runtime dependency must be pinned to an exact version`,
      );
    if (FORBIDDEN_RUNTIME.includes(d.name))
      problems.push(`${d.name}: a verifier must not depend on this package`);
    if (d.files.length === 0)
      problems.push(`${d.name}: declared as a dependency and imported by no file in src/`);
  }
  for (const name of importers.keys())
    if (!(pkg.dependencies ?? {})[name])
      problems.push(`${name}: imported by src/ and not declared in dependencies`);

  const lines = [];
  lines.push(`# Dependency graph: ${pkg.name}@${pkg.version}`, "");
  lines.push("## Runtime dependencies", "");
  lines.push(
    details
      ? "| Package | Pinned version | Licence | Install scripts | Imported by |"
      : "| Package | Pinned version | Imported by |",
  );
  lines.push(details ? "| --- | --- | --- | --- | --- |" : "| --- | --- | --- |");
  for (const d of runtime) {
    const manifest = join(root, "node_modules", ...d.name.split("/"), "package.json");
    let licence = "not installed";
    let scripts = "not installed";
    if (existsSync(manifest)) {
      const m = JSON.parse(readFileSync(manifest, "utf8"));
      licence = typeof m.license === "string" ? m.license : JSON.stringify(m.license ?? "unknown");
      const hooks = Object.keys(m.scripts ?? {}).filter((s) =>
        /^(?:pre|post)?install$|^prepare$/.test(s),
      );
      scripts = hooks.length === 0 ? "none" : hooks.join(", ");
    }
    lines.push(
      details
        ? `| ${d.name} | ${d.version} | ${licence} | ${scripts} | ${d.files.length} file(s) |`
        : `| ${d.name} | ${d.version} | ${d.files.length} file(s) |`,
    );
  }
  lines.push(
    "",
    "Development-only (not installed for users of the package): " +
      (Object.keys(pkg.devDependencies ?? {})
        .sort()
        .join(", ") || "none"),
    "",
  );
  lines.push("## Source files and what each imports", "");
  for (const [file, entry] of Object.entries(graph)) {
    if (!file.startsWith("src/") || /\/__tests__\/|\.test\.ts$/.test(file)) continue;
    const parts = [
      ...new Set(entry.internal),
      ...new Set(entry.external),
      ...new Set(entry.builtin),
    ];
    lines.push(
      `- \`${file}\`: ${parts.length === 0 ? "nothing" : parts.map((p) => `\`${p}\``).join(", ")}`,
    );
  }
  lines.push("");
  return { markdown: lines.join("\n"), problems, runtime };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), ".."));
  const { markdown, problems } = dependencyReport(root);
  console.log(markdown);
  if (problems.length > 0) {
    for (const p of problems) console.log(`PROBLEM: ${p}`);
    process.exit(1);
  }
}
