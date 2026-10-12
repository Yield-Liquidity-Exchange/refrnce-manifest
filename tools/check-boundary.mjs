// Fails when any file of this package reaches outside it.
//
//   node tools/check-boundary.mjs [package-root]
//
// Rules, each reported with the file and line that breaks it:
//   - A relative import must resolve to a file inside the package (and, for src/, inside src/).
//   - A bare import must be a package listed in package.json: "dependencies" for src/, either list for
//     test/ and tools/. Node built-ins (node:...) are allowed only in the command line entry and outside
//     src/manifest and src/solana, which run in the browser too.
//   - No app alias (@/...), no absolute path, no URL, no import of a module whose name marks it as one
//     that does not belong in a verifier (server-only modules, the manifest builder, signing, anchoring,
//     the registry, issuing).
//   - Nothing whose target cannot be read from the text: a dynamic import or require with a template literal
//     or a variable, createRequire, a computed import.meta.resolve. These fail, because the guard could not say
//     where they lead.
//   - Triple-slash path references, and the paths in tsconfig files (extends, include, exclude, files,
//     references), must stay inside the package.
//
// Every script and module extension is scanned (.ts .mts .cts .tsx .js .mjs .cjs .jsx), and tsconfig*.json.
// The check is a text scan, so a planted violation is found whatever its shape. It runs in CI, in the build
// (prebuild) and in test/boundary.test.ts, which plants violations to prove that it fails.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SKIP_DIRS = new Set(["node_modules", "dist", ".git"]);
const SOURCE_EXT = /\.(?:ts|mts|cts|tsx|js|mjs|cjs|jsx)$/;
const TSCONFIG = /^tsconfig.*\.json$/;
const RESOLVE_SUFFIXES = [
  "",
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".js",
  ".mjs",
  ".cjs",
  ".json",
  "/index.ts",
  "/index.js",
];

/** Names of modules the application keeps private: a verifier never imports any of them. */
const PRIVATE_NAME =
  /(?:^|\/)(?:builder|registry|registry-client|anchor|sign|issue)(?:\.[a-z]+)*$|\.server(?:\.[a-z]+)*$/;

/** Files that may use Node built-ins (everything else in src/ runs in the browser too). */
const NODE_ALLOWED_IN_SRC = new Set(["src/cli.ts", "src/cli-core.ts"]);

/** Static import / export-from / dynamic import / require / require.resolve specifiers, with line numbers. */
export function importsOf(text) {
  const out = [];
  const patterns = [
    /\b(?:import|export)\s[^;'"]*?\sfrom\s*["']([^"']+)["']/g,
    /\bimport\s*["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']/g,
    /\brequire\s*\(\s*["']([^"']+)["']/g,
    /\brequire\.resolve\s*\(\s*["']([^"']+)["']/g,
    /\bimport\.meta\.resolve\s*\(\s*["']([^"']+)["']/g,
    /^\s*\/\/\/\s*<reference\s+path\s*=\s*["']([^"']+)["']/gm,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(text))) {
      const line = text.slice(0, m.index).split("\n").length;
      out.push({ spec: m[1], line });
    }
  }
  return out;
}

/** Uses whose target is not a string literal: the guard cannot tell where they lead, so they fail. */
export function opaqueImportsOf(text) {
  const out = [];
  const patterns = [
    [/\bimport\s*\(\s*(?!["'])/g, "a dynamic import whose target is not a string literal"],
    [/\brequire\s*\(\s*(?!["'])/g, "a require whose target is not a string literal"],
    [
      /\brequire\.resolve\s*\(\s*(?!["'])/g,
      "a require.resolve whose target is not a string literal",
    ],
    [/\bimport\.meta\.resolve\s*\(\s*(?!["'])/g, "an import.meta.resolve with a computed target"],
    [
      new RegExp("\\bcreate" + "Require\\s*\\("),
      "createRequire loads modules the guard cannot see",
    ],
  ];
  for (const [re, why] of patterns) {
    const g = new RegExp(re.source, "g");
    let m;
    while ((m = g.exec(text))) out.push({ why, line: text.slice(0, m.index).split("\n").length });
  }
  return out;
}

function listFiles(root) {
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (SKIP_DIRS.has(name)) continue;
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else if (SOURCE_EXT.test(name) || TSCONFIG.test(name)) files.push(full);
    }
  };
  walk(root);
  return files.sort();
}

const posix = (p) => p.split(sep).join("/");
const escapes = (wanted) =>
  wanted.startsWith("..") || isAbsolute(wanted) || /^[a-zA-Z]:/.test(wanted);

function resolveRelative(fromFile, spec) {
  const base = resolve(dirname(fromFile), spec);
  // TypeScript sources name the compiled file: "./x.js" stands for "./x.ts".
  const candidates = [
    base,
    base.replace(/\.js$/, ".ts"),
    base.replace(/\.mjs$/, ".mts"),
    base.replace(/\.cjs$/, ".cts"),
    base.replace(/\.jsx$/, ".tsx"),
  ];
  for (const c of candidates)
    for (const suffix of RESOLVE_SUFFIXES) {
      const p = c + suffix;
      if (existsSync(p) && statSync(p).isFile()) return p;
    }
  return null;
}

/** The paths a tsconfig names (extends, include, exclude, files, references). */
function tsconfigPaths(text) {
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    return [{ spec: "(not valid JSON)", bad: true }];
  }
  const out = [];
  const add = (v) => typeof v === "string" && out.push({ spec: v });
  for (const key of ["extends", "include", "exclude", "files"])
    for (const v of Array.isArray(json[key]) ? json[key] : [json[key]]) add(v);
  for (const r of Array.isArray(json.references) ? json.references : []) add(r?.path);
  for (const key of ["outDir", "rootDir", "baseUrl", "declarationDir"])
    add(json.compilerOptions?.[key]);
  return out;
}

/**
 * @param {string} root the package root
 * @returns {{ violations: { file: string, line: number, spec: string, reason: string }[], graph: Record<string, { internal: string[], external: string[], builtin: string[], test: boolean }> }}
 */
export function checkBoundary(root) {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const runtime = new Set(Object.keys(pkg.dependencies ?? {}));
  const dev = new Set([...runtime, ...Object.keys(pkg.devDependencies ?? {})]);
  const builtins = new Set(builtinModules);
  const violations = [];
  const graph = {};

  for (const file of listFiles(root)) {
    const rel = posix(relative(root, file));
    const isTest =
      /(?:^|\/)__tests__\//.test(rel) || /\.test\.ts$/.test(rel) || rel.startsWith("test/");
    const inSrc = rel.startsWith("src/");
    const isomorphic =
      !isTest && (rel.startsWith("src/manifest/") || rel.startsWith("src/solana/"));
    const allowed = inSrc && !isTest ? runtime : dev;
    const entry = { internal: [], external: [], builtin: [], test: isTest };
    graph[rel] = entry;
    const text = readFileSync(file, "utf8");
    const bad = (line, spec, reason) => violations.push({ file: rel, line, spec, reason });

    if (TSCONFIG.test(file.split(sep).pop())) {
      for (const { spec, bad: invalid } of tsconfigPaths(text)) {
        if (invalid) bad(1, spec, "a tsconfig the guard cannot read");
        else if (escapes(posix(relative(root, resolve(dirname(file), spec.replace(/\*.*$/, ""))))))
          bad(1, spec, "a tsconfig path that leads outside the package");
      }
      continue;
    }

    for (const { why, line } of opaqueImportsOf(text)) bad(line, "(computed)", why);

    for (const { spec, line } of importsOf(text)) {
      if (spec.startsWith("@/") || spec.startsWith("~/")) {
        bad(
          line,
          spec,
          "an application path alias: the package imports nothing from the application",
        );
      } else if (spec.startsWith(".")) {
        // Outside the package is outside whether or not a file exists there.
        const wanted = posix(relative(root, resolve(dirname(file), spec)));
        if (escapes(wanted)) {
          bad(line, spec, "resolves to a file outside the package");
          continue;
        }
        const target = resolveRelative(file, spec);
        if (!target) {
          bad(line, spec, "does not resolve to a file");
          continue;
        }
        const targetRel = posix(relative(root, target));
        if (inSrc && !targetRel.startsWith("src/")) {
          bad(line, spec, "a source file imports from outside src/");
          continue;
        }
        if (PRIVATE_NAME.test(targetRel.replace(/\.(?:ts|js|json)$/, ""))) {
          bad(
            line,
            spec,
            "imports a module of a kind that stays private (server-only, builder, signer, anchor, registry, issuing)",
          );
          continue;
        }
        entry.internal.push(targetRel);
      } else if (/^(?:[a-zA-Z]:|\/|file:|https?:|data:)/.test(spec)) {
        bad(line, spec, "an absolute path or URL");
      } else if (spec.startsWith("node:") || builtins.has(spec)) {
        if (isomorphic || (inSrc && !isTest && !NODE_ALLOWED_IN_SRC.has(rel)))
          bad(line, spec, "a Node built-in in code that also runs in the browser");
        else entry.builtin.push(spec);
      } else {
        const name = spec.startsWith("@")
          ? spec.split("/").slice(0, 2).join("/")
          : spec.split("/")[0];
        if (!allowed.has(name))
          bad(
            line,
            spec,
            `a package that package.json does not list as a ${inSrc ? "dependency" : "dependency or devDependency"}`,
          );
        else entry.external.push(name);
      }
    }
  }
  return { violations, graph };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), ".."));
  const { violations, graph } = checkBoundary(root);
  if (violations.length > 0) {
    for (const v of violations) console.log(`${v.file}:${v.line}  ${v.spec}  ${v.reason}`);
    console.log(`\nboundary check FAILED: ${violations.length} imports reach outside the package`);
    process.exit(1);
  }
  console.log(
    `boundary check passed: ${Object.keys(graph).length} files, no import reaches outside the package`,
  );
}
