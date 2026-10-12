// Lists every TODO and FIXME left in the package's files, tagged (TODO(name)) or bare, and exits 1 if there is
// any.
//
//   node tools/list-todos.mjs [package-root]
//
// The unit tests only warn about these (a package can be built and tested with a TODO open). This command is
// the release gate: it must print nothing before the repository is made public, and the public CI runs it
// without `continue-on-error`, so an open item fails the build until it is resolved.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SKIP_DIRS = new Set(["node_modules", "dist", ".git"]);
const MARKER = /\b(?:TODO|FIXME)\b(?:\(([^)]*)\))?/g;

/** @returns {{ file: string, line: number, tag: string }[]} */
export function listTodos(root) {
  const found = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (SKIP_DIRS.has(name)) continue;
      const full = join(dir, name);
      if (statSync(full).isDirectory()) {
        walk(full);
        continue;
      }
      // The tools and tests name the marker in order to find it; they are not where a TODO is left.
      const rel = relative(root, full).split(sep).join("/");
      if (rel.startsWith("tools/") || rel.startsWith("test/")) continue;
      readFileSync(full, "utf8")
        .split(/\r?\n/)
        .forEach((text, i) => {
          for (const m of text.matchAll(MARKER))
            found.push({ file: rel, line: i + 1, tag: m[1] ?? "untagged" });
        });
    }
  };
  walk(root);
  return found;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), ".."));
  const todos = listTodos(root);
  for (const t of todos) console.log(`${t.file}:${t.line}  TODO(${t.tag})`);
  if (todos.length > 0) {
    console.log(
      `\n${todos.length} open TODO marker(s): resolve them before the repository is made public`,
    );
    process.exit(1);
  }
  console.log("no open TODO markers");
}
