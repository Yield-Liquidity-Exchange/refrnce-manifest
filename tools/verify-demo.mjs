// Runs the built command line against the demo record in examples/ and exits with its exit code.
//
//   npm run build && npm run verify:demo
//
// This is the one check that talks to a real Solana endpoint, so it is not part of the unit tests. It
// refuses to run while only the placeholder is present: a placeholder must never read as a pass.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const record = join(root, "examples", "demo-envelope.json");
const cli = join(root, "dist", "cli.js");

if (!existsSync(record)) {
  console.log(
    "examples/demo-envelope.json does not exist: only the placeholder is present, so there is nothing to verify",
  );
  process.exit(3);
}
if (!existsSync(cli)) {
  console.log("dist/cli.js does not exist: run `npm run build` first");
  process.exit(3);
}
const args = [cli, record, "--cluster", "mainnet-beta", ...process.argv.slice(2)];
const result = spawnSync(process.execPath, args, { stdio: "inherit" });
process.exit(result.status ?? 2);
