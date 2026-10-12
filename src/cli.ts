#!/usr/bin/env node
// trace-verify: checks a Trace Manifest record against the chain. All logic is in cli-core.ts.
import process from "node:process";
import { runCli } from "./cli-core.js";

process.exitCode = await runCli(process.argv.slice(2), {
  out: (line) => console.log(line),
  err: (line) => console.error(line),
});
