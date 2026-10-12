// The logic of the trace-verify command, kept apart from process.argv and process.exit so that tests can run
// it with a fake RPC and read what it prints.
//
//   trace-verify <envelope.json> [artifact-file ...] [--rpc URL] [--cluster mainnet-beta|devnet|testnet]
//
// Exit codes:
//   0  verified          the record is intact, signed by a pinned issuer key, anchored, and every Observed and
//                        Derived claim reproduces from the chain
//   1  does not match    something in the record or a supplied file differs from what was signed, anchored or
//                        found on the chain
//   2  unable to check   the check could not be completed (an outage, a missing answer): no finding about the
//                        record is made
//   3  usage error       bad arguments, an unreadable file, a file that is not JSON; nothing was checked
//
// Rules this file keeps:
//   - The RPC URL is never printed. Only its host is. An error about it is fixed text that does not repeat it.
//   - An RPC URL must be https; http is accepted only for localhost (for tests against a local server).
//   - Everything that comes from the record and is printed has control characters removed first, so a hostile
//     record cannot move the cursor, recolour the terminal or hide text.
//   - The RPC endpoint is never read from the record.
import { readFileSync, statSync } from "node:fs";
import { basename } from "node:path";
import { CHECK_NAMES, verifyEnvelope } from "./manifest/verify/core.js";
import type { CheckResult, Verdict, VerifyResult } from "./manifest/verify/core.js";
import type { ClaimCheck } from "./manifest/verify/rederive.js";
import { MANIFEST_CLUSTERS, TRACE_ID_PATTERN, type ManifestCluster } from "./manifest/types.js";
import {
  RpcConfigError,
  checkUserEndpoint,
  createResilientRpc,
  type FetchLike,
} from "./solana/rpc.js";
import { VERSION } from "./version.js";

export const EXIT = { verified: 0, does_not_match: 1, unable_to_check: 2, usage: 3 } as const;

export const USAGE = [
  "usage: trace-verify <envelope.json> [artifact-file ...] [--rpc URL ...] [--cluster CLUSTER]",
  "",
  "  <envelope.json>   the record to check",
  "  artifact-file     files the record lists (check C6); give only artifact files, never the envelope",
  "  --rpc URL         ask this Solana RPC endpoint (https; http only for localhost). Give it more than",
  "                    once for an ordered list: a transaction one endpoint reports missing is then",
  "                    checked against the next. Replaces the default endpoint. Needs --cluster.",
  "                    Only host names are ever printed.",
  "  --cluster NAME    mainnet-beta, devnet or testnet: the cluster the endpoints serve. Without it the",
  "                    cluster named in the record is used, with the default public endpoint for it",
  "                    (one endpoint: a transaction it reports missing counts as missing).",
  "  --help, --version",
  "",
  "exit codes: 0 verified, 1 does not match, 2 unable to check, 3 usage error",
].join("\n");

export interface CliIo {
  out(line: string): void;
  err(line: string): void;
}

export interface CliDeps {
  /** Replaces the platform fetch (tests). */
  fetch?: FetchLike;
  /** Replaces the pinned issuer key list (tests only: the command line has no way to set it). */
  issuerKeys?: unknown;
}

const MAX_ENVELOPE_FILE_BYTES = 20 * 1024 * 1024;
const MAX_ARTIFACT_FILE_BYTES = 64 * 1024 * 1024;
const MAX_ARTIFACT_FILES = 1000;
const MAX_RPC_ENDPOINTS = 8;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

// ─── Output safety ───────────────────────────────────────────────────────────

// What is replaced before text from a record reaches a terminal: C0 and C1 controls, DEL; line and paragraph
// separators; every invisible or direction-changing format character (soft hyphen, combining grapheme joiner,
// Arabic letter mark, Mongolian free variation selectors, zero-width characters and marks, bidirectional
// overrides and isolates, invisible operators, the byte order mark); variation selectors; tag characters.
const isUnsafe = (code: number): boolean =>
  code <= 0x1f ||
  (code >= 0x7f && code <= 0x9f) ||
  code === 0xad ||
  code === 0x34f ||
  code === 0x61c ||
  (code >= 0x180b && code <= 0x180e) ||
  (code >= 0x200b && code <= 0x200f) ||
  (code >= 0x2028 && code <= 0x202e) ||
  (code >= 0x2060 && code <= 0x206f) ||
  (code >= 0xfe00 && code <= 0xfe0f) ||
  code === 0xfeff ||
  (code >= 0xe0000 && code <= 0xe007f) ||
  (code >= 0xe0100 && code <= 0xe01ef);

/** Text from the record or a file, made safe to print on one terminal line and cut to `max` characters. */
export function safe(value: unknown, max = 300): string {
  const text = typeof value === "string" ? value : String(value);
  const clean = Array.from(text, (ch) => (isUnsafe(ch.codePointAt(0) ?? 0) ? "?" : ch)).join("");
  return clean.length > max ? `${clean.slice(0, max)}...` : clean;
}

// ─── Arguments ───────────────────────────────────────────────────────────────

export type Parsed =
  | { kind: "run"; envelopePath: string; artifactPaths: string[]; rpc: string[]; cluster?: string }
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "error"; message: string };

export function parseArgs(argv: readonly string[]): Parsed {
  const positional: string[] = [];
  const rpc: string[] = [];
  let cluster: string | undefined;
  let optionsEnded = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (optionsEnded || !arg.startsWith("-") || arg === "-") {
      positional.push(arg);
      continue;
    }
    if (arg === "--") optionsEnded = true;
    else if (arg === "--help" || arg === "-h") return { kind: "help" };
    else if (arg === "--version") return { kind: "version" };
    else if (arg === "--rpc" || arg === "--cluster") {
      const value = argv[++i];
      if (value === undefined) return { kind: "error", message: `${arg} needs a value` };
      if (arg === "--rpc") rpc.push(value);
      else cluster = value;
    } else if (arg.startsWith("--rpc=")) rpc.push(arg.slice("--rpc=".length));
    else if (arg.startsWith("--cluster=")) cluster = arg.slice("--cluster=".length);
    else return { kind: "error", message: `unknown option ${safe(arg, 40)}` };
  }
  const [envelopePath, ...artifactPaths] = positional;
  if (envelopePath === undefined) return { kind: "error", message: "an envelope file is required" };
  return { kind: "run", envelopePath, artifactPaths, rpc, cluster };
}

/** The identity of an endpoint for de-duplication: scheme, lower-case host and port, path without a trailing slash, query. */
export function endpointKey(href: string): string {
  const u = new URL(href);
  return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, "")}${u.search}`;
}

export const isCluster = (v: unknown): v is ManifestCluster =>
  typeof v === "string" && (MANIFEST_CLUSTERS as readonly string[]).includes(v);

// ─── The command ─────────────────────────────────────────────────────────────

const VERDICT_LABEL: Record<Verdict, string> = {
  verified: "VERIFIED",
  does_not_match: "DOES NOT MATCH",
  unable_to_check: "UNABLE TO CHECK",
};

const VERDICT_MEANING: Record<Verdict, string> = {
  verified:
    "The record is intact, was signed by a pinned issuer key and anchored on Solana, and every Observed and Derived claim in it reproduces from the chain.",
  does_not_match:
    "Something in this record, or in a file supplied with it, differs from what was signed, anchored or found on the chain.",
  unable_to_check:
    "The check could not be completed, so there is no verdict on the record. This is not a finding that it was changed: try again later or with another endpoint.",
};

const CLAIM_STATUS_LABEL: Record<ClaimCheck["status"], string> = {
  reproduced: "reproduced",
  mismatch: "DOES NOT MATCH",
  unavailable: "could not check",
  not_checked: "not independently checked",
};

const CHECK_STATUS_LABEL: Record<CheckResult["status"], string> = {
  pass: "pass",
  fail: "FAIL",
  unavailable: "could not check",
  skipped: "skipped",
};

function formatEvidence(value: unknown): string {
  if (Array.isArray(value)) {
    const shown = value.slice(0, 20).map((v) => safe(v, 120));
    return `[${shown.join(", ")}${value.length > 20 ? `, ... ${value.length - 20} more` : ""}]`;
  }
  return safe(value, 300);
}

function printChecks(result: VerifyResult, out: (line: string) => void): void {
  const rows = result.checks.map((c) => [c.id, CHECK_NAMES[c.id], CHECK_STATUS_LABEL[c.status]]);
  const w0 = Math.max(...rows.map((r) => r[1].length));
  const w1 = Math.max(...rows.map((r) => r[2].length));
  result.checks.forEach((c, i) => {
    out(`${rows[i][0]}  ${rows[i][1].padEnd(w0)}  ${rows[i][2].padEnd(w1)}  ${safe(c.detail)}`);
    if (c.evidence)
      for (const [k, v] of Object.entries(c.evidence))
        out(`      ${c.id}.${safe(k, 60)} = ${formatEvidence(v)}`);
  });
}

function printClaims(result: VerifyResult, out: (line: string) => void): void {
  const r = result.rederive;
  out("Claims (checks C7 and C8)");
  if (!r) {
    out("  not compared: the claims are compared only after C1 to C4 pass");
    return;
  }
  const c = r.counts.by_status;
  out(
    `  ${c.reproduced} reproduced, ${c.mismatch} do not match, ${c.unavailable} could not be checked, ${c.not_checked} not independently checked`,
  );
  for (const w of r.warnings) out(`  warning: ${safe(w.detail)}`);
  for (const t of r.transactions)
    if (t.status !== "read")
      out(
        `  transaction ${safe(t.signature, 100)}: ${t.status === "not_found" ? "not found at finalized" : "could not be read"}`,
      );
  for (const claim of r.claims) {
    const id = claim.claim_id ? safe(claim.claim_id, 12) : "(not in the record)";
    out(`  ${id}  ${safe(claim.code, 40)}  ${CLAIM_STATUS_LABEL[claim.status]}`);
    out(`      ${safe(claim.detail)}`);
    if (claim.status === "mismatch" && claim.field !== undefined) {
      out(`      field:    ${safe(claim.field, 100)}`);
      out(`      chain:    ${safe(claim.expected ?? "(none)", 300)}`);
      out(`      record:   ${safe(claim.found ?? "(none)", 300)}`);
    }
  }
  if (r.truncated) out("  (more rows exist than are listed; the counts above are complete)");
}

/** Runs the command and returns its exit code. Never throws; prints nothing but through `io`. */
export async function runCli(
  argv: readonly string[],
  io: CliIo,
  deps: CliDeps = {},
): Promise<number> {
  const usageError = (message: string): number => {
    io.err(`error: ${message}`);
    io.err(USAGE);
    return EXIT.usage;
  };
  try {
    const parsed = parseArgs(argv);
    if (parsed.kind === "help") {
      io.out(USAGE);
      return EXIT.verified;
    }
    if (parsed.kind === "version") {
      io.out(`trace-verify ${VERSION}`);
      return EXIT.verified;
    }
    if (parsed.kind === "error") return usageError(parsed.message);

    if (parsed.cluster !== undefined && !isCluster(parsed.cluster))
      return usageError("--cluster must be mainnet-beta, devnet or testnet");
    if (parsed.rpc.length > 0 && parsed.cluster === undefined)
      return usageError("--rpc needs --cluster: name the cluster that endpoint serves");
    if (parsed.rpc.length > MAX_RPC_ENDPOINTS)
      return usageError(`at most ${MAX_RPC_ENDPOINTS} --rpc endpoints`);
    if (parsed.artifactPaths.length > MAX_ARTIFACT_FILES)
      return usageError(`at most ${MAX_ARTIFACT_FILES} artifact files`);

    // The files. Only a regular file is read: a device, a pipe or a directory is refused before any read, so
    // a path such as /dev/zero cannot be made to fill the memory.
    let rawText: string;
    let envelope: unknown;
    try {
      const st = statSync(parsed.envelopePath);
      if (!st.isFile()) return usageError("the envelope path is not a regular file");
      if (st.size > MAX_ENVELOPE_FILE_BYTES)
        return usageError("the envelope file is larger than a record can be");
      rawText = readFileSync(parsed.envelopePath, "utf8");
    } catch {
      return usageError("the envelope file could not be read");
    }
    // A byte order mark that an editor put at the start of the file is not part of the JSON: it is dropped.
    if (rawText.charCodeAt(0) === 0xfeff) rawText = rawText.slice(1);
    try {
      envelope = JSON.parse(rawText);
    } catch {
      return usageError("the envelope file is not JSON, so nothing was checked");
    }
    const files: { name: string; bytes: Uint8Array }[] = [];
    for (const p of parsed.artifactPaths) {
      try {
        const st = statSync(p);
        if (!st.isFile())
          return usageError(`artifact ${safe(basename(p), 60)} is not a regular file`);
        if (st.size > MAX_ARTIFACT_FILE_BYTES)
          return usageError(`artifact file ${safe(basename(p), 60)} is too large`);
        files.push({ name: basename(p), bytes: new Uint8Array(readFileSync(p)) });
      } catch {
        return usageError(`artifact file ${safe(basename(p), 60)} could not be read`);
      }
    }

    // The cluster: named by the user, or else by the record (which only selects among the public endpoints).
    const recordCluster = (envelope as { anchor?: { cluster?: unknown } } | null)?.anchor?.cluster;
    const clusterSource = parsed.cluster !== undefined ? "from --cluster" : "named by the record";
    const cluster: ManifestCluster =
      parsed.cluster !== undefined
        ? (parsed.cluster as ManifestCluster)
        : isCluster(recordCluster)
          ? recordCluster
          : "mainnet-beta";

    // The RPC client.
    // With no --rpc, the library's default for the cluster: ONE public endpoint, so a transaction it reports
    // missing is reported as a mismatch. With --rpc, exactly the endpoints given, in the order given: a
    // transaction the first reports missing is confirmed against the second, and so on.
    let rpc: ReturnType<typeof createResilientRpc>;
    let rpcLine: string;
    const userHosts = new Set<string>();
    try {
      if (parsed.rpc.length === 0) {
        rpc = createResilientRpc({ cluster, fetch: deps.fetch });
        rpcLine = "default public endpoint for the cluster (one endpoint)";
      } else {
        const hrefs: string[] = [];
        const seenEndpoints = new Set<string>();
        for (const value of parsed.rpc) {
          let url: URL;
          try {
            url = new URL(value);
          } catch {
            return usageError("an --rpc value is not a URL");
          }
          if (url.username !== "" || url.password !== "")
            return usageError("an --rpc URL must not contain a user name or password");
          let href: string;
          if (url.protocol === "https:") href = checkUserEndpoint(url.href);
          else if (url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname)) href = url.href;
          else
            return usageError("an --rpc URL must be https (http is accepted only for localhost)");
          // The same endpoint written twice is one endpoint: otherwise it would "confirm" its own answer.
          // The host is case-insensitive (URL lower-cases it) and a trailing slash does not make a new path.
          const key = endpointKey(href);
          if (seenEndpoints.has(key)) continue;
          seenEndpoints.add(key);
          hrefs.push(href);
          userHosts.add(url.host);
        }
        rpc = createResilientRpc({ cluster, endpoints: hrefs, fetch: deps.fetch });
        const hosts = [...new Set(hrefs.map((h) => new URL(h).host))];
        rpcLine = `${hosts.join(", ")} (your --rpc${hosts.length > 1 ? ", in this order" : ", the only endpoint asked"})`;
      }
    } catch (e) {
      return usageError(e instanceof RpcConfigError ? e.message : "the RPC endpoint is not usable");
    }

    const traceId = (envelope as { manifest?: { trace_id?: unknown } } | null)?.manifest?.trace_id;
    io.out(`trace-verify ${VERSION}`);
    io.out(`Record:   ${safe(basename(parsed.envelopePath), 100)}`);
    if (typeof traceId === "string" && TRACE_ID_PATTERN.test(traceId))
      io.out(`Trace ID: ${traceId}`);
    io.out(`Cluster:  ${cluster} (${clusterSource})`);
    io.out(`RPC:      ${rpcLine}`);
    io.out("Registry: not checked (this tool does not query the registry; C5 is skipped)");
    io.out("");

    const result = await verifyEnvelope(envelope, {
      rpc,
      cluster,
      files,
      rawText,
      issuerKeys: deps.issuerKeys,
    });

    printChecks(result, io.out);
    io.out("");
    printClaims(result, io.out);
    io.out("");
    for (const e of result.rpc_endpoints ?? [])
      io.out(
        `RPC endpoint used: ${safe(e.hostname, 100)}${e.user_supplied || userHosts.has(e.hostname) ? " (supplied by you)" : ""}, ${e.answers} answer(s)${e.cached_answers > 0 ? `, ${e.cached_answers} from cache` : ""}`,
      );
    if ((result.rpc_endpoints ?? []).length === 0) io.out("RPC endpoint used: none answered");
    io.out(`Verdict: ${VERDICT_LABEL[result.verdict]}`);
    io.out(VERDICT_MEANING[result.verdict]);
    return EXIT[result.verdict];
  } catch {
    io.err("error: unexpected failure; no verdict was reached");
    return EXIT.unable_to_check;
  }
}
