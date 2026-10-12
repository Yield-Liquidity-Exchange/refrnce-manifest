// src/manifest/manifest-rules.ts — the rules a JSON Schema cannot express.
//
// Isomorphic: no Node imports. This file is the ONE list of those rules and the ONE function that checks them:
//
//   - MANIFEST_RULES is the list. The published JSON Schema's description is written from it (schema/json-schema.ts),
//     so a rule cannot be enforced without being published, or published without being enforced.
//   - checkManifestRules(subject) checks an envelope or a bare manifest (as returned by JSON.parse) against the
//     runtime schema AND every rule below, and returns the violations by rule id. It never throws and never
//     accepts what it cannot read. The builder calls it before it returns a manifest; the verifier
//     must call it for check C1.
//   - detectDuplicateKeys(text) is the one rule that cannot be checked after JSON.parse (the parser keeps the last
//     of two equal keys and says nothing). The verifier must run it on the raw text first.
//
// Messages name the rule, the claim id and the field, never claim content: manifest values may be case data.
import { canonicalizeJcs } from "./canonical.js";
import { ClaimRuleError, assertClaimAllowed } from "./claim-rules.js";
import {
  EnvelopeSchema,
  MAX_CANONICAL_CHARS,
  MAX_CLAIM_VALUE_DEPTH,
  MAX_STRING_LENGTH,
  ManifestSchema,
  type Manifest,
} from "./types.js";

export interface ManifestRule {
  id: string;
  /** "manifest": checked by checkManifestRules. "raw_text": checked on the JSON text, by detectDuplicateKeys. */
  where: "manifest" | "raw_text";
  /** One sentence. Written, word for word, into the description of the published JSON Schema. */
  text: string;
}

export const MANIFEST_RULES: readonly ManifestRule[] = Object.freeze([
  {
    id: "issued_at_calendar_date",
    where: "manifest",
    text: "issued_at is a real calendar date (30 February is refused).",
  },
  { id: "claim_ids_unique", where: "manifest", text: "claim ids are unique." },
  {
    id: "references_resolve",
    where: "manifest",
    text: "every claim reference (provenance.inputs, provenance.basis, value.from_owner_claim, value.to_owner_claim) names a claim in the manifest and not the claim itself.",
  },
  {
    id: "claim_type_matches_provenance",
    where: "manifest",
    text: "claim.type equals claim.provenance.type.",
  },
  {
    id: "formulas_listed",
    where: "manifest",
    text: "every formula a derived claim cites is listed in tooling.formulas.",
  },
  {
    id: "artifact_names_unique",
    where: "manifest",
    text: "artifact names are unique ignoring case.",
  },
  {
    id: "claim_code_allowed",
    where: "manifest",
    text: "claim.code is in the claim rules table and claim.type is the one type the table allows for that code (assertClaimAllowed).",
  },
  {
    id: "observed_signature_in_subject",
    where: "manifest",
    text: "every observed claim's provenance.signature is one of subject.signatures.",
  },
  {
    id: "envelope_key_id",
    where: "manifest",
    text: "signature.key_id equals manifest.issuer.key_id (checked when an envelope is given).",
  },
  {
    id: "envelope_anchor_memo",
    where: "manifest",
    text: "anchor.memo equals trace-manifest:1: followed by manifest_hash (checked when an envelope is given).",
  },
  {
    id: "no_negative_zero",
    where: "manifest",
    text: "no number is negative zero (JSON.parse reads -0 as -0, and the canonical text writes 0).",
  },
  {
    id: "no_proto_key",
    where: "manifest",
    text: "no object has an own __proto__ key (it would be dropped silently when parsed into an ordinary object).",
  },
  {
    id: "value_depth",
    where: "manifest",
    text: `claim values nest at most ${MAX_CLAIM_VALUE_DEPTH} levels.`,
  },
  {
    id: "size_limits",
    where: "manifest",
    text: `no string is longer than ${MAX_STRING_LENGTH} characters and the canonical manifest is at most ${MAX_CANONICAL_CHARS / (1024 * 1024)} MB (the builder refuses more, and a verifier should too).`,
  },
  {
    id: "retrieved_at_calendar_date",
    where: "manifest",
    text: "an attributed claim's retrieved_at is a real calendar day.",
  },
  {
    id: "tooling_matches_claims",
    where: "manifest",
    text:
      "tooling matches the claims: every TX_FEE claim's decoder equals tooling.normaliser, and every PROGRAM_LABEL source is trace-program-registry@ followed by the version of tooling.decoder_registry. " +
      "The versions of individual instruction decoders are not stamped in tooling, so they are not cross-checked; each claim names its own.",
  },
  {
    id: "canonical_form",
    where: "manifest",
    text: "the manifest has a canonical form: a lone surrogate (or anything else canonicalisation refuses) makes canonicalisation throw, so check C2 must report a failure and not crash.",
  },
  {
    id: "duplicate_keys_raw_text",
    where: "raw_text",
    text: "no JSON object repeats a key. JSON.parse keeps the last of two equal keys without a word, so a verifier must run detectDuplicateKeys on the raw text before parsing it.",
  },
]);

export interface RuleViolation {
  /** A MANIFEST_RULES id, or "schema" (the runtime schema refused the structure) or "unreadable". */
  rule: string;
  message: string;
  /** Where in the record, for structural issues only (property names and array positions, never values). */
  path?: string;
}

const MAX_VIOLATIONS = 100;

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json =>
  typeof v === "object" && v !== null && !Array.isArray(v);

function ruleOf(issue: { path: (string | number)[]; message: string; params?: unknown }): string {
  const rule = (issue.params as { rule?: unknown } | undefined)?.rule;
  if (typeof rule === "string") return rule;
  if (issue.path[issue.path.length - 1] === "retrieved_at") return "retrieved_at_calendar_date";
  const message = issue.message;
  if (message.includes("negative zero")) return "no_negative_zero";
  if (message.startsWith("nesting deeper")) return "value_depth";
  if (message.includes("__proto__")) return "no_proto_key";
  if (message.startsWith("provenance.type") && message.includes("does not match claim.type"))
    return "claim_type_matches_provenance";
  return "schema";
}

/**
 * Walks one subtree with an explicit stack (a hostile nesting depth must not overflow the call stack) and
 * reports negative zero, an own __proto__ key and nesting beyond the limit. `maxDepth` counts levels below
 * the starting node.
 */
function scan(
  root: unknown,
  maxDepth: number,
  report: (rule: string, message: string) => void,
): void {
  const stack: { v: unknown; depth: number }[] = [{ v: root, depth: 0 }];
  const seen = new Set<string>();
  const once = (rule: string, message: string) => {
    if (!seen.has(rule)) {
      seen.add(rule);
      report(rule, message);
    }
  };
  let visited = 0;
  while (stack.length > 0) {
    const { v, depth } = stack.pop()!;
    if (++visited > 5_000_000) return once("value_depth", "the record is too large to scan");
    if (typeof v === "number") {
      if (Object.is(v, -0)) once("no_negative_zero", "a number is negative zero");
      continue;
    }
    if (typeof v === "string") {
      if (v.length > MAX_STRING_LENGTH)
        once("size_limits", `a string is longer than ${MAX_STRING_LENGTH} characters`);
      continue;
    }
    if (typeof v !== "object" || v === null) continue;
    if (depth >= maxDepth) {
      once("value_depth", `nesting is deeper than ${maxDepth} levels`);
      continue; // do not descend: this is what keeps a nesting bomb cheap
    }
    if (Array.isArray(v)) {
      for (const item of v) stack.push({ v: item, depth: depth + 1 });
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(v, "__proto__"))
      once("no_proto_key", 'an object has an own "__proto__" key');
    for (const item of Object.values(v)) stack.push({ v: item, depth: depth + 1 });
  }
}

const versionOf = (nameAtVersion: string): string =>
  nameAtVersion.slice(nameAtVersion.indexOf("@") + 1);

/**
 * Checks an envelope ({ manifest, manifest_hash, signature, anchor }) or a bare manifest, as JSON.parse returns it,
 * against the runtime schema and every rule in MANIFEST_RULES. Returns [] only if all hold. Never throws: a value
 * it cannot read (a getter or Proxy that throws) is reported as "unreadable", not passed.
 */
export function checkManifestRules(subject: unknown): RuleViolation[] {
  const out: RuleViolation[] = [];
  const seen = new Set<string>();
  const add = (rule: string, message: string, path?: string) => {
    const key = `${rule}|${message}|${path ?? ""}`;
    if (seen.has(key) || out.length >= MAX_VIOLATIONS) return;
    seen.add(key);
    out.push(path === undefined ? { rule, message } : { rule, message, path });
  };
  try {
    run(subject, add);
  } catch {
    // Fail closed, with a fixed message: whatever threw may have been hostile.
    add("unreadable", "the record could not be read (a property getter or Proxy threw)");
  }
  return out;
}

function run(subject: unknown, add: (rule: string, message: string, path?: string) => void): void {
  if (!isObject(subject)) {
    add("schema", "the record is not an object");
    return;
  }
  const isEnvelope =
    "manifest" in subject ||
    "manifest_hash" in subject ||
    "signature" in subject ||
    "anchor" in subject;

  // Scans that do not depend on the structure being right: -0, __proto__ and depth, per claim and for the rest.
  const rawManifest = isEnvelope ? subject.manifest : subject;
  if (isObject(rawManifest) && Array.isArray(rawManifest.claims)) {
    rawManifest.claims.forEach((claim, i) =>
      scan(claim, MAX_CLAIM_VALUE_DEPTH + 4, (rule, message) =>
        add(rule, message, `${isEnvelope ? "manifest." : ""}claims[${i}]`),
      ),
    );
  }
  const others: Json = { ...subject };
  if (isEnvelope) delete others.manifest;
  else delete others.claims;
  scan(others, 12, (rule, message) => add(rule, message));
  if (isEnvelope && isObject(rawManifest)) {
    const rest: Json = { ...rawManifest };
    delete rest.claims;
    scan(rest, 12, (rule, message) => add(rule, message, "manifest"));
  }

  const parsed = (isEnvelope ? EnvelopeSchema : ManifestSchema).safeParse(subject);
  if (!parsed.success) {
    for (const issue of parsed.error.issues)
      add(ruleOf(issue), issue.message, issue.path.join("."));
    return; // the rules below read fields that only exist in a well-formed record
  }

  const manifest: Manifest = isEnvelope
    ? (parsed.data as { manifest: Manifest }).manifest
    : (parsed.data as Manifest);

  const signatures = new Set(manifest.subject.signatures);
  const expectedLabelSource = `trace-program-registry@${versionOf(manifest.tooling.decoder_registry)}`;
  for (const claim of manifest.claims) {
    try {
      assertClaimAllowed(claim);
    } catch (e) {
      add(
        "claim_code_allowed",
        `claim ${claim.id}: ${e instanceof ClaimRuleError ? e.message : "claim code or type refused"}`,
      );
    }
    const p = claim.provenance;
    if (p.type === "observed") {
      if (!signatures.has(p.signature))
        add(
          "observed_signature_in_subject",
          `claim ${claim.id} is observed in a transaction that subject.signatures does not list`,
        );
      if (claim.code === "TX_FEE" && p.decoder !== manifest.tooling.normaliser)
        add(
          "tooling_matches_claims",
          `claim ${claim.id} (TX_FEE) names a different normaliser than tooling.normaliser`,
        );
    }
    if (
      claim.code === "PROGRAM_LABEL" &&
      p.type === "attributed" &&
      p.source !== expectedLabelSource
    )
      add(
        "tooling_matches_claims",
        `claim ${claim.id} (PROGRAM_LABEL) names a different registry version than tooling.decoder_registry`,
      );
  }

  if (isEnvelope) {
    const envelope = parsed.data as {
      manifest_hash: string;
      signature: { key_id: string };
      anchor?: { memo: string };
    };
    if (envelope.signature.key_id !== manifest.issuer.key_id)
      add("envelope_key_id", "signature.key_id is not the key id in manifest.issuer.key_id");
    if (envelope.anchor && envelope.anchor.memo !== `trace-manifest:1:${envelope.manifest_hash}`)
      add("envelope_anchor_memo", "anchor.memo is not trace-manifest:1: followed by manifest_hash");
  }

  try {
    if (canonicalizeJcs(manifest).length > MAX_CANONICAL_CHARS)
      add("size_limits", "the canonical manifest is larger than 16 MB");
  } catch (e) {
    add(
      "canonical_form",
      `canonicalisation refused the manifest: ${e instanceof Error ? e.message : "unknown reason"}`,
    );
  }
}

// ─── Duplicate keys in raw JSON text ─────────────────────────────────────────

export interface DuplicateKey {
  /** The object that repeats the key, as $.a.b[2]. */
  path: string;
  /** The key, with JSON escapes decoded (so "a" and "a" are one key, as JSON.parse sees them). */
  key: string;
}

type Frame =
  | { kind: "object"; keys: Set<string>; expectKey: boolean; lastKey: string }
  | { kind: "array"; index: number };

/**
 * Keys that appear twice in one JSON object, found in the raw text. JSON.parse keeps the last one and reports
 * nothing, so a verifier must call this BEFORE parsing and refuse the document if the list is not empty.
 * Linear time, an explicit stack (no recursion), no allocation per value. Throws SyntaxError on an
 * unterminated string or an invalid escape in a key; it does not otherwise validate the text (JSON.parse does).
 */
export function detectDuplicateKeys(text: string): DuplicateKey[] {
  const found: DuplicateKey[] = [];
  const stack: Frame[] = [];
  const n = text.length;

  const beginValue = () => {
    const top = stack[stack.length - 1];
    if (top?.kind === "array") top.index++;
  };
  const pathOf = (depth: number): string => {
    let path = "$";
    for (let k = 0; k < depth; k++) {
      const f = stack[k];
      path += f.kind === "object" ? `.${f.lastKey}` : `[${f.index}]`;
    }
    return path;
  };

  let i = 0;
  while (i < n) {
    const c = text.charCodeAt(i);
    if (c === 32 || c === 9 || c === 10 || c === 13 || c === 58) {
      i++; // whitespace and ":"
    } else if (c === 123) {
      beginValue();
      stack.push({ kind: "object", keys: new Set(), expectKey: true, lastKey: "" });
      i++;
    } else if (c === 91) {
      beginValue();
      stack.push({ kind: "array", index: -1 });
      i++;
    } else if (c === 125 || c === 93) {
      stack.pop();
      i++;
    } else if (c === 44) {
      const top = stack[stack.length - 1];
      if (top?.kind === "object") top.expectKey = true;
      i++;
    } else if (c === 34) {
      let j = i + 1;
      let escaped = false;
      while (j < n && text.charCodeAt(j) !== 34) {
        if (text.charCodeAt(j) === 92) {
          escaped = true;
          j++;
        }
        j++;
      }
      if (j >= n) throw new SyntaxError("detectDuplicateKeys: unterminated string");
      const top = stack[stack.length - 1];
      if (top?.kind === "object" && top.expectKey) {
        const token = text.slice(i, j + 1);
        const key = escaped ? (JSON.parse(token) as string) : token.slice(1, -1);
        top.expectKey = false;
        top.lastKey = key;
        if (top.keys.has(key)) found.push({ path: pathOf(stack.length - 1), key });
        else top.keys.add(key);
      } else beginValue();
      i = j + 1;
    } else {
      // A number, true, false or null: skip to the next delimiter.
      beginValue();
      while (i < n) {
        const d = text.charCodeAt(i);
        if (
          d === 44 ||
          d === 93 ||
          d === 125 ||
          d === 32 ||
          d === 9 ||
          d === 10 ||
          d === 13 ||
          d === 58
        )
          break;
        i++;
      }
    }
  }
  return found;
}
