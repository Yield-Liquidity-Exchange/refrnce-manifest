// Isomorphic: runs in Node and the browser. No node: imports, no @solana/web3.js, no bs58.
//
// A Claim is one statement in a Trace Manifest, and Provenance is the proof of where it came from.
// There is one Provenance shape per claim type, so a claim can never exist without the evidence its
// type requires. Everything in a claim must survive an RFC 8785 canonicaliser, which accepts only
// integers: so no floats, NaN, Infinity, null or undefined anywhere, and token amounts are decimal
// strings of raw base units (parse them with BigInt, never Number).
import { z } from "zod";

// ─── Claim types ─────────────────────────────────────────────────────────────

export const ClaimTypeSchema = z.enum(["observed", "derived", "attributed", "inferred"]);
export type ClaimType = z.infer<typeof ClaimTypeSchema>;

// ─── JSON-safe claim value ───────────────────────────────────────────────────

export type ClaimValue = string | number | boolean | ClaimValue[] | { [key: string]: ClaimValue };

/** Deepest arrays/objects nesting a claim value may have. Checked iteratively before any recursive parsing. */
export const MAX_CLAIM_VALUE_DEPTH = 64;

/**
 * The checks zod's shape schema cannot make, done with an explicit stack so a hostile value can never
 * overflow the call stack: nesting depth, -0, an own "__proto__" key (it would be silently dropped while
 * parsing, so a later hash would cover different data than was submitted), and anything that is not a
 * real array or a plain Object.prototype object (RegExp, typed arrays, boxed primitives, class instances
 * and null-prototype objects would be silently coerced to plain objects).
 */
function checkClaimValueStructure(value: unknown, ctx: z.RefinementCtx): void {
  const fail = (message: string) => ctx.addIssue({ code: z.ZodIssueCode.custom, message });
  const stack: { v: unknown; depth: number }[] = [{ v: value, depth: 0 }];
  while (stack.length > 0) {
    const { v, depth } = stack.pop()!;
    if (typeof v === "number") {
      if (Object.is(v, -0)) return fail("negative zero is not allowed");
      continue;
    }
    // Everything else that is not an object is left to the shape schema below.
    if (typeof v !== "object" || v === null) continue;
    if (depth >= MAX_CLAIM_VALUE_DEPTH)
      return fail(`nesting deeper than ${MAX_CLAIM_VALUE_DEPTH} levels`);
    if (Array.isArray(v)) {
      for (const item of v) stack.push({ v: item, depth: depth + 1 });
      continue;
    }
    if (Object.getPrototypeOf(v) !== Object.prototype)
      return fail("only plain objects and arrays are allowed");
    if (Object.prototype.hasOwnProperty.call(v, "__proto__"))
      return fail('a "__proto__" key is not allowed');
    for (const item of Object.values(v)) stack.push({ v: item, depth: depth + 1 });
  }
}

const ClaimValueShapeSchema: z.ZodType<ClaimValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().int().safe(),
    z.boolean(),
    z.array(ClaimValueShapeSchema),
    z.record(ClaimValueShapeSchema),
  ]),
);

/**
 * Strings, safe integers, booleans, and arrays/objects of them. A float, null, undefined or -0 is
 * rejected at any depth. The structural check runs first; the recursive shape parse only runs on a value
 * that passed it (a failed refinement leaves the pipeline dirty, so it is skipped).
 */
export const ClaimValueSchema: z.ZodType<ClaimValue, z.ZodTypeDef, unknown> = z
  .unknown()
  .superRefine(checkClaimValueStructure)
  .pipe(ClaimValueShapeSchema);

// ─── Provenance (discriminated on `type`, one shape per claim type) ──────────

/** Claim IDs are c-0001, c-0002 ... (four digits, widening to c-10000 with no leading zero, so one ID has one spelling). */
const ClaimIdSchema = z
  .string()
  .regex(/^c-(?!0000$)(\d{4}|[1-9]\d{4,})$/, "claim id must look like c-0001");

/** name@version, e.g. "spl-token-transfer@1.0.0". */
const NameAtVersionSchema = z
  .string()
  .regex(
    /^[A-Za-z0-9._+-]+@[A-Za-z0-9._+-]+$/,
    "must be name@version using only letters, digits and . _ + -, e.g. decoder-name@1.0.0",
  );

/** Dotted instruction path with no leading zeros: "2" is top-level instruction 2, "2.1" an inner instruction of it. */
export const IX_PATH_PATTERN = /^(0|[1-9]\d*)(\.(0|[1-9]\d*))*$/;
const IxPathSchema = z.string().regex(IX_PATH_PATTERN, "ix_path must be dotted integers, e.g. 2.1");

const ObservedProvenanceSchema = z
  .object({
    type: z.literal("observed"),
    signature: z.string().min(1),
    slot: z
      .number()
      .int()
      .safe()
      .nonnegative()
      .refine((n) => !Object.is(n, -0), "negative zero is not allowed"),
    ix_path: IxPathSchema,
    decoder: NameAtVersionSchema,
  })
  .strict();

const DerivedProvenanceSchema = z
  .object({
    type: z.literal("derived"),
    formula: NameAtVersionSchema,
    inputs: z.array(ClaimIdSchema).min(1),
  })
  .strict();

const AttributedProvenanceSchema = z
  .object({
    type: z.literal("attributed"),
    source: z.string().min(1),
    source_ref: z.string().min(1).optional(),
    /** ISO 8601 UTC timestamp, e.g. 2026-10-07T08:30:00Z. */
    retrieved_at: z.string().datetime().optional(),
  })
  .strict();

const InferredProvenanceSchema = z
  .object({
    type: z.literal("inferred"),
    analyst_id: z.string().min(1),
    basis: z.array(ClaimIdSchema).min(1),
  })
  .strict();

/** zod's .optional() accepts an explicit undefined, which a canonicaliser would have to guess about. */
function rejectUndefinedKeys(value: Record<string, unknown>, ctx: z.RefinementCtx): void {
  for (const [key, v] of Object.entries(value)) {
    if (v === undefined)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: [key],
        message: "must be omitted, not undefined",
      });
  }
}

export const ProvenanceSchema = z
  .discriminatedUnion("type", [
    ObservedProvenanceSchema,
    DerivedProvenanceSchema,
    AttributedProvenanceSchema,
    InferredProvenanceSchema,
  ])
  .superRefine(rejectUndefinedKeys);

export type ObservedProvenance = z.infer<typeof ObservedProvenanceSchema>;
export type DerivedProvenance = z.infer<typeof DerivedProvenanceSchema>;
export type AttributedProvenance = z.infer<typeof AttributedProvenanceSchema>;
export type InferredProvenance = z.infer<typeof InferredProvenanceSchema>;
export type Provenance = z.infer<typeof ProvenanceSchema>;

// ─── Claim ───────────────────────────────────────────────────────────────────

export const ClaimSchema = z
  .object({
    id: ClaimIdSchema,
    type: ClaimTypeSchema,
    code: z.string().min(1),
    value: ClaimValueSchema,
    provenance: ProvenanceSchema,
  })
  .strict()
  .superRefine((claim, ctx) => {
    if (claim.provenance.type !== claim.type)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["provenance", "type"],
        message: `provenance.type "${claim.provenance.type}" does not match claim.type "${claim.type}"`,
      });
  });

export type Claim = z.infer<typeof ClaimSchema>;

// ─── Deterministic claim IDs ─────────────────────────────────────────────────

/** Numeric, segment-by-segment order of two ix_paths: 2 < 2.0 < 2.1 < 2.10 < 10. Both must match IX_PATH_PATTERN. */
export function compareIxPath(a: string, b: string): number {
  const as = a.split(".");
  const bs = b.split(".");
  for (let i = 0; i < Math.min(as.length, bs.length); i++) {
    // No leading zeros, so a longer digit string is a larger number; equal lengths compare as text.
    if (as[i].length !== bs[i].length) return as[i].length - bs[i].length;
    if (as[i] !== bs[i]) return as[i] < bs[i] ? -1 : 1;
  }
  return as.length - bs.length;
}

/** Code-unit order, never localeCompare: the result must not depend on the machine's locale. */
function compareCode(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

type Draft = { code: string; provenance: Provenance };

function orderKey(d: Draft): string {
  return d.provenance.type === "observed" ? `${d.provenance.ix_path} / ${d.code}` : `${d.code}`;
}

function compareDrafts(a: Draft, b: Draft): number {
  const ax = a.provenance.type === "observed" ? a.provenance.ix_path : null;
  const bx = b.provenance.type === "observed" ? b.provenance.ix_path : null;
  // Only observed claims carry an ix_path; every other type sorts after all observed claims.
  if (ax !== null && bx === null) return -1;
  if (ax === null && bx !== null) return 1;
  if (ax !== null && bx !== null) {
    const byPath = compareIxPath(ax, bx);
    if (byPath !== 0) return byPath;
  }
  return compareCode(a.code, b.code);
}

/**
 * Assigns c-0001, c-0002 ... in order of ix_path (numeric), then code. Claims without an ix_path (every
 * type except observed) come after all observed claims, ordered by code. The result is sorted in ID
 * order and does not depend on the input order. Two claims that share the whole sort key cannot be
 * ordered without guessing, so that throws.
 */
export function assignClaimIds<T extends Draft>(
  drafts: readonly T[],
  tiebreak?: (a: T, b: T) => number,
): (T & { id: string })[] {
  for (const d of drafts) {
    if (d.provenance.type === "observed" && !IX_PATH_PATTERN.test(d.provenance.ix_path))
      throw new Error(`invalid ix_path "${d.provenance.ix_path}" on claim ${d.code}`);
  }
  const compare = (a: T, b: T) => compareDrafts(a, b) || (tiebreak ? tiebreak(a, b) : 0);
  const sorted = [...drafts].sort(compare);
  for (let i = 1; i < sorted.length; i++) {
    if (compare(sorted[i - 1], sorted[i]) === 0)
      throw new Error(
        `ambiguous claim order: two claims share the sort key "${orderKey(sorted[i])}"`,
      );
  }
  return sorted.map((d, i) => ({ ...d, id: `c-${String(i + 1).padStart(4, "0")}` }));
}

// ─── Manifest and Envelope ───────────────────────────────────────
//
// The manifest is the hashed body. The envelope wraps it with the hash, the signature and the anchor,
// which sit outside the hashed body because each depends on the hash. Every object is strict: a field
// the schema does not name would be signed and never checked. Numbers are safe integers only and nothing
// is null, so the whole manifest survives the RFC 8785 canonicaliser.

export const MANIFEST_SCHEMA_ID = "trace-manifest/1.0";

/** TRC- and 12 Crockford base32 characters (0-9 and A-Z without I, L, O, U), upper case only. */
export const TRACE_ID_PATTERN = /^TRC-[0-9A-HJKMNP-TV-Z]{12}$/;
/** The same rule as the issuer key list (verify/signature.ts, tested to agree), so no signable key id is rejected here. */
export const KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
/** What hashManifest and the artifact hash return: "sha256:" and 64 lower-case hex digits. */
export const SHA256_PREFIXED_PATTERN = /^sha256:[0-9a-f]{64}$/;
/** UTC, whole seconds, a Z: one spelling for one instant. The calendar check is in the schema, not the pattern. */
export const ISSUED_AT_PATTERN =
  /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/;
/**
 * A file name, never a path: starts and ends with a letter or digit (so no trailing dot or space), and holds
 * only letters, digits and . _ - between. Windows device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) are
 * refused with or without an extension, in any case: such a file cannot be created there, and the case-
 * insensitive spelling is written out because JSON Schema patterns carry no flags.
 */
export const ARTIFACT_NAME_PATTERN =
  /^(?![Cc][Oo][Nn](?:\.|$)|[Pp][Rr][Nn](?:\.|$)|[Aa][Uu][Xx](?:\.|$)|[Nn][Uu][Ll](?:\.|$)|[Cc][Oo][Mm][1-9](?:\.|$)|[Ll][Pp][Tt][1-9](?:\.|$))[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$/;
/**
 * Base58 text of a 64-byte Solana or Ed25519 signature: 64 to 88 characters. Usually 86 to 88; a signature that
 * starts with zero bytes is shorter, because each leading zero byte is written as one "1". The verifier checks
 * that the text decodes to exactly 64 bytes.
 */
export const SIGNATURE_BASE58_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{64,88}$/;
/** What an anchor Memo carries: the manifest hash, nothing else. */
export const ANCHOR_MEMO_PATTERN = /^trace-manifest:1:sha256:[0-9a-f]{64}$/;
/** Issuer display name: 1 to 100 printable ASCII characters (space to tilde). */
export const ISSUER_NAME_PATTERN = /^[ -~]{1,100}$/;

export const MANIFEST_CLUSTERS = ["mainnet-beta", "devnet", "testnet"] as const;
export const ClusterSchema = z.enum(MANIFEST_CLUSTERS);
export type ManifestCluster = z.infer<typeof ClusterSchema>;

/** Bounds, so a hostile manifest cannot make a verifier loop over an unbounded list. */
export const MAX_SUBJECT_SIGNATURES = 1000;
export const MAX_MANIFEST_CLAIMS = 100_000;
export const MAX_MANIFEST_ARTIFACTS = 1000;
/** Longest string (UTF-16 code units) anywhere in a manifest, and the largest canonical manifest, in characters. */
export const MAX_STRING_LENGTH = 20_000;
export const MAX_CANONICAL_CHARS = 16 * 1024 * 1024;

/**
 * The only fields of a claim VALUE that hold the ID of another claim in the same manifest. Everything that
 * rewrites or checks claim references goes through this table (and the provenance fields below), never a
 * search over the JSON text. A new reference field is added here first.
 */
export const CLAIM_ID_VALUE_FIELDS = ["from_owner_claim", "to_owner_claim"] as const;

function valueField(claim: Claim, field: string): unknown {
  const value = claim.value;
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  return Object.prototype.hasOwnProperty.call(value, field) ? value[field] : undefined;
}

/** The IDs a claim refers to: the named value fields, Derived inputs and Inferred basis. May repeat. */
export function claimReferences(claim: Claim): string[] {
  const refs: string[] = [];
  for (const field of CLAIM_ID_VALUE_FIELDS) {
    const ref = valueField(claim, field);
    if (typeof ref === "string") refs.push(ref);
  }
  if (claim.provenance.type === "derived") refs.push(...claim.provenance.inputs);
  if (claim.provenance.type === "inferred") refs.push(...claim.provenance.basis);
  return refs;
}

const Sha256PrefixedSchema = z
  .string()
  .regex(SHA256_PREFIXED_PATTERN, "must be sha256: and 64 lower-case hex digits");

const SignatureBase58Schema = z
  .string()
  .regex(SIGNATURE_BASE58_PATTERN, "must be base58 text of a 64-byte signature");

/** True when the YYYY-MM-DD at the start of an ISSUED_AT_PATTERN match is a real day (leap years included). */
function isRealCalendarDay(text: string): boolean {
  const year = Number(text.slice(0, 4));
  const month = Number(text.slice(5, 7));
  const day = Number(text.slice(8, 10));
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  return day <= daysInMonth;
}

const IssuedAtSchema = z
  .string()
  .regex(ISSUED_AT_PATTERN, "must be UTC to the second, like 2026-10-07T03:15:00Z")
  .refine(isRealCalendarDay, {
    message: "is not a real calendar date",
    params: { rule: "issued_at_calendar_date" },
  });

const IssuerSchema = z
  .object({
    /** The brand, from one config constant.  */
    name: z
      .string()
      .regex(ISSUER_NAME_PATTERN, "must be 1 to 100 characters with no control characters"),
    key_id: z.string().regex(KEY_ID_PATTERN, "key_id must be 1-64 of A-Z a-z 0-9 . _ -"),
  })
  .strict();

const SubjectSchema = z
  .object({
    chain: z.literal("solana"),
    cluster: ClusterSchema,
    signatures: z.array(SignatureBase58Schema).min(1).max(MAX_SUBJECT_SIGNATURES),
  })
  .strict();

const ToolingSchema = z
  .object({
    /** name@version of the normaliser that built the claims. */
    normaliser: NameAtVersionSchema,
    /** name@version of the decoder registry. */
    decoder_registry: NameAtVersionSchema,
    /** name@version of every formula the manifest may cite; at least those its Derived claims name. */
    formulas: z.array(NameAtVersionSchema).min(1).max(100),
  })
  .strict();

const ArtifactSchema = z
  .object({
    name: z.string().regex(ARTIFACT_NAME_PATTERN, "must be a plain file name, 1 to 128 characters"),
    sha256: Sha256PrefixedSchema,
    bytes: z
      .number()
      .int()
      .safe()
      .nonnegative()
      .refine((n) => !Object.is(n, -0), {
        message: "negative zero is not allowed",
        params: { rule: "no_negative_zero" },
      }),
  })
  .strict();

export const ManifestSchema = z
  .object({
    schema: z.literal(MANIFEST_SCHEMA_ID),
    trace_id: z.string().regex(TRACE_ID_PATTERN, "must be TRC- and 12 Crockford base32 characters"),
    issuer: IssuerSchema,
    issued_at: IssuedAtSchema,
    subject: SubjectSchema,
    tooling: ToolingSchema,
    claims: z.array(ClaimSchema).min(1).max(MAX_MANIFEST_CLAIMS),
    artifacts: z.array(ArtifactSchema).max(MAX_MANIFEST_ARTIFACTS),
  })
  .strict()
  .superRefine((m, ctx) => {
    // The rule id travels with the issue (issue.params.rule), so manifest-rules.ts can report it by name.
    const add = (rule: string, path: (string | number)[], message: string) =>
      ctx.addIssue({ code: z.ZodIssueCode.custom, path, message, params: { rule } });

    const dupe = (
      rule: string,
      items: readonly string[],
      base: (string | number)[],
      what: string,
    ) => {
      const seen = new Set<string>();
      items.forEach((item, i) => {
        if (seen.has(item)) add(rule, [...base, i], `duplicate ${what}`);
        seen.add(item);
      });
    };
    dupe("schema", m.subject.signatures, ["subject", "signatures"], "signature");
    dupe("schema", m.tooling.formulas, ["tooling", "formulas"], "formula");
    // Case-insensitive: two names that differ only in case would collide when unpacked on some systems.
    dupe(
      "artifact_names_unique",
      m.artifacts.map((a) => a.name.toLowerCase()),
      ["artifacts"],
      "artifact name",
    );

    const ids = new Set<string>();
    m.claims.forEach((c, i) => {
      if (ids.has(c.id)) add("claim_ids_unique", ["claims", i, "id"], `duplicate claim id ${c.id}`);
      ids.add(c.id);
    });
    const formulas = new Set(m.tooling.formulas);
    m.claims.forEach((c, i) => {
      for (const field of CLAIM_ID_VALUE_FIELDS) {
        const v = valueField(c, field);
        if (v !== undefined && !ClaimIdSchema.safeParse(v).success)
          add("references_resolve", ["claims", i, "value", field], "must be a claim id");
      }
      for (const ref of claimReferences(c)) {
        if (ref === c.id)
          add("references_resolve", ["claims", i], `claim ${c.id} refers to itself`);
        else if (!ids.has(ref))
          add(
            "references_resolve",
            ["claims", i],
            `claim ${c.id} refers to ${ref}, which is not in the manifest`,
          );
      }
      if (c.provenance.type === "derived" && !formulas.has(c.provenance.formula))
        add(
          "formulas_listed",
          ["claims", i, "provenance", "formula"],
          `formula ${c.provenance.formula} is not listed in tooling.formulas`,
        );
    });
  });

export type Manifest = z.infer<typeof ManifestSchema>;
export type ManifestArtifact = z.infer<typeof ArtifactSchema>;

const EnvelopeSignatureSchema = z
  .object({
    alg: z.literal("Ed25519"),
    key_id: z.string().regex(KEY_ID_PATTERN, "key_id must be 1-64 of A-Z a-z 0-9 . _ -"),
    /** Base58 text of the 64-byte signature over the manifest hash. */
    value: SignatureBase58Schema,
  })
  .strict();

const AnchorSchema = z
  .object({
    cluster: ClusterSchema,
    tx_signature: SignatureBase58Schema,
    slot: z.number().int().safe().nonnegative(),
    block_time: z.number().int().safe().nonnegative(),
    memo: z
      .string()
      .regex(ANCHOR_MEMO_PATTERN, "must be trace-manifest:1:sha256: and 64 hex digits"),
  })
  .strict();

export const EnvelopeSchema = z
  .object({
    manifest: ManifestSchema,
    manifest_hash: Sha256PrefixedSchema,
    signature: EnvelopeSignatureSchema,
    anchor: AnchorSchema,
  })
  .strict();

export type Envelope = z.infer<typeof EnvelopeSchema>;
