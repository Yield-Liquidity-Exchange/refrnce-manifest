// Decoder registry. decodeTransaction turns the flat node list from buildInstructionTree into
// exactly one result per node, in input order. Whatever a decoder does, the run never throws and no
// instruction is dropped: a program outside the dictionary is unknown_program, a known program whose bytes
// no decoder explains (or that has no decoder yet) is unknown_variant, and a decoder that throws, returns
// a Promise, or returns data that is not manifest-safe is error. Every status other than decoded keeps
// program ID, accounts and data as hex, taken from a snapshot made before any decoder runs.
// Pure and isomorphic: no network, no Node-only imports.
import type { InstructionNode } from "../instruction-tree.js";
import { REGISTRY_VERSION, programLabel } from "../programs.js";
import { readOnlyMap } from "../readonly-map.js";
import { jupiterV6Decoder } from "./jupiter-v6.js";
import { memoDecoder } from "./memo.js";
import { splTokenDecoder, token2022Decoder } from "./spl-token.js";
import { systemDecoder } from "./system.js";
import { rawResult, snapshotNode } from "./unknown.js";

export { REGISTRY_VERSION };

export type DecodeContext = Readonly<Record<string, unknown>>;

/** Manifest-safe value: integers only (token amounts are strings of base units) and never null. */
export type FieldValue = string | number | boolean | FieldValue[] | { [key: string]: FieldValue };

export interface DecodedFields {
  kind: string;
  fields: Record<string, FieldValue>;
}

export interface Decoder {
  programId: string;
  name: string;
  version: string;
  /**
   * Returns the decoded instruction, or null for a variant this decoder does not recognise. Must be
   * synchronous and may throw. It is handed a frozen copy of the node, so it cannot alter the evidence.
   */
  decode(node: InstructionNode, ctx: DecodeContext): DecodedFields | null;
}

interface ResultBase {
  ix_path: string;
  program_id: string;
  accounts: string[];
  /** Label from the program dictionary, when the program is in it. */
  program?: string;
  failed: boolean;
  stack_height?: number;
}

export interface DecodedInstruction extends ResultBase {
  decode_status: "decoded";
  /** "name@version" of the decoder that produced the result. */
  decoder: string;
  kind: string;
  fields: Record<string, FieldValue>;
}

export interface RawInstructionResult extends ResultBase {
  decode_status: "unknown_program" | "unknown_variant" | "error";
  /** Instruction data as lowercase hex. */
  data: string;
  /** "name@version" of the decoder that was tried, when one was. */
  decoder?: string;
  /** Why the status is error: a fixed message or the message of the exception a decoder threw. Never a stack. */
  error?: string;
}

export type DecodeResult = DecodedInstruction | RawInstructionResult;

export type DecoderRegistry = ReadonlyMap<string, Decoder>;

/**
 * Decoders keyed by program ID. Read-only, so no caller can change what later transactions decode to.
 * Memo, System, SPL Token and Token-2022 and Jupiter v6 are registered.
 */
export const defaultRegistry: DecoderRegistry = readOnlyMap<string, Decoder>(
  [memoDecoder, systemDecoder, splTokenDecoder, token2022Decoder, jupiterV6Decoder].map(
    (d) => [d.programId, d] as const,
  ),
);

const FALLBACK_MESSAGE = "decoder threw an error whose message could not be read";
const NOT_SYNC_MESSAGE = "decoders must be synchronous";
const BAD_SHAPE_MESSAGE = "decoder returned a value that is neither null nor { kind, fields }";
const BAD_FIELDS_MESSAGE =
  "decoder fields must hold only well-formed strings, safe integers, booleans, arrays and plain objects, nested at most 32 deep, with no null, undefined, symbol keys, hidden or accessor properties";
const UNREADABLE_NODE_MESSAGE = "instruction node could not be read";

/** The thrown value's message, extracted defensively: a hostile value must not escape from the catch. */
function safeMessage(e: unknown): string {
  try {
    if (typeof e === "string") return e;
    if (e instanceof Error) {
      const message = e.message;
      if (typeof message === "string") return message;
    }
  } catch {
    // fall through to the fixed message
  }
  return FALLBACK_MESSAGE;
}

const MAX_DEPTH = 32;
const MAX_VISITED = 100_000;

function isPlainObject(v: object): boolean {
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** True when the text is well-formed UTF-16 (no lone surrogate), so it can be hashed canonically later. */
function isWellFormedText(text: string): boolean {
  const native = (text as { isWellFormed?: () => boolean }).isWellFormed;
  if (typeof native === "function") return native.call(text);
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = text.charCodeAt(i + 1); // NaN past the end, so a trailing high surrogate fails
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

/**
 * Deep-copies decoder output while checking it is manifest-safe. Accepted: well-formed strings, safe
 * integers (not -0), booleans, and arrays or plain objects of those. Rejected, never silently dropped:
 * symbol keys, non-enumerable and accessor properties, extra properties on arrays, sparse arrays, lone
 * surrogates in values or keys. Own keys are listed once and each descriptor read once, so a getter cannot
 * change what is checked. Nested at most MAX_DEPTH deep and at most MAX_VISITED values in all, so a cyclic
 * or enormous structure is rejected instead of looping. Returns undefined when the data is not safe
 * (undefined is never a valid value, so it cannot be confused with a result).
 */
function cloneSafe(root: unknown): FieldValue | undefined {
  let visited = 0;
  const ownData = (target: object, key: string): { value: unknown } | undefined => {
    const d = Object.getOwnPropertyDescriptor(target, key);
    return d && "value" in d && d.enumerable ? { value: d.value } : undefined;
  };
  const walk = (v: unknown, depth: number): FieldValue | undefined => {
    if (++visited > MAX_VISITED || depth > MAX_DEPTH) return undefined;
    if (typeof v === "string") return isWellFormedText(v) ? v : undefined;
    if (typeof v === "boolean") return v;
    if (typeof v === "number") return Number.isSafeInteger(v) && !Object.is(v, -0) ? v : undefined;
    if (typeof v !== "object" || v === null) return undefined;
    const keys = Reflect.ownKeys(v);
    if (Array.isArray(v)) {
      // Only the index keys 0..length-1 and "length" may exist: no extras, no symbols, no holes.
      const length = v.length;
      let indexKeys = 0;
      for (const key of keys) {
        if (typeof key === "symbol") return undefined;
        if (key === "length") continue;
        if (!/^(0|[1-9]\d*)$/.test(key) || Number(key) >= length) return undefined;
        indexKeys++;
      }
      if (indexKeys !== length) return undefined;
      const out: FieldValue[] = [];
      for (let i = 0; i < length; i++) {
        const d = ownData(v, String(i));
        if (!d) return undefined;
        const item = walk(d.value, depth + 1);
        if (item === undefined) return undefined;
        out.push(item);
      }
      return out;
    }
    if (!isPlainObject(v)) return undefined;
    const out: { [key: string]: FieldValue } = {};
    for (const key of keys) {
      if (typeof key === "symbol" || !isWellFormedText(key)) return undefined;
      const d = ownData(v, key);
      if (!d) return undefined;
      const item = walk(d.value, depth + 1);
      if (item === undefined) return undefined;
      // defineProperty, not assignment: a key named "__proto__" must become an own property, not a prototype.
      Object.defineProperty(out, key, {
        value: item,
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  };
  return walk(root, 0);
}

const noop = () => undefined;

function decodeNode(
  node: InstructionNode,
  ctx: DecodeContext,
  registry: DecoderRegistry,
): DecodeResult {
  const { evidence, bytes, readable } = snapshotNode(node);
  if (!readable) return rawResult(evidence, "error", { error: UNREADABLE_NODE_MESSAGE });
  const program = programLabel(evidence.program_id);
  if (program === undefined) return rawResult(evidence, "unknown_program");

  let tag: string | undefined;
  try {
    const decoder = registry.get(evidence.program_id);
    if (!decoder) return rawResult(evidence, "unknown_variant", { program });
    tag = `${decoder.name}@${decoder.version}`;

    // The decoder gets its own frozen copy, so nothing it does can change the evidence kept above or the
    // node a later instruction is read from.
    const view: InstructionNode = Object.freeze({
      ix_path: evidence.ix_path,
      program_id: evidence.program_id,
      accounts: Object.freeze([...evidence.accounts]) as string[],
      data: Uint8Array.from(bytes),
      failed: evidence.failed,
      ...(evidence.stack_height === undefined ? {} : { stack_height: evidence.stack_height }),
    });
    const out: unknown = decoder.decode(view, ctx);

    if (out === null) return rawResult(evidence, "unknown_variant", { program, decoder: tag });
    if (typeof out === "object" || typeof out === "function") {
      const then = (out as { then?: unknown }).then;
      if (typeof then === "function") {
        // An async decoder's rejection would otherwise be unhandled and can kill a Node worker.
        try {
          then.call(out, undefined, noop);
        } catch {
          // nothing more to do: the result is an error either way
        }
        return rawResult(evidence, "error", { program, decoder: tag, error: NOT_SYNC_MESSAGE });
      }
    }
    if (typeof out !== "object")
      return rawResult(evidence, "error", { program, decoder: tag, error: BAD_SHAPE_MESSAGE });
    const { kind, fields } = out as { kind?: unknown; fields?: unknown };
    if (
      typeof kind !== "string" ||
      typeof fields !== "object" ||
      fields === null ||
      Array.isArray(fields)
    )
      return rawResult(evidence, "error", { program, decoder: tag, error: BAD_SHAPE_MESSAGE });
    const safeFields = cloneSafe(fields);
    if (safeFields === undefined || typeof safeFields !== "object" || Array.isArray(safeFields))
      return rawResult(evidence, "error", { program, decoder: tag, error: BAD_FIELDS_MESSAGE });

    const result: DecodedInstruction = {
      ix_path: evidence.ix_path,
      program_id: evidence.program_id,
      program,
      accounts: [...evidence.accounts],
      decode_status: "decoded",
      decoder: tag,
      kind,
      fields: safeFields,
      failed: evidence.failed,
    };
    if (evidence.stack_height !== undefined) result.stack_height = evidence.stack_height;
    return result;
  } catch (e) {
    return rawResult(evidence, "error", {
      program,
      ...(tag === undefined ? {} : { decoder: tag }),
      error: safeMessage(e),
    });
  }
}

/** One result per node, in input order. Never throws, whatever a decoder or a node does. */
export function decodeTransaction(
  tree: readonly InstructionNode[],
  ctx: DecodeContext,
  registry: DecoderRegistry = defaultRegistry,
): DecodeResult[] {
  // One frozen copy shared by the whole run, so a decoder cannot change the context later decoders see.
  // Spreading a hostile context (a throwing getter, a Proxy that throws) must not make the whole call throw.
  let frozenCtx: DecodeContext;
  try {
    frozenCtx = Object.freeze({ ...ctx });
  } catch {
    frozenCtx = Object.freeze({});
  }
  const results: DecodeResult[] = [];
  // An index loop, not map: a hole in the list is read as an unreadable node instead of being skipped.
  for (let i = 0; i < tree.length; i++) results.push(decodeNode(tree[i], frozenCtx, registry));
  return results;
}
