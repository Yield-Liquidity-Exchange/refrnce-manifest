// Fallback for instructions no decoder explains. It keeps program ID, accounts and data (as
// lowercase hex) so nothing in the evidence is lost, and never interprets the bytes. The evidence is
// snapshotted from the node BEFORE any decoder runs, and every non-decoded result is built from that
// snapshot, so a buggy or hostile decoder cannot corrupt what is kept. Pure and isomorphic.
import type { InstructionNode } from "../instruction-tree.js";
import type { RawInstructionResult } from "./index.js";

/** Lowercase hex of the bytes, two digits per byte. */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Everything kept about a node, copied out of it once. */
export interface RawEvidence {
  ix_path: string;
  program_id: string;
  accounts: string[];
  /** Instruction data as lowercase hex. */
  data: string;
  failed: boolean;
  stack_height?: number;
}

export interface NodeSnapshot {
  evidence: RawEvidence;
  /** A private copy of the data bytes, from which decoders are handed their own copies. */
  bytes: Uint8Array;
  /** False when some field of the node could not be read (a throwing getter, a hole in the list). */
  readable: boolean;
}

const IX_PATH = /^\d+(\.\d+)*$/;

/**
 * Reads each field of the node exactly once and checks its type strictly: nothing is coerced, so a wrong
 * type can never turn into evidence or into a known program ID. A field that cannot be read or has the
 * wrong type yields a fixed empty value and marks the snapshot unreadable; this function never throws.
 * stack_height is optional and omitted unless it is a non-negative safe integer.
 */
export function snapshotNode(node: InstructionNode): NodeSnapshot {
  let readable = true;
  const read = <T>(fn: () => unknown, ok: (v: unknown) => v is T, fallback: T): T => {
    try {
      const v = fn();
      if (ok(v)) return v;
    } catch {
      // unreadable, handled below
    }
    readable = false;
    return fallback;
  };
  const bytes = read(
    () => node.data,
    (v): v is Uint8Array => v instanceof Uint8Array,
    new Uint8Array(0),
  );
  const evidence: RawEvidence = {
    ix_path: read(
      () => node.ix_path,
      (v): v is string => typeof v === "string" && IX_PATH.test(v),
      "",
    ),
    program_id: read(
      () => node.program_id,
      (v): v is string => typeof v === "string",
      "",
    ),
    // Copied here, once, so the elements checked are the elements kept.
    accounts: read(
      () => {
        const accounts = node.accounts;
        if (!Array.isArray(accounts)) return undefined;
        // By index, not by iterator: an instance with its own Symbol.iterator must not change what is kept.
        const copy: unknown[] = [];
        for (let i = 0; i < accounts.length; i++) copy.push(accounts[i]);
        return copy;
      },
      (v): v is string[] => Array.isArray(v) && v.every((a) => typeof a === "string"),
      [],
    ),
    data: "",
    failed: read(
      () => node.failed,
      (v): v is boolean => typeof v === "boolean",
      false,
    ),
  };
  const stackHeight = read<unknown>(
    () => node.stack_height,
    (v): v is unknown => true,
    undefined,
  );
  if (typeof stackHeight === "number" && Number.isSafeInteger(stackHeight) && stackHeight >= 0)
    evidence.stack_height = stackHeight;
  // Copy the bytes once, after the type check, so later mutation of the node cannot change them.
  // The typed-array copy constructor copies the real contents and never consults an own Symbol.iterator.
  const copy = new Uint8Array(bytes);
  evidence.data = toHex(copy);
  return { evidence, bytes: copy, readable };
}

/** The raw result for a node that was not decoded. Optional keys are omitted, never set to undefined. */
export function rawResult(
  evidence: RawEvidence,
  decode_status: RawInstructionResult["decode_status"],
  extra: { program?: string; decoder?: string; error?: string } = {},
): RawInstructionResult {
  const result: RawInstructionResult = {
    ix_path: evidence.ix_path,
    program_id: evidence.program_id,
    accounts: [...evidence.accounts],
    data: evidence.data,
    decode_status,
    failed: evidence.failed,
  };
  if (extra.program !== undefined) result.program = extra.program;
  if (extra.decoder !== undefined) result.decoder = extra.decoder;
  if (extra.error !== undefined) result.error = extra.error;
  if (evidence.stack_height !== undefined) result.stack_height = evidence.stack_height;
  return result;
}
