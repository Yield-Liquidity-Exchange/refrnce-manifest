// Flat, ordered instruction tree of a raw getTransaction result (encoding json). Outer instruction i has
// ix_path "i"; the inner instructions the runtime recorded for it have "i.j", j counting from 0 in listed
// order. Nodes come out in execution order: an outer instruction, then its inner ones, then the next outer.
// Every node carries the resolved program ID, resolved account addresses and the decoded data bytes, so
// later decoders never touch account indexes. Pure and isomorphic: no network, no Node-only imports.
import { decodeBase58 } from "./base58.js";
import { resolveAccountKeys, type RawInstruction, type RawTransaction } from "./account-keys.js";

export interface InstructionNode {
  /** "i" for an outer instruction, "i.j" for its j-th inner instruction. */
  ix_path: string;
  program_id: string;
  accounts: string[];
  data: Uint8Array;
  /** Present only when the RPC reported it. */
  stack_height?: number;
  /** True on every node when the transaction failed (meta.err is not null). */
  failed: boolean;
}

export function buildInstructionTree(tx: RawTransaction): InstructionNode[] {
  const keys = resolveAccountKeys(tx);
  const meta = tx.meta;
  if (!meta) throw new Error("transaction has no meta, so its failure state is unknown");
  const failed = meta.err !== null && meta.err !== undefined;
  const outer = tx.transaction.message.instructions;

  const resolve = (index: number): string => {
    // Untrusted JSON: only a real integer in range is an index. A string such as "length" would otherwise
    // read an inherited property and come out as a program ID or an account.
    if (!Number.isInteger(index) || index < 0 || index >= keys.length)
      throw new Error(`account index ${String(index)} is outside the ${keys.length} resolved keys`);
    return keys[index];
  };
  const toNode = (ix: RawInstruction, ix_path: string): InstructionNode => {
    const node: InstructionNode = {
      ix_path,
      program_id: resolve(ix.programIdIndex),
      accounts: ix.accounts.map(resolve),
      data: decodeBase58(ix.data),
      failed,
    };
    // Manifest data holds only integers, so anything else (NaN, Infinity, 1.5) is treated as not reported.
    const stackHeight = ix.stackHeight;
    if (typeof stackHeight === "number" && Number.isInteger(stackHeight) && stackHeight >= 0)
      node.stack_height = stackHeight;
    return node;
  };

  const inner = new Map<number, RawInstruction[]>();
  for (const group of meta.innerInstructions ?? []) {
    if (!Number.isInteger(group.index) || group.index < 0 || group.index >= outer.length)
      throw new Error(
        `inner instruction group refers to outer instruction ${group.index}, which does not exist`,
      );
    inner.set(group.index, [...(inner.get(group.index) ?? []), ...group.instructions]);
  }

  const nodes: InstructionNode[] = [];
  outer.forEach((ix, i) => {
    nodes.push(toNode(ix, String(i)));
    (inner.get(i) ?? []).forEach((child, j) => nodes.push(toNode(child, `${i}.${j}`)));
  });
  return nodes;
}
