// Account keys of a raw getTransaction result (encoding json). Instructions refer to accounts by index
// into one combined list: the message's static keys, then the writable addresses loaded from address
// lookup tables, then the readonly ones. Getting that order wrong makes every program ID and account
// after the first lookup-table entry resolve to the wrong address, so this is the one place it lives.
// Pure and isomorphic: no network, no Node-only imports.

export interface RawInstruction {
  programIdIndex: number;
  accounts: number[];
  /** base58 text */
  data: string;
  stackHeight?: number | null;
}

export interface RawTransaction {
  version?: number | "legacy";
  transaction: {
    message: { accountKeys: string[]; instructions: RawInstruction[] };
  };
  meta: {
    err: unknown;
    innerInstructions?: { index: number; instructions: RawInstruction[] }[] | null;
    /** Absent on legacy transactions; present with empty arrays on some RPC nodes. */
    loadedAddresses?: { writable?: string[]; readonly?: string[] } | null;
  } | null;
}

/** Static keys, then loadedAddresses.writable, then loadedAddresses.readonly. Legacy transactions have no loaded addresses. */
export function resolveAccountKeys(tx: RawTransaction): string[] {
  if (!tx.meta) throw new Error("transaction has no meta, so its loaded addresses are unknown");
  const loaded = tx.meta.loadedAddresses;
  return [
    ...tx.transaction.message.accountKeys,
    ...(loaded?.writable ?? []),
    ...(loaded?.readonly ?? []),
  ];
}
