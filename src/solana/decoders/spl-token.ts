// SPL Token and Token-2022 base instruction decoder. Token-2022 keeps the SPL Token base
// instructions byte for byte, so one decoder is registered under both program IDs. Instruction data starts
// with a u8 tag; amounts are u64 little-endian and are printed as decimal strings of raw base units.
// Tags, data layouts and account orders were checked against the official sources (2026-10-07):
//   solana-program/token         interface/src/instruction.rs  (TokenInstruction::unpack, account docs)
//   solana-program/token-2022    interface/src/instruction.rs  (same base tags; extensions are 25 and up)
//   tag  instruction          data after the tag      accounts (single owner form)
//   1    InitializeAccount    -                       [account, mint, owner, rent]
//   3    Transfer             u64 amount              [source, destination, authority]
//   7    MintTo               u64 amount              [mint, destination, authority]
//   8    Burn                 u64 amount              [account, mint, authority]
//   9    CloseAccount         -                       [account, destination, authority]
//   12   TransferChecked      u64 amount, u8 decimals [source, mint, destination, authority]
//   14   MintToChecked        u64 amount, u8 decimals [mint, destination, authority]
//   15   BurnChecked          u64 amount, u8 decimals [account, mint, authority]
//   16   InitializeAccount2   32-byte owner           [account, mint, rent]
//   17   SyncNative           -                       [account] (older form adds [rent])
//   18   InitializeAccount3   32-byte owner           [account, mint]
// Where an authority is listed, any accounts after it are kept in order as extra_accounts: the multisig
// signers, or on Token-2022 the accounts a transfer hook asks for. Every other tag returns null, which
// flags Token-2022 extension instructions (25 and up) and the base instructions this task leaves out
// (approve, revoke, set authority, freeze, thaw, ...) as unknown_variant with their raw bytes kept.
// Data length and account count must match the layout exactly (the program itself ignores trailing data
// bytes; an instruction that carries any is flagged rather than read). Pure and isomorphic.
import { PROGRAM_IDS } from "../programs.js";
import { readAddress, readU64String } from "./bytes.js";
import type { DecodedFields, Decoder, FieldValue } from "./index.js";

interface Layout {
  kind: string;
  /** Exact data length, tag included. */
  length: number;
  /** Account names in the official order. */
  accounts: readonly string[];
  /** How many of the last names may be absent (SyncNative's Rent sysvar). */
  optional?: number;
  /** True when accounts after the named ones are allowed and kept as extra_accounts. */
  extra?: boolean;
  amount?: boolean;
  decimals?: boolean;
  /** True when a 32-byte owner follows the tag. */
  ownerInData?: boolean;
}

// Data offsets: the tag is byte 0, a u64 amount is bytes 1..8, decimals is byte 9, an owner is bytes 1..32.
const LAYOUTS: ReadonlyMap<number, Layout> = new Map<number, Layout>([
  [
    1,
    { kind: "token_initialize_account", length: 1, accounts: ["account", "mint", "owner", "rent"] },
  ],
  [
    3,
    {
      kind: "token_transfer",
      length: 9,
      accounts: ["source", "destination", "authority"],
      extra: true,
      amount: true,
    },
  ],
  [
    7,
    {
      kind: "token_mint_to",
      length: 9,
      accounts: ["mint", "destination", "authority"],
      extra: true,
      amount: true,
    },
  ],
  [
    8,
    {
      kind: "token_burn",
      length: 9,
      accounts: ["account", "mint", "authority"],
      extra: true,
      amount: true,
    },
  ],
  [
    9,
    {
      kind: "token_close_account",
      length: 1,
      accounts: ["account", "destination", "authority"],
      extra: true,
    },
  ],
  [
    12,
    {
      kind: "token_transfer_checked",
      length: 10,
      accounts: ["source", "mint", "destination", "authority"],
      extra: true,
      amount: true,
      decimals: true,
    },
  ],
  [
    14,
    {
      kind: "token_mint_to_checked",
      length: 10,
      accounts: ["mint", "destination", "authority"],
      extra: true,
      amount: true,
      decimals: true,
    },
  ],
  [
    15,
    {
      kind: "token_burn_checked",
      length: 10,
      accounts: ["account", "mint", "authority"],
      extra: true,
      amount: true,
      decimals: true,
    },
  ],
  [
    16,
    {
      kind: "token_initialize_account2",
      length: 33,
      accounts: ["account", "mint", "rent"],
      ownerInData: true,
    },
  ],
  [17, { kind: "token_sync_native", length: 1, accounts: ["account", "rent"], optional: 1 }],
  [
    18,
    {
      kind: "token_initialize_account3",
      length: 33,
      accounts: ["account", "mint"],
      ownerInData: true,
    },
  ],
]);

function decodeToken(data: Uint8Array, accounts: readonly string[]): DecodedFields | null {
  if (data.length === 0) return null;
  const layout = LAYOUTS.get(data[0]);
  if (!layout || data.length !== layout.length) return null;

  const named = layout.accounts.length;
  const required = named - (layout.optional ?? 0);
  if (accounts.length < required) return null;
  if (!layout.extra && accounts.length > named) return null;

  const fields: Record<string, FieldValue> = {};
  for (let i = 0; i < named && i < accounts.length; i++) fields[layout.accounts[i]] = accounts[i];
  if (layout.extra) fields.extra_accounts = accounts.slice(named);
  if (layout.amount) {
    const amount = readU64String(data, 1);
    if (amount === undefined) return null;
    fields.amount = amount;
  }
  if (layout.decimals) fields.decimals = data[9];
  if (layout.ownerInData) {
    const owner = readAddress(data, 1);
    if (owner === undefined) return null;
    fields.owner = owner;
  }
  return { kind: layout.kind, fields };
}

function tokenDecoder(programId: string): Decoder {
  // Frozen: the decoder is shared by every caller, so none may reassign its version or decode.
  return Object.freeze<Decoder>({
    programId,
    name: "spl-token",
    version: "1.0.0",
    decode(node) {
      return decodeToken(node.data, node.accounts);
    },
  });
}

export const splTokenDecoder: Decoder = tokenDecoder(PROGRAM_IDS.splToken);
export const token2022Decoder: Decoder = tokenDecoder(PROGRAM_IDS.token2022);
