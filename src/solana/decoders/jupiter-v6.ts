//   - The union of both IDLs decodes; where they clash the current IDL wins. This module uses each item's
//     explicit discriminator bytes from the current IDL (one of them, create_idempotent_associated_token_
//     account, deliberately differs from the hash of its name; a test pins every other one to the hash).
//   - route_v2, shared_accounts_route_v2, exact_out_route_v2 and shared_accounts_exact_out_route_v2 decode to
//     kind "route" with the leading scalar arguments (the IDL's own list and widths) and route_plan_decoded
//     false. The route_plan vec (a RoutePlanStepV2 per hop, each a Swap enum of 191 variants) is NOT decoded:
//     the bytes after the scalars are left unread. The legs of a swap are reported by SwapsEvent and by the
//     token transfers, which are decoded and reconcile. Data shorter than the scalars plus the 4-byte route_plan
//     length prefix returns null (a real instruction always carries the prefix; without it the data is cut off).
//   - SwapsEvent (event CPI): tag, discriminator, u32 leg count n, then n SwapEventV2 legs of 112 bytes in IDL
//     order input_mint, input_amount, output_mint, output_amount, amm (amm LAST here, FIRST in SwapEvent).
//     Exactly 16 + 4 + 112n bytes, n from 1 to 32, one account; anything else returns null, never a partial
//     decode. Output is flat: leg_count and leg_<i>_<field>. Events are keyed on the emitting program: this
//     decoder is registered under the Jupiter program ID only, so the same bytes sent to another program
//     (the legacy SwapEvent discriminator also appears in Raydium CPMM logs) are never read as Jupiter's.
import idl from "../idl/jupiter-v6.idl.json" with { type: "json" };
import onchainIdl from "../idl/jupiter-v6-onchain.idl.json" with { type: "json" };
import { PROGRAM_IDS } from "../programs.js";
import { sha256 } from "../sha256.js";
import { readAddress, readU32, readU64String } from "./bytes.js";
import type { DecodedFields, Decoder, FieldValue } from "./index.js";

const DISCRIMINATOR_LENGTH = 8;

const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const first8 = (preimage: string) =>
  sha256(new TextEncoder().encode(preimage)).slice(0, DISCRIMINATOR_LENGTH);
/** Anchor's Rust function name for an IDL camelCase name: an underscore before each capital, lowercased. */
const snakeCase = (name: string) => name.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);

interface InstructionInfo {
  kind: string;
  instruction: string;
  /** Leading scalar arguments to read (the route_v2 family only). */
  scalars?: ScalarLayout;
}

const INSTRUCTIONS = new Map<string, InstructionInfo>(
  idl.instructions.map((ix) => {
    const instruction = snakeCase(ix.name);
    const kind = /route/i.test(ix.name) ? "route" : instruction;
    return [hex(first8(`global:${instruction}`)), { kind, instruction }] as const;
  }),
);

// ---- the current IDL ----------------------------------------------------------------------

interface CurrentIdlItem {
  name: string;
  discriminator: number[];
  args?: { name: string; type: unknown }[];
}
interface CurrentIdlType {
  name: string;
  type: { kind: string; fields?: { name: string; type: unknown }[] };
}
const CURRENT = onchainIdl as unknown as {
  instructions: CurrentIdlItem[];
  events: CurrentIdlItem[];
  types: CurrentIdlType[];
};

/** The IDL's explicit discriminator as hex. Anchor 0.30+ writes it for every instruction and event. */
function explicitDiscriminator(item: CurrentIdlItem): string {
  const d = item.discriminator;
  if (
    !Array.isArray(d) ||
    d.length !== DISCRIMINATOR_LENGTH ||
    !d.every((b) => Number.isInteger(b) && b >= 0 && b <= 0xff)
  )
    throw new Error(`the current Jupiter IDL has no usable discriminator for ${item.name}`);
  return hex(Uint8Array.from(d));
}

const SCALAR_WIDTH: Readonly<Record<string, number>> = { u8: 1, u16: 2, u64: 8 };

interface ScalarField {
  name: string;
  type: "u8" | "u16" | "u64";
  /** Offset from the start of the instruction data, discriminator included. */
  at: number;
}
interface ScalarLayout {
  fields: ScalarField[];
  /** Bytes the scalars end at; shorter data is not this instruction. */
  length: number;
}

/**
 * The leading u8/u16/u64 arguments of an instruction, read from the IDL's own argument list. The only
 * argument after them must be route_plan: it is not decoded (see the header), and stopping anywhere else
 * would mean the IDL changed shape, so loading fails loudly instead of reading a wrong offset.
 */
function scalarLayout(ix: CurrentIdlItem): ScalarLayout {
  const args = ix.args ?? [];
  const fields: ScalarField[] = [];
  let at = DISCRIMINATOR_LENGTH;
  for (const a of args) {
    if (typeof a.type !== "string" || !(a.type in SCALAR_WIDTH)) break;
    fields.push({ name: a.name, type: a.type as ScalarField["type"], at });
    at += SCALAR_WIDTH[a.type];
  }
  const rest = args.slice(fields.length);
  if (rest.length !== 1 || rest[0].name !== "route_plan")
    throw new Error(
      `${ix.name}: expected scalar arguments then route_plan in the current Jupiter IDL`,
    );
  return { fields, length: at };
}

const V2_ROUTES: ReadonlySet<string> = new Set([
  "route_v2",
  "shared_accounts_route_v2",
  "exact_out_route_v2",
  "shared_accounts_exact_out_route_v2",
]);

// The current IDL is applied after the 2024 one, so on a clash it wins.
for (const ix of CURRENT.instructions) {
  INSTRUCTIONS.set(explicitDiscriminator(ix), {
    kind: /route/i.test(ix.name) ? "route" : ix.name,
    instruction: ix.name,
    ...(V2_ROUTES.has(ix.name) ? { scalars: scalarLayout(ix) } : {}),
  });
}
for (const name of V2_ROUTES)
  if (!CURRENT.instructions.some((ix) => ix.name === name))
    throw new Error(`the current Jupiter IDL has no ${name} instruction`);

/** The u32 length of the route_plan vec that follows the scalars. Its content is not read. */
const ROUTE_PLAN_LENGTH_PREFIX = 4;

function decodeRoute(data: Uint8Array, info: InstructionInfo): DecodedFields | null {
  const layout = info.scalars;
  if (!layout || data.length < layout.length + ROUTE_PLAN_LENGTH_PREFIX) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const fields: Record<string, FieldValue> = { instruction: info.instruction };
  for (const f of layout.fields) {
    if (f.type === "u64") fields[f.name] = readU64String(data, f.at) as string;
    else fields[f.name] = f.type === "u16" ? view.getUint16(f.at, true) : view.getUint8(f.at);
  }
  fields.route_plan_decoded = false;
  return { kind: info.kind, fields };
}

const EVENT_TAG = hex(first8("anchor:event").reverse());

interface EventField {
  name: string;
  type: "publicKey" | "u64";
  offset: number;
}

function eventLayout(eventName: string) {
  const event = idl.events.find((e) => e.name === eventName);
  if (!event) throw new Error(`the vendored Jupiter IDL has no ${eventName} event`);
  let offset = 0;
  const fields: EventField[] = event.fields.map((f) => {
    if (f.type !== "publicKey" && f.type !== "u64")
      throw new Error(`${eventName}.${f.name} has type ${String(f.type)}, which is not supported`);
    const field: EventField = { name: snakeCase(f.name), type: f.type, offset };
    offset += f.type === "publicKey" ? 32 : 8;
    return field;
  });
  return { discriminator: hex(first8(`event:${eventName}`)), fields, bodyLength: offset };
}

const SWAP_EVENT = eventLayout("SwapEvent");

function decodeSwapEvent(data: Uint8Array, accounts: readonly string[]): DecodedFields | null {
  const bodyAt = 2 * DISCRIMINATOR_LENGTH;
  if (hex(data.subarray(DISCRIMINATOR_LENGTH, bodyAt)) !== SWAP_EVENT.discriminator) return null;
  if (data.length !== bodyAt + SWAP_EVENT.bodyLength) return null;
  // The event-authority account is the only account of an event call.
  if (accounts.length !== 1) return null;
  const fields: Record<string, FieldValue> = {};
  for (const f of SWAP_EVENT.fields) {
    const at = bodyAt + f.offset;
    const value = f.type === "publicKey" ? readAddress(data, at) : readU64String(data, at);
    if (value === undefined) return null;
    fields[f.name] = value;
  }
  return { kind: "swap_event", fields };
}

// SwapsEvent: u32 count then that many SwapEventV2 legs. The leg layout is read from the current IDL.
const MAX_LEGS = 32;

function swapsEventLayout() {
  const event = CURRENT.events.find((e) => e.name === "SwapsEvent");
  if (!event) throw new Error("the current Jupiter IDL has no SwapsEvent event");
  const struct = CURRENT.types.find((t) => t.name === "SwapsEvent")?.type.fields ?? [];
  if (
    struct.length !== 1 ||
    JSON.stringify(struct[0].type) !== JSON.stringify({ vec: { defined: { name: "SwapEventV2" } } })
  )
    throw new Error("SwapsEvent is not a single vec of SwapEventV2 in the current Jupiter IDL");
  let offset = 0;
  const legFields = CURRENT.types.find((t) => t.name === "SwapEventV2")?.type.fields ?? [];
  const leg: EventField[] = legFields.map((f) => {
    if (f.type !== "pubkey" && f.type !== "u64")
      throw new Error(
        `SwapEventV2.${f.name} has type ${JSON.stringify(f.type)}, which is not supported`,
      );
    const field: EventField = {
      name: f.name,
      type: f.type === "pubkey" ? "publicKey" : "u64",
      offset,
    };
    offset += f.type === "pubkey" ? 32 : 8;
    return field;
  });
  if (leg.length === 0) throw new Error("the current Jupiter IDL has no SwapEventV2 fields");
  return { discriminator: explicitDiscriminator(event), leg, legLength: offset };
}

const SWAPS_EVENT = swapsEventLayout();

function decodeSwapsEvent(data: Uint8Array, accounts: readonly string[]): DecodedFields | null {
  const countAt = 2 * DISCRIMINATOR_LENGTH;
  if (hex(data.subarray(DISCRIMINATOR_LENGTH, countAt)) !== SWAPS_EVENT.discriminator) return null;
  // The event-authority account is the only account of an event call.
  if (accounts.length !== 1) return null;
  const count = readU32(data, countAt);
  if (count === undefined || count < 1 || count > MAX_LEGS) return null;
  const legsAt = countAt + 4;
  // Exact length: a short body is cut off, a long one holds bytes this decoder does not understand.
  if (data.length !== legsAt + count * SWAPS_EVENT.legLength) return null;
  const fields: Record<string, FieldValue> = { leg_count: count };
  for (let i = 0; i < count; i++) {
    for (const f of SWAPS_EVENT.leg) {
      const at = legsAt + i * SWAPS_EVENT.legLength + f.offset;
      const value = f.type === "publicKey" ? readAddress(data, at) : readU64String(data, at);
      if (value === undefined) return null;
      fields[`leg_${i}_${f.name}`] = value;
    }
  }
  return { kind: "swaps_event", fields };
}

// Frozen: the decoder is shared by every caller, so none may reassign its version or decode.
export const jupiterV6Decoder: Decoder = Object.freeze<Decoder>({
  programId: PROGRAM_IDS.jupiterV6,
  name: "jupiter-v6",
  version: "1.1.0",
  decode(node) {
    const data = node.data;
    if (data.length < DISCRIMINATOR_LENGTH) return null;
    const head = hex(data.subarray(0, DISCRIMINATOR_LENGTH));
    if (head === EVENT_TAG)
      return decodeSwapEvent(data, node.accounts) ?? decodeSwapsEvent(data, node.accounts);
    const ix = INSTRUCTIONS.get(head);
    if (!ix) return null;
    return ix.scalars
      ? decodeRoute(data, ix)
      : { kind: ix.kind, fields: { instruction: ix.instruction } };
  },
});
