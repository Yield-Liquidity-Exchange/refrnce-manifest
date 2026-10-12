// Normaliser: one raw Solana transaction in, classified claims out.
//
// Reading of route_plan_decoded: a route claim always says
// route_plan_decoded false and its amounts are requested/quoted, but there is NO warning merely because the
// route plan is not decoded (it never is). A warning is raised only when a Jupiter node under the swap is
// undecoded, a route has no counted swap event, a swap event is not an inner instruction, or a swap leg side
// matches no decoded transfer. Matching is one-to-one: a decoded transfer satisfies at most one leg side.
// The two swap warnings are RECONCILIATION_WARNING (Derived), formulas swap-completeness@1.0.0 and
// swap-leg-reconciliation@1.0.0. Their inputs list every claim the check looked at (the SWAP_EVENT legs, the
// compared TOKEN_TRANSFER claims, the PROGRAM_INVOKED claims of the Jupiter nodes), so a verifier can re-run
// the check from the inputs alone. Each leg warning carries the ix_path of its event.
//
// Where a claim sits, and how a verifier re-checks it:
//   - ix_path of an OWNER_* claim is the FIRST USE: the first transfer that needed the account. It is not
//     the ix_path of the evidence. The value says where the evidence is:
//       OWNER_FROM_TX_META         evidence "meta.preTokenBalances|meta.postTokenBalances" and account_index
//                                  (the account's index in the resolved key list): re-check against those lists.
//       OWNER_FROM_TX_INSTRUCTION  evidence_ix_path, the InitializeAccount / 2 / 3 that named the owner:
//                                  re-check by searching the WHOLE transaction for that initialise
//                                  instruction on the account, with no undecoded token instruction on the
//                                  account that could have changed its owner.
//   - TX_FEE has ix_path "0" because Observed provenance requires one; it is TRANSACTION scope, not
//     instruction 0. Re-check it against meta.fee and account key 0 (the fee payer).
//
// Numbering: claims are ordered by ix_path (numeric), then code, then, for claims that still tie, by the
// canonical JSON (RFC 8785) of the claim value, compared in code-unit order. That is a total order over the
// claims of one transaction (a tie that even this cannot break throws, it is never guessed), and it does not
// depend on input order, the clock or randomness. IDs are then assigned by assignClaimIds. Claims refer to
// each other (a transfer to its owner claims, a derived claim to its inputs) by draft key while ordering and
// by claim ID afterwards, so the order never depends on the IDs.
//
// Pure apart from the injected owner rpc; isomorphic: no Node-only imports.
import { canonicalizeJcs } from "../manifest/canonical.js";
import { assertClaimAllowed, claimTypeForCode } from "../manifest/claim-rules.js";
import {
  NET_FLOW_FORMULA,
  RECONCILE_FORMULA,
  netFlow,
  reconciliationOutputs,
} from "../manifest/formulas.js";
import {
  ClaimSchema,
  assignClaimIds,
  type Claim,
  type ClaimType,
  type ClaimValue,
  type Provenance,
} from "../manifest/types.js";
import { resolveAccountKeys } from "./account-keys.js";
import {
  decodeTransaction,
  defaultRegistry,
  type DecodedInstruction,
  type DecoderRegistry,
  type DecodeResult,
} from "./decoders/index.js";
import { ENTITY_LABEL_SOURCE, entityLabel } from "./entity-labels.js";
import { buildInstructionTree } from "./instruction-tree.js";
import {
  OWNER_METHOD_CLAIM_CODE,
  resolveOwner,
  type OwnerCache,
  type OwnerResolution,
  type OwnerRpc,
  type OwnerTransaction,
} from "./owner-resolution.js";
import { PROGRAM_IDS, REGISTRY_VERSION } from "./programs.js";
import { reconcile, type ReconcileTransaction } from "./reconcile.js";

// ─── Public types and constants ──────────────────────────────────────────────

/** A raw getTransaction result (encoding json) with the fields the normaliser reads. */
export type NormaliseTransaction = OwnerTransaction &
  ReconcileTransaction & {
    slot: number;
    meta: { fee: number } | null;
  };

export interface NormaliseContext {
  /** Only owner resolution's current-state method uses it, and only when the transaction proves nothing. */
  rpc?: OwnerRpc;
  cache?: OwnerCache;
}

export interface NormaliseOptions {
  /** Defaults to the shared decoder registry. A test can pass its own. */
  registry?: DecoderRegistry;
}

export interface NormalisedTransaction {
  signature: string;
  slot: number;
  claims: Claim[];
}

/** The tool that built claims that no instruction decoder owns (the fee). */
export const NORMALISER_ID = "trace-claims-normaliser@1.0.0";
/** The decoder named on owner claims that come from the transaction itself. */
export const OWNER_RESOLVER_ID = "owner-resolution@1.0.0";
const ATA_FORMULA = "ata-derivation@1.0.0";
const COMPLETENESS_FORMULA = "swap-completeness@1.0.0";
const LEG_FORMULA = "swap-leg-reconciliation@1.0.0";

/** Source of PROGRAM_LABEL claims: the label dictionary ships with the decoder set, so it shares its version. */
export const PROGRAM_LABEL_SOURCE = `trace-program-registry@${REGISTRY_VERSION.slice(REGISTRY_VERSION.indexOf("@") + 1)}`;

/** Shown where an owner or a mint cannot be named. Never null: manifest data holds no nulls. */
export const UNRESOLVED = "unresolved";

// ─── Drafts ──────────────────────────────────────────────────────────────────

type Fields = Record<string, ClaimValue>;

interface ClaimDraft {
  /** Local name, only used until IDs exist. */
  key: string;
  code: string;
  type: ClaimType;
  value: Fields;
  /** value field -> key of the claim it names; replaced by that claim's ID. */
  refs: Record<string, string>;
  /** Derived claims hold draft keys in inputs until the IDs exist. */
  provenance: Provenance;
  /** Canonical JSON of the value: the documented tiebreaker. */
  tie: string;
}

function compareTie(a: ClaimDraft, b: ClaimDraft): number {
  return a.tie < b.tie ? -1 : a.tie > b.tie ? 1 : 0;
}

/** A deep copy that shares nothing with the decoder results, so claims are plain data. */
function plain<T extends ClaimValue>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function textField(r: DecodedInstruction, name: string): string {
  const v = r.fields[name];
  if (typeof v !== "string")
    throw new Error(`decoded ${r.kind} at ${r.ix_path} has no text field "${name}"`);
  return v;
}

function listField(r: DecodedInstruction, name: string): ClaimValue[] {
  const v = r.fields[name];
  return Array.isArray(v) ? plain(v) : [];
}

function decimalsField(r: DecodedInstruction): Fields {
  const d = r.fields.decimals;
  return typeof d === "number" ? { decimals: d } : {};
}

const JUPITER = PROGRAM_IDS.jupiterV6;
const outerOf = (ixPath: string) => ixPath.split(".")[0];

interface SwapLeg {
  amm: string;
  input_mint: string;
  input_amount: string;
  output_mint: string;
  output_amount: string;
}

/** The legs a decoded swap_event (one) or swaps_event (leg_count) reports. */
function legsOf(r: DecodedInstruction): SwapLeg[] {
  const read = (prefix: string): SwapLeg => ({
    amm: textField(r, `${prefix}amm`),
    input_mint: textField(r, `${prefix}input_mint`),
    input_amount: textField(r, `${prefix}input_amount`),
    output_mint: textField(r, `${prefix}output_mint`),
    output_amount: textField(r, `${prefix}output_amount`),
  });
  if (r.kind === "swap_event") return [read("")];
  const count = r.fields.leg_count;
  if (typeof count !== "number" || !Number.isSafeInteger(count) || count < 1)
    throw new Error(`decoded swaps_event at ${r.ix_path} has no leg_count`);
  return Array.from({ length: count }, (_, i) => read(`leg_${i}_`));
}

const isSwapEvent = (r: DecodeResult): r is DecodedInstruction =>
  r.decode_status === "decoded" &&
  r.program_id === JUPITER &&
  (r.kind === "swap_event" || r.kind === "swaps_event");

// ─── The normaliser ──────────────────────────────────────────────────────────

/**
 * Transaction in, claims out. Throws on a transaction that cannot be read (no meta, no signature, no slot,
 * a fee that is not a safe integer, an instruction that points outside the account list): a half-built
 * claim list is never returned. Instruction-level problems are not errors: they come back as claims that
 * keep the raw bytes.
 */
export async function normaliseSolanaTransaction(
  tx: NormaliseTransaction,
  ctx: NormaliseContext = {},
  options: NormaliseOptions = {},
): Promise<NormalisedTransaction> {
  const keys = resolveAccountKeys(tx); // throws without meta
  const signature = tx.transaction.signatures?.[0];
  if (typeof signature !== "string" || signature.length === 0)
    throw new Error("transaction has no signature");
  const slot = tx.slot;
  if (!Number.isSafeInteger(slot) || slot < 0) throw new Error("transaction has no valid slot");
  const fee = tx.meta?.fee;
  if (typeof fee !== "number" || !Number.isSafeInteger(fee) || fee < 0)
    throw new Error("transaction fee is not a non-negative safe integer");
  const failed = tx.meta?.err !== null && tx.meta?.err !== undefined;

  const tree = buildInstructionTree(tx);
  const decoded = decodeTransaction(tree, {}, options.registry ?? defaultRegistry);

  const drafts: ClaimDraft[] = [];
  let counter = 0;
  const add = (
    code: string,
    value: Fields,
    provenance: Provenance,
    refs: Record<string, string> = {},
    key: string = `k${counter++}`,
  ): string => {
    const type = claimTypeForCode(code);
    if (type === undefined) throw new Error(`claim code ${code} is not in the claim rules`);
    drafts.push({ key, code, type, value, refs, provenance, tie: canonicalizeJcs(value) });
    return key;
  };
  const observed = (ix_path: string, decoder: string): Provenance => ({
    type: "observed",
    signature,
    slot,
    ix_path,
    decoder,
  });

  // Mints of token accounts: from the transaction's token balances and from decoded instructions that name
  // a mint beside an account. A plain SPL transfer carries no mint of its own.
  const mints = new Map<string, Set<string>>();
  const noteMint = (account: unknown, mint: unknown) => {
    if (typeof account !== "string" || typeof mint !== "string") return;
    const set = mints.get(account) ?? new Set<string>();
    set.add(mint);
    mints.set(account, set);
  };
  for (const list of [tx.meta?.preTokenBalances, tx.meta?.postTokenBalances])
    for (const b of Array.isArray(list) ? list : [])
      if (b && Number.isInteger(b.accountIndex)) noteMint(keys[b.accountIndex], b.mint);
  for (const r of decoded)
    if (r.decode_status === "decoded" && r.kind.startsWith("token_"))
      for (const role of ["account", "source", "destination"])
        noteMint(r.fields[role], r.fields.mint);
  /** The one mint the transaction names for the account, or undefined when it names none or several. */
  const mintOf = (account: string): string | undefined => {
    const set = mints.get(account);
    return set && set.size === 1 ? [...set][0] : undefined;
  };

  // Owner resolution, once per token account, in the order the accounts first appear.
  const owners = new Map<string, OwnerResolution>();
  const ownerUse = new Map<string, { ix: string; transferKeys: string[] }>();
  const ownerOf = async (account: string): Promise<OwnerResolution> => {
    let found = owners.get(account);
    if (!found) {
      found = await resolveOwner(account, {
        tx,
        decoded,
        ...(ctx.rpc ? { rpc: ctx.rpc } : {}),
        ...(ctx.cache ? { cache: ctx.cache } : {}),
      });
      owners.set(account, found);
    }
    return found;
  };

  const invokedKey = new Map<string, string>(); // ix_path -> PROGRAM_INVOKED draft key
  const legs: { outer: string; ix: string; index: number; leg: SwapLeg; key: string }[] = [];
  const transfers: { outer: string; mint: string | undefined; amount: string; key: string }[] = [];
  const labelled = new Set<string>();

  for (const r of decoded) {
    const ix = r.ix_path;

    if (r.program !== undefined && !labelled.has(r.program_id)) {
      labelled.add(r.program_id);
      add(
        "PROGRAM_LABEL",
        { program_id: r.program_id, label: r.program },
        { type: "attributed", source: PROGRAM_LABEL_SOURCE, source_ref: r.program_id },
      );
    }

    if (r.decode_status !== "decoded") {
      invokedKey.set(
        ix,
        add(
          "PROGRAM_INVOKED",
          {
            program_id: r.program_id,
            ...(r.program !== undefined ? { program: r.program } : {}),
            decode_status: r.decode_status,
            data: r.data,
            accounts: [...r.accounts],
            ...(r.decoder !== undefined ? { decoder_tried: r.decoder } : {}),
            ...(r.error !== undefined ? { error: r.error } : {}),
            failed: r.failed,
          },
          observed(ix, r.decoder ?? REGISTRY_VERSION),
        ),
      );
      continue;
    }

    const prov = observed(ix, r.decoder);
    switch (r.kind) {
      case "system_transfer":
      case "system_create_account":
      case "system_transfer_with_seed": {
        const value: Fields = {
          instruction: r.kind.slice("system_".length),
          from: textField(r, "from"),
          to: textField(r, "to"),
          lamports: textField(r, "lamports"),
          failed: r.failed,
        };
        if (r.kind === "system_create_account") {
          value.space = textField(r, "space");
          value.assigned_program = textField(r, "owner");
        }
        if (r.kind === "system_transfer_with_seed") {
          value.base = textField(r, "base");
          value.seed = textField(r, "seed");
        }
        add("SOL_TRANSFER", value, prov);
        break;
      }
      case "token_transfer":
      case "token_transfer_checked": {
        const source = textField(r, "source");
        const destination = textField(r, "destination");
        const amount = textField(r, "amount");
        const mint =
          typeof r.fields.mint === "string"
            ? r.fields.mint
            : (mintOf(source) ?? mintOf(destination));
        const key = `t:${ix}`;
        const value: Fields = {
          instruction: r.kind.slice("token_".length),
          token_program: r.program_id,
          source,
          destination,
          authority: textField(r, "authority"),
          amount,
          mint: mint ?? UNRESOLVED,
          ...(mint === undefined
            ? { mint_reason: "the transaction names no single mint for the account" }
            : {}),
          ...decimalsField(r),
          extra_accounts: listField(r, "extra_accounts"),
          failed: r.failed,
        };
        const refs: Record<string, string> = {};
        for (const [side, account] of [
          ["from", source],
          ["to", destination],
        ] as const) {
          // Owners are not resolved for a failed instruction: it moved nothing.
          const res: OwnerResolution = r.failed
            ? {
                owner: null,
                method: "unresolved",
                reason: "the instruction failed, so no owner was resolved",
              }
            : await ownerOf(account);
          value[`${side}_owner`] = res.owner ?? UNRESOLVED;
          value[`${side}_owner_method`] = res.method;
          if (res.owner !== null && res.method !== "unresolved") {
            refs[`${side}_owner_claim`] = `own:${account}`;
            const use = ownerUse.get(account) ?? { ix, transferKeys: [] };
            use.transferKeys.push(key);
            ownerUse.set(account, use);
          } else value[`${side}_owner_reason`] = res.reason ?? "no reason given";
        }
        add("TOKEN_TRANSFER", value, prov, refs, key);
        if (!r.failed) transfers.push({ outer: outerOf(ix), mint, amount, key });
        break;
      }
      case "token_mint_to":
      case "token_mint_to_checked":
        add(
          "TOKEN_MINT",
          {
            instruction: r.kind.slice("token_".length),
            token_program: r.program_id,
            mint: textField(r, "mint"),
            destination: textField(r, "destination"),
            authority: textField(r, "authority"),
            amount: textField(r, "amount"),
            ...decimalsField(r),
            extra_accounts: listField(r, "extra_accounts"),
            failed: r.failed,
          },
          prov,
        );
        break;
      case "token_burn":
      case "token_burn_checked":
        add(
          "TOKEN_BURN",
          {
            instruction: r.kind.slice("token_".length),
            token_program: r.program_id,
            account: textField(r, "account"),
            mint: textField(r, "mint"),
            authority: textField(r, "authority"),
            amount: textField(r, "amount"),
            ...decimalsField(r),
            extra_accounts: listField(r, "extra_accounts"),
            failed: r.failed,
          },
          prov,
        );
        break;
      case "token_close_account":
        // No owner of any kind: a close authority is not proof of who owns the account.
        add(
          "ACCOUNT_CLOSED",
          {
            token_program: r.program_id,
            account: textField(r, "account"),
            destination: textField(r, "destination"),
            authority: textField(r, "authority"),
            extra_accounts: listField(r, "extra_accounts"),
            failed: r.failed,
          },
          prov,
        );
        break;
      default: {
        const swapEvent = isSwapEvent(r);
        if (swapEvent && ix.includes(".") && !r.failed) {
          legsOf(r).forEach((leg, index) => {
            const key = add(
              "SWAP_EVENT",
              {
                ...leg,
                event: r.kind,
                leg_index: index,
                statement: `Jupiter reported input ${leg.input_amount} of ${leg.input_mint} and output ${leg.output_amount} of ${leg.output_mint} through ${leg.amm}`,
                failed: false,
              },
              prov,
            );
            legs.push({ outer: outerOf(ix), ix, index, leg, key });
          });
          break;
        }
        const value: Fields = {
          program_id: r.program_id,
          ...(r.program !== undefined ? { program: r.program } : {}),
          decode_status: "decoded",
          kind: r.kind,
          fields: plain(r.fields),
          failed: r.failed,
        };
        if (r.kind === "route") {
          // A route node is never a complete route plan, and its amounts are what was asked for and quoted.
          (value.fields as Fields).route_plan_decoded = false;
          if ("in_amount" in r.fields || "quoted_out_amount" in r.fields)
            value.amounts_note =
              "in_amount and quoted_out_amount are the requested and quoted amounts, not executed amounts";
        }
        if (swapEvent) {
          value.counted = false;
          value.not_counted_reason = r.failed
            ? "the transaction failed, so the event did not take effect"
            : "not an inner instruction, so it is not a swap event emitted by a swap";
        }
        invokedKey.set(ix, add("PROGRAM_INVOKED", value, prov));
      }
    }
  }

  add(
    "TX_FEE",
    { lamports: String(BigInt(fee)), fee_payer: keys[0] ?? UNRESOLVED, failed },
    observed("0", NORMALISER_ID),
  );

  // Entity labels: a registered address that takes part in the transaction, as a key or as a
  // resolved owner, gets one Attributed ENTITY_LABEL naming it. Never Observed: the name is Refrnce's own.
  const labelledAddresses = new Set<string>();
  for (const address of [...keys, ...[...owners.values()].map((o) => o.owner ?? "")]) {
    const name = entityLabel(address);
    if (name === undefined || labelledAddresses.has(address)) continue;
    labelledAddresses.add(address);
    add(
      "ENTITY_LABEL",
      { address, label: name },
      { type: "attributed", source: ENTITY_LABEL_SOURCE, source_ref: address },
    );
  }

  // Owner claims, one per resolved token account, placed at the first instruction that needed it.
  for (const [account, use] of ownerUse) {
    const res = owners.get(account);
    if (!res || res.owner === null || res.method === "unresolved") continue;
    const value: Fields = { account, owner: res.owner, method: res.method };
    let provenance: Provenance;
    if (res.method === "tx_meta") {
      value.evidence = "meta.preTokenBalances|meta.postTokenBalances";
      value.account_index = keys.indexOf(account);
    } else if (res.method === "tx_instruction") {
      // The initialise instruction that named this owner: the first one, in tree order, for this account.
      const init = decoded.find(
        (d) =>
          d.decode_status === "decoded" &&
          !d.failed &&
          d.kind.startsWith("token_initialize_account") &&
          d.fields.account === account &&
          d.fields.owner === res.owner,
      );
      if (!init)
        throw new Error("internal error: no initialise instruction for a tx_instruction owner");
      value.evidence_ix_path = init.ix_path;
    }
    if (res.method === "ata_derivation") {
      provenance = { type: "derived", formula: ATA_FORMULA, inputs: use.transferKeys };
    } else if (res.method === "current_state") {
      if (typeof res.slot !== "number") throw new Error("current-state owner without a slot");
      value.slot = res.slot;
      value.caveat = res.caveat ?? "current state, not state at transaction slot";
      provenance = {
        type: "attributed",
        source: `RPC state at slot ${res.slot}`,
        source_ref: "getAccountInfo",
      };
    } else provenance = observed(use.ix, OWNER_RESOLVER_ID);
    add(OWNER_METHOD_CLAIM_CODE[res.method], value, provenance, {}, `own:${account}`);
  }

  // Net flows and balance reconciliation, over the observed claims built so far. They name
  // claims by draft key, replaced by claim IDs below like every other reference. Reconciliation runs for a
  // failed transaction too: failed claims count on neither side, so only the fee is compared.
  const evidence = drafts
    .filter((d) => d.type === "observed")
    // refs name the owner claims (by draft key) a transfer's owners came from; net_flow@1 lists them as inputs.
    .map((d) => ({
      id: d.key,
      code: d.code,
      value: { ...d.value, ...d.refs },
      provenance: d.provenance,
    }));
  for (const out of netFlow(evidence))
    add(out.code, out.value, { type: "derived", formula: NET_FLOW_FORMULA, inputs: out.inputs });
  for (const out of reconciliationOutputs(reconcile(evidence, tx)))
    add(out.code, out.value, { type: "derived", formula: RECONCILE_FORMULA, inputs: out.inputs });

  // Swap completeness and leg reconciliation. Not for a failed transaction: nothing took effect.
  if (!failed) {
    const warn = (formula: string, value: Fields, inputs: string[]) =>
      add("RECONCILIATION_WARNING", value, { type: "derived", formula, inputs });
    const invoked = (ix: string): string => {
      const key = invokedKey.get(ix);
      if (key === undefined) throw new Error(`internal error: no PROGRAM_INVOKED claim at ${ix}`);
      return key;
    };

    const ids = (list: { key: string }[]) => list.map((x) => x.key);
    const groups = new Map<string, DecodeResult[]>();
    for (const r of decoded)
      if (r.program_id === JUPITER) {
        const outer = outerOf(r.ix_path);
        groups.set(outer, [...(groups.get(outer) ?? []), r]);
      }

    for (const [outer, nodes] of groups) {
      const undecoded = nodes.filter((n) => n.decode_status !== "decoded");
      if (undecoded.length > 0) {
        warn(
          COMPLETENESS_FORMULA,
          {
            swap_ix_path: outer,
            undecoded_ix_paths: undecoded.map((n) => n.ix_path),
            reason: `swap incomplete: ${undecoded.length} Jupiter instruction(s) under instruction ${outer} could not be decoded, so any decoded swap legs are not the whole swap`,
          },
          undecoded.map((n) => invoked(n.ix_path)),
        );
        continue;
      }
      for (const n of nodes)
        if (isSwapEvent(n) && !n.ix_path.includes("."))
          warn(
            COMPLETENESS_FORMULA,
            {
              swap_ix_path: outer,
              reason: `swap event at ${n.ix_path} is not an inner instruction and is not counted`,
            },
            [invoked(n.ix_path)],
          );
      const mine = legs.filter((l) => l.outer === outer);
      if (mine.length === 0) {
        const route = nodes.find((n) => n.decode_status === "decoded" && n.kind === "route");
        if (route)
          warn(
            COMPLETENESS_FORMULA,
            {
              swap_ix_path: outer,
              reason:
                "no swap event reported for this route: the route plan is not decoded, so the legs of the swap are unknown",
            },
            // everything the check looked at: the route and every other Jupiter node under the instruction
            nodes.map((n) => invoked(n.ix_path)),
          );
        continue;
      }
      // One-to-one: a decoded transfer satisfies at most one leg side, so a missing intermediate transfer
      // of a multi-leg swap is reported. Legs are taken in tree order, input before output.
      const here = transfers.filter((t) => t.outer === outer).map((t) => ({ ...t, used: false }));
      // The inputs of a leg warning are everything the check looked at, so it can be re-run from them.
      const looked = [...ids(mine), ...ids(here)];
      for (const { ix, leg, index } of mine)
        for (const side of ["input", "output"] as const) {
          const mint = side === "input" ? leg.input_mint : leg.output_mint;
          const amount = side === "input" ? leg.input_amount : leg.output_amount;
          const hit = here.find(
            (t) => !t.used && t.mint === mint && BigInt(t.amount) === BigInt(amount),
          );
          if (hit) hit.used = true;
          else
            warn(
              LEG_FORMULA,
              {
                swap_ix_path: outer,
                event_ix_path: ix,
                leg_index: index,
                side,
                reason: `no decoded token transfer under instruction ${outer} matches the ${side} of swap leg ${index} of the event at ${ix} (same mint and amount, each transfer used once)`,
              },
              looked,
            );
        }
    }
  }

  // Number, rewrite references to IDs, check every claim.
  const numbered = assignClaimIds(drafts, compareTie);
  const idOf = new Map(numbered.map((d) => [d.key, d.id]));
  const idFor = (key: string): string => {
    const id = idOf.get(key);
    if (id === undefined) throw new Error(`internal error: claim reference ${key} has no claim`);
    return id;
  };
  const claims = numbered.map((d): Claim => {
    const value: Fields = { ...d.value };
    for (const [field, key] of Object.entries(d.refs)) value[field] = idFor(key);
    const provenance: Provenance =
      d.provenance.type === "derived"
        ? { ...d.provenance, inputs: [...new Set(d.provenance.inputs.map(idFor))].sort() }
        : d.provenance;
    const claim: Claim = { id: d.id, type: d.type, code: d.code, value, provenance };
    assertClaimAllowed(claim);
    return ClaimSchema.parse(claim);
  });
  return { signature, slot, claims };
}
