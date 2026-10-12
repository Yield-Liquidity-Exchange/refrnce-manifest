// src/manifest/verify/rpc-sources.ts — which RPC endpoint answered the reads of ONE verification,
// for the page's "RPC endpoint used" line. verifyEnvelope wraps the injected rpc with recordRpcSources: when the
// rpc reports its sources (createResilientRpc's getTransactionWithSource), every answer it gives (a transaction,
// or "not found") is counted against its endpoint; otherwise the rpc is used as it is and nothing is recorded.
//
// What reaches the result is a clean host and two flags, checked here: never a URL, a path or a query (they may
// hold a provider key), never text the rpc chose. A source that is not clean is left out, except that an answer
// from a user-supplied endpoint always keeps its row and its flag (shown as "user-supplied endpoint" when its host
// cannot be shown), so the page can always warn that the user chose the source. An answer that is
// not { tx, source } is an invalid answer (RpcProtocolError, so unavailable), never a pass. Recording is per call
// of recordRpcSources, so a client shared across verifications (and its session cache) cannot mix their reports.
import {
  RpcNotFoundError,
  RpcProtocolError,
  isCleanHost,
  type RpcSource,
  type RpcTransaction,
  type SolanaRpc,
} from "../../solana/rpc.js";

/** One endpoint that answered during a verification. */
export interface RpcEndpointUse {
  hostname: string;
  /** The user pasted this endpoint: the page warns that the user chose the source. */
  user_supplied: boolean;
  /** Answers it gave (transactions and "not found"). */
  answers: number;
  /** How many of those came from the session cache (first fetched from this endpoint). */
  cached_answers: number;
}

/** What the row shows when a user-supplied endpoint answered but its hostname cannot be shown.  */
export const UNSHOWN_USER_ENDPOINT = "user-supplied endpoint";

/**
 * The source as the result may carry it. A clean host (isCleanHost: DNS name or IP literal, optional port) and two
 * booleans pass as they are. An answer from a user-supplied endpoint is never dropped, so the page can always warn
 * that the user chose the source: when its host is not clean it is shown as UNSHOWN_USER_ENDPOINT. Any other
 * source that is not clean is left out.
 */
function cleanSource(source: unknown): RpcSource | undefined {
  try {
    if (typeof source !== "object" || source === null) return undefined;
    const { hostname, user_supplied, from_cache } = source as Record<string, unknown>;
    if (user_supplied === true)
      return {
        hostname: isCleanHost(hostname) ? (hostname as string) : UNSHOWN_USER_ENDPOINT,
        user_supplied: true,
        from_cache: from_cache === true,
      };
    if (!isCleanHost(hostname)) return undefined;
    if (user_supplied !== false || typeof from_cache !== "boolean") return undefined;
    return { hostname: hostname as string, user_supplied: false, from_cache };
  } catch {
    return undefined;
  }
}

type GetTransaction = Pick<SolanaRpc, "getTransaction">;

export interface RecordedRpc<R> {
  /** The rpc to read through: a recording wrapper, or `rpc` itself when it reports no sources. */
  rpc: R | GetTransaction;
  /** True when `rpc` reports its sources, so the result can carry rpc_endpoints. */
  active: boolean;
  /** The endpoints that answered so far, in order of first answer. */
  used(): RpcEndpointUse[];
}

/** Wraps `rpc` to record its sources. Never throws. */
export function recordRpcSources<R>(rpc: R): RecordedRpc<R> {
  const uses = new Map<string, RpcEndpointUse>();
  const used = () => [...uses.values()].map((u) => ({ ...u }));
  let withSource: unknown;
  try {
    withSource = (rpc as { getTransactionWithSource?: unknown } | undefined)
      ?.getTransactionWithSource;
  } catch {
    withSource = undefined;
  }
  if (typeof withSource !== "function") return { rpc, active: false, used };
  const fn = withSource as (signature: string) => Promise<unknown>;

  const record = (raw: unknown) => {
    const source = cleanSource(raw);
    if (!source) return;
    const key = `${source.hostname} ${source.user_supplied}`;
    const use = uses.get(key) ?? {
      hostname: source.hostname,
      user_supplied: source.user_supplied,
      answers: 0,
      cached_answers: 0,
    };
    use.answers += 1;
    if (source.from_cache) use.cached_answers += 1;
    uses.set(key, use);
  };

  const wrapped: GetTransaction = {
    async getTransaction(signature: string): Promise<RpcTransaction> {
      let answer: unknown;
      try {
        answer = await fn.call(rpc, signature);
      } catch (e) {
        if (e instanceof RpcNotFoundError) record(e.source);
        throw e;
      }
      let tx: unknown;
      let source: unknown;
      try {
        if (typeof answer !== "object" || answer === null) throw new Error("not an object");
        const txDesc = Object.getOwnPropertyDescriptor(answer, "tx");
        const sourceDesc = Object.getOwnPropertyDescriptor(answer, "source");
        if (!txDesc || !("value" in txDesc)) throw new Error("no tx");
        tx = txDesc.value;
        source = sourceDesc && "value" in sourceDesc ? sourceDesc.value : undefined;
      } catch {
        throw new RpcProtocolError("bad_result");
      }
      record(source);
      // The transaction is checked by the caller (parseTransactionResult), as for any injected rpc.
      return tx as RpcTransaction;
    },
  };
  return { rpc: wrapped, active: true, used };
}
