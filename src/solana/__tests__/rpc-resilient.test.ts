import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_RESILIENT_TIMEOUT_MS,
  DEFAULT_RETRY_BACKOFF_MS,
  RPC_ENDPOINTS,
  RpcError,
  RpcHttpError,
  RpcNetworkError,
  RpcNotFoundError,
  RpcProtocolError,
  RpcTimeoutError,
  RpcUnconfirmedNotFoundError,
  checkUserEndpoint,
  createResilientRpc,
  createTransactionCache,
  defaultRpcEndpoints,
  type ResilientRpcOptions,
} from "../rpc.js";

// Markers planted in URLs and upstream text: none may ever appear in an error, a source or a result.
const KEY_MARKER = "secret-key-marker-123";
const UPSTREAM_TEXT = "upstream-said-something-hostile";

const E1 = `https://one.example.test/v2/${KEY_MARKER}`;
const E2 = `https://two.example.test/rpc?api-key=${KEY_MARKER}`;
const E3 = "https://three.example.test/";

const SIG = "5".repeat(88);
const SIG_B = "6".repeat(88);
const SIG_C = "7".repeat(88);
const ADDRESS = "7".repeat(44);

function txResult(signature = SIG, meta: unknown = { err: null, fee: 5000 }) {
  return {
    slot: 1234,
    blockTime: 1791345000,
    transaction: {
      signatures: [signature],
      message: {
        header: {
          numRequiredSignatures: 1,
          numReadonlySignedAccounts: 0,
          numReadonlyUnsignedAccounts: 1,
        },
        accountKeys: [ADDRESS, "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"],
        instructions: [{ programIdIndex: 1, accounts: [0], data: "2" }],
      },
    },
    meta,
  };
}

type Reply =
  | { kind: "result"; result: unknown }
  | { kind: "status"; status: number }
  | { kind: "rpc_error" }
  | { kind: "throw" }
  | { kind: "hang" };

const ok = (result: unknown = undefined): Reply => ({ kind: "result", result });
const http = (status: number): Reply => ({ kind: "status", status });

/**
 * A fetch whose answers are scripted per endpoint host: each host has a queue of replies (the last one repeats).
 * A result of undefined means "the transaction asked for".
 */
function scriptedFetch(script: Record<string, Reply[]>) {
  const calls: string[] = [];
  const fetch = vi.fn(async (input: string, init: RequestInit) => {
    const host = new URL(input).hostname;
    calls.push(host);
    const queue = script[host];
    if (!queue) throw new TypeError(`no script for ${host}`);
    const reply = queue.length > 1 ? queue.shift()! : queue[0];
    const req = JSON.parse(String(init.body)) as { id: number; params: unknown[] };
    switch (reply.kind) {
      case "status":
        return new Response(UPSTREAM_TEXT, { status: reply.status });
      case "rpc_error":
        return Response.json({
          jsonrpc: "2.0",
          id: req.id,
          error: { code: -32005, message: UPSTREAM_TEXT },
        });
      case "throw":
        // What a browser gives for CORS, DNS or offline: a bare TypeError, here carrying hostile text.
        throw new TypeError(`Failed to fetch ${UPSTREAM_TEXT} ${input}`);
      case "hang":
        return new Promise<Response>(() => {});
      case "result": {
        const result =
          reply.result === undefined ? txResult(req.params[0] as string) : reply.result;
        return Response.json({ jsonrpc: "2.0", id: req.id, result });
      }
    }
  });
  return { fetch, calls };
}

function client(
  fetch: ResilientRpcOptions["fetch"],
  over: Partial<ResilientRpcOptions> = {},
): {
  rpc: ReturnType<typeof createResilientRpc>;
  sleep: ReturnType<typeof vi.fn>;
} {
  const sleep = vi.fn(async (_ms: number) => {});
  const rpc = createResilientRpc({
    cluster: "mainnet-beta",
    endpoints: [E1, E2],
    fetch,
    sleep,
    jitter: false,
    ...over,
  });
  return { rpc, sleep };
}

async function caught(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  throw new Error("expected a rejection");
}

function expectNoSecrets(value: unknown) {
  const text =
    value instanceof Error
      ? `${value.message} ${String(value)} ${JSON.stringify(value)} ${JSON.stringify(Object.entries(value))}`
      : JSON.stringify(value);
  expect(text).not.toContain(KEY_MARKER);
  expect(text).not.toContain(UPSTREAM_TEXT);
  expect(text).not.toContain("/v2/");
  expect(text).not.toContain("api-key");
}

// ─── Configuration ───────────────────────────────────────────────────────────

describe("endpoint configuration", () => {
  it("without a web origin (Node, a file: page) the public endpoint is the only one", () => {
    expect(defaultRpcEndpoints("mainnet-beta")).toEqual(["https://api.mainnet-beta.solana.com"]);
    expect(defaultRpcEndpoints("mainnet-beta", "null")).toEqual([
      "https://api.mainnet-beta.solana.com",
    ]);
  });

  it("the per-request timeout is 8 seconds and the retry backoff half a second", () => {
    expect(DEFAULT_RESILIENT_TIMEOUT_MS).toBe(8_000);
    expect(DEFAULT_RETRY_BACKOFF_MS).toBe(500);
  });

  it("refuses an empty list and an unknown cluster with fixed text", () => {
    expect(() => createResilientRpc({ cluster: "mainnet-beta", endpoints: [] })).toThrow(
      /at least one/,
    );
    expect(() => createResilientRpc({ cluster: "localnet" as never, endpoints: [E1] })).toThrow(
      /cluster/,
    );
  });

  it("refuses a bad endpoint without echoing it", () => {
    let e: unknown;
    try {
      createResilientRpc({ cluster: "mainnet-beta", endpoints: [`ftp://${KEY_MARKER}/`] });
    } catch (err) {
      e = err;
    }
    expect(e).toBeInstanceOf(TypeError);
    expectNoSecrets(e);
  });

  it("clamps a huge timeout and refuses a non-positive one", () => {
    expect(() =>
      createResilientRpc({ cluster: "devnet", endpoints: [E1], timeoutMs: 0 }),
    ).toThrow();
    expect(() =>
      createResilientRpc({ cluster: "devnet", endpoints: [E1], timeoutMs: 1e12 }),
    ).not.toThrow();
  });
});

describe("user-supplied endpoint", () => {
  it("takes first position and is flagged user_supplied in the result", async () => {
    const { fetch, calls } = scriptedFetch({
      "mine.example.test": [ok()],
      "one.example.test": [ok()],
    });
    const { rpc } = client(fetch, { userEndpoint: `https://mine.example.test/${KEY_MARKER}` });
    const { source } = await rpc.getTransactionWithSource(SIG);
    expect(calls).toEqual(["mine.example.test"]);
    expect(source).toEqual({
      hostname: "mine.example.test",
      user_supplied: true,
      from_cache: false,
    });
    expectNoSecrets(source);
  });

  it("a configured endpoint that answers is not flagged user_supplied", async () => {
    const { fetch } = scriptedFetch({
      "mine.example.test": [{ kind: "throw" }],
      "one.example.test": [ok()],
    });
    const { rpc } = client(fetch, { userEndpoint: "https://mine.example.test/" });
    const { source } = await rpc.getTransactionWithSource(SIG);
    expect(source).toEqual({
      hostname: "one.example.test",
      user_supplied: false,
      from_cache: false,
    });
  });

  it.each([
    ["http (not https)", `http://mine.example.test/${KEY_MARKER}`],
    ["credentials in the URL", `https://user:${KEY_MARKER}@mine.example.test/`],
    ["not a URL", `not a url ${KEY_MARKER}`],
    ["javascript:", `javascript:alert('${KEY_MARKER}')`],
    ["a relative path", `/${KEY_MARKER}`],
    ["too long", `https://mine.example.test/${KEY_MARKER}${"a".repeat(3000)}`],
    ["not a string", 42],
  ])("refuses %s with fixed text that does not echo it", (_name, url) => {
    let e: unknown;
    try {
      checkUserEndpoint(url);
    } catch (err) {
      e = err;
    }
    expect(e).toBeInstanceOf(TypeError);
    expect((e as Error).message).toBe("the RPC endpoint must be an https URL");
    expectNoSecrets(e);
    expect(() =>
      createResilientRpc({ cluster: "mainnet-beta", endpoints: [E1], userEndpoint: url as string }),
    ).toThrow("the RPC endpoint must be an https URL");
  });

  it("accepts an https URL with a key in its path or query (the user's own) and reports only the host", async () => {
    expect(checkUserEndpoint(`https://Mine.Example.Test/${KEY_MARKER}?k=1`)).toBe(
      `https://mine.example.test/${KEY_MARKER}?k=1`,
    );
  });
});

// ─── Retry and fall-through ──────────────────────────────────────────────────

describe("429: one retry with backoff, then the next endpoint", () => {
  it("429 then success: the same endpoint answers after one backoff", async () => {
    const { fetch, calls } = scriptedFetch({ "one.example.test": [http(429), ok()] });
    const { rpc, sleep } = client(fetch);
    const { tx, source } = await rpc.getTransactionWithSource(SIG);
    expect(tx.transaction.signatures[0]).toBe(SIG);
    expect(calls).toEqual(["one.example.test", "one.example.test"]);
    expect(sleep).toHaveBeenCalledTimes(1);
    expect(sleep).toHaveBeenCalledWith(DEFAULT_RETRY_BACKOFF_MS);
    expect(source.hostname).toBe("one.example.test");
  });

  it("429 twice from the first endpoint falls through to the second (Definition of Done)", async () => {
    const { fetch, calls } = scriptedFetch({
      "one.example.test": [http(429)],
      "two.example.test": [ok()],
    });
    const { rpc, sleep } = client(fetch);
    const { source } = await rpc.getTransactionWithSource(SIG);
    expect(calls).toEqual(["one.example.test", "one.example.test", "two.example.test"]);
    expect(sleep).toHaveBeenCalledTimes(1);
    expect(source).toEqual({
      hostname: "two.example.test",
      user_supplied: false,
      from_cache: false,
    });
  });

  it("retries exactly once: a third 429 from the same endpoint is never asked for", async () => {
    const { fetch, calls } = scriptedFetch({
      "one.example.test": [http(429)],
      "two.example.test": [http(429)],
    });
    const { rpc } = client(fetch);
    const e = await caught(rpc.getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcHttpError);
    expect(calls).toEqual([
      "one.example.test",
      "one.example.test",
      "two.example.test",
      "two.example.test",
    ]);
  });

  it("jitter adds at most half the backoff and never shortens it", async () => {
    const waits: number[] = [];
    for (let i = 0; i < 20; i++) {
      const { fetch } = scriptedFetch({ "one.example.test": [http(429), ok()] });
      const sleep = vi.fn(async (ms: number) => {
        waits.push(ms);
      });
      await createResilientRpc({
        cluster: "mainnet-beta",
        endpoints: [E1],
        fetch,
        sleep,
      }).getTransaction(SIG);
    }
    for (const w of waits) {
      expect(w).toBeGreaterThanOrEqual(DEFAULT_RETRY_BACKOFF_MS);
      expect(w).toBeLessThan(DEFAULT_RETRY_BACKOFF_MS * 1.5);
    }
  });
});

describe("network errors (offline, DNS, CORS): one retry, then the next endpoint", () => {
  it("a CORS-style TypeError once, then success: retried on the same endpoint", async () => {
    const { fetch, calls } = scriptedFetch({ "one.example.test": [{ kind: "throw" }, ok()] });
    const { rpc } = client(fetch);
    const { source } = await rpc.getTransactionWithSource(SIG);
    expect(calls).toEqual(["one.example.test", "one.example.test"]);
    expect(source.hostname).toBe("one.example.test");
  });

  it("a CORS failure on every try falls through to the second endpoint", async () => {
    const { fetch, calls } = scriptedFetch({
      "one.example.test": [{ kind: "throw" }],
      "two.example.test": [ok()],
    });
    const { rpc } = client(fetch);
    const { source } = await rpc.getTransactionWithSource(SIG);
    expect(calls).toEqual(["one.example.test", "one.example.test", "two.example.test"]);
    expect(source.hostname).toBe("two.example.test");
  });
});

describe("the single-endpoint guarantees hold under the endpoint list", () => {
  it("every request asks fetch to refuse redirects, and a 3xx is never followed: the next endpoint answers", async () => {
    const seen: RequestInit[] = [];
    const fetch = vi.fn(async (input: string, init: RequestInit) => {
      seen.push(init);
      const { id } = JSON.parse(String(init.body)) as { id: number };
      if (new URL(input).hostname === "one.example.test")
        return new Response(null, { status: 302, headers: { location: "https://evil.test/" } });
      return Response.json({ jsonrpc: "2.0", id, result: txResult() });
    });
    const { rpc } = client(fetch);
    const { source } = await rpc.getTransactionWithSource(SIG);
    expect(source.hostname).toBe("two.example.test");
    expect(seen.every((i) => i.redirect === "error")).toBe(true);
    expect(fetch.mock.calls.map((c) => new URL(c[0]).hostname)).not.toContain("evil.test");
  });
});

describe("other failures fall through without a retry", () => {
  it("a timeout is not retried (8 s already spent): the next endpoint is asked", async () => {
    const { fetch, calls } = scriptedFetch({
      "one.example.test": [{ kind: "hang" }],
      "two.example.test": [ok()],
    });
    const { rpc, sleep } = client(fetch, { timeoutMs: 20 });
    const { source } = await rpc.getTransactionWithSource(SIG);
    expect(calls).toEqual(["one.example.test", "two.example.test"]);
    expect(sleep).not.toHaveBeenCalled();
    expect(source.hostname).toBe("two.example.test");
  });

  it.each([500, 502, 503, 403])(
    "HTTP %i is not retried: the next endpoint is asked",
    async (status) => {
      const { fetch, calls } = scriptedFetch({
        "one.example.test": [http(status)],
        "two.example.test": [ok()],
      });
      const { rpc } = client(fetch);
      await rpc.getTransaction(SIG);
      expect(calls).toEqual(["one.example.test", "two.example.test"]);
    },
  );

  it("a JSON-RPC error body is a failure of that endpoint, never an answer", async () => {
    const { fetch, calls } = scriptedFetch({
      "one.example.test": [{ kind: "rpc_error" }],
      "two.example.test": [ok()],
    });
    const { rpc } = client(fetch);
    const { source } = await rpc.getTransactionWithSource(SIG);
    expect(calls).toEqual(["one.example.test", "two.example.test"]);
    expect(source.hostname).toBe("two.example.test");
  });

  it("a malformed result or another transaction falls through", async () => {
    const { fetch, calls } = scriptedFetch({
      "one.example.test": [ok({ slot: "x" }), ok(txResult(SIG_B))],
      "two.example.test": [ok()],
    });
    const { rpc } = client(fetch);
    await rpc.getTransaction(SIG);
    await rpc.getTransaction(SIG_C);
    expect(calls).toEqual([
      "one.example.test",
      "two.example.test",
      "one.example.test",
      "two.example.test",
    ]);
  });

  it("JSON-RPC errors on every endpoint are a protocol failure, never 'not found'", async () => {
    const { fetch } = scriptedFetch({
      "one.example.test": [{ kind: "rpc_error" }],
      "two.example.test": [{ kind: "rpc_error" }],
    });
    const e = await caught(client(fetch).rpc.getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcProtocolError);
    expect(e).not.toBeInstanceOf(RpcNotFoundError);
    expectNoSecrets(e);
  });
});

describe("a definite answer is final", () => {
  it("a transaction from the first endpoint: the second is never asked", async () => {
    const { fetch, calls } = scriptedFetch({
      "one.example.test": [ok()],
      "two.example.test": [ok()],
    });
    await client(fetch).rpc.getTransaction(SIG);
    expect(calls).toEqual(["one.example.test"]);
  });
});

describe("'not found' from the first endpoint is cross-checked once against the next", () => {
  it("both say not found: RpcNotFoundError, naming the endpoint that confirmed it", async () => {
    const { fetch, calls } = scriptedFetch({
      "one.example.test": [ok(null)],
      "two.example.test": [ok(null)],
      "three.example.test": [ok()],
    });
    const e = await caught(client(fetch, { endpoints: [E1, E2, E3] }).rpc.getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcNotFoundError);
    expect((e as RpcNotFoundError).source).toEqual({
      hostname: "two.example.test",
      user_supplied: false,
      from_cache: false,
    });
    expect(calls).toEqual(["one.example.test", "two.example.test"]); // once, not a third time
    expectNoSecrets(e);
  });

  it("a lying (or lagging) first endpoint says not found, the second has it: the transaction wins", async () => {
    const { fetch } = scriptedFetch({
      "one.example.test": [ok(null)],
      "two.example.test": [ok()],
    });
    const { tx, source } = await client(fetch).rpc.getTransactionWithSource(SIG);
    expect(tx.transaction.signatures[0]).toBe(SIG);
    expect(source.hostname).toBe("two.example.test");
  });

  it("the cross-check cannot be completed: unconfirmed (unavailable), never 'not found'", async () => {
    const { fetch } = scriptedFetch({
      "one.example.test": [ok(null)],
      "two.example.test": [http(503)],
    });
    const e = await caught(client(fetch).rpc.getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcUnconfirmedNotFoundError);
    expect(e).not.toBeInstanceOf(RpcNotFoundError);
    expect((e as RpcError).code).toBe("unconfirmed");
  });

  it("with a single endpoint there is nothing to cross-check: not found is reported", async () => {
    const { fetch, calls } = scriptedFetch({ "one.example.test": [ok(null)] });
    const e = await caught(client(fetch, { endpoints: [E1] }).rpc.getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcNotFoundError);
    expect(calls).toEqual(["one.example.test"]);
  });

  it("not found from a later endpoint (the first having failed) is not corroborated: unconfirmed, no further endpoint asked", async () => {
    const { fetch, calls } = scriptedFetch({
      "one.example.test": [http(500)],
      "two.example.test": [ok(null)],
      "three.example.test": [ok()],
    });
    const e = await caught(client(fetch, { endpoints: [E1, E2, E3] }).rpc.getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcUnconfirmedNotFoundError);
    expect(e).not.toBeInstanceOf(RpcNotFoundError);
    expect(calls).toEqual(["one.example.test", "two.example.test"]);
  });
});

describe("total outage", () => {
  it("every endpoint down: a transport error (unavailable), never 'not found'", async () => {
    const { fetch } = scriptedFetch({
      "one.example.test": [{ kind: "throw" }],
      "two.example.test": [http(429)],
    });
    const e = await caught(client(fetch).rpc.getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcError);
    expect(e).not.toBeInstanceOf(RpcNotFoundError);
    expect(["network", "http", "timeout", "protocol"]).toContain((e as RpcError).code);
    expectNoSecrets(e);
  });

  it("every endpoint timing out gives RpcTimeoutError", async () => {
    const { fetch } = scriptedFetch({
      "one.example.test": [{ kind: "hang" }],
      "two.example.test": [{ kind: "hang" }],
    });
    const e = await caught(client(fetch, { timeoutMs: 10 }).rpc.getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcTimeoutError);
  });

  it("a fetch that throws a non-Error value is still a typed error", async () => {
    const fetch = vi.fn(async () => {
      throw `${UPSTREAM_TEXT}`;
    });
    const e = await caught(client(fetch, { endpoints: [E1] }).rpc.getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcNetworkError);
    expectNoSecrets(e);
  });
});

// ─── Cache ───────────────────────────────────────────────────────────────────

describe("in-session cache of getTransaction results", () => {
  it("a second read of the same signature makes no request and says it came from the cache", async () => {
    const { fetch, calls } = scriptedFetch({ "one.example.test": [ok()] });
    const { rpc } = client(fetch);
    const first = await rpc.getTransactionWithSource(SIG);
    const second = await rpc.getTransactionWithSource(SIG);
    expect(calls).toEqual(["one.example.test"]);
    expect(second.tx).toEqual(first.tx);
    expect(second.source).toEqual({
      hostname: "one.example.test",
      user_supplied: false,
      from_cache: true,
    });
  });

  it("copies in and out: mutating a returned transaction cannot poison the cache", async () => {
    const { fetch } = scriptedFetch({ "one.example.test": [ok()] });
    const { rpc } = client(fetch);
    const first = await rpc.getTransaction(SIG);
    first.slot = 999;
    first.transaction.signatures[0] = "tampered";
    const second = await rpc.getTransaction(SIG);
    expect(second.slot).toBe(1234);
    expect(second.transaction.signatures[0]).toBe(SIG);
    second.slot = 7;
    expect((await rpc.getTransaction(SIG)).slot).toBe(1234);
  });

  it("never caches 'not found' or a failure", async () => {
    const { fetch, calls } = scriptedFetch({
      "one.example.test": [ok(null), http(500), ok()],
      "two.example.test": [ok(null), http(500)],
    });
    const { rpc } = client(fetch);
    expect(await caught(rpc.getTransaction(SIG))).toBeInstanceOf(RpcNotFoundError);
    expect(await caught(rpc.getTransaction(SIG))).toBeInstanceOf(RpcHttpError);
    await rpc.getTransaction(SIG);
    expect(calls).toEqual([
      "one.example.test",
      "two.example.test",
      "one.example.test",
      "two.example.test",
      "one.example.test",
    ]);
  });

  it("never caches an answer without a transaction status (meta null)", async () => {
    const { fetch, calls } = scriptedFetch({ "one.example.test": [ok(txResult(SIG, null))] });
    const { rpc } = client(fetch);
    await rpc.getTransaction(SIG);
    await rpc.getTransaction(SIG);
    expect(calls).toHaveLength(2);
  });

  it("is keyed by cluster: a shared cache never serves a devnet answer to a mainnet read", async () => {
    const cache = createTransactionCache();
    const { fetch, calls } = scriptedFetch({ "one.example.test": [ok()] });
    await client(fetch, { cluster: "devnet", cache }).rpc.getTransaction(SIG);
    await client(fetch, { cluster: "mainnet-beta", cache }).rpc.getTransaction(SIG);
    expect(calls).toHaveLength(2);
    await client(fetch, { cluster: "mainnet-beta", cache }).rpc.getTransaction(SIG);
    expect(calls).toHaveLength(2);
  });

  it("is bounded: the least recently used entry is evicted", async () => {
    const cache = createTransactionCache({ maxEntries: 2 });
    const { fetch, calls } = scriptedFetch({ "one.example.test": [ok()] });
    const { rpc } = client(fetch, { cache });
    await rpc.getTransaction(SIG);
    await rpc.getTransaction(SIG_B);
    await rpc.getTransaction(SIG); // SIG is now the most recent
    await rpc.getTransaction(SIG_C); // evicts SIG_B
    expect(cache.size).toBe(2);
    calls.length = 0;
    await rpc.getTransaction(SIG);
    expect(calls).toHaveLength(0);
    await rpc.getTransaction(SIG_B);
    expect(calls).toHaveLength(1);
  });

  it("is bounded by size: an answer larger than the byte budget is not kept", async () => {
    const cache = createTransactionCache({ maxBytes: 100 });
    const { fetch, calls } = scriptedFetch({ "one.example.test": [ok()] });
    const { rpc } = client(fetch, { cache });
    await rpc.getTransaction(SIG);
    await rpc.getTransaction(SIG);
    expect(calls).toHaveLength(2);
    expect(cache.size).toBe(0);
  });

  it("an oversized answer does not evict the answers already cached", async () => {
    // A hostile or verbose endpoint must not be able to flush the session's cache with one huge answer.
    const big = txResult(SIG_B, { err: null, fee: 5000, logMessages: ["x".repeat(5000)] });
    const cache = createTransactionCache({ maxBytes: 2000 });
    const { fetch, calls } = scriptedFetch({ "one.example.test": [ok(), ok(big)] });
    const { rpc } = client(fetch, { cache });
    await rpc.getTransaction(SIG);
    await rpc.getTransaction(SIG_B);
    expect(cache.size).toBe(1);
    calls.length = 0;
    await rpc.getTransaction(SIG);
    expect(calls).toHaveLength(0);
  });

  it("a cached answer keeps the source it came from (a user-supplied endpoint stays flagged)", async () => {
    const { fetch } = scriptedFetch({ "mine.example.test": [ok()] });
    const { rpc } = client(fetch, { userEndpoint: "https://mine.example.test/" });
    await rpc.getTransaction(SIG);
    const { source } = await rpc.getTransactionWithSource(SIG);
    expect(source).toEqual({
      hostname: "mine.example.test",
      user_supplied: true,
      from_cache: true,
    });
  });
});

// ─── Reporting ───────────────────────────────────────────────────────────────

describe("the endpoint is reported by hostname only", () => {
  it("never the path, query or key of the URL that answered", async () => {
    const { fetch } = scriptedFetch({
      "one.example.test": [http(500)],
      "two.example.test": [ok()],
    });
    const { source } = await client(fetch).rpc.getTransactionWithSource(SIG);
    expect(source.hostname).toBe("two.example.test");
    expectNoSecrets(source);
  });

  it("no error text from any path carries a URL, a key or upstream text", async () => {
    const replies: Reply[][] = [
      [http(429)],
      [{ kind: "throw" }],
      [{ kind: "rpc_error" }],
      [ok(null)],
      [ok({ junk: UPSTREAM_TEXT })],
    ];
    for (const r of replies) {
      const { fetch } = scriptedFetch({ "one.example.test": r, "two.example.test": r });
      const e = await caught(client(fetch).rpc.getTransaction(SIG));
      expect(e).toBeInstanceOf(RpcError);
      expectNoSecrets(e);
    }
  });
});

describe("other calls", () => {
  it("refuses a malformed signature before any request", async () => {
    const { fetch } = scriptedFetch({ "one.example.test": [ok()] });
    await expect(client(fetch).rpc.getTransaction("0OIl")).rejects.toBeInstanceOf(TypeError);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("getAccountInfo falls through the same way and is never cached", async () => {
    const info = { context: { slot: 9 }, value: null };
    const { fetch, calls } = scriptedFetch({
      "one.example.test": [http(429)],
      "two.example.test": [ok(info)],
    });
    const { rpc } = client(fetch);
    expect((await rpc.getAccountInfo(ADDRESS)).context.slot).toBe(9);
    await rpc.getAccountInfo(ADDRESS);
    expect(calls.filter((h) => h === "two.example.test")).toHaveLength(2);
  });

  it("exposes its cluster so the verifier can refuse a mismatch", () => {
    expect(createResilientRpc({ cluster: "devnet", endpoints: [E1] }).cluster).toBe("devnet");
  });
});
