// Tests for the fetch-based Solana JSON-RPC client. Why each case matters: the public verifier
// turns "the RPC could not answer" into Unable to check and "the chain says no" into Does not match. If a
// transport failure were ever mistaken for an answer (a 200 carrying an error, a JSON-RPC error object, a
// truncated or foreign body), an outage would read as tampering, or worse, a broken provider's junk would be
// parsed as a transaction. Errors carry stable codes and fixed text, never the URL (it may hold a provider
// key) or upstream text (it is attacker-controllable when the user pastes their own endpoint).
import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_RPC_TIMEOUT_MS,
  RpcConfigError,
  RpcError,
  RpcHttpError,
  RpcNetworkError,
  RpcNotFoundError,
  RpcProtocolError,
  RpcTimeoutError,
  createSolanaRpc,
  parseTransactionResult,
} from "../rpc.js";

const URL_SECRET_PART = "private-path-xyz";
const RPC_URL = `https://rpc.example.test/${URL_SECRET_PART}`;
const UPSTREAM_TEXT = "upstream-said-something-hostile";

const SIG = "5".repeat(88);
const ADDRESS = "7".repeat(44);

function txResult(signature = SIG) {
  return {
    slot: 1234,
    blockTime: 1791345000,
    version: 0,
    transaction: {
      signatures: [signature],
      message: {
        header: {
          numRequiredSignatures: 1,
          numReadonlySignedAccounts: 0,
          numReadonlyUnsignedAccounts: 1,
        },
        accountKeys: [ADDRESS, "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"],
        recentBlockhash: "1".repeat(32),
        instructions: [{ programIdIndex: 1, accounts: [0], data: "2", stackHeight: null }],
      },
    },
    meta: { err: null, fee: 5000, loadedAddresses: { writable: [], readonly: [] } },
  };
}

type Handler = (request: { id: unknown; method: string; params: unknown[] }) => Response;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function fakeFetch(handler: Handler) {
  return vi.fn(async (_url: string | URL | Request, init?: RequestInit) =>
    handler(JSON.parse(String(init?.body))),
  );
}

const answer =
  (result: unknown): Handler =>
  (req) =>
    jsonResponse({ jsonrpc: "2.0", id: req.id, result });

async function caught(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  throw new Error("expected a rejection");
}

function expectSafeMessage(e: unknown) {
  expect(e).toBeInstanceOf(RpcError);
  const text = `${(e as Error).message} ${String(e)} ${JSON.stringify(e)}`;
  expect(text).not.toContain(URL_SECRET_PART);
  expect(text).not.toContain(UPSTREAM_TEXT);
}

describe("createSolanaRpc requests", () => {
  it("asks getTransaction for raw json at finalized with maxSupportedTransactionVersion 0", async () => {
    // The verifier reads instruction bytes and account indexes, so it needs encoding json; a confirmed
    // (not finalized) answer could still be rolled back, so it must never count as an anchor.
    const fetch = fakeFetch(answer(txResult()));
    const rpc = createSolanaRpc({ url: RPC_URL, fetch });
    const tx = await rpc.getTransaction(SIG);
    expect(tx.slot).toBe(1234);
    const [url, init] = fetch.mock.calls[0];
    expect(String(url)).toBe(RPC_URL);
    expect(init?.method).toBe("POST");
    const body = JSON.parse(String(init?.body));
    expect(body).toMatchObject({
      jsonrpc: "2.0",
      method: "getTransaction",
      params: [
        SIG,
        { encoding: "json", commitment: "finalized", maxSupportedTransactionVersion: 0 },
      ],
    });
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("asks getAccountInfo for base64 at finalized and returns the owner-resolution shape", async () => {
    const value = { owner: ADDRESS, data: ["AAAA", "base64"], lamports: 1, executable: false };
    const fetch = fakeFetch(answer({ context: { slot: 99 }, value }));
    const rpc = createSolanaRpc({ url: RPC_URL, fetch });
    const info = await rpc.getAccountInfo(ADDRESS);
    expect(info.context.slot).toBe(99);
    expect(info.value?.owner).toBe(ADDRESS);
    const body = JSON.parse(String(fetch.mock.calls[0][1]?.body));
    expect(body.method).toBe("getAccountInfo");
    expect(body.params).toEqual([ADDRESS, { encoding: "base64", commitment: "finalized" }]);
  });

  it("returns value null for an account that does not exist (an answer, not an error)", async () => {
    const rpc = createSolanaRpc({
      url: RPC_URL,
      fetch: fakeFetch(answer({ context: { slot: 1 }, value: null })),
    });
    expect((await rpc.getAccountInfo(ADDRESS)).value).toBeNull();
  });

  it("uses a fresh request id per call and checks the reply carries it", async () => {
    const ids: unknown[] = [];
    const fetch = fakeFetch((req) => {
      ids.push(req.id);
      return jsonResponse({ jsonrpc: "2.0", id: req.id, result: txResult() });
    });
    const rpc = createSolanaRpc({ url: RPC_URL, fetch });
    await rpc.getTransaction(SIG);
    await rpc.getTransaction(SIG);
    expect(new Set(ids).size).toBe(2);
  });

  it("does not retry: one failed call is one fetch", async () => {
    const fetch = fakeFetch(() => new Response("busy", { status: 429 }));
    const rpc = createSolanaRpc({ url: RPC_URL, fetch });
    await caught(rpc.getTransaction(SIG));
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe("not found is distinct from transport failure", () => {
  it("a null getTransaction result is RpcNotFoundError (the chain answered: no such transaction)", async () => {
    const rpc = createSolanaRpc({ url: RPC_URL, fetch: fakeFetch(answer(null)) });
    const e = await caught(rpc.getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcNotFoundError);
    expect((e as RpcError).code).toBe("not_found");
  });
});

describe("transport failures are typed errors with fixed text", () => {
  it("a fetch that never settles times out with RpcTimeoutError, even if it ignores the abort signal", async () => {
    const fetch = vi.fn(() => new Promise<Response>(() => {}));
    const rpc = createSolanaRpc({ url: RPC_URL, fetch, timeoutMs: 20 });
    const e = await caught(rpc.getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcTimeoutError);
    expect((e as RpcError).code).toBe("timeout");
    expectSafeMessage(e);
  });

  it("the timeout aborts the request's signal", async () => {
    let signal: AbortSignal | undefined;
    const fetch = vi.fn(
      (_u: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          signal = init?.signal ?? undefined;
          signal?.addEventListener("abort", () =>
            reject(new DOMException("aborted", "AbortError")),
          );
        }),
    );
    const rpc = createSolanaRpc({ url: RPC_URL, fetch, timeoutMs: 20 });
    expect(await caught(rpc.getTransaction(SIG))).toBeInstanceOf(RpcTimeoutError);
    expect(signal?.aborted).toBe(true);
  });

  it("the default timeout is 15 seconds", () => {
    expect(DEFAULT_RPC_TIMEOUT_MS).toBe(15_000);
  });

  it("a rejected fetch (DNS, CORS, offline) is RpcNetworkError without the upstream text", async () => {
    const fetch = vi.fn(async () => {
      throw new TypeError(`${UPSTREAM_TEXT} ${RPC_URL}`);
    });
    const e = await caught(createSolanaRpc({ url: RPC_URL, fetch }).getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcNetworkError);
    expect((e as RpcError).code).toBe("network");
    expectSafeMessage(e);
  });

  it.each([429, 500, 502, 503, 404, 403])(
    "HTTP %i is RpcHttpError carrying only the status",
    async (status) => {
      const fetch = fakeFetch(() => new Response(UPSTREAM_TEXT, { status }));
      const e = await caught(createSolanaRpc({ url: RPC_URL, fetch }).getTransaction(SIG));
      expect(e).toBeInstanceOf(RpcHttpError);
      expect((e as RpcHttpError).status).toBe(status);
      expect((e as RpcError).code).toBe("http");
      expectSafeMessage(e);
    },
  );
});

describe("protocol failures: a 200 is not an answer until its shape is proven", () => {
  const cases: [string, Handler][] = [
    ["a 200 with an error string body", () => new Response(`error: ${UPSTREAM_TEXT}`)],
    ["a 200 with an empty body", () => new Response("")],
    ["a JSON array (batch) body", () => jsonResponse([])],
    ["a JSON string body", () => jsonResponse(UPSTREAM_TEXT)],
    [
      "a JSON-RPC error object",
      (req) =>
        jsonResponse({
          jsonrpc: "2.0",
          id: req.id,
          error: { code: -32005, message: UPSTREAM_TEXT },
        }),
    ],
    [
      "a reply with neither result nor error",
      (req) => jsonResponse({ jsonrpc: "2.0", id: req.id }),
    ],
    [
      "a reply to another request id",
      () => jsonResponse({ jsonrpc: "2.0", id: 999999, result: txResult() }),
    ],
    ["a reply without jsonrpc 2.0", (req) => jsonResponse({ id: req.id, result: txResult() })],
    ["a result that is a string", answer(UPSTREAM_TEXT)],
    ["a result missing the message", answer({ ...txResult(), transaction: { signatures: [SIG] } })],
    ["a result whose meta has no err field", answer({ ...txResult(), meta: { fee: 1 } })],
    ["a result with a float slot", answer({ ...txResult(), slot: 1.5 })],
    [
      "a result with a string account index",
      answer({
        ...txResult(),
        transaction: {
          ...txResult().transaction,
          message: {
            ...txResult().transaction.message,
            instructions: [{ programIdIndex: "length", accounts: [], data: "" }],
          },
        },
      }),
    ],
    ["a result for a different transaction signature", answer(txResult("4".repeat(88)))],
  ];

  it.each(cases)("%s is RpcProtocolError", async (_name, handler) => {
    const e = await caught(
      createSolanaRpc({ url: RPC_URL, fetch: fakeFetch(handler) }).getTransaction(SIG),
    );
    expect(e).toBeInstanceOf(RpcProtocolError);
    expect((e as RpcError).code).toBe("protocol");
    expectSafeMessage(e);
  });

  it("keeps the JSON-RPC numeric error code (not its message) for diagnosis", async () => {
    const fetch = fakeFetch((req) =>
      jsonResponse({ jsonrpc: "2.0", id: req.id, error: { code: -32009, message: UPSTREAM_TEXT } }),
    );
    const e = (await caught(
      createSolanaRpc({ url: RPC_URL, fetch }).getTransaction(SIG),
    )) as RpcProtocolError;
    expect(e.reason).toBe("rpc_error");
    expect(e.rpcCode).toBe(-32009);
  });

  it("a getAccountInfo result of the wrong shape is RpcProtocolError", async () => {
    for (const result of [
      null,
      {},
      { context: {}, value: null },
      { context: { slot: 1 }, value: { owner: 5 } },
    ]) {
      const e = await caught(
        createSolanaRpc({ url: RPC_URL, fetch: fakeFetch(answer(result)) }).getAccountInfo(ADDRESS),
      );
      expect(e).toBeInstanceOf(RpcProtocolError);
    }
  });

  it("a body over the cap is refused by its declared length before reading", async () => {
    const fetch = fakeFetch(
      () => new Response("{}", { headers: { "content-length": String(10 * 1024 * 1024) } }),
    );
    const e = (await caught(
      createSolanaRpc({ url: RPC_URL, fetch, maxBodyBytes: 1024 }).getTransaction(SIG),
    )) as RpcProtocolError;
    expect(e).toBeInstanceOf(RpcProtocolError);
    expect(e.reason).toBe("body_too_large");
  });

  it("a body over the cap is refused while streaming when no length is declared", async () => {
    const chunk = new TextEncoder().encode("x".repeat(512));
    let pulled = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        if (pulled > 100) controller.close();
        else controller.enqueue(chunk);
      },
    });
    const fetch = fakeFetch(() => new Response(stream));
    const e = (await caught(
      createSolanaRpc({ url: RPC_URL, fetch, maxBodyBytes: 2048 }).getTransaction(SIG),
    )) as RpcProtocolError;
    expect(e.reason).toBe("body_too_large");
    expect(pulled).toBeLessThan(20); // stopped early, did not drain the stream
  });

  it("a body that is not valid UTF-8 is RpcProtocolError", async () => {
    const fetch = fakeFetch(() => new Response(new Uint8Array([0x7b, 0xff, 0xfe, 0x7d])));
    const e = await caught(createSolanaRpc({ url: RPC_URL, fetch }).getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcProtocolError);
  });
});

describe("configuration", () => {
  it.each([
    "",
    "not a url",
    "ftp://rpc.example.test/",
    "javascript:alert(1)",
    "file:///etc/passwd",
  ])("refuses url %j without echoing it", (url) => {
    expect(() => createSolanaRpc({ url })).toThrow(/http or https/);
  });

  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1.5])(
    "refuses timeoutMs %s",
    (timeoutMs) => {
      expect(() => createSolanaRpc({ url: RPC_URL, timeoutMs })).toThrow();
    },
  );

  it("refuses a malformed signature or address before any request", async () => {
    const fetch = fakeFetch(answer(txResult()));
    const rpc = createSolanaRpc({ url: RPC_URL, fetch });
    await expect(rpc.getTransaction("not base58 0OIl")).rejects.toThrow();
    await expect(rpc.getAccountInfo("x".repeat(500))).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("parseTransactionResult (also used by the verifier on injected RPC clients)", () => {
  it("keeps fields it does not check, so later readers (the normaliser) see the full transaction", () => {
    const parsed = parseTransactionResult(txResult(), SIG);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect((parsed.tx.meta as Record<string, unknown>).fee).toBe(5000);
      expect(parsed.tx.transaction.message.recentBlockhash).toBe("1".repeat(32));
    }
  });

  it("reports null as not found and junk as malformed", () => {
    expect(parseTransactionResult(null, SIG)).toEqual({ ok: false, reason: "not_found" });
    expect(parseTransactionResult({}, SIG)).toEqual({ ok: false, reason: "malformed" });
    expect(parseTransactionResult(txResult("4".repeat(88)), SIG)).toEqual({
      ok: false,
      reason: "wrong_transaction",
    });
  });
});

describe("L1: redirects are refused, never followed", () => {
  it("asks fetch not to follow redirects", async () => {
    const fetch = fakeFetch(answer(txResult()));
    await createSolanaRpc({ url: RPC_URL, fetch }).getTransaction(SIG);
    expect(fetch.mock.calls[0][1]?.redirect).toBe("error");
  });

  it("a 3xx answer (a fetch that did not follow) is RpcNetworkError, not an HTTP status", async () => {
    for (const status of [301, 302, 307, 308]) {
      const fetch = fakeFetch(
        () => new Response(null, { status, headers: { location: "https://elsewhere.test/" } }),
      );
      const e = await caught(createSolanaRpc({ url: RPC_URL, fetch }).getTransaction(SIG));
      expect(e, String(status)).toBeInstanceOf(RpcNetworkError);
      expectSafeMessage(e);
    }
  });

  it("an answer a fetch reached by following a redirect anyway is RpcNetworkError", async () => {
    const fetch = fakeFetch((req) => {
      const res = jsonResponse({ jsonrpc: "2.0", id: req.id, result: txResult() });
      Object.defineProperty(res, "redirected", { value: true });
      return res;
    });
    const e = await caught(createSolanaRpc({ url: RPC_URL, fetch }).getTransaction(SIG));
    expect(e).toBeInstanceOf(RpcNetworkError);
  });
});

describe("L2: configuration errors are typed", () => {
  it.each([2 ** 31, 2 ** 40, Number.MAX_SAFE_INTEGER])(
    "refuses timeoutMs %s (above the platform timer's 2^31-1 ms)",
    (timeoutMs) => {
      expect(() => createSolanaRpc({ url: RPC_URL, timeoutMs })).toThrow(RpcConfigError);
    },
  );

  it("accepts timeoutMs of exactly 2^31-1", () => {
    expect(() => createSolanaRpc({ url: RPC_URL, timeoutMs: 2 ** 31 - 1 })).not.toThrow();
  });

  it.each([0, -1, Number.NaN, 1.5])("refuses timeoutMs %s with RpcConfigError", (timeoutMs) => {
    expect(() => createSolanaRpc({ url: RPC_URL, timeoutMs })).toThrow(RpcConfigError);
  });

  it("a bad url is RpcConfigError (still a TypeError for older callers) with fixed text", () => {
    let e: unknown;
    try {
      createSolanaRpc({ url: `ftp://h/${URL_SECRET_PART}` });
    } catch (x) {
      e = x;
    }
    expect(e).toBeInstanceOf(RpcConfigError);
    expect(e).toBeInstanceOf(TypeError);
    expect((e as RpcConfigError).code).toBe("config");
    expect(String(e)).not.toContain(URL_SECRET_PART);
  });
});
