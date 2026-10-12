// The verifier on the synthetic record, one tamper at a time. Each test asserts the whole status vector
// C1..C8, not just the check it targets: a tamper must fail the check that owns it and nothing else, an
// outage must never read as tampering, and nothing doubtful may ever come out as verified.
import { beforeAll, describe, expect, it } from "vitest";
import {
  verifyEnvelope,
  type CheckStatus,
  type VerifyResult,
} from "../src/manifest/verify/core.js";
import type { Claim, Envelope } from "../src/manifest/types.js";
import { ARTIFACT, fakeRpc, makeFixture, signHash, type Fixture } from "./helpers/fixture.js";
import { hashManifest } from "../src/manifest/hash.js";

let fx: Fixture;
beforeAll(async () => {
  fx = await makeFixture();
});

const P: CheckStatus = "pass";
const F: CheckStatus = "fail";
const S: CheckStatus = "skipped";
const U: CheckStatus = "unavailable";
const vector = (r: VerifyResult) => r.checks.map((c) => c.status);
const clone = <T>(v: T): T => structuredClone(v);

function run(envelope: unknown, f: Fixture = fx, over: Record<string, unknown> = {}) {
  return verifyEnvelope(envelope, {
    rpc: fakeRpc(f.chain),
    cluster: f.envelope.anchor.cluster,
    issuerKeys: f.issuerKeys,
    ...over,
  });
}

describe("the honest record", () => {
  it("passes C1 to C4, C7 and C8; C5 and C6 are skipped without a registry and files; verdict verified", async () => {
    const r = await run(clone(fx.envelope));
    expect(vector(r)).toEqual([P, P, P, P, S, S, P, P]);
    expect(r.verdict).toBe("verified");
  });

  it("with its artifact, C6 passes too", async () => {
    const r = await run(clone(fx.envelope), fx, {
      files: [{ name: ARTIFACT.name, bytes: fx.artifactBytes }],
    });
    expect(vector(r)).toEqual([P, P, P, P, S, P, P, P]);
  });

  it("asks the chain for the anchor and the one subject transaction, and nothing else", async () => {
    const rpc = fakeRpc(fx.chain);
    await run(clone(fx.envelope), fx, { rpc });
    expect(rpc.calls.sort()).toEqual(
      [fx.envelope.anchor.tx_signature, ...fx.envelope.manifest.subject.signatures].sort(),
    );
  });
});

describe("tampering", () => {
  it("a claim value edited, old hash and signature kept: C2 fails and C7/C8 are not run", async () => {
    const env = clone(fx.envelope);
    const claim = env.manifest.claims.find((c) => c.code === "SOL_TRANSFER") as Claim;
    (claim.value as Record<string, unknown>).amount = "1";
    const r = await run(env);
    expect(vector(r)).toEqual([P, F, P, P, S, S, S, S]);
    expect(r.verdict).toBe("does_not_match");
  });

  it("a manifest edited and re-hashed but not re-signed: C3 fails", async () => {
    const env = clone(fx.envelope);
    env.manifest.issued_at = "2026-10-01T00:00:01Z";
    env.manifest_hash = await hashManifest(env.manifest);
    env.anchor.memo = `trace-manifest:1:${env.manifest_hash}`;
    const r = await run(env);
    expect(r.checks[2].status).toBe(F);
    expect(r.verdict).toBe("does_not_match");
  });

  it("signed by a key that is not in the pinned list: C3 fails", async () => {
    const r = await run(clone(fx.envelope), fx, { issuerKeys: { keys: [] } });
    expect(r.checks[2].status).toBe(F);
    expect(r.checks[2].detail).toContain("not in the pinned issuer key list");
  });

  it("a development key on a mainnet record is refused", async () => {
    const dev = await makeFixture({ cluster: "mainnet-beta" });
    const env: Envelope = clone(dev.envelope);
    env.signature.key_id = "trace-dev-20990101-abcdef";
    env.manifest.issuer.key_id = env.signature.key_id;
    env.manifest_hash = await hashManifest(env.manifest);
    env.signature = await signHash({ ...dev.key, keyId: env.signature.key_id }, env.manifest_hash);
    env.anchor.memo = `trace-manifest:1:${env.manifest_hash}`;
    const keys = { keys: [{ ...dev.issuerKeys.keys[0], key_id: env.signature.key_id }] };
    const r = await run(env, dev, { issuerKeys: keys });
    expect(r.checks[2].status).toBe(F);
    expect(r.checks[2].detail).toContain("development key");
  });

  it("an anchor whose memo carries another hash: C4 fails", async () => {
    const env = clone(fx.envelope);
    const chain = new Map(fx.chain);
    const anchor = clone(chain.get(env.anchor.tx_signature)) as {
      transaction: { message: { instructions: { data: string }[] } };
    };
    anchor.transaction.message.instructions[1].data =
      anchor.transaction.message.instructions[0].data; // not the memo
    chain.set(env.anchor.tx_signature, anchor);
    const r = await run(env, { ...fx, chain });
    expect(r.checks[3].status).toBe(F);
    expect(r.verdict).toBe("does_not_match");
  });

  it("an anchor the chain does not have: C4 fails (a single endpoint's 'not found' is definite)", async () => {
    const chain = new Map(fx.chain);
    chain.delete(fx.envelope.anchor.tx_signature);
    const r = await run(clone(fx.envelope), { ...fx, chain });
    expect(r.checks[3].status).toBe(F);
  });

  it("an artifact with other bytes, and a file the record does not list: C6 fails", async () => {
    const changed = await run(clone(fx.envelope), fx, {
      files: [{ name: ARTIFACT.name, bytes: new TextEncoder().encode("changed") }],
    });
    expect(changed.checks[5].status).toBe(F);
    const unlisted = await run(clone(fx.envelope), fx, {
      files: [{ name: "other.txt", bytes: new Uint8Array([1]) }],
    });
    expect(unlisted.checks[5].status).toBe(F);
  });

  it("a repeated key in the file text is refused by C1 (JSON.parse would keep the last silently)", async () => {
    const text = JSON.stringify(fx.envelope).replace(
      '"manifest_hash"',
      '"manifest_hash":"x","manifest_hash"',
    );
    const r = await run(JSON.parse(text), fx, { rawText: text });
    expect(r.checks[0].status).toBe(F);
    expect(r.verdict).toBe("does_not_match");
  });
});

describe("claims against the chain (a record that is signed and anchored)", () => {
  const forged = (alter: (claims: Claim[]) => Claim[]) => makeFixture({ alterClaims: alter });

  it("an amount that is not what the transaction moved: C7 fails, C1 to C4 pass", async () => {
    const f = await forged((cs) =>
      cs.map((c) =>
        c.code === "SOL_TRANSFER"
          ? ({ ...c, value: { ...(c.value as object), amount: "999999" } } as Claim)
          : c,
      ),
    );
    const r = await run(clone(f.envelope), f);
    expect(r.checks.slice(0, 4).map((c) => c.status)).toEqual([P, P, P, P]);
    expect(r.checks[6].status).toBe(F);
    expect(r.verdict).toBe("does_not_match");
  });

  it("a claim removed from the record: the transaction gives a claim the record lacks (both directions are checked)", async () => {
    const f = await forged((cs) =>
      cs
        .filter((c) => c.code !== "TX_FEE")
        .map((c, i) => ({ ...c, id: `c-${String(i + 1).padStart(4, "0")}` })),
    );
    const r = await run(clone(f.envelope), f);
    expect(vector(r)).toEqual([P, P, P, P, S, S, F, P]);
    expect(r.verdict).toBe("does_not_match");
  });

  it("an Observed claim added that no transaction gives: C7 fails", async () => {
    const f = await forged((cs) => {
      const extra = clone(cs.find((c) => c.code === "TX_FEE") as Claim);
      return [
        ...cs,
        {
          ...extra,
          id: "c-0099",
          code: "SOL_TRANSFER",
          value: { ...(extra.value as object), amount: "5" },
        } as Claim,
      ];
    });
    const r = await run(clone(f.envelope), f);
    expect(vector(r)).toEqual([P, P, P, P, S, S, F, P]);
    expect(r.verdict).toBe("does_not_match");
  });
});

describe("outages are never tampering", () => {
  it("an RPC that throws network errors: unable to check, no check fails", async () => {
    const rpc = {
      async getTransaction(): Promise<never> {
        const { RpcNetworkError } = await import("../src/solana/rpc.js");
        throw new RpcNetworkError();
      },
    };
    const r = await run(clone(fx.envelope), fx, { rpc });
    expect(r.verdict).toBe("unable_to_check");
    expect(r.checks[0].status).toBe(P);
    expect(r.checks[1].status).toBe(P);
    expect(r.checks[3].status).toBe(U);
    expect(r.checks[6].status === U || r.checks[6].status === S).toBe(true);
    expect(vector(r)).not.toContain(F);
  });

  it("with re-derivation turned off the verdict can never be verified", async () => {
    const r = await run(clone(fx.envelope), fx, { rederive: false });
    expect(r.verdict).toBe("unable_to_check");
    expect(r.checks[6].status).toBe(S);
  });

  it("an endpoint for another cluster than the record's: C4, C7, C8 unavailable, not a tamper verdict", async () => {
    const r = await run(clone(fx.envelope), fx, { cluster: "mainnet-beta" });
    expect(r.verdict).toBe("unable_to_check");
    expect(vector(r)).not.toContain(F);
  });
});

describe("hostile input never throws", () => {
  it.each([[null], [undefined], [42], ["text"], [[]], [{}], [{ manifest: 1 }]])(
    "%j",
    async (input) => {
      const r = await verifyEnvelope(input, { rpc: fakeRpc(fx.chain) });
      expect(r.verdict).toBe("does_not_match");
      expect(r.checks).toHaveLength(8);
      expect(r.checks[0].status).toBe(F);
    },
  );
});
