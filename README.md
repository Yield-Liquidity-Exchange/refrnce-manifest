# trace-manifest-verifier

An independent checker for **Trace Manifest** records. A Trace Manifest is a signed, hashed list of claims
about Solana transactions, with its hash written to Solana in a Memo. This tool takes the record and checks
it against the chain, without trusting the issuer or any service run by them: it recomputes the hash,
verifies the signature against pinned issuer keys, reads the anchor transaction, and reads the subject
transactions again to see whether every claim the record makes about them reproduces.

It gives one of three answers: **Verified**, **Does not match**, or **Unable to check**.

## What the tool checks (C1 to C8)

Eight checks run on every record, in this order. Each one ends as `pass`, `fail`, `unavailable` (it could not
be completed) or `skipped` (it did not apply).

| Check | Name            | What it does                                                                                                                                                                                                                                                      |
| ----- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C1    | Schema          | The file is a well-formed `trace-manifest/1.0` envelope: strict schema, size limits, no repeated keys, and the rules a JSON Schema cannot express.                                                                                                                |
| C2    | Hash            | The manifest, written in its canonical form (RFC 8785), hashes with SHA-256 to the `manifest_hash` the record states.                                                                                                                                             |
| C3    | Signature       | The Ed25519 signature over that hash verifies against the issuer key with the signature's `key_id` in the list pinned in this package. The key is never taken from the record. A key marked development is refused for mainnet records.                           |
| C4    | Anchor          | The anchor transaction, read at `finalized`, was signed by the issuer key, carries the Memo `trace-manifest:1:<manifest_hash>`, and is on the same cluster as the subject. Its block time is reported next to the issuer's own `issued_at`, never merged with it. |
| C5    | Registry        | Looks the Trace ID up in a public registry when the caller supplies a lookup. **The command line tool does not query a registry, so C5 is always `skipped` there.** An unreachable registry never blocks a verdict.                                               |
| C6    | Artifacts       | Files you pass alongside the record match the names, sizes and SHA-256 hashes it lists. A file the record does not list fails. With no files, C6 is `skipped`.                                                                                                    |
| C7    | Observed claims | Every Observed claim is reproduced by reading the subject transactions again and running the same decoders and normaliser the issuer used, and the transactions give no Observed claim the record lacks. Both directions, as sets.                                |
| C8    | Derived claims  | Every Derived claim recomputes from the claims it names, and the warnings that can only come from the transaction itself are re-derived from it. A claim that does not recompute is a mismatch whatever the chain says.                                           |

The verdict is **Verified** only when C1 to C4, C7 and C8 pass and C6 passes or has no files. Any `fail`
makes it **Does not match**. Anything else (an outage, an unknown formula, a skipped required check) is
**Unable to check**, which is not a finding that the record was changed.

## What a Manifest proves

A record that passes every check proves:

- The record existed, unchanged, by the anchor time: its hash is in a Solana transaction signed by the issuer key.
- It was signed by the Refrnce Trace issuer key pinned in the verifier's code, never by a key the file supplies.
- Each Observed and Derived claim re-derives from public Solana data through the verifier's decoders and formulas.
- Each file supplied with it matches the hash the record lists for that file.

## What a Manifest does not prove

It does not prove:

- The real-world identity of the owner of any wallet.
- Anyone's intent, or whether any activity was lawful.
- That the record is complete: it covers only the transactions and claims it lists.
- That the Solana RPC endpoint answered honestly: the chain is read through the endpoint the verifier reports.
- Attributed labels or Inferred analyst findings: they are listed with their source and are not independently checked.
- The issue time: that is the issuer's own statement; only the anchor time comes from the chain.

## Quick start

Requires Node.js 22 or later.

```
git clone <repository address>   # TODO(repo-url): the public repository address
cd trace-manifest-verifier
npm install
npm run build
node dist/cli.js path/to/envelope.json
```

`npm install --global .` in the same directory installs the command as `trace-verify`.

```
trace-verify <envelope.json> [artifact-file ...] [--rpc URL ...] [--cluster mainnet-beta|devnet|testnet]
```

- `<envelope.json>` is the record (a leading byte order mark is ignored). Pass the files it lists
  (`artifact-file`) to run check C6; pass only those files, never the envelope itself. Both must be regular
  files.
- Without `--rpc`, the command asks **one** endpoint: the default public endpoint for the cluster the record
  names. That selection is the only thing the record influences; it never supplies a URL. **With one endpoint,
  a transaction it reports as missing is reported as a mismatch (`Does not match`).** Public endpoints do not
  keep all history, and a transaction that has been pruned from the one you asked can look exactly like a
  record that cites a transaction that never existed. If a result reports a transaction as not found, ask
  again with a second endpoint before drawing a conclusion.
- `--rpc URL` asks your own endpoint **instead of** the default. Give it more than once for an ordered list
  (at most eight): a transaction that the first endpoint reports as missing is then checked against the
  second, and counts as missing only if the second agrees too; if the second cannot answer, the result is
  `Unable to check`. Pass the default public endpoint yourself as one of the entries if you want it in the
  list. Each URL must be `https` (`http` is accepted only for `localhost`), must carry no user name or
  password, and **`--rpc` needs `--cluster`**, the cluster those endpoints serve. Only the host names are ever
  printed, never the path or query, because they may hold your key.
- `--cluster NAME` names the cluster. Without it the cluster named in the record is used, and the output says
  so. Pass it yourself to insist on one: an endpoint for another cluster than the record's gives
  `unable to check`, never a tamper verdict.

It prints the verdict, each check C1 to C8 with its evidence, and one result line for every claim.

| Exit code | Meaning                                                                                          |
| --------- | ------------------------------------------------------------------------------------------------ |
| 0         | Verified                                                                                         |
| 1         | Does not match                                                                                   |
| 2         | Unable to check                                                                                  |
| 3         | Usage error: bad arguments, an unreadable file, or a file that is not JSON. Nothing was checked. |

As a library:

```ts
import { verifyEnvelope, createResilientRpc } from "trace-manifest-verifier";

const text = await readFile("envelope.json", "utf8");
const rpc = createResilientRpc({ cluster: "mainnet-beta" });
const result = await verifyEnvelope(JSON.parse(text), {
  rpc,
  cluster: "mainnet-beta",
  rawText: text,
});
console.log(result.verdict, result.checks);
```

Development: `npm test` runs the unit tests (no network), `npm run boundary` fails if any file imports from
outside the package, `npm run deps` prints the dependency graph, and `npm run verify:demo` runs the built
command against the demo record in `examples/` (this one talks to a real Solana endpoint).

## Schema reference

The JSON Schema of the envelope is [`schema/trace-manifest-1.0.schema.json`](schema/trace-manifest-1.0.schema.json)
(also available as `trace-manifest-verifier/schema`). It states structure only. A verifier must also run the
rules a JSON Schema cannot express, which are listed in the schema's description and implemented by
`checkManifestRules` and `detectDuplicateKeys` (exported by this package).

An envelope has four parts:

| Field           | Holds                                                                                                                                               |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `manifest`      | The hashed body: `schema`, `trace_id`, `issuer`, `issued_at`, `subject` (chain, cluster, transaction signatures), `tooling`, `claims`, `artifacts`. |
| `manifest_hash` | `sha256:` and the SHA-256 of the manifest's canonical form.                                                                                         |
| `signature`     | `alg` (`Ed25519`), `key_id`, and the base58 signature over the hash.                                                                                |
| `anchor`        | `cluster`, `tx_signature`, `slot`, `block_time` and `memo` of the Solana transaction that carries the hash.                                         |

A claim has an `id`, a `type` (one of the four labels below), a `code` from the claim rules table, a `value`,
and a `provenance` that matches its type. Token amounts are decimal strings of raw base units, compared as
integers, never as floating point numbers. There are no nulls anywhere in a record.

## Claim labels

Every claim carries exactly one of four labels. The verifier re-checks the first two and lists the last two
without checking them.

- **Observed**: Read directly from the transaction record. Re-checked by the verifier.
- **Derived**: Computed from other claims by a named formula. Re-checked by the verifier.
- **Attributed**: Taken from a named source. Not independently verified.
- **Inferred**: An analyst's conclusion from other claims. Not independently verified.

Entity labels (an Attributed claim that gives a known address a name) come from a registry that is not part
of this open package: the normaliser here never writes one, and the verifier lists any such claim in a record
as not independently checked, whatever it says.

## Trust assumptions

- **The RPC endpoint answers honestly.** The verifier reads the chain through the endpoint it is given. An
  endpoint that lies, consistently, can make a forged record appear to reproduce. The command prints the
  host that answered; pass your own endpoint with `--rpc` if you do not trust the default. By default one
  endpoint is used, so a transaction it reports as missing is reported as a mismatch, and pruned history
  can look like one; give a second `--rpc` to cross-check, in which case a transaction counts as missing
  only when both agree.
- **The issuer keys pinned in this package are the right ones.** The signing key is looked up by `key_id` in
  `src/manifest/issuer-keys.json`, never in the record. If you do not trust your copy of this package, you
  do not trust the result: check that list against the issuer's own publication. A key marked development
  is trusted only for records off mainnet. A change of keys needs a new release of the package.
- **The decoders are the issuer's decoders.** C7 and C8 re-run the same decoders and formulas that built the
  record, so an instruction they cannot read appears in the record as an undecoded claim (with its raw bytes)
  rather than being silently dropped; it does not appear as a wrong decode.
- **Times.** `issued_at` is the issuer's own statement. Only the anchor's block time comes from the chain,
  and it is a validator's estimate accurate to seconds.
- **Attributed and Inferred claims are not verified.** They are counted and listed, never passed.
- **Web Crypto.** SHA-256 and Ed25519 come from the platform; where Web Crypto is missing the affected checks
  are `unavailable`.

## The demo envelope

`examples/demo-envelope.json` is a record anchored on Solana mainnet, included as an example to run the
command on. While it is absent, `examples/demo-envelope.PLACEHOLDER.json` stands in: it is not a record, it
does not verify, and `npm run verify:demo` refuses to run until the real file replaces it.

```
node dist/cli.js examples/demo-envelope.json --cluster mainnet-beta
```

## About the demo record

The demo record is a worked example, not a case. The notice that goes with it:

> This is a demonstration record. It was made from public Solana transactions sent from a wallet controlled by Refrnce, to show how Trace Manifest works. It does not say or imply that any person or organisation did anything wrong. It is not legal, financial or investment advice, and it has not been reviewed by a court, a regulator or a lawyer. A Verified result means the record is unchanged and that its Observed and Derived claims match the chain; it does not identify who controls any account, other than the account Refrnce has labelled as its own demo wallet.

## Licence

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
