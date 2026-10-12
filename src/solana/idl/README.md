# Vendored Jupiter v6 IDL files

The Jupiter decoder (`../decoders/jupiter-v6.ts`) reads instruction and event layouts from two Anchor IDL
files. Both are saved byte for byte as published. JSON cannot carry a comment, so their provenance is
recorded here. Do not edit them, do not reformat them (a formatter would change their bytes), and do not
replace one without redoing the hashes below. A test (`test/package.test.ts`) fails if a file no
longer matches its recorded size and SHA-256.

The decoder uses both files and prefers the on-chain one where they overlap. Anything either file does not
name is not decoded: it comes out as an unknown variant with its raw bytes kept.

## `jupiter-v6.idl.json` (January 2024)

| Field               | Value                                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------------ |
| Source              | `jup-ag/jupiter-cpi`, the Jupiter team's CPI crate: https://github.com/jup-ag/jupiter-cpi, `idl.json`  |
| Pinned URL          | https://raw.githubusercontent.com/jup-ag/jupiter-cpi/12bc5f67b94a2c3edc74d6e721a19442124a0bad/idl.json |
| Commit              | `12bc5f67b94a2c3edc74d6e721a19442124a0bad` (2024-01-10)                                                |
| Retrieved           | 2026-10-07                                                                                             |
| Size                | 76690 bytes                                                                                            |
| SHA-256 of the file | `764ea6d71b77458fd33aeb308d6e6bb19e660fc5320c5359f3b9cac96eba5c50`                                     |
| Contents            | 44 instructions, 2 events (`SwapEvent`, `FeeEvent`)                                                    |

The file carries no program address. The same commit declares it in `src/lib.rs` (`declare_id!`):
`JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4`, which is the ID in `../programs.ts`.

To check it, download the pinned URL and compare the SHA-256.

## `jupiter-v6-onchain.idl.json` (published by the program on Solana)

| Field               | Value                                                                                                             |
| ------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Program             | `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4` (the file's own `address` field)                                    |
| IDL account         | `C88XWfp26heEmDkmfSzeXP7Fd7GQJ2j9dDTUsyiZbUTa`, owned by the Jupiter program                                      |
| Derivation          | the program derived address of `[]` under the program ID, then `create_with_seed(base, "anchor:idl", programId)`  |
| Account layout      | 8-byte discriminator `184662bf3a907b9e`, 32-byte authority, u32 length, then zlib-compressed JSON                 |
| Authority           | `9u9iZBWqGsp5hXBxkVZtBTuLSGNAG9gEQLgpuVw39ASg`                                                                    |
| Retrieved           | 2026-10-07, by a read-only `getAccountInfo` (base64, finalized) on a public Solana mainnet RPC, at slot 454043028 |
| Inflated size       | 32453 bytes                                                                                                       |
| SHA-256 of the file | `12a0856158b2b6927d683a2ba21566f82e39989aca476e23c02d845fc38cdca8`                                                |
| Contents            | 19 instructions, 6 events, Anchor 0.30+ format (explicit discriminators, snake_case names)                        |

To check it, read the IDL account at the address above, inflate the data after the 44-byte header, and
compare the SHA-256 of the result.

## Licence

These two files are Jupiter's published interface descriptions, included as data. Their terms are those of their publisher and are not covered by this package's licence; see `NOTICE`. TODO(idl-licence): confirm the publisher's terms for both files before the repository is made public.
