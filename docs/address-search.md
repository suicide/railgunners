# Address Search Stem

`railgunners address search` only emits derived all-chains addresses. Every one of those addresses starts with `0zk1qy`.

A structurally valid address can start with `0zk1q8`, `0zk1q9`, or `0zk1qx` and sort before every derived address. Those strings are not derived wallets, but a conforming sender can still pay them. Note creation reduces the encoded master public key modulo the BN254 scalar field, so a `0zk1q8` alias of a real key is spendable by that key's holder, while a residue with no known preimage is a burn note.

The search stem is hardcoded as `0zk1qy` in `crates/railgunners-cli/src/workflows/address_search.rs`.

## What `0zk1q` is

`0zk1q` is fixed for every version-1 address, not only all-chains addresses.

- `0zk` is the human-readable prefix.
- `1` is the Bech32 separator.
- The payload starts with version byte `0x01`. Bech32m packs bytes into 5-bit symbols, so the first symbol is `00000`, which is `q`.

The next symbol is not fixed. It takes the leftover 3 bits of the version byte (`001`) plus the top 2 bits of the master-public-key integer:

| Top 2 bits | First master-public-key byte | Address |
| --- | --- | --- |
| `00` | `0x00–0x3F` | `0zk1qy…` |
| `01` | `0x40–0x7F` | `0zk1q9…` |
| `10` | `0x80–0xBF` | `0zk1qx…` |
| `11` | `0xC0–0xFF` | `0zk1q8…` |

The network identifier and viewing public key affect later symbols only. They do not change this character.

## Why derivation is always `y`

`derive_master_public_key` in `crates/railgunners-core/src/keys.rs` returns `Poseidon(spending x, spending y, nullifying key)` over the BN254 scalar field. That output is strictly less than the field modulus in `crates/railgunners-types/src/field.rs`. The modulus begins `0x30`, so it is less than `2^254`. A derived master public key therefore always has top 2 bits `00`, and a derived address always starts with `0zk1qy`.

`0zk1qy` is necessary for a derived address. It is not sufficient for field membership. A master public key whose first byte is `0x31–0x3F` still encodes as `0zk1qy`, but it is above the modulus. Derivation never emits that integer either.

## `q` is a zero group, `0` is not

A 5-bit group of zero encodes as `q`. It does not encode as `0`.

The zero master public key and zero viewing public key in address vector 1 therefore encode as `0zk1qyqqqq…`, not `0zk1qy000…`:

```text
0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca
```

That vector is chain type 0, chain id 1. The `q` run is the zero key material. The later `unpd9kxwatw` fragment is the network identifier, not more zero key bytes.

The Bech32 character `0` is 5-bit value 15 (`01111`). `--leading-zeroes` counts literal `0` characters immediately after the all-chains `0zk1qy` stem. That is the lexicographically smallest class a derived wallet can hit. A near-zero key does not produce those characters.

## `0zk1q8` receives through field reduction

`0zk1q8` means the master public key's top 2 bits were `11`. That integer is at least `2^254`, so it is above the field. It is not a Poseidon output and not a key from mnemonic or raw-seed derivation.

ASCII `8` sorts before `9`, `x`, and `y`. A `0zk1q8…` string therefore sorts before every derived address, including a derived `0zk1qy000…` address. Later `0` characters in such a string are the same kind of crafted 5-bit group: value 15, not zero key bytes.

A note public key is `Poseidon(receiver master public key mod P, random)`. `derive_note_public_key` in `crates/railgunners-core/src/note.rs` reduces the encoded 32-byte master public key modulo the BN254 scalar field unconditionally. It does not reject an out-of-field key. This is required note-creation behavior, matching the TypeScript engine, `railgun-rust`, and Kohaku:

- an `m + 4P` alias encodes as `0zk1q8`, hashes as `Poseidon(m, random)`, and is spendable by the holder of `m` when the viewing public key is copied from the canonical address;
- an out-of-field integer whose residue has no known preimage creates a note bound to that residue. It is structurally valid and can receive, but nobody can spend it unless a preimage is later found.

Address decode stays structural and returns the encoded integer. Only the Poseidon input is reduced, so address round-tripping and the `0zk1q8` encoding are unchanged.

The viewing public key embedded in the same address is independent. It can be a real key. It is what lets the receiver decrypt the note and recognize the reduced commitment.

Spending proves knowledge of a spending public key and nullifying key whose Poseidon hash equals the reduced receiver master public key, which is always in-field.

`0zk1q9` and `0zk1qx` are the same kind of object. Their top 2 bits are `01` and `10`. They are above the field too.

## Receive without a known spend key

The case that can receive and still not be spent is different. It is an in-field master public key that was not produced by `derive_master_public_key` from keys the holder knows.

A sender can form a note public key and commitment to that integer. Spending requires a preimage: a valid BabyJubJub spending public key and an in-field nullifying key whose Poseidon hash is exactly that integer. Without that preimage, the note cannot be spent.

That address still starts with `0zk1qy`. It is not a `0zk1q8` address.

## Validation still accepts the encoding

`MasterPublicKey::new` in `crates/railgunners-types/src/keys.rs` checks that the integer fits in 32 bytes. It does not check BN254 scalar-field membership. Canonical RAILGUN address vectors include values in that 32-byte range that are outside the modulus.

Address vector 3 is one of them. Its master public key is `ee6b4c70…`, its top 2 bits are `11`, and the all-chains encoding is:

```text
0zk1q8hxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kfrv7j6fe3z53llhxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kg0zpzts
```

`address validate` reports that string as structurally valid. Structural validity is not wallet derivation, note receipt, or spendability.

## Search consequence

`--lower-than` compares encoded address strings. The search keeps the lexicographically smallest supplied target, then requires a derived candidate to be strictly smaller.

Every candidate starts with `0zk1qy`. A target that starts with `0zk1q8`, `0zk1q9`, or `0zk1qx` is smaller than every candidate, so the search cannot match it. One such target also makes a multi-target search unsatisfiable, because the smallest target wins. Without `--max-attempts`, that search does not stop.

The command does not reject these targets. `--leading-zeroes` remains the search for the smallest addresses a derived wallet can actually use.
