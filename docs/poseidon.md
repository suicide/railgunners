# Poseidon Backend

This repository keeps the current Poseidon backend implementation in `railgun-core::crypto` rather than in a separate crate or a direct runtime dependency because exact RAILGUN compatibility requirements matter more than backend interchangeability right now.

## Why Not `light-poseidon`

The repository originally used `light-poseidon`, but that backend is not sufficient for the RAILGUN txid path.

Public upstream source:

- `https://github.com/Lightprotocol/light-poseidon/blob/main/light-poseidon/src/lib.rs`

That implementation documents:

- width `2 <= t <= 13`
- inputs `1 <= n <= 12`

RAILGUN txid derivation requires exact Poseidon hashing over padded lists of **13 inputs** for both nullifiers and commitments, so the txid path needs a width-14 permutation. The upstream test suite also asserts that inputs above 12 fail:

- `https://github.com/Lightprotocol/light-poseidon/blob/main/light-poseidon/tests/bn254_fq_x5.rs`

Because this is a hard interoperability requirement rather than an implementation preference, the backend had to change.

## Why The Backend Stays In `railgun-core`

The current need is shared protocol behavior, not a standalone reusable package.

Keeping the backend in `railgun-core::crypto`:

- preserves the existing internal facade boundary
- keeps txid-specific normalization semantics local and explicit
- avoids introducing a new crate boundary before there is real reuse pressure
- makes it straightforward to validate exact compatibility against known working implementations

This is not a new cryptographic design. The local code is a compatibility-oriented transcription of a known Circom-compatible Poseidon path using fixed, externally sourced constants and public regression vectors.

## Canonical Merkle Zero

The canonical RAILGUN Merkle zero used for txid padding is:

- decimal: `2051258411002736885948763699317990061539314419500486054347250703186609807356`

Public RAILGUN engine derivation:

- `https://github.com/Railgun-Community/engine/blob/main/src/models/merkletree-types.ts`
- `https://github.com/Railgun-Community/engine/blob/main/src/utils/constants.ts`

The engine derives it as:

```text
keccak256(fromUTF8String("Railgun")) % SNARK_PRIME
```

Public txid usage:

- `https://github.com/Railgun-Community/engine/blob/main/src/transaction/railgun-txid.ts`

Cross-checking Rust implementation:

- `https://github.com/ethereum/kohaku/blob/master/crates/railgun-rs/src/railgun/merkle_tree/merkle_tree.rs`

## Constants Provenance

The local constants file is vendored from a pinned upstream Circom-compatible backend:

- upstream file:
  - `https://github.com/logos-storage/rs-poseidon/blob/bdbb8ba2735406e6e7b747abd3bc6711d55370aa/src/poseidon/poseidon_constants_opt.json`
- upstream parser model:
  - `https://github.com/logos-storage/rs-poseidon/blob/bdbb8ba2735406e6e7b747abd3bc6711d55370aa/src/poseidon/constants.rs`
- upstream compatibility claim:
  - `https://github.com/logos-storage/rs-poseidon/blob/bdbb8ba2735406e6e7b747abd3bc6711d55370aa/README.md`

Deeper provenance for those constants is documented by `circomlibjs`:

- `https://github.com/iden3/circomlibjs/blob/main/src/poseidon_opt.js`
- `https://github.com/iden3/circomlibjs/blob/main/src/poseidon_constants_opt.js`

`circomlibjs` documents that the parameters are generated from the reference Poseidon generation script and use round counts chosen from the Poseidon paper recommendations, with the optimized structure derived from Neptune.

## Vendored File Verification

Local vendored file:

- `crates/railgun-core/src/crypto/poseidon/poseidon_constants_opt.json`

Pinned upstream commit:

- `bdbb8ba2735406e6e7b747abd3bc6711d55370aa`

Pinned upstream GitHub blob SHA:

- `29aec839cfa22c3bbd517ff1f92269b7437c33aa`

SHA-256 of the local vendored file:

- `86759f8bcb4103b24c122d6e3505b6c3077e92b6f95bd0857207a0e50601ead1`

SHA-256 of the upstream raw file at that commit:

- `86759f8bcb4103b24c122d6e3505b6c3077e92b6f95bd0857207a0e50601ead1`

You can verify the local file with:

```sh
sha256sum crates/railgun-core/src/crypto/poseidon/poseidon_constants_opt.json
```

And compare it to the pinned upstream raw file with:

```sh
curl -L "https://raw.githubusercontent.com/logos-storage/rs-poseidon/bdbb8ba2735406e6e7b747abd3bc6711d55370aa/src/poseidon/poseidon_constants_opt.json" | sha256sum
```

## Validation Strategy

The local backend is treated as suspect until it matches known working implementations.

Current public-source parity coverage includes:

- Kohaku sequential vectors:
  - `https://github.com/ethereum/kohaku/blob/master/crates/poseidon-rust/src/lib.rs`
- Lightprotocol repeated-one Circom vectors:
  - `https://github.com/Lightprotocol/light-poseidon/blob/main/light-poseidon/tests/bn254_fq_x5.rs`
- RAILGUN engine txid composition behavior:
  - `https://github.com/Railgun-Community/engine/blob/main/src/transaction/railgun-txid.ts`

The txid leaf Merkle proof vector in this repository continues to validate through the new local backend path.

## Semantics Split

The current implementation intentionally keeps two different normalization regimes:

- general Poseidon facade helpers use strict canonical field conversions where appropriate
- txid-specific helpers apply broadcaster/engine-compatible modulo normalization before hashing

This split keeps the general crypto surface strict while preserving exact txid interoperability.

## More Test Vectors

Additional vector-generation scripts should be added under `scripts/poseidon/` so future parity cases can be generated from public reference implementations rather than copied manually.

Recommended future generators:

- a `circomlibjs`-based script for generic Poseidon vectors
- a txid-specific script that mirrors the public engine txid path

Until those scripts are added, any new vectors committed here should cite the exact public source file they were taken from.
