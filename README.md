# railgun-rs

`railgun-rs` is a modular Rust implementation of the RAILGUN privacy system libraries.

The project is intended to support developers building wallets and other applications that interact with RAILGUN smart contracts and surrounding infrastructure such as broadcasters and the Proof of Innocence system.

The repository is designed around a few core ideas:

- Rust-first protocol libraries with first-class WASM support
- strong domain types instead of stringly typed APIs
- modular crates so consumers can adopt only what they need
- optional integrations rather than hard lock-in to one external stack
- a small CLI built on the same public SDK surface

## Current State

The repository is currently in its scaffolding phase.

At the moment it provides:

- shared project direction and contribution rules
- an initial Cargo workspace
- foundational crates for shared types, core traits, WASM bindings, and CLI scaffolding

Additional crates and adapters will be added when real feature work requires them.

## Workspace

The current workspace includes:

- `crates/railgun-types` for shared domain primitives
- `crates/railgun-core` for shared protocol traits and errors
- `crates/railgun-wasm` for thin WASM-oriented bindings
- `crates/railgun-cli` for a minimal command-line interface

## Project Docs

- `VISION.md` explains the project goals and non-goals
- `ARCHITECTURE_CONSTITUTION.md` defines the non-negotiable architectural rules
- `ARCHITECTURE.md` explains the intended workspace shape and layering model
- `CONTRIBUTING.md` explains how developers and AI should contribute

## Development

This repository includes a Nix development environment in `flake.nix`.

The flake now uses `crane` for Rust builds and checks while keeping a pinned Rust toolchain in the development shell.

Basic validation:

```sh
cargo check
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
```

Local Nix validation from the working tree:

```sh
nix flake check
nix build .#default
```

## CLI

The workspace includes a small offline-first CLI in `crates/railgun-cli`.

Current address commands:

```sh
railguncli address encode --master-public-key "0000000000000000000000000000000000000000000000000000000000000000" --chain-type 0 --chain-id 1 --viewing-public-key "0000000000000000000000000000000000000000000000000000000000000000" --json
railguncli address decode --address "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca" --json
railguncli address validate --address "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca" --json
```

Notes:

- `address encode` defaults `--version` to `1`
- `address encode` defaults to the all-chains scope when no chain override is provided
- pass both `--chain-type` and `--chain-id` to encode a chain-scoped address
- `address decode` returns semantic `chainScope` plus raw `networkID`
- `address validate` exits non-zero for malformed input and returns stable JSON in `--json` mode

Current mnemonic commands:

```sh
railguncli mnemonic generate
railguncli mnemonic generate --words 24 --json
railguncli mnemonic validate --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
railguncli mnemonic seed --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --show-secrets --json
```

Notes:

- `generate` supports `--words` values `12`, `15`, `18`, `21`, and `24`
- `validate` prints `valid` on success and exits non-zero on failure
- `seed` requires `--show-secrets` so secret-bearing output is always explicit
- `--json` emits stable machine-readable output for scripting

Current key commands:

```sh
railguncli keys derive --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --index 0 --show-secrets --json
railguncli keys inspect-viewing-private --private-key "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef" --json
railguncli keys inspect-spending-private --private-key "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef" --json
railguncli keys inspect-master-public --spending-public-key-x "15684838006997671713939066069845237677934334329285343229142447933587909549584" --spending-public-key-y "11878614856120328179849762231924033298788609151532558727282528569229552954628" --nullifying-key "8368299126798249740586535953124199418524409103803955764525436743456763691384" --json
```

Notes:

- `keys derive` uses canonical Railgun wallet paths for the requested `--index`
- `keys derive` defaults `--index` to `0`
- `keys derive` requires `--show-secrets` because it emits private keys
- `keys derive` also emits `packedSpendingPublicKey` so it can feed `viewing-key encode`
- `inspect-viewing-private` derives `viewingPublicKey` and `nullifyingKey`
- `inspect-spending-private` derives `spendingPublicKey`
- `inspect-master-public` derives `masterPublicKey` from decimal public inputs

Current shareable viewing key commands:

```sh
railguncli viewing-key encode --viewing-private-key "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef" --packed-spending-public-key "eb68b98efb30b4c3beccfd1776fb0f92bfaf9fef89bc0c54dd4cb76c21b8741b" --show-secrets --json
railguncli viewing-key decode --shareable-viewing-key "82a576privc42067d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599efa473707562c420eb68b98efb30b4c3beccfd1776fb0f92bfaf9fef89bc0c54dd4cb76c21b8741b" --show-secrets --json
railguncli viewing-key decode --shareable-viewing-key "82a576privc42067d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599efa473707562c420eb68b98efb30b4c3beccfd1776fb0f92bfaf9fef89bc0c54dd4cb76c21b8741b" --chain-type 0 --chain-id 1 --show-secrets --json
```

Notes:

- `viewing-key decode` defaults address derivation to the all-chains `0zk` scope
- pass both `--chain-type` and `--chain-id` to derive a chain-scoped address instead
- both `encode` and `decode` require `--show-secrets` because shareable viewing keys contain the viewing private key
- decoded output includes packed and unpacked spending public key data, plus derived viewing-key and address fields

## Status

This is early-stage infrastructure work. The focus right now is on architectural clarity, crate boundaries, and contribution rules before implementing issue-driven functionality.
