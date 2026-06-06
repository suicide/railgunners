# railgunners

`railgunners` is a modular Rust implementation of the RAILGUN privacy system libraries.

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

Current note-modeling behavior includes sender-visibility rules used during note reconstruction:

- hidden sender: a present non-null 15-byte `senderRandom` means `encodedMPK` carries the receiver MPK directly
- visible sender: missing or all-zero-sentinel `senderRandom` means `encodedMPK = receiverMPK XOR senderMPK`
- low-level sender recovery treats missing `senderRandom` as visible mode, but V2 received-note reconstruction preserves the upstream ambiguity rule when plaintext omits `senderRandom` and `encodedMPK == receiverMPK`

## Workspace

The current workspace includes:

- `crates/railgunners-artifacts` for proving-artifact metadata and optional downloads
- `crates/railgunners-broadcaster` for typed broadcaster-facing models and helpers
- `crates/railgunners-poi` for typed Proof of Innocence models, validation, and optional transports
- `crates/railgunners-prover` for proving-oriented abstractions and helpers
- `crates/railgunners-types` for shared domain primitives
- `crates/railgunners-core` for shared protocol traits and errors
- `crates/railgunners-wasm` for thin WASM-oriented bindings
- `crates/railgunners-cli` for a minimal command-line interface

## Project Docs

- `VISION.md` explains the project goals and non-goals
- `ARCHITECTURE_CONSTITUTION.md` defines the non-negotiable architectural rules
- `ARCHITECTURE.md` explains the intended workspace shape and layering model
- `CONTRIBUTING.md` explains how developers and AI should contribute

## Development

This repository includes a Nix development environment in `flake.nix`.

The flake now uses `crane` for Rust builds and checks while keeping a pinned Rust toolchain in the development shell.

For the closest match to CI-style local results, run Rust commands inside `nix develop`.

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

`nix flake check` currently covers the pinned-toolchain equivalents of `cargo fmt --all --check`, `cargo check --workspace --all-targets --all-features`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, and `cargo deny check`, plus the CLI package build.

## CLI

The workspace includes a small offline-first CLI in `crates/railgunners-cli`.

Current address commands:

```sh
railgunners address encode --master-public-key "0000000000000000000000000000000000000000000000000000000000000000" --chain-type 0 --chain-id 1 --viewing-public-key "0000000000000000000000000000000000000000000000000000000000000000" --json
railgunners address decode --address "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca" --json
railgunners address validate --address "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca" --json
railgunners address search --lower-than "0zk1qy0000k0k4w2akdev8ju4z7yp4w4x0zz9ehxdqe9chsjuujeklwdtrv7j6fe3z53lug74ey6tjlpk2xlfdp2pnfnc4972qwpk9fvhafqtrv9ctnxgjhush3njwh" --lower-than "0zk1qyduss9nnfyycfwt03fwds69c7z27rmmulcxsq3lvn0yhwjxfa7lnrv7j6fe3z53la7dxtysu5dtqp9lh6k6qeft3j5cvawwdq7zx6t9ltsncagyz06wk4n66nt" --leading-zeroes 4 --prefix 0000dus --suffix nt --jobs 8 --progress-every 1000 --show-secrets --json
railgunners address search --seed-mode raw --leading-zeroes 4 --jobs 8 --progress-every 1000 --show-secrets --json
```

Notes:

- `address encode` defaults `--version` to `1`
- `address encode` defaults to the all-chains scope when no chain override is provided
- pass both `--chain-type` and `--chain-id` to encode a chain-scoped address
- `address decode` returns semantic `chainScope` plus raw `networkID`
- `address validate` exits non-zero for malformed input and returns stable JSON in `--json` mode
- `address search` searches only all-chains `0zk` addresses and can optionally compare against the minimum repeatable `--lower-than`
- `address search` requires `--show-secrets` because success output includes the mnemonic and view-only secrets
- `address search` requires at least one of `--lower-than`, `--leading-zeroes`, `--prefix`, or `--suffix`
- `address search` supports `--seed-mode bip39|raw`, `--jobs`, `--progress-every`, `--max-attempts`, and combinable `--lower-than`, `--leading-zeroes`, `--prefix`, and `--suffix` filters
- `--leading-zeroes` counts literal `0` characters immediately after the all-chains `0zk1qy` stem and stops on the first match meeting the threshold
- `--seed-mode raw` searches direct 64-byte seeds instead of BIP-39 mnemonics, omits `mnemonic` and `wordCount` from success output, and returns `rawSeed` instead

Current mnemonic commands:

```sh
railgunners mnemonic generate
railgunners mnemonic generate --words 24 --json
railgunners mnemonic validate --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
railgunners mnemonic seed --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --show-secrets --json
```

Notes:

- `generate` supports `--words` values `12`, `15`, `18`, `21`, and `24`
- `validate` prints `valid` on success and exits non-zero on failure
- `seed` requires `--show-secrets` so secret-bearing output is always explicit
- `--json` emits stable machine-readable output for scripting

Current key commands:

```sh
railgunners keys derive --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --index 0 --show-secrets --json
railgunners keys derive --raw-seed "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4" --index 0 --show-secrets --json
railgunners keys inspect-viewing-private --private-key "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef" --json
railgunners keys inspect-spending-private --private-key "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef" --json
railgunners keys inspect-master-public --spending-public-key-x "15684838006997671713939066069845237677934334329285343229142447933587909549584" --spending-public-key-y "11878614856120328179849762231924033298788609151532558727282528569229552954628" --nullifying-key "8368299126798249740586535953124199418524409103803955764525436743456763691384" --json
```

Notes:

- `keys derive` uses canonical Railgun wallet paths for the requested `--index`
- `keys derive` defaults `--index` to `0`
- `keys derive` requires exactly one of `--mnemonic` or `--raw-seed`
- `keys derive` requires `--show-secrets` because it emits private keys
- `keys derive` also emits `packedSpendingPublicKey` so it can feed `viewing-key encode`
- `address search --seed-mode raw` output can be ingested directly with `keys derive --raw-seed`
- `inspect-viewing-private` derives `viewingPublicKey` and `nullifyingKey`
- `inspect-spending-private` derives `spendingPublicKey`
- `inspect-master-public` derives `masterPublicKey` from decimal public inputs

Current shareable viewing key commands:

```sh
railgunners viewing-key encode --viewing-private-key "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef" --packed-spending-public-key "eb68b98efb30b4c3beccfd1776fb0f92bfaf9fef89bc0c54dd4cb76c21b8741b" --show-secrets --json
railgunners viewing-key decode --shareable-viewing-key "82a576privc42067d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599efa473707562c420eb68b98efb30b4c3beccfd1776fb0f92bfaf9fef89bc0c54dd4cb76c21b8741b" --show-secrets --json
railgunners viewing-key decode --shareable-viewing-key "82a576privc42067d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599efa473707562c420eb68b98efb30b4c3beccfd1776fb0f92bfaf9fef89bc0c54dd4cb76c21b8741b" --chain-type 0 --chain-id 1 --show-secrets --json
```

Notes:

- `viewing-key decode` defaults address derivation to the all-chains `0zk` scope
- pass both `--chain-type` and `--chain-id` to derive a chain-scoped address instead
- both `encode` and `decode` require `--show-secrets` because shareable viewing keys contain the viewing private key
- decoded output includes packed and unpacked spending public key data, plus derived viewing-key and address fields

## Status

This is early-stage infrastructure work. The focus right now is on architectural clarity, crate boundaries, and contribution rules before implementing issue-driven functionality.
