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

## Status

This is early-stage infrastructure work. The focus right now is on architectural clarity, crate boundaries, and contribution rules before implementing issue-driven functionality.
